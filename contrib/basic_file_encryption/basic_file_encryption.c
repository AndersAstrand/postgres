/*-------------------------------------------------------------------------
 *
 * basic_file_encryption.c
 *	  Reference implementation of a file encryption module.
 *
 * Encrypts each record with AES-256-GCM using a server-wide hex-encoded key
 * configured through the basic_file_encryption.key GUC.  A fresh 12-byte IV
 * is generated at random for every record and prepended to the ciphertext;
 * the 16-byte GCM authentication tag is appended.  The on-disk layout of a
 * single encrypted record is therefore:
 *
 *	  [ IV  12 bytes ] [ ciphertext N bytes ] [ tag  16 bytes ]
 *
 * Authentication-tag verification on decrypt detects tampering and key
 * mismatch.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * contrib/basic_file_encryption/basic_file_encryption.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include <openssl/err.h>
#include <openssl/evp.h>

#include "access/xlog.h"
#include "fmgr.h"
#include "lib/stringinfo.h"
#include "port.h"
#include "storage/file_encryption.h"
#include "utils/builtins.h"
#include "utils/guc.h"

PG_MODULE_MAGIC;

#define BFE_KEY_LEN			32
#define BFE_IV_LEN			12
#define BFE_TAG_LEN			16

/*
 * Per-page trailer layout (when basic_file_encryption is configured for
 * page-level encryption via --file-encryption-page-reserved-size=32):
 *
 *	  bytes [0..11]:   IV     (12 bytes, fresh per encrypt)
 *	  bytes [12..27]:  tag    (16 bytes, GCM auth tag)
 *	  bytes [28..31]:  unused (zero-padded; reserved for future use)
 *
 * Total: 32 bytes, aligned to MAXIMUM_ALIGNOF.  The cluster's
 * --file-encryption-page-reserved-size must match BFE_PAGE_TRAILER_SIZE.
 */
#define BFE_PAGE_TRAILER_SIZE	32
#define BFE_PAGE_BODY_SIZE		(BLCKSZ - BFE_PAGE_TRAILER_SIZE)
#define BFE_PAGE_IV_OFFSET		0
#define BFE_PAGE_TAG_OFFSET		BFE_IV_LEN

/*
 * Per-file header: a 4-byte magic plus a random salt that is authenticated
 * as AEAD additional data for every record.  That binds each ciphertext
 * record to the file whose header was present when it was encrypted.
 *
 * IV uniqueness comes from the fresh random 96-bit IV generated per record.
 */
#define BFE_HEADER_MAGIC	0x42464531	/* "BFE1" */
#define BFE_SALT_LEN		BFE_IV_LEN
#define BFE_HEADER_SIZE		(sizeof(uint32) + BFE_SALT_LEN)

typedef struct BasicFileEncryptionState
{
	unsigned char key[BFE_KEY_LEN];
} BasicFileEncryptionState;

typedef struct BasicFileEncryptionFilePrivate
{
	unsigned char salt[BFE_SALT_LEN];
} BasicFileEncryptionFilePrivate;

/* GUC */
static char *basic_file_encryption_key = NULL;

static void bfe_startup(FileEncryptionModuleState *state);
static void bfe_shutdown(FileEncryptionModuleState *state);
static void bfe_init_file(const FileEncryptionModuleState *state,
						  FileEncryptionFileState *fstate,
						  const char *path,
						  char *header);
static void bfe_open_file(const FileEncryptionModuleState *state,
						  FileEncryptionFileState *fstate,
						  const char *path,
						  const char *header);
static void bfe_close_file(const FileEncryptionModuleState *state,
						   FileEncryptionFileState *fstate);
static void bfe_encrypt(const FileEncryptionModuleState *state,
						FileEncryptionFileState *fstate,
						const char *path, uint64 file_offset,
						const char *data, Size data_len,
						StringInfo dst);
static void bfe_decrypt(const FileEncryptionModuleState *state,
						FileEncryptionFileState *fstate,
						const char *path, uint64 file_offset,
						const char *data, Size data_len,
						StringInfo dst);

/*
 * Module callbacks.  Mutable so _PG_file_encryption_module_init can switch
 * page-level encryption on or off based on the cluster's
 * GetPageReservedSize() — the unified encrypt_cb / decrypt_cb run for both
 * record streams (BufFile / spill files; fstate != NULL) and relation
 * pages (fstate == NULL); turning page mode on means setting
 * page_reserved_size to BFE_PAGE_TRAILER_SIZE so the bfe_encrypt /
 * bfe_decrypt page-mode branch is reachable.
 */
static FileEncryptionCallbacks basic_file_encryption_callbacks = {
	PG_FILE_ENCRYPTION_MAGIC,
	.file_header_size = BFE_HEADER_SIZE,

	.startup_cb = bfe_startup,
	.shutdown_cb = bfe_shutdown,
	.init_file_cb = bfe_init_file,
	.open_file_cb = bfe_open_file,
	.close_file_cb = bfe_close_file,
	.encrypt_cb = bfe_encrypt,
	.decrypt_cb = bfe_decrypt,
};

/*
 * GUC check hook: validate that the configured key is exactly
 * BFE_KEY_LEN * 2 hex characters.
 */
static bool
check_key(char **newval, void **extra, GucSource source)
{
	const char *str = *newval;

	if (str == NULL || *str == '\0')
		return true;			/* unset; module load will reject later */

	if (strlen(str) != BFE_KEY_LEN * 2)
	{
		GUC_check_errdetail("basic_file_encryption.key must be %d hex characters (got %zu).",
							BFE_KEY_LEN * 2, strlen(str));
		return false;
	}

	for (const char *p = str; *p; p++)
	{
		if (!isxdigit((unsigned char) *p))
		{
			GUC_check_errdetail("basic_file_encryption.key must contain only hexadecimal digits.");
			return false;
		}
	}

	return true;
}

void
_PG_init(void)
{
	DefineCustomStringVariable("basic_file_encryption.key",
							   "Hex-encoded 256-bit AES key used to encrypt files.",
							   NULL,
							   &basic_file_encryption_key,
							   "",
							   PGC_POSTMASTER,
							   GUC_SUPERUSER_ONLY,
							   check_key, NULL, NULL);

	MarkGUCPrefixReserved("basic_file_encryption");
}

const FileEncryptionCallbacks *
_PG_file_encryption_module_init(void)
{
	uint32		cluster_reserved = GetPageReservedSize();

	/*
	 * Adapt to the cluster's reservation: opt into page encryption only
	 * when initdb reserved exactly BFE_PAGE_TRAILER_SIZE bytes.  When the
	 * cluster reserved zero bytes, leave page_reserved_size at zero and
	 * run as a record-stream-only module (BufFile and reorderbuffer
	 * spill).  When it reserved a different non-zero size, advertise the
	 * size we want so load_and_validate_module can raise a clear
	 * "requires N bytes, cluster has M" error.
	 */
	if (cluster_reserved == BFE_PAGE_TRAILER_SIZE)
		basic_file_encryption_callbacks.page_reserved_size = BFE_PAGE_TRAILER_SIZE;

	return &basic_file_encryption_callbacks;
}

/*
 * Decode the configured hex key into the per-process state.  When the key
 * is unset, leave private_data NULL and defer the error to the first
 * encrypt/decrypt call — running ereport(ERROR) here would prevent the
 * postmaster from starting at all, which makes mis-configurations harder
 * to recover from than failing only when encryption is actually used.
 */
static void
bfe_startup(FileEncryptionModuleState *state)
{
	BasicFileEncryptionState *priv;
	uint64		decoded;

	if (basic_file_encryption_key == NULL ||
		basic_file_encryption_key[0] == '\0')
	{
		state->private_data = NULL;
		return;
	}

	priv = palloc0_object(BasicFileEncryptionState);

	/* check_key already validated length and alphabet, so hex_decode won't fail. */
	decoded = hex_decode(basic_file_encryption_key,
						 strlen(basic_file_encryption_key),
						 (char *) priv->key);
	Assert(decoded == BFE_KEY_LEN);
	(void) decoded;

	state->private_data = priv;
}

/*
 * Resolve the per-process key, raising the deferred "key not set" error if
 * bfe_startup didn't manage to decode one.  Called at the top of every
 * encrypt/decrypt entry point.
 */
static inline BasicFileEncryptionState *
bfe_require_key(const FileEncryptionModuleState *state)
{
	BasicFileEncryptionState *priv = state->private_data;

	if (priv == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("basic_file_encryption.key is not set")));
	return priv;
}

static void
bfe_shutdown(FileEncryptionModuleState *state)
{
	BasicFileEncryptionState *priv = state->private_data;

	if (priv != NULL)
	{
		explicit_bzero(priv->key, sizeof(priv->key));
		pfree(priv);
		state->private_data = NULL;
	}
}

/*
 * Raise an error using the latest queued OpenSSL error, if any.
 */
static pg_noreturn void
bfe_openssl_error(const char *op)
{
	unsigned long e = ERR_get_error();
	char		buf[256];

	if (e == 0)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("basic_file_encryption: %s failed", op)));

	ERR_error_string_n(e, buf, sizeof(buf));
	ereport(ERROR,
			(errcode(ERRCODE_INTERNAL_ERROR),
			 errmsg("basic_file_encryption: %s failed: %s", op, buf)));
}

/*
 * Initialize a fresh file: generate a random salt and write the on-disk
 * header.  The salt becomes part of the AAD on every record encrypted
 * for this file, so swapping records between files (under the same key)
 * is rejected by AES-GCM's tag check.
 */
static void
bfe_init_file(const FileEncryptionModuleState *state,
			  FileEncryptionFileState *fstate,
			  const char *path,
			  char *header)
{
	BasicFileEncryptionFilePrivate *priv;
	uint32		magic = BFE_HEADER_MAGIC;

	priv = palloc0_object(BasicFileEncryptionFilePrivate);

	if (!pg_strong_random(priv->salt, sizeof(priv->salt)))
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("basic_file_encryption: could not generate file salt")));

	memcpy(header, &magic, sizeof(magic));
	memcpy(header + sizeof(magic), priv->salt, sizeof(priv->salt));

	fstate->private_data = priv;
}

static void
bfe_open_file(const FileEncryptionModuleState *state,
			  FileEncryptionFileState *fstate,
			  const char *path,
			  const char *header)
{
	BasicFileEncryptionFilePrivate *priv;
	uint32		magic;

	memcpy(&magic, header, sizeof(magic));
	if (magic != BFE_HEADER_MAGIC)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("basic_file_encryption: bad header magic in \"%s\"",
						path),
				 errdetail("Expected %#x, got %#x.",
						   BFE_HEADER_MAGIC, magic)));

	priv = palloc0_object(BasicFileEncryptionFilePrivate);
	memcpy(priv->salt, header + sizeof(magic), sizeof(priv->salt));
	fstate->private_data = priv;
}

static void
bfe_close_file(const FileEncryptionModuleState *state,
			   FileEncryptionFileState *fstate)
{
	if (fstate->private_data != NULL)
	{
		explicit_bzero(fstate->private_data,
					   sizeof(BasicFileEncryptionFilePrivate));
		pfree(fstate->private_data);
		fstate->private_data = NULL;
	}
}

/*
 * Mix the AAD bytes into an EVP cipher context.  The AAD differs by mode:
 *
 *   record mode (fstate != NULL): per-file salt || file_offset(be64)
 *	   The salt is generated once per file (init_file_cb) and persisted in
 *	   the per-file header, so a record from one file doesn't decrypt
 *	   when substituted into another (even at the same offset, even
 *	   under the same key).
 *
 *   page mode (fstate == NULL):   filename(basename) || file_offset(be64)
 *	   Only the relation file's basename is bound, NOT the full path.
 *	   relpath() formats paths as e.g. "base/<dboid>/<relfilenode>" or
 *	   "pg_tblspc/<spcoid>/<dboid>/<relfilenode>" — the leading
 *	   directories carry dbOid and spcOid, both of which can change for
 *	   the same on-disk page bytes (CREATE DATABASE's FILE_COPY strategy
 *	   clones a database directory byte-for-byte; ALTER DATABASE ... SET
 *	   TABLESPACE moves files across spcOid trees).  Binding only the
 *	   basename ("<relfilenode>", "<relfilenode>.<segno>",
 *	   "<relfilenode>_fsm", ...) keeps the AAD invariant under those
 *	   operations while still preventing cross-relation page substitution
 *	   within a database.
 *
 * Either way, EVP_*Update with the same AAD bytes yields the same tag.
 */
static void
bfe_aad_update(EVP_CIPHER_CTX *ctx, bool encrypting,
			   FileEncryptionFileState *fstate,
			   const char *path, uint64 file_offset)
{
	int			outlen;
	unsigned char offset_be[8];
	int (*update) (EVP_CIPHER_CTX *, unsigned char *, int *,
				   const unsigned char *, int);

	update = encrypting ? EVP_EncryptUpdate : EVP_DecryptUpdate;

	if (fstate != NULL)
	{
		BasicFileEncryptionFilePrivate *file_priv = fstate->private_data;

		if (update(ctx, NULL, &outlen, file_priv->salt, BFE_SALT_LEN) != 1)
			bfe_openssl_error("AAD salt update");
	}
	else
	{
		const char *basename = strrchr(path, '/');

		basename = basename ? basename + 1 : path;
		if (update(ctx, NULL, &outlen,
				   (const unsigned char *) basename, (int) strlen(basename)) != 1)
			bfe_openssl_error("AAD path update");
	}

	for (int i = 0; i < 8; i++)
		offset_be[i] = (unsigned char) (file_offset >> ((7 - i) * 8));
	if (update(ctx, NULL, &outlen, offset_be, 8) != 1)
		bfe_openssl_error("AAD offset update");
}

/*
 * Encrypt one record or one page with AES-256-GCM.
 *
 *   record mode (fstate != NULL): produces IV(12) || ciphertext(data_len)
 *	   || tag(16) into dst, growing dst as needed.
 *
 *   page mode (fstate == NULL): caller passes data_len == BLCKSZ; we
 *	   encrypt the first BFE_PAGE_BODY_SIZE bytes of data into the same
 *	   prefix of dst, then place IV / tag / zero-padding in the trailing
 *	   BFE_PAGE_TRAILER_SIZE bytes.  dst->len comes out exactly BLCKSZ.
 */
static void
bfe_encrypt(const FileEncryptionModuleState *state,
			FileEncryptionFileState *fstate,
			const char *path, uint64 file_offset,
			const char *data, Size data_len,
			StringInfo dst)
{
	BasicFileEncryptionState *priv = bfe_require_key(state);
	EVP_CIPHER_CTX *ctx;
	unsigned char iv[BFE_IV_LEN];
	unsigned char tag[BFE_TAG_LEN];
	int			outlen;
	int			finallen;
	bool		page_mode = (fstate == NULL);
	int			body_len;

	if (!pg_strong_random(iv, sizeof(iv)))
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("basic_file_encryption: could not generate IV")));

	if (page_mode)
	{
		Assert(data_len == BLCKSZ);
		body_len = BFE_PAGE_BODY_SIZE;
		enlargeStringInfo(dst, BLCKSZ);
	}
	else
	{
		body_len = (int) data_len;
		enlargeStringInfo(dst, BFE_IV_LEN + body_len + BFE_TAG_LEN);
		/* Record-mode layout puts IV at the start of dst. */
		memcpy(dst->data + dst->len, iv, BFE_IV_LEN);
		dst->len += BFE_IV_LEN;
	}

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		bfe_openssl_error("EVP_CIPHER_CTX_new");

	PG_TRY();
	{
		if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
			bfe_openssl_error("EVP_EncryptInit_ex");
		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, BFE_IV_LEN, NULL) != 1)
			bfe_openssl_error("EVP_CTRL_GCM_SET_IVLEN");
		if (EVP_EncryptInit_ex(ctx, NULL, NULL, priv->key, iv) != 1)
			bfe_openssl_error("EVP_EncryptInit_ex (key/iv)");

		bfe_aad_update(ctx, true, fstate, path, file_offset);

		if (EVP_EncryptUpdate(ctx,
							  (unsigned char *) dst->data + dst->len, &outlen,
							  (const unsigned char *) data, body_len) != 1)
			bfe_openssl_error("EVP_EncryptUpdate");
		Assert(outlen == body_len);
		dst->len += outlen;

		if (EVP_EncryptFinal_ex(ctx,
								(unsigned char *) dst->data + dst->len,
								&finallen) != 1)
			bfe_openssl_error("EVP_EncryptFinal_ex");
		Assert(finallen == 0);
		dst->len += finallen;

		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, BFE_TAG_LEN, tag) != 1)
			bfe_openssl_error("EVP_CTRL_GCM_GET_TAG");
	}
	PG_FINALLY();
	{
		EVP_CIPHER_CTX_free(ctx);
	}
	PG_END_TRY();

	if (page_mode)
	{
		/* Lay out the trailer: IV || tag || zero pad. */
		memcpy(dst->data + BFE_PAGE_BODY_SIZE + BFE_PAGE_IV_OFFSET,
			   iv, BFE_IV_LEN);
		memcpy(dst->data + BFE_PAGE_BODY_SIZE + BFE_PAGE_TAG_OFFSET,
			   tag, BFE_TAG_LEN);
		memset(dst->data + BFE_PAGE_BODY_SIZE + BFE_PAGE_TAG_OFFSET + BFE_TAG_LEN,
			   0, BFE_PAGE_TRAILER_SIZE - BFE_IV_LEN - BFE_TAG_LEN);
		dst->len = BLCKSZ;
	}
	else
	{
		memcpy(dst->data + dst->len, tag, BFE_TAG_LEN);
		dst->len += BFE_TAG_LEN;
	}
	dst->data[dst->len] = '\0';
}

/*
 * Decrypt one record or one page with AES-256-GCM.
 *
 *   record mode (fstate != NULL): expects data to be IV(12) ||
 *	   ciphertext(N) || tag(16); writes the N decrypted plaintext bytes
 *	   into dst.
 *
 *   page mode (fstate == NULL): expects data_len == BLCKSZ; the IV and
 *	   tag live in the trailing BFE_PAGE_TRAILER_SIZE bytes; the body is
 *	   data[0..BFE_PAGE_BODY_SIZE).  On success dst->len is exactly
 *	   BLCKSZ, with the trailing BFE_PAGE_TRAILER_SIZE bytes of dst
 *	   zeroed (per the file_encryption.h contract: plaintext pages have
 *	   zero trailers so pd_checksum verifies on the read side).
 *
 * On tag-verification failure, raises ERRCODE_DATA_CORRUPTED.
 */
static void
bfe_decrypt(const FileEncryptionModuleState *state,
			FileEncryptionFileState *fstate,
			const char *path, uint64 file_offset,
			const char *data, Size data_len,
			StringInfo dst)
{
	BasicFileEncryptionState *priv = bfe_require_key(state);
	EVP_CIPHER_CTX *ctx;
	const unsigned char *iv;
	const unsigned char *ciphertext;
	unsigned char tag[BFE_TAG_LEN];
	int			outlen;
	int			finallen;
	bool		page_mode = (fstate == NULL);
	int			ciphertext_len;

	if (page_mode)
	{
		if (data_len != BLCKSZ)
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("basic_file_encryption: page-mode decrypt got %zu bytes, expected %d",
							data_len, BLCKSZ)));
		ciphertext_len = BFE_PAGE_BODY_SIZE;
		ciphertext = (const unsigned char *) data;
		iv = (const unsigned char *) data + BFE_PAGE_BODY_SIZE +
			BFE_PAGE_IV_OFFSET;
		memcpy(tag, data + BFE_PAGE_BODY_SIZE + BFE_PAGE_TAG_OFFSET,
			   BFE_TAG_LEN);

		enlargeStringInfo(dst, BLCKSZ);
	}
	else
	{
		if (data_len < BFE_IV_LEN + BFE_TAG_LEN)
			ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg("basic_file_encryption: encrypted record is too short (%zu bytes)",
							data_len)));
		iv = (const unsigned char *) data;
		ciphertext = iv + BFE_IV_LEN;
		ciphertext_len = (int) (data_len - BFE_IV_LEN - BFE_TAG_LEN);
		memcpy(tag, ciphertext + ciphertext_len, BFE_TAG_LEN);

		enlargeStringInfo(dst, ciphertext_len);
	}

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		bfe_openssl_error("EVP_CIPHER_CTX_new");

	PG_TRY();
	{
		if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
			bfe_openssl_error("EVP_DecryptInit_ex");
		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, BFE_IV_LEN, NULL) != 1)
			bfe_openssl_error("EVP_CTRL_GCM_SET_IVLEN");
		if (EVP_DecryptInit_ex(ctx, NULL, NULL, priv->key, iv) != 1)
			bfe_openssl_error("EVP_DecryptInit_ex (key/iv)");

		bfe_aad_update(ctx, false, fstate, path, file_offset);

		if (EVP_DecryptUpdate(ctx,
							  (unsigned char *) dst->data + dst->len, &outlen,
							  ciphertext, ciphertext_len) != 1)
			bfe_openssl_error("EVP_DecryptUpdate");
		Assert(outlen == ciphertext_len);
		dst->len += outlen;

		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
								BFE_TAG_LEN, tag) != 1)
			bfe_openssl_error("EVP_CTRL_GCM_SET_TAG");

		if (EVP_DecryptFinal_ex(ctx,
								(unsigned char *) dst->data + dst->len,
								&finallen) != 1)
			ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg("basic_file_encryption: authentication tag verification failed"),
					 errdetail("Path \"%s\" offset %llu was tampered with, or the key has changed.",
							   path, (unsigned long long) file_offset)));
		Assert(finallen == 0);
		dst->len += finallen;
	}
	PG_FINALLY();
	{
		EVP_CIPHER_CTX_free(ctx);
	}
	PG_END_TRY();

	if (page_mode)
	{
		/* Zero the trailer per the file_encryption.h contract. */
		memset(dst->data + BFE_PAGE_BODY_SIZE, 0, BFE_PAGE_TRAILER_SIZE);
		dst->len = BLCKSZ;
	}
	dst->data[dst->len] = '\0';
}

