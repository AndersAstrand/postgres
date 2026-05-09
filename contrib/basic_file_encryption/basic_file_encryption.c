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
static void bfe_encrypt_page(const FileEncryptionModuleState *state,
							 const RelFileLocator *locator,
							 ForkNumber fork, BlockNumber blocknum,
							 const char *src, char *dst);
static void bfe_decrypt_page(const FileEncryptionModuleState *state,
							 const RelFileLocator *locator,
							 ForkNumber fork, BlockNumber blocknum,
							 const char *src, char *dst);

/*
 * Module callbacks.  Mutable so _PG_file_encryption_module_init can switch
 * page-level encryption on or off based on the cluster's
 * GetPageReservedSize() — that way the same module supports clusters that
 * are encrypting only spill/BufFile (reserved = 0) and clusters that also
 * encrypt relation pages (reserved = BFE_PAGE_TRAILER_SIZE).
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
	 * Adapt to the cluster's reservation: register the page callbacks only
	 * when initdb reserved exactly BFE_PAGE_TRAILER_SIZE bytes.  When the
	 * cluster reserved zero bytes, run as a record-stream-only module
	 * (BufFile and reorderbuffer spill); when it reserved a different size,
	 * leave the page callbacks unset so load_and_validate_module raises a
	 * clear "requires N bytes, cluster has M" error.
	 */
	if (cluster_reserved == BFE_PAGE_TRAILER_SIZE)
	{
		basic_file_encryption_callbacks.page_reserved_size = BFE_PAGE_TRAILER_SIZE;
		basic_file_encryption_callbacks.encrypt_page_cb = bfe_encrypt_page;
		basic_file_encryption_callbacks.decrypt_page_cb = bfe_decrypt_page;
	}

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
 * Build the AAD blob bound to a single record: the file's salt followed
 * by the record's logical file offset (big-endian, so it's
 * platform-portable).  Returns the AAD length.
 */
static int
bfe_build_aad(const BasicFileEncryptionFilePrivate *file_priv,
			  uint64 file_offset,
			  unsigned char *aad)
{
	memcpy(aad, file_priv->salt, BFE_SALT_LEN);
	for (int i = 0; i < 8; i++)
		aad[BFE_SALT_LEN + i] = (unsigned char) (file_offset >> ((7 - i) * 8));
	return BFE_SALT_LEN + 8;
}

static void
bfe_encrypt(const FileEncryptionModuleState *state,
			FileEncryptionFileState *fstate,
			const char *path, uint64 file_offset,
			const char *data, Size data_len,
			StringInfo dst)
{
	BasicFileEncryptionState *priv = bfe_require_key(state);
	BasicFileEncryptionFilePrivate *file_priv = fstate->private_data;
	EVP_CIPHER_CTX *ctx;
	unsigned char iv[BFE_IV_LEN];
	unsigned char tag[BFE_TAG_LEN];
	unsigned char aad[BFE_SALT_LEN + 8];
	int			aad_len;
	int			outlen;
	int			finallen;

	if (!pg_strong_random(iv, sizeof(iv)))
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("basic_file_encryption: could not generate IV")));

	aad_len = bfe_build_aad(file_priv, file_offset, aad);

	enlargeStringInfo(dst, BFE_IV_LEN + (int) data_len + BFE_TAG_LEN);

	memcpy(dst->data + dst->len, iv, BFE_IV_LEN);
	dst->len += BFE_IV_LEN;

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

		/* Bind the file's salt and the record's offset as AAD. */
		if (EVP_EncryptUpdate(ctx, NULL, &outlen, aad, aad_len) != 1)
			bfe_openssl_error("EVP_EncryptUpdate (AAD)");

		if (EVP_EncryptUpdate(ctx,
							  (unsigned char *) dst->data + dst->len, &outlen,
							  (const unsigned char *) data, (int) data_len) != 1)
			bfe_openssl_error("EVP_EncryptUpdate");
		dst->len += outlen;

		if (EVP_EncryptFinal_ex(ctx,
								(unsigned char *) dst->data + dst->len,
								&finallen) != 1)
			bfe_openssl_error("EVP_EncryptFinal_ex");
		dst->len += finallen;

		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, BFE_TAG_LEN, tag) != 1)
			bfe_openssl_error("EVP_CTRL_GCM_GET_TAG");
	}
	PG_FINALLY();
	{
		EVP_CIPHER_CTX_free(ctx);
	}
	PG_END_TRY();

	memcpy(dst->data + dst->len, tag, BFE_TAG_LEN);
	dst->len += BFE_TAG_LEN;
	dst->data[dst->len] = '\0';
}

static void
bfe_decrypt(const FileEncryptionModuleState *state,
			FileEncryptionFileState *fstate,
			const char *path, uint64 file_offset,
			const char *data, Size data_len,
			StringInfo dst)
{
	BasicFileEncryptionState *priv = bfe_require_key(state);
	BasicFileEncryptionFilePrivate *file_priv = fstate->private_data;
	EVP_CIPHER_CTX *ctx;
	const unsigned char *iv;
	const unsigned char *ciphertext;
	const unsigned char *tag;
	unsigned char aad[BFE_SALT_LEN + 8];
	int			aad_len;
	Size		ciphertext_len;
	int			outlen;
	int			finallen;

	if (data_len < BFE_IV_LEN + BFE_TAG_LEN)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("basic_file_encryption: encrypted record is too short (%zu bytes)",
						data_len)));

	iv = (const unsigned char *) data;
	ciphertext = iv + BFE_IV_LEN;
	ciphertext_len = data_len - BFE_IV_LEN - BFE_TAG_LEN;
	tag = ciphertext + ciphertext_len;

	aad_len = bfe_build_aad(file_priv, file_offset, aad);

	enlargeStringInfo(dst, (int) ciphertext_len);

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

		if (EVP_DecryptUpdate(ctx, NULL, &outlen, aad, aad_len) != 1)
			bfe_openssl_error("EVP_DecryptUpdate (AAD)");

		if (EVP_DecryptUpdate(ctx,
							  (unsigned char *) dst->data + dst->len, &outlen,
							  ciphertext, (int) ciphertext_len) != 1)
			bfe_openssl_error("EVP_DecryptUpdate");
		dst->len += outlen;

		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
								BFE_TAG_LEN, (void *) tag) != 1)
			bfe_openssl_error("EVP_CTRL_GCM_SET_TAG");

		if (EVP_DecryptFinal_ex(ctx,
								(unsigned char *) dst->data + dst->len,
								&finallen) != 1)
			ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg("basic_file_encryption: authentication tag verification failed"),
					 errdetail("File contents may have been tampered with, or the key has changed.")));
		dst->len += finallen;
	}
	PG_FINALLY();
	{
		EVP_CIPHER_CTX_free(ctx);
	}
	PG_END_TRY();

	dst->data[dst->len] = '\0';
}

/*
 * Build the AAD blob bound to a relation page: relNumber || fork ||
 * blocknum, big-endian for portability.
 *
 * Notably, dbOid and spcOid are *not* included.  CREATE DATABASE with the
 * default FILE_COPY strategy clones a source database's catalog files
 * byte-for-byte into the new database's directory; binding dbOid (or
 * spcOid, which can change with ALTER DATABASE ... SET TABLESPACE) into
 * the AAD would make those pages undecryptable in the new location.  We
 * accept the weaker binding — pages remain swappable between databases
 * if their relNumber happens to match — to keep file-level operations
 * working transparently.
 */
static int
bfe_build_page_aad(const RelFileLocator *locator, ForkNumber fork,
				   BlockNumber blocknum, unsigned char *aad)
{
	int			off = 0;

	for (int i = 0; i < 8; i++)
		aad[off++] = (unsigned char) (locator->relNumber >> ((7 - i) * 8));
	for (int i = 0; i < 4; i++)
		aad[off++] = (unsigned char) (((uint32) fork) >> ((3 - i) * 8));
	for (int i = 0; i < 4; i++)
		aad[off++] = (unsigned char) (blocknum >> ((3 - i) * 8));

	return off;
}

/*
 * Encrypt a relation page with AES-256-GCM.  Lays out the trailer at
 * the tail of dst as documented at the top of this file.
 */
static void
bfe_encrypt_page(const FileEncryptionModuleState *state,
				 const RelFileLocator *locator,
				 ForkNumber fork, BlockNumber blocknum,
				 const char *src, char *dst)
{
	BasicFileEncryptionState *priv = bfe_require_key(state);
	EVP_CIPHER_CTX *ctx;
	unsigned char iv[BFE_IV_LEN];
	unsigned char tag[BFE_TAG_LEN];
	unsigned char aad[24];
	int			aad_len;
	int			outlen;
	int			finallen;

	if (!pg_strong_random(iv, sizeof(iv)))
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("basic_file_encryption: could not generate page IV")));

	aad_len = bfe_build_page_aad(locator, fork, blocknum, aad);
	Assert(aad_len <= (int) sizeof(aad));

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

		if (EVP_EncryptUpdate(ctx, NULL, &outlen, aad, aad_len) != 1)
			bfe_openssl_error("EVP_EncryptUpdate (AAD)");

		if (EVP_EncryptUpdate(ctx,
							  (unsigned char *) dst, &outlen,
							  (const unsigned char *) src,
							  BFE_PAGE_BODY_SIZE) != 1)
			bfe_openssl_error("EVP_EncryptUpdate");
		Assert(outlen == BFE_PAGE_BODY_SIZE);

		if (EVP_EncryptFinal_ex(ctx,
								(unsigned char *) dst + outlen,
								&finallen) != 1)
			bfe_openssl_error("EVP_EncryptFinal_ex");
		Assert(finallen == 0);

		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, BFE_TAG_LEN, tag) != 1)
			bfe_openssl_error("EVP_CTRL_GCM_GET_TAG");
	}
	PG_FINALLY();
	{
		EVP_CIPHER_CTX_free(ctx);
	}
	PG_END_TRY();

	memcpy(dst + BFE_PAGE_BODY_SIZE + BFE_PAGE_IV_OFFSET, iv, BFE_IV_LEN);
	memcpy(dst + BFE_PAGE_BODY_SIZE + BFE_PAGE_TAG_OFFSET, tag, BFE_TAG_LEN);
	/* Zero any reserved-but-unused bytes in the trailer. */
	memset(dst + BFE_PAGE_BODY_SIZE + BFE_PAGE_TAG_OFFSET + BFE_TAG_LEN, 0,
		   BFE_PAGE_TRAILER_SIZE - BFE_TAG_LEN - BFE_IV_LEN);
}

/*
 * Decrypt a relation page.  Verifies the auth tag (rejects tampering
 * and wrong-key reads), and zeros the trailer in dst per the
 * file_encryption.h contract.
 */
static void
bfe_decrypt_page(const FileEncryptionModuleState *state,
				 const RelFileLocator *locator,
				 ForkNumber fork, BlockNumber blocknum,
				 const char *src, char *dst)
{
	BasicFileEncryptionState *priv = bfe_require_key(state);
	EVP_CIPHER_CTX *ctx;
	const unsigned char *iv;
	unsigned char tag[BFE_TAG_LEN];
	unsigned char aad[24];
	int			aad_len;
	int			outlen;
	int			finallen;

	iv = (const unsigned char *) src + BFE_PAGE_BODY_SIZE + BFE_PAGE_IV_OFFSET;
	memcpy(tag, src + BFE_PAGE_BODY_SIZE + BFE_PAGE_TAG_OFFSET, BFE_TAG_LEN);

	aad_len = bfe_build_page_aad(locator, fork, blocknum, aad);
	Assert(aad_len <= (int) sizeof(aad));

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

		if (EVP_DecryptUpdate(ctx, NULL, &outlen, aad, aad_len) != 1)
			bfe_openssl_error("EVP_DecryptUpdate (AAD)");

		if (EVP_DecryptUpdate(ctx,
							  (unsigned char *) dst, &outlen,
							  (const unsigned char *) src,
							  BFE_PAGE_BODY_SIZE) != 1)
			bfe_openssl_error("EVP_DecryptUpdate");
		Assert(outlen == BFE_PAGE_BODY_SIZE);

		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
								BFE_TAG_LEN, tag) != 1)
			bfe_openssl_error("EVP_CTRL_GCM_SET_TAG");

		if (EVP_DecryptFinal_ex(ctx,
								(unsigned char *) dst + outlen,
								&finallen) != 1)
			ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg("basic_file_encryption: page authentication tag verification failed"),
					 errdetail("Page (rel %u, fork %d, block %u) was tampered with, or the key has changed.",
							   locator->relNumber, fork, blocknum)));
		Assert(finallen == 0);
	}
	PG_FINALLY();
	{
		EVP_CIPHER_CTX_free(ctx);
	}
	PG_END_TRY();

	/* Zero the trailer in plaintext, per the file_encryption.h contract. */
	memset(dst + BFE_PAGE_BODY_SIZE, 0, BFE_PAGE_TRAILER_SIZE);
}
