/*-------------------------------------------------------------------------
 *
 * basic_file_encryption.c
 *	  Reference implementation of a file encryption module.
 *
 * Uses the hex-encoded key configured through the
 * basic_file_encryption.key GUC as a key-encryption key.  Each encryption
 * call gets a fresh 256-bit data-encryption key, which encrypts the
 * caller's plaintext with AES-256-GCM.  The data key is then wrapped with
 * AES-256-GCM under the configured key and stored in the trailer.  The
 * configured key therefore never encrypts relation or spill-file bytes
 * directly.
 *
 * The on-disk layout the module produces is the same regardless of who's
 * calling (BufFile, reorderbuffer spill, md.c relation pages):
 *
 *	  [ ciphertext N bytes ]
 *	  [ data IV 12 bytes ] [ data tag 16 bytes ]
 *	  [ wrap IV 12 bytes ] [ wrapped data key 32 bytes ]
 *	  [ wrap tag 16 bytes ] [ format 4 bytes ] [ pad 4 bytes ]
 *
 * The 4 bytes of zero padding bring the per-call overhead to 96, which is
 * a multiple of MAXIMUM_ALIGNOF and is therefore a legal value for the
 * cluster's --file-encryption-page-reserved-size.
 *
 * AAD = basename(path) || file_offset(be64).  Using only the basename
 * (not the full path) keeps CREATE DATABASE FILE_COPY and ALTER DATABASE
 * SET TABLESPACE working — both clone files into a directory whose
 * leading components carry dbOid / spcOid that change for the same
 * on-disk bytes.  The basename ("<relfilenode>[.<seg>]" for relation
 * files; "<xid>-<lsn>.snap" for reorderbuffer spill files; the segment
 * basename for BufFile) stays invariant under those operations while
 * still preventing cross-relation page substitution within a database.
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
#define BFE_FORMAT_MAGIC	0x31454642	/* "BFE1" in native byte order */

/*
 * Per-call ciphertext overhead.  Equal to a data-encryption IV/tag, a
 * wrapped data-encryption key with its own IV/tag, a format marker, and
 * zero padding so the overhead is a multiple of MAXIMUM_ALIGNOF (8) and
 * the value is an acceptable --file-encryption-page-reserved-size.
 */
#define BFE_FORMAT_LEN		sizeof(uint32)
#define BFE_OVERHEAD_SIZE	96
#define BFE_PAD_SIZE		(BFE_OVERHEAD_SIZE - \
							 (2 * BFE_IV_LEN) - \
							 (2 * BFE_TAG_LEN) - \
							 BFE_KEY_LEN - \
							 BFE_FORMAT_LEN)
StaticAssertDecl(BFE_PAD_SIZE == 4, "unexpected basic_file_encryption padding");

typedef struct BasicFileEncryptionState
{
	unsigned char kek[BFE_KEY_LEN];
} BasicFileEncryptionState;

/* GUC */
static char *basic_file_encryption_key = NULL;

static void bfe_startup(FileEncryptionModuleState *state);
static void bfe_shutdown(FileEncryptionModuleState *state);
static void bfe_encrypt(const FileEncryptionModuleState *state,
						const char *path, uint64 file_offset,
						const char *data, Size data_len,
						StringInfo dst);
static void bfe_decrypt(const FileEncryptionModuleState *state,
						const char *path, uint64 file_offset,
						const char *data, Size data_len,
						StringInfo dst);
static inline BasicFileEncryptionState *bfe_require_kek(const FileEncryptionModuleState *state);
static pg_noreturn void bfe_openssl_error(const char *op);
static void bfe_aad_update(EVP_CIPHER_CTX *ctx, bool encrypting,
						   const char *path, uint64 file_offset);
static void bfe_encrypt_with_key(const unsigned char *key,
								 const unsigned char *iv,
								 const char *path, uint64 file_offset,
								 const unsigned char *data, int data_len,
								 StringInfo dst,
								 unsigned char *tag);
static void bfe_decrypt_with_key(const unsigned char *key,
								 const unsigned char *iv,
								 const unsigned char *tag,
								 const char *path, uint64 file_offset,
								 const unsigned char *data, int data_len,
								 StringInfo dst);

static const FileEncryptionCallbacks basic_file_encryption_callbacks = {
	PG_FILE_ENCRYPTION_MAGIC,
	.overhead_size = BFE_OVERHEAD_SIZE,

	.startup_cb = bfe_startup,
	.shutdown_cb = bfe_shutdown,
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
							   "Hex-encoded 256-bit AES key used to wrap file encryption keys.",
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
						 (char *) priv->kek);
	Assert(decoded == BFE_KEY_LEN);
	(void) decoded;

	state->private_data = priv;
}

static void
bfe_shutdown(FileEncryptionModuleState *state)
{
	BasicFileEncryptionState *priv = state->private_data;

	if (priv != NULL)
	{
		explicit_bzero(priv->kek, sizeof(priv->kek));
		pfree(priv);
		state->private_data = NULL;
	}
}

/*
 * Resolve the per-process key-encryption key, raising the deferred
 * "key not set" error
 * if bfe_startup didn't manage to decode one.
 */
static inline BasicFileEncryptionState *
bfe_require_kek(const FileEncryptionModuleState *state)
{
	BasicFileEncryptionState *priv = state->private_data;

	if (priv == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("basic_file_encryption.key is not set")));
	return priv;
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
 * Mix the AAD bytes into an EVP cipher context.
 *
 * AAD = basename(path) || file_offset(be64).  Only the basename is
 * bound, NOT the full path, so file-level operations that change the
 * path's leading components (CREATE DATABASE FILE_COPY moves a clone
 * to a new dboid directory; ALTER DATABASE SET TABLESPACE moves files
 * across spcOid trees) keep producing decryptable bytes.  Within a
 * given namespace the basename is unique enough — relation segments
 * are "<relfilenode>[.<seg>]", reorderbuffer spill files are
 * "xid-<xid>-lsn-...snap", BufFile fileset segments embed the per-set
 * name — so this still prevents cross-file substitution at the same
 * offset.
 */
static void
bfe_aad_update(EVP_CIPHER_CTX *ctx, bool encrypting,
			   const char *path, uint64 file_offset)
{
	int			outlen;
	const char *basename = strrchr(path, '/');
	unsigned char offset_be[8];
	int (*update) (EVP_CIPHER_CTX *, unsigned char *, int *,
				   const unsigned char *, int);

	update = encrypting ? EVP_EncryptUpdate : EVP_DecryptUpdate;

	basename = basename ? basename + 1 : path;
	if (update(ctx, NULL, &outlen,
			   (const unsigned char *) basename, (int) strlen(basename)) != 1)
		bfe_openssl_error("AAD path update");

	for (int i = 0; i < 8; i++)
		offset_be[i] = (unsigned char) (file_offset >> ((7 - i) * 8));
	if (update(ctx, NULL, &outlen, offset_be, 8) != 1)
		bfe_openssl_error("AAD offset update");
}

/*
 * Encrypt data_len bytes with the supplied AES-256-GCM key and IV.  The
 * ciphertext is appended to dst and tag receives the authentication tag.
 */
static void
bfe_encrypt_with_key(const unsigned char *key,
					 const unsigned char *iv,
					 const char *path, uint64 file_offset,
					 const unsigned char *data, int data_len,
					 StringInfo dst,
					 unsigned char *tag)
{
	EVP_CIPHER_CTX *ctx;
	int			outlen;
	int			finallen;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		bfe_openssl_error("EVP_CIPHER_CTX_new");

	PG_TRY();
	{
		if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
			bfe_openssl_error("EVP_EncryptInit_ex");
		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, BFE_IV_LEN, NULL) != 1)
			bfe_openssl_error("EVP_CTRL_GCM_SET_IVLEN");
		if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
			bfe_openssl_error("EVP_EncryptInit_ex (key/iv)");

		bfe_aad_update(ctx, true, path, file_offset);

		if (EVP_EncryptUpdate(ctx,
							  (unsigned char *) dst->data + dst->len, &outlen,
							  data, data_len) != 1)
			bfe_openssl_error("EVP_EncryptUpdate");
		Assert(outlen == data_len);
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
}

/*
 * Decrypt data_len bytes with the supplied AES-256-GCM key and IV.  The
 * plaintext is appended to dst.
 */
static void
bfe_decrypt_with_key(const unsigned char *key,
					 const unsigned char *iv,
					 const unsigned char *tag,
					 const char *path, uint64 file_offset,
					 const unsigned char *data, int data_len,
					 StringInfo dst)
{
	EVP_CIPHER_CTX *ctx;
	int			outlen;
	int			finallen;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		bfe_openssl_error("EVP_CIPHER_CTX_new");

	PG_TRY();
	{
		if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
			bfe_openssl_error("EVP_DecryptInit_ex");
		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, BFE_IV_LEN, NULL) != 1)
			bfe_openssl_error("EVP_CTRL_GCM_SET_IVLEN");
		if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
			bfe_openssl_error("EVP_DecryptInit_ex (key/iv)");

		bfe_aad_update(ctx, false, path, file_offset);

		if (EVP_DecryptUpdate(ctx,
							  (unsigned char *) dst->data + dst->len, &outlen,
							  data, data_len) != 1)
			bfe_openssl_error("EVP_DecryptUpdate");
		Assert(outlen == data_len);
		dst->len += outlen;

		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
								BFE_TAG_LEN, (unsigned char *) tag) != 1)
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
}

/*
 * Encrypt data_len plaintext bytes into dst, producing exactly
 * data_len + BFE_OVERHEAD_SIZE output bytes.  Layout:
 *
 *	  dst[0 .. data_len)                                ciphertext
 *	  dst[data_len     .. data_len+12)                  data IV
 *	  dst[data_len+12  .. data_len+28)                  data tag
 *	  dst[data_len+28  .. data_len+40)                  wrap IV
 *	  dst[data_len+40  .. data_len+72)                  wrapped data key
 *	  dst[data_len+72  .. data_len+88)                  wrap tag
 *	  dst[data_len+88  .. data_len+92)                  format magic
 *	  dst[data_len+92  .. data_len+96)                  zero padding
 */
static void
bfe_encrypt(const FileEncryptionModuleState *state,
			const char *path, uint64 file_offset,
			const char *data, Size data_len,
			StringInfo dst)
{
	BasicFileEncryptionState *priv = bfe_require_kek(state);
	unsigned char data_key[BFE_KEY_LEN];
	unsigned char data_iv[BFE_IV_LEN];
	unsigned char data_tag[BFE_TAG_LEN];
	unsigned char wrap_iv[BFE_IV_LEN];
	unsigned char wrap_tag[BFE_TAG_LEN];
	uint32		format = BFE_FORMAT_MAGIC;
	int			body_len = (int) data_len;
	int			wrapped_key_start;

	if (!pg_strong_random(data_key, sizeof(data_key)) ||
		!pg_strong_random(data_iv, sizeof(data_iv)) ||
		!pg_strong_random(wrap_iv, sizeof(wrap_iv)))
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("basic_file_encryption: could not generate encryption key material")));

	enlargeStringInfo(dst, body_len + BFE_OVERHEAD_SIZE);

	PG_TRY();
	{
		bfe_encrypt_with_key(data_key, data_iv, path, file_offset,
							 (const unsigned char *) data, body_len,
							 dst, data_tag);

		memcpy(dst->data + dst->len, data_iv, BFE_IV_LEN);
		dst->len += BFE_IV_LEN;
		memcpy(dst->data + dst->len, data_tag, BFE_TAG_LEN);
		dst->len += BFE_TAG_LEN;
		memcpy(dst->data + dst->len, wrap_iv, BFE_IV_LEN);
		dst->len += BFE_IV_LEN;

		wrapped_key_start = dst->len;
		bfe_encrypt_with_key(priv->kek, wrap_iv, path, file_offset,
							 data_key, BFE_KEY_LEN, dst, wrap_tag);
		Assert(dst->len == wrapped_key_start + BFE_KEY_LEN);

		memcpy(dst->data + dst->len, wrap_tag, BFE_TAG_LEN);
		dst->len += BFE_TAG_LEN;
		memcpy(dst->data + dst->len, &format, sizeof(format));
		dst->len += sizeof(format);
		memset(dst->data + dst->len, 0, BFE_PAD_SIZE);
		dst->len += BFE_PAD_SIZE;
		Assert(dst->len == body_len + BFE_OVERHEAD_SIZE);
		dst->data[dst->len] = '\0';
	}
	PG_FINALLY();
	{
		explicit_bzero(data_key, sizeof(data_key));
		explicit_bzero(data_iv, sizeof(data_iv));
		explicit_bzero(data_tag, sizeof(data_tag));
		explicit_bzero(wrap_iv, sizeof(wrap_iv));
		explicit_bzero(wrap_tag, sizeof(wrap_tag));
	}
	PG_END_TRY();
}

/*
 * Decrypt data_len bytes (which must include BFE_OVERHEAD_SIZE bytes of
 * trailer that bfe_encrypt produced) into dst.  On success, dst contains
 * exactly data_len - BFE_OVERHEAD_SIZE plaintext bytes.  Raises
 * ERRCODE_DATA_CORRUPTED on tag-verification failure.
 */
static void
bfe_decrypt(const FileEncryptionModuleState *state,
			const char *path, uint64 file_offset,
			const char *data, Size data_len,
			StringInfo dst)
{
	BasicFileEncryptionState *priv = bfe_require_kek(state);
	const unsigned char *data_iv;
	const unsigned char *data_tag;
	const unsigned char *wrap_iv;
	const unsigned char *wrapped_key;
	const unsigned char *wrap_tag;
	unsigned char data_key[BFE_KEY_LEN];
	StringInfoData unwrapped_key;
	char		unwrapped_key_buf[BFE_KEY_LEN + 1];
	uint32		format;
	int			body_len;

	if (data_len < BFE_OVERHEAD_SIZE)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("basic_file_encryption: encrypted blob is too short (%zu bytes)",
						data_len)));

	body_len = (int) (data_len - BFE_OVERHEAD_SIZE);
	data_iv = (const unsigned char *) data + body_len;
	data_tag = data_iv + BFE_IV_LEN;
	wrap_iv = data_tag + BFE_TAG_LEN;
	wrapped_key = wrap_iv + BFE_IV_LEN;
	wrap_tag = wrapped_key + BFE_KEY_LEN;
	memcpy(&format, wrap_tag + BFE_TAG_LEN, sizeof(format));

	if (format != BFE_FORMAT_MAGIC)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("basic_file_encryption: encrypted blob has an unrecognized format")));

	unwrapped_key.data = unwrapped_key_buf;
	unwrapped_key.len = 0;
	unwrapped_key.maxlen = sizeof(unwrapped_key_buf);
	unwrapped_key.cursor = 0;
	enlargeStringInfo(dst, body_len);

	PG_TRY();
	{
		bfe_decrypt_with_key(priv->kek, wrap_iv, wrap_tag, path, file_offset,
							 wrapped_key, BFE_KEY_LEN, &unwrapped_key);
		if (unwrapped_key.len != BFE_KEY_LEN)
			ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg("basic_file_encryption: wrapped key decrypted to %d bytes, expected %d",
							unwrapped_key.len, BFE_KEY_LEN)));

		memcpy(data_key, unwrapped_key.data, BFE_KEY_LEN);
		bfe_decrypt_with_key(data_key, data_iv, data_tag, path, file_offset,
							 (const unsigned char *) data, body_len, dst);
		Assert(dst->len == body_len);
	}
	PG_FINALLY();
	{
		explicit_bzero(data_key, sizeof(data_key));
		explicit_bzero(unwrapped_key_buf, sizeof(unwrapped_key_buf));
	}
	PG_END_TRY();

	dst->data[dst->len] = '\0';
}
