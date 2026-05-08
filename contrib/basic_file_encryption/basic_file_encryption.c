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

static const FileEncryptionCallbacks basic_file_encryption_callbacks = {
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
	return &basic_file_encryption_callbacks;
}

/*
 * Decode the configured hex key into the per-process state.  Errors out if
 * the key is empty or invalid; the module is unusable without one.
 */
static void
bfe_startup(FileEncryptionModuleState *state)
{
	BasicFileEncryptionState *priv;
	uint64		decoded;

	if (basic_file_encryption_key == NULL ||
		basic_file_encryption_key[0] == '\0')
		ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("basic_file_encryption.key is not set")));

	priv = palloc0_object(BasicFileEncryptionState);

	/* check_key already validated length and alphabet, so hex_decode won't fail. */
	decoded = hex_decode(basic_file_encryption_key,
						 strlen(basic_file_encryption_key),
						 (char *) priv->key);
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
	BasicFileEncryptionState *priv = state->private_data;
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
	BasicFileEncryptionState *priv = state->private_data;
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
