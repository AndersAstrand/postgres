/*-------------------------------------------------------------------------
 *
 * basic_file_encryption.c
 *	  Reference implementation of a file encryption module.
 *
 * The config string passed to _PG_file_encryption_module_init is exactly
 * 64 hex characters: a 256-bit AES key-encryption key (KEK).  The KEK
 * never encrypts user bytes directly; it only wraps data-encryption keys
 * (DEKs).
 *
 * Two encryption flows share the same KEK:
 *
 *   * Record-stream encryption (BufFile, reorderbuffer spill files) uses a
 *     fresh DEK per call.  The DEK is wrapped under the KEK and stored in
 *     the per-record trailer.  Per-call overhead: 96 bytes.
 *
 *   * Per-relation page encryption uses one DEK per RelFileLocator,
 *     generated at relation-create time and wrapped under the KEK into
 *     the relation's KEY fork.  Each page's trailer holds only the
 *     per-page IV, tag, and a format marker.  Per-page overhead: 32 bytes.
 *
 * AAD bindings:
 *
 *   * Record-stream encrypt/decrypt binds basename(path) || file_offset(be64).
 *     Using only the basename keeps CREATE DATABASE FILE_COPY and ALTER
 *     DATABASE SET TABLESPACE working — both clone files into directories
 *     whose leading components change for the same on-disk bytes.
 *
 *   * Object-key wrap (DEK ciphertext stored in the KEY fork) binds
 *     relNumber(be32).  Only the relfilenode is bound, so the same
 *     restrictions on CROSS-database operations apply: a KEY blob is
 *     valid for any relation with that relfilenode.  Within a database
 *     the relfilenode is unique enough to detect substitution.
 *
 *   * Page encrypt/decrypt binds fork(be32) || blocknum(be32).  The
 *     per-relation DEK already pins which relation we're decrypting; the
 *     AAD also distinguishes MAIN block N from INIT block N so neither can
 *     be substituted for the other on disk.  On unlogged-relation reset,
 *     reinit re-encrypts INIT bytes under MAIN's AAD rather than raw-copying
 *     the ciphertext.
 *
 * Authentication-tag verification on decrypt detects tampering and key
 * mismatch.  Errors are surfaced to the host via the *errmsg out-param;
 * the module never calls ereport or exit directly, which keeps the same
 * .so loadable from both backend and libpgcommon-based frontend tools.
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

#include "common/file_encryption_module.h"
#include "fmgr.h"
#include "lib/stringinfo.h"
#include "port.h"

PG_MODULE_MAGIC;

/*
 * Tiny hex decoder.  The backend's utils/adt/encode.c hex_decode lives
 * outside libpgcommon, so a dual-loadable .so can't reach it from a
 * frontend host.  Returns the number of bytes written to dst, or
 * (size_t) -1 on a bad input character.
 */
static inline int
bfe_hex_nibble(unsigned char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static size_t
bfe_hex_decode(const char *src, size_t len, unsigned char *dst)
{
	size_t		i;

	if (len % 2 != 0)
		return (size_t) -1;
	for (i = 0; i < len / 2; i++)
	{
		int			hi = bfe_hex_nibble((unsigned char) src[i * 2]);
		int			lo = bfe_hex_nibble((unsigned char) src[i * 2 + 1]);

		if (hi < 0 || lo < 0)
			return (size_t) -1;
		dst[i] = (unsigned char) ((hi << 4) | lo);
	}
	return len / 2;
}

#define BFE_KEY_LEN			32
#define BFE_IV_LEN			12
#define BFE_TAG_LEN			16
#define BFE_FORMAT_LEN		sizeof(uint32)
#define BFE_FORMAT_MAGIC	0x31454642	/* "BFE1" - record-stream format */
#define BFE_PAGE_FORMAT_MAGIC 0x50454642	/* "BFEP" - page format */
#define BFE_OBJ_FORMAT_MAGIC  0x4F454642	/* "BFEO" - object-key wrap format */

/*
 * Record-stream overhead: per-call DEK wrapped under the KEK alongside the
 * record body.  IV + tag + wrap IV + wrapped DEK + wrap tag + format + pad.
 */
#define BFE_OVERHEAD_SIZE	96
#define BFE_PAD_SIZE		(BFE_OVERHEAD_SIZE - \
							 (2 * BFE_IV_LEN) - \
							 (2 * BFE_TAG_LEN) - \
							 BFE_KEY_LEN - \
							 BFE_FORMAT_LEN)
StaticAssertDecl(BFE_PAD_SIZE == 4, "unexpected basic_file_encryption record padding");

/*
 * Per-page overhead: the DEK comes from per-relation state, so the trailer
 * only needs the per-page IV, tag, and format marker.
 */
#define BFE_PAGE_OVERHEAD_SIZE	32
#define BFE_PAGE_PAD_SIZE	(BFE_PAGE_OVERHEAD_SIZE - BFE_IV_LEN - BFE_TAG_LEN - BFE_FORMAT_LEN)
StaticAssertDecl(BFE_PAGE_PAD_SIZE == 0, "unexpected basic_file_encryption page padding");

/*
 * Per-relation key-wrap blob written to KEY_FORKNUM block 0:
 *
 *   [ IV 12B ][ wrapped DEK 32B ][ wrap tag 16B ][ format 4B ]
 *
 * Total 64 bytes.  The core wraps this in its FEKeyBlockHeader; the module
 * only sees the 64-byte payload.
 */
#define BFE_OBJ_WRAP_SIZE	(BFE_IV_LEN + BFE_KEY_LEN + BFE_TAG_LEN + BFE_FORMAT_LEN)

typedef struct BasicFileEncryptionState
{
	unsigned char kek[BFE_KEY_LEN];
} BasicFileEncryptionState;

/* Cached per-relation DEK, opaque to the core. */
typedef struct BFEObjectState
{
	unsigned char dek[BFE_KEY_LEN];
} BFEObjectState;

/*
 * Module-static KEK, populated by _PG_file_encryption_module_init from the
 * supplied config string.  Set once per postmaster (inherited by forked
 * children via copy-on-write) and once per frontend tool invocation.
 */
static unsigned char bfe_kek_static[BFE_KEY_LEN];
static bool bfe_kek_set = false;

static void bfe_startup(FileEncryptionModuleState *state);
static void bfe_shutdown(FileEncryptionModuleState *state);
static bool bfe_encrypt(const FileEncryptionModuleState *state,
						const char *path, uint64 file_offset,
						const char *data, Size data_len,
						StringInfo dst, char **errmsg);
static bool bfe_decrypt(const FileEncryptionModuleState *state,
						const char *path, uint64 file_offset,
						const char *data, Size data_len,
						StringInfo dst, char **errmsg);
static bool bfe_generate_object_key(FileEncryptionModuleState *state,
									const RelFileLocator *locator,
									StringInfo dst, char **errmsg);
static void *bfe_object_open(FileEncryptionModuleState *state,
							 const RelFileLocator *locator,
							 const char *wrapped, Size wrapped_len,
							 char **errmsg);
static void bfe_object_close(FileEncryptionModuleState *state,
							 void *object_state);
static bool bfe_encrypt_page(FileEncryptionModuleState *state,
							 void *object_state,
							 ForkNumber fork, BlockNumber blocknum,
							 const char *src, char *dst, char **errmsg);
static bool bfe_decrypt_page(FileEncryptionModuleState *state,
							 void *object_state,
							 ForkNumber fork, BlockNumber blocknum,
							 const char *src, char *dst, char **errmsg);

static BasicFileEncryptionState *bfe_require_kek(const FileEncryptionModuleState *state,
												 char **errmsg);
static char *bfe_openssl_errstr(const char *op);

typedef void (*BFEAadFn) (EVP_CIPHER_CTX *ctx, bool encrypting,
						  void *ctx_data, bool *aad_ok);

static bool bfe_aes_gcm_encrypt(const unsigned char *key,
								const unsigned char *iv,
								BFEAadFn aad_fn, void *aad_ctx,
								const unsigned char *data, int data_len,
								unsigned char *out,
								unsigned char *tag,
								char **errmsg);
static bool bfe_aes_gcm_decrypt(const unsigned char *key,
								const unsigned char *iv,
								const unsigned char *tag,
								BFEAadFn aad_fn, void *aad_ctx,
								const unsigned char *data, int data_len,
								unsigned char *out,
								char **errmsg);

static const FileEncryptionCallbacks basic_file_encryption_callbacks = {
	PG_FILE_ENCRYPTION_MAGIC,
	.overhead_size = BFE_OVERHEAD_SIZE,
	.page_overhead_size = BFE_PAGE_OVERHEAD_SIZE,

	.startup_cb = bfe_startup,
	.shutdown_cb = bfe_shutdown,
	.encrypt_cb = bfe_encrypt,
	.decrypt_cb = bfe_decrypt,

	.generate_object_key_cb = bfe_generate_object_key,
	.object_open_cb = bfe_object_open,
	.object_close_cb = bfe_object_close,
	.encrypt_page_cb = bfe_encrypt_page,
	.decrypt_page_cb = bfe_decrypt_page,
};

/*
 * Module entry point.  The config string is exactly 64 hex characters
 * (the 256-bit KEK).  Validate, decode into a module static, and hand
 * back the callback table.  Same signature for backend and frontend
 * hosts.
 */
bool
_PG_file_encryption_module_init(const char *config,
								const FileEncryptionCallbacks **callbacks_out,
								char **errmsg)
{
	size_t		decoded;

	if (config == NULL || config[0] == '\0')
	{
		*errmsg = pstrdup("basic_file_encryption: 'config' is empty; expected a 64-character hex key");
		return false;
	}

	if (strlen(config) != BFE_KEY_LEN * 2)
	{
		*errmsg = psprintf("basic_file_encryption: 'config' must be %d hex characters (got %zu)",
						   BFE_KEY_LEN * 2, strlen(config));
		return false;
	}

	for (const char *p = config; *p; p++)
	{
		if (!isxdigit((unsigned char) *p))
		{
			*errmsg = pstrdup("basic_file_encryption: 'config' must contain only hexadecimal digits");
			return false;
		}
	}

	decoded = bfe_hex_decode(config, strlen(config), bfe_kek_static);
	if (decoded != BFE_KEY_LEN)
	{
		*errmsg = psprintf("basic_file_encryption: hex decode of 'config' produced %lu bytes, expected %d",
						   (unsigned long) decoded, BFE_KEY_LEN);
		return false;
	}
	bfe_kek_set = true;

	*callbacks_out = &basic_file_encryption_callbacks;
	return true;
}

/*
 * Copy the module-static KEK into a per-process state struct.  The static
 * is populated by _PG_file_encryption_module_init; if the host loaded us
 * without going through that entry point, fail closed at first use
 * (bfe_require_kek reports it as a config error).
 */
static void
bfe_startup(FileEncryptionModuleState *state)
{
	BasicFileEncryptionState *priv;

	if (!bfe_kek_set)
	{
		state->private_data = NULL;
		return;
	}

	priv = palloc0_object(BasicFileEncryptionState);
	memcpy(priv->kek, bfe_kek_static, BFE_KEY_LEN);
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
 * Resolve the per-process key-encryption key.  Returns NULL and sets
 * *errmsg if the module was loaded without a valid configuration.
 */
static BasicFileEncryptionState *
bfe_require_kek(const FileEncryptionModuleState *state, char **errmsg)
{
	BasicFileEncryptionState *priv = state->private_data;

	if (priv == NULL)
	{
		*errmsg = pstrdup("basic_file_encryption: module was loaded without a valid configuration");
		return NULL;
	}
	return priv;
}

/*
 * Format the latest OpenSSL error into a palloc'd string of the form
 * "<op> failed: <openssl detail>", suitable for the caller's *errmsg.
 */
static char *
bfe_openssl_errstr(const char *op)
{
	unsigned long e = ERR_get_error();
	char		buf[256];

	if (e == 0)
		return psprintf("basic_file_encryption: %s failed", op);

	ERR_error_string_n(e, buf, sizeof(buf));
	return psprintf("basic_file_encryption: %s failed: %s", op, buf);
}

/*
 * AAD-update callbacks.  Each flow has its own AAD shape; using a single
 * function-pointer entry point keeps bfe_aes_gcm_{encrypt,decrypt} agnostic
 * to the caller.  *aad_ok is set to false on OpenSSL update failure; the
 * caller surfaces the OpenSSL error itself.
 */
typedef struct RecordAadCtx
{
	const char *path;
	uint64		file_offset;
} RecordAadCtx;

typedef struct ObjectAadCtx
{
	const RelFileLocator *locator;
} ObjectAadCtx;

typedef struct PageAadCtx
{
	ForkNumber	fork;
	BlockNumber blocknum;
} PageAadCtx;

static void
bfe_aad_update_record(EVP_CIPHER_CTX *ctx, bool encrypting,
					  void *ctx_data, bool *aad_ok)
{
	RecordAadCtx *c = ctx_data;
	int			outlen;
	const char *basename = strrchr(c->path, '/');
	unsigned char offset_be[8];
	int			(*update) (EVP_CIPHER_CTX *, unsigned char *, int *,
						   const unsigned char *, int);

	update = encrypting ? EVP_EncryptUpdate : EVP_DecryptUpdate;

	basename = basename ? basename + 1 : c->path;
	if (update(ctx, NULL, &outlen,
			   (const unsigned char *) basename, (int) strlen(basename)) != 1)
	{
		*aad_ok = false;
		return;
	}

	for (int i = 0; i < 8; i++)
		offset_be[i] = (unsigned char) (c->file_offset >> ((7 - i) * 8));
	if (update(ctx, NULL, &outlen, offset_be, 8) != 1)
		*aad_ok = false;
}

static void
bfe_aad_update_object(EVP_CIPHER_CTX *ctx, bool encrypting,
					  void *ctx_data, bool *aad_ok)
{
	ObjectAadCtx *c = ctx_data;
	int			outlen;
	unsigned char buf[4];
	int			(*update) (EVP_CIPHER_CTX *, unsigned char *, int *,
						   const unsigned char *, int);

	update = encrypting ? EVP_EncryptUpdate : EVP_DecryptUpdate;

	for (int i = 0; i < 4; i++)
		buf[i] = (unsigned char) (c->locator->relNumber >> ((3 - i) * 8));
	if (update(ctx, NULL, &outlen, buf, 4) != 1)
		*aad_ok = false;
}

/*
 * Bind fork(be32) || blocknum(be32).  Including the fork distinguishes
 * MAIN block N from INIT block N so an attacker with disk write access
 * cannot swap one for the other.  reinit re-encrypts INIT bytes under
 * MAIN's AAD when copying INIT into MAIN on unlogged-relation reset --
 * see ResetUnloggedRelationsInDbspaceDir() in storage/file/reinit.c.
 */
static void
bfe_aad_update_page(EVP_CIPHER_CTX *ctx, bool encrypting,
					void *ctx_data, bool *aad_ok)
{
	PageAadCtx *c = ctx_data;
	int			outlen;
	unsigned char buf[8];
	int			(*update) (EVP_CIPHER_CTX *, unsigned char *, int *,
						   const unsigned char *, int);
	uint32		fork_be = (uint32) c->fork;

	update = encrypting ? EVP_EncryptUpdate : EVP_DecryptUpdate;

	for (int i = 0; i < 4; i++)
		buf[i] = (unsigned char) (fork_be >> ((3 - i) * 8));
	for (int i = 0; i < 4; i++)
		buf[4 + i] = (unsigned char) (c->blocknum >> ((3 - i) * 8));
	if (update(ctx, NULL, &outlen, buf, 8) != 1)
		*aad_ok = false;
}

/*
 * Encrypt data_len bytes with the supplied AES-256-GCM key and IV.  The
 * ciphertext is written to 'out' (data_len bytes); 'tag' receives the
 * 16-byte authentication tag.  Returns true on success; on failure
 * cleans up the OpenSSL context, writes an error to *errmsg, and
 * returns false.
 */
static bool
bfe_aes_gcm_encrypt(const unsigned char *key,
					const unsigned char *iv,
					BFEAadFn aad_fn, void *aad_ctx,
					const unsigned char *data, int data_len,
					unsigned char *out,
					unsigned char *tag,
					char **errmsg)
{
	EVP_CIPHER_CTX *ctx;
	int			outlen;
	int			finallen;
	bool		aad_ok = true;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
	{
		*errmsg = bfe_openssl_errstr("EVP_CIPHER_CTX_new");
		return false;
	}

#define FAIL(op) do { \
		*errmsg = bfe_openssl_errstr(op); \
		EVP_CIPHER_CTX_free(ctx); \
		return false; \
	} while (0)

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
		FAIL("EVP_EncryptInit_ex");
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, BFE_IV_LEN, NULL) != 1)
		FAIL("EVP_CTRL_GCM_SET_IVLEN");
	if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
		FAIL("EVP_EncryptInit_ex (key/iv)");

	if (aad_fn != NULL)
	{
		aad_fn(ctx, true, aad_ctx, &aad_ok);
		if (!aad_ok)
			FAIL("AAD update");
	}

	if (EVP_EncryptUpdate(ctx, out, &outlen, data, data_len) != 1)
		FAIL("EVP_EncryptUpdate");
	if (outlen != data_len)
	{
		*errmsg = psprintf("basic_file_encryption: EVP_EncryptUpdate produced %d bytes, expected %d",
						   outlen, data_len);
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	if (EVP_EncryptFinal_ex(ctx, out + outlen, &finallen) != 1)
		FAIL("EVP_EncryptFinal_ex");
	if (finallen != 0)
	{
		*errmsg = psprintf("basic_file_encryption: EVP_EncryptFinal_ex produced %d trailing bytes, expected 0",
						   finallen);
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, BFE_TAG_LEN, tag) != 1)
		FAIL("EVP_CTRL_GCM_GET_TAG");

#undef FAIL

	EVP_CIPHER_CTX_free(ctx);
	return true;
}

/*
 * Decrypt data_len bytes with the supplied AES-256-GCM key, IV, and
 * expected tag.  Plaintext is written to 'out'.  Returns false with
 * *errmsg set on tag-verification failure or any other error.
 */
static bool
bfe_aes_gcm_decrypt(const unsigned char *key,
					const unsigned char *iv,
					const unsigned char *tag,
					BFEAadFn aad_fn, void *aad_ctx,
					const unsigned char *data, int data_len,
					unsigned char *out,
					char **errmsg)
{
	EVP_CIPHER_CTX *ctx;
	int			outlen;
	int			finallen;
	bool		aad_ok = true;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
	{
		*errmsg = bfe_openssl_errstr("EVP_CIPHER_CTX_new");
		return false;
	}

#define FAIL(op) do { \
		*errmsg = bfe_openssl_errstr(op); \
		EVP_CIPHER_CTX_free(ctx); \
		return false; \
	} while (0)

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
		FAIL("EVP_DecryptInit_ex");
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, BFE_IV_LEN, NULL) != 1)
		FAIL("EVP_CTRL_GCM_SET_IVLEN");
	if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
		FAIL("EVP_DecryptInit_ex (key/iv)");

	if (aad_fn != NULL)
	{
		aad_fn(ctx, false, aad_ctx, &aad_ok);
		if (!aad_ok)
			FAIL("AAD update");
	}

	if (EVP_DecryptUpdate(ctx, out, &outlen, data, data_len) != 1)
		FAIL("EVP_DecryptUpdate");
	if (outlen != data_len)
	{
		*errmsg = psprintf("basic_file_encryption: EVP_DecryptUpdate produced %d bytes, expected %d",
						   outlen, data_len);
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
							BFE_TAG_LEN, (unsigned char *) tag) != 1)
		FAIL("EVP_CTRL_GCM_SET_TAG");

	if (EVP_DecryptFinal_ex(ctx, out + outlen, &finallen) != 1)
	{
		*errmsg = pstrdup("basic_file_encryption: authentication tag verification failed");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	if (finallen != 0)
	{
		*errmsg = psprintf("basic_file_encryption: EVP_DecryptFinal_ex produced %d trailing bytes, expected 0",
						   finallen);
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

#undef FAIL

	EVP_CIPHER_CTX_free(ctx);
	return true;
}

/*
 * ============================================================
 *	  Record-stream encryption (BufFile, reorderbuffer spill)
 * ============================================================
 *
 * Layout (caller plaintext: data_len bytes):
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
static bool
bfe_encrypt(const FileEncryptionModuleState *state,
			const char *path, uint64 file_offset,
			const char *data, Size data_len,
			StringInfo dst, char **errmsg)
{
	BasicFileEncryptionState *priv;
	unsigned char data_key[BFE_KEY_LEN];
	unsigned char data_iv[BFE_IV_LEN];
	unsigned char data_tag[BFE_TAG_LEN];
	unsigned char wrap_iv[BFE_IV_LEN];
	unsigned char wrap_tag[BFE_TAG_LEN];
	uint32		format = BFE_FORMAT_MAGIC;
	int			body_len = (int) data_len;
	RecordAadCtx aad = {.path = path,.file_offset = file_offset};
	bool		ok;

	priv = bfe_require_kek(state, errmsg);
	if (priv == NULL)
		return false;

	if (!pg_strong_random(data_key, sizeof(data_key)) ||
		!pg_strong_random(data_iv, sizeof(data_iv)) ||
		!pg_strong_random(wrap_iv, sizeof(wrap_iv)))
	{
		*errmsg = pstrdup("basic_file_encryption: could not generate encryption key material");
		return false;
	}

	enlargeStringInfo(dst, body_len + BFE_OVERHEAD_SIZE);

	ok = bfe_aes_gcm_encrypt(data_key, data_iv,
							 bfe_aad_update_record, &aad,
							 (const unsigned char *) data, body_len,
							 (unsigned char *) dst->data + dst->len, data_tag,
							 errmsg);
	if (!ok)
	{
		explicit_bzero(data_key, sizeof(data_key));
		return false;
	}
	dst->len += body_len;

	memcpy(dst->data + dst->len, data_iv, BFE_IV_LEN);
	dst->len += BFE_IV_LEN;
	memcpy(dst->data + dst->len, data_tag, BFE_TAG_LEN);
	dst->len += BFE_TAG_LEN;
	memcpy(dst->data + dst->len, wrap_iv, BFE_IV_LEN);
	dst->len += BFE_IV_LEN;

	ok = bfe_aes_gcm_encrypt(priv->kek, wrap_iv,
							 bfe_aad_update_record, &aad,
							 data_key, BFE_KEY_LEN,
							 (unsigned char *) dst->data + dst->len, wrap_tag,
							 errmsg);
	explicit_bzero(data_key, sizeof(data_key));
	if (!ok)
		return false;
	dst->len += BFE_KEY_LEN;

	memcpy(dst->data + dst->len, wrap_tag, BFE_TAG_LEN);
	dst->len += BFE_TAG_LEN;
	memcpy(dst->data + dst->len, &format, sizeof(format));
	dst->len += sizeof(format);
	memset(dst->data + dst->len, 0, BFE_PAD_SIZE);
	dst->len += BFE_PAD_SIZE;
	dst->data[dst->len] = '\0';

	return true;
}

static bool
bfe_decrypt(const FileEncryptionModuleState *state,
			const char *path, uint64 file_offset,
			const char *data, Size data_len,
			StringInfo dst, char **errmsg)
{
	BasicFileEncryptionState *priv;
	const unsigned char *data_iv;
	const unsigned char *data_tag;
	const unsigned char *wrap_iv;
	const unsigned char *wrapped_key;
	const unsigned char *wrap_tag;
	unsigned char data_key[BFE_KEY_LEN];
	uint32		format;
	int			body_len;
	RecordAadCtx aad = {.path = path,.file_offset = file_offset};

	priv = bfe_require_kek(state, errmsg);
	if (priv == NULL)
		return false;

	if (data_len < BFE_OVERHEAD_SIZE)
	{
		*errmsg = psprintf("basic_file_encryption: encrypted blob is too short (%zu bytes)",
						   data_len);
		return false;
	}

	body_len = (int) (data_len - BFE_OVERHEAD_SIZE);
	data_iv = (const unsigned char *) data + body_len;
	data_tag = data_iv + BFE_IV_LEN;
	wrap_iv = data_tag + BFE_TAG_LEN;
	wrapped_key = wrap_iv + BFE_IV_LEN;
	wrap_tag = wrapped_key + BFE_KEY_LEN;
	memcpy(&format, wrap_tag + BFE_TAG_LEN, sizeof(format));

	if (format != BFE_FORMAT_MAGIC)
	{
		*errmsg = psprintf("basic_file_encryption: encrypted blob has unrecognized format 0x%08x",
						   format);
		return false;
	}

	enlargeStringInfo(dst, body_len);

	if (!bfe_aes_gcm_decrypt(priv->kek, wrap_iv, wrap_tag,
							 bfe_aad_update_record, &aad,
							 wrapped_key, BFE_KEY_LEN, data_key,
							 errmsg))
		return false;

	if (!bfe_aes_gcm_decrypt(data_key, data_iv, data_tag,
							 bfe_aad_update_record, &aad,
							 (const unsigned char *) data, body_len,
							 (unsigned char *) dst->data + dst->len,
							 errmsg))
	{
		explicit_bzero(data_key, sizeof(data_key));
		return false;
	}
	explicit_bzero(data_key, sizeof(data_key));
	dst->len += body_len;
	dst->data[dst->len] = '\0';
	return true;
}

/*
 * ============================================================
 *	  Per-relation page encryption
 * ============================================================
 *
 * Object-key wrap layout (64 bytes, written to KEY fork block payload):
 *
 *	  wrapped[0  .. 12)   wrap IV
 *	  wrapped[12 .. 44)   wrapped DEK
 *	  wrapped[44 .. 60)   wrap tag
 *	  wrapped[60 .. 64)   format magic
 */
static bool
bfe_generate_object_key(FileEncryptionModuleState *state,
						const RelFileLocator *locator,
						StringInfo dst, char **errmsg)
{
	BasicFileEncryptionState *priv;
	unsigned char dek[BFE_KEY_LEN];
	unsigned char wrap_iv[BFE_IV_LEN];
	unsigned char wrap_tag[BFE_TAG_LEN];
	uint32		format = BFE_OBJ_FORMAT_MAGIC;
	ObjectAadCtx aad = {.locator = locator};
	bool		ok;

	priv = bfe_require_kek(state, errmsg);
	if (priv == NULL)
		return false;

	if (!pg_strong_random(dek, sizeof(dek)) ||
		!pg_strong_random(wrap_iv, sizeof(wrap_iv)))
	{
		*errmsg = pstrdup("basic_file_encryption: could not generate object key material");
		return false;
	}

	enlargeStringInfo(dst, BFE_OBJ_WRAP_SIZE);

	memcpy(dst->data + dst->len, wrap_iv, BFE_IV_LEN);
	dst->len += BFE_IV_LEN;

	ok = bfe_aes_gcm_encrypt(priv->kek, wrap_iv,
							 bfe_aad_update_object, &aad,
							 dek, BFE_KEY_LEN,
							 (unsigned char *) dst->data + dst->len, wrap_tag,
							 errmsg);
	explicit_bzero(dek, sizeof(dek));
	if (!ok)
		return false;
	dst->len += BFE_KEY_LEN;

	memcpy(dst->data + dst->len, wrap_tag, BFE_TAG_LEN);
	dst->len += BFE_TAG_LEN;
	memcpy(dst->data + dst->len, &format, sizeof(format));
	dst->len += sizeof(format);

	dst->data[dst->len] = '\0';
	return true;
}

static void *
bfe_object_open(FileEncryptionModuleState *state,
				const RelFileLocator *locator,
				const char *wrapped, Size wrapped_len,
				char **errmsg)
{
	BasicFileEncryptionState *priv;
	BFEObjectState *obj;
	const unsigned char *wrap_iv;
	const unsigned char *wrapped_dek;
	const unsigned char *wrap_tag;
	uint32		format;
	ObjectAadCtx aad = {.locator = locator};

	priv = bfe_require_kek(state, errmsg);
	if (priv == NULL)
		return NULL;

	if (wrapped_len != BFE_OBJ_WRAP_SIZE)
	{
		*errmsg = psprintf("basic_file_encryption: wrapped object key has unexpected length %zu (want %zu)",
						   wrapped_len, (Size) BFE_OBJ_WRAP_SIZE);
		return NULL;
	}

	wrap_iv = (const unsigned char *) wrapped;
	wrapped_dek = wrap_iv + BFE_IV_LEN;
	wrap_tag = wrapped_dek + BFE_KEY_LEN;
	memcpy(&format, wrap_tag + BFE_TAG_LEN, sizeof(format));

	if (format != BFE_OBJ_FORMAT_MAGIC)
	{
		*errmsg = psprintf("basic_file_encryption: wrapped object key has unrecognized format 0x%08x",
						   format);
		return NULL;
	}

	obj = palloc0_object(BFEObjectState);

	if (!bfe_aes_gcm_decrypt(priv->kek, wrap_iv, wrap_tag,
							 bfe_aad_update_object, &aad,
							 wrapped_dek, BFE_KEY_LEN, obj->dek,
							 errmsg))
	{
		explicit_bzero(obj->dek, sizeof(obj->dek));
		pfree(obj);
		return NULL;
	}

	return obj;
}

static void
bfe_object_close(FileEncryptionModuleState *state, void *object_state)
{
	BFEObjectState *obj = object_state;

	if (obj == NULL)
		return;
	explicit_bzero(obj->dek, sizeof(obj->dek));
	pfree(obj);
}

/*
 * Page layout (BLCKSZ bytes):
 *
 *	  dst[0 .. BLCKSZ - 32)             ciphertext (body)
 *	  dst[BLCKSZ - 32 .. BLCKSZ - 20)   data IV (12B)
 *	  dst[BLCKSZ - 20 .. BLCKSZ -  4)   data tag (16B)
 *	  dst[BLCKSZ -  4 .. BLCKSZ)        format magic (4B)
 */
static bool
bfe_encrypt_page(FileEncryptionModuleState *state,
				 void *object_state,
				 ForkNumber fork, BlockNumber blocknum,
				 const char *src, char *dst,
				 char **errmsg)
{
	BFEObjectState *obj = object_state;
	unsigned char data_iv[BFE_IV_LEN];
	unsigned char data_tag[BFE_TAG_LEN];
	uint32		format = BFE_PAGE_FORMAT_MAGIC;
	int			body_len = BLCKSZ - BFE_PAGE_OVERHEAD_SIZE;
	PageAadCtx	aad = {.fork = fork,.blocknum = blocknum};

	if (!pg_strong_random(data_iv, sizeof(data_iv)))
	{
		*errmsg = pstrdup("basic_file_encryption: could not generate page IV");
		return false;
	}

	if (!bfe_aes_gcm_encrypt(obj->dek, data_iv,
							 bfe_aad_update_page, &aad,
							 (const unsigned char *) src, body_len,
							 (unsigned char *) dst, data_tag,
							 errmsg))
		return false;

	memcpy(dst + body_len, data_iv, BFE_IV_LEN);
	memcpy(dst + body_len + BFE_IV_LEN, data_tag, BFE_TAG_LEN);
	memcpy(dst + body_len + BFE_IV_LEN + BFE_TAG_LEN, &format, sizeof(format));
	return true;
}

static bool
bfe_decrypt_page(FileEncryptionModuleState *state,
				 void *object_state,
				 ForkNumber fork, BlockNumber blocknum,
				 const char *src, char *dst,
				 char **errmsg)
{
	BFEObjectState *obj = object_state;
	const unsigned char *data_iv;
	const unsigned char *data_tag;
	uint32		format;
	int			body_len = BLCKSZ - BFE_PAGE_OVERHEAD_SIZE;
	PageAadCtx	aad = {.fork = fork,.blocknum = blocknum};

	data_iv = (const unsigned char *) src + body_len;
	data_tag = data_iv + BFE_IV_LEN;
	memcpy(&format, data_tag + BFE_TAG_LEN, sizeof(format));

	if (format != BFE_PAGE_FORMAT_MAGIC)
	{
		*errmsg = psprintf("basic_file_encryption: encrypted page has unrecognized format 0x%08x",
						   format);
		return false;
	}

	if (!bfe_aes_gcm_decrypt(obj->dek, data_iv, data_tag,
							 bfe_aad_update_page, &aad,
							 (const unsigned char *) src, body_len,
							 (unsigned char *) dst,
							 errmsg))
		return false;

	/* Zero the plaintext trailer so pd_checksum verifies (the writer's
	 * trailer is zeros per PageInit, and the decrypt output must match). */
	memset(dst + body_len, 0, BFE_PAGE_OVERHEAD_SIZE);
	return true;
}
