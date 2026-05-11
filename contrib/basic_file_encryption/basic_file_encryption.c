/*-------------------------------------------------------------------------
 *
 * basic_file_encryption.c
 *	  Reference implementation of a file encryption module.
 *
 * The hex-encoded key in the basic_file_encryption.key GUC is a
 * key-encryption key (KEK).  It never encrypts user bytes directly; it
 * only wraps data-encryption keys (DEKs).
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
#include "utils/memutils.h"

PG_MODULE_MAGIC;

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
static void bfe_generate_object_key(FileEncryptionModuleState *state,
									const RelFileLocator *locator,
									StringInfo dst);
static void *bfe_object_open(FileEncryptionModuleState *state,
							 const RelFileLocator *locator,
							 const char *wrapped, Size wrapped_len);
static void bfe_object_close(FileEncryptionModuleState *state,
							 void *object_state);
static void bfe_encrypt_page(FileEncryptionModuleState *state,
							 void *object_state,
							 ForkNumber fork, BlockNumber blocknum,
							 const char *src, char *dst);
static void bfe_decrypt_page(FileEncryptionModuleState *state,
							 void *object_state,
							 ForkNumber fork, BlockNumber blocknum,
							 const char *src, char *dst);

static inline BasicFileEncryptionState *bfe_require_kek(const FileEncryptionModuleState *state);
static pg_noreturn void bfe_openssl_error(const char *op);
static void bfe_aad_update_record(EVP_CIPHER_CTX *ctx, bool encrypting,
								  const char *path, uint64 file_offset);
static void bfe_aad_update_object(EVP_CIPHER_CTX *ctx, bool encrypting,
								  const RelFileLocator *locator);
static void bfe_aad_update_page(EVP_CIPHER_CTX *ctx, bool encrypting,
								ForkNumber fork, BlockNumber blocknum);
typedef void (*BFEAadFn) (EVP_CIPHER_CTX *ctx, bool encrypting, void *ctx_data);
static void bfe_aes_gcm_encrypt(const unsigned char *key,
								const unsigned char *iv,
								BFEAadFn aad_fn, void *aad_ctx,
								const unsigned char *data, int data_len,
								unsigned char *out,
								unsigned char *tag);
static void bfe_aes_gcm_decrypt(const unsigned char *key,
								const unsigned char *iv,
								const unsigned char *tag,
								BFEAadFn aad_fn, void *aad_ctx,
								const unsigned char *data, int data_len,
								unsigned char *out);

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
 * "key not set" error if bfe_startup didn't manage to decode one.
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
 * AAD-update callbacks.  Each flow has its own AAD shape; using a single
 * function-pointer entry point keeps bfe_aes_gcm_{encrypt,decrypt} agnostic
 * to the caller.
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
					  const char *path, uint64 file_offset)
{
	int			outlen;
	const char *basename = strrchr(path, '/');
	unsigned char offset_be[8];
	int			(*update) (EVP_CIPHER_CTX *, unsigned char *, int *,
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

static void
bfe_aad_update_object(EVP_CIPHER_CTX *ctx, bool encrypting,
					  const RelFileLocator *locator)
{
	int			outlen;
	unsigned char buf[4];
	int			(*update) (EVP_CIPHER_CTX *, unsigned char *, int *,
						   const unsigned char *, int);

	update = encrypting ? EVP_EncryptUpdate : EVP_DecryptUpdate;

	for (int i = 0; i < 4; i++)
		buf[i] = (unsigned char) (locator->relNumber >> ((3 - i) * 8));
	if (update(ctx, NULL, &outlen, buf, 4) != 1)
		bfe_openssl_error("AAD object update");
}

static void
bfe_aad_update_page(EVP_CIPHER_CTX *ctx, bool encrypting,
					ForkNumber fork, BlockNumber blocknum)
{
	int			outlen;
	unsigned char buf[8];
	int			(*update) (EVP_CIPHER_CTX *, unsigned char *, int *,
						   const unsigned char *, int);
	uint32		fork_be = (uint32) fork;

	update = encrypting ? EVP_EncryptUpdate : EVP_DecryptUpdate;

	/*
	 * Bind fork(be32) || blocknum(be32).  Including the fork distinguishes
	 * MAIN block N from INIT block N so an attacker with disk write access
	 * cannot swap one for the other.  reinit re-encrypts INIT bytes under
	 * MAIN's AAD when copying INIT into MAIN on unlogged-relation reset --
	 * see ResetUnloggedRelationsInDbspaceDir() in storage/file/reinit.c.
	 */
	for (int i = 0; i < 4; i++)
		buf[i] = (unsigned char) (fork_be >> ((3 - i) * 8));
	for (int i = 0; i < 4; i++)
		buf[4 + i] = (unsigned char) (blocknum >> ((3 - i) * 8));
	if (update(ctx, NULL, &outlen, buf, 8) != 1)
		bfe_openssl_error("AAD page update");
}

/* Adapter functions matching BFEAadFn. */
static void
record_aad_adapter(EVP_CIPHER_CTX *ctx, bool encrypting, void *p)
{
	RecordAadCtx *c = p;

	bfe_aad_update_record(ctx, encrypting, c->path, c->file_offset);
}

static void
object_aad_adapter(EVP_CIPHER_CTX *ctx, bool encrypting, void *p)
{
	ObjectAadCtx *c = p;

	bfe_aad_update_object(ctx, encrypting, c->locator);
}

static void
page_aad_adapter(EVP_CIPHER_CTX *ctx, bool encrypting, void *p)
{
	PageAadCtx *c = p;

	bfe_aad_update_page(ctx, encrypting, c->fork, c->blocknum);
}

/*
 * Encrypt data_len bytes with the supplied AES-256-GCM key and IV.  The
 * ciphertext is written to 'out' (data_len bytes); 'tag' receives the
 * 16-byte authentication tag.
 */
static void
bfe_aes_gcm_encrypt(const unsigned char *key,
					const unsigned char *iv,
					BFEAadFn aad_fn, void *aad_ctx,
					const unsigned char *data, int data_len,
					unsigned char *out,
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

		if (aad_fn != NULL)
			aad_fn(ctx, true, aad_ctx);

		if (EVP_EncryptUpdate(ctx, out, &outlen, data, data_len) != 1)
			bfe_openssl_error("EVP_EncryptUpdate");
		Assert(outlen == data_len);

		if (EVP_EncryptFinal_ex(ctx, out + outlen, &finallen) != 1)
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
}

/*
 * Decrypt data_len bytes with the supplied AES-256-GCM key, IV, and
 * expected tag.  Plaintext is written to 'out'.  Raises
 * ERRCODE_DATA_CORRUPTED on tag-verification failure.
 */
static void
bfe_aes_gcm_decrypt(const unsigned char *key,
					const unsigned char *iv,
					const unsigned char *tag,
					BFEAadFn aad_fn, void *aad_ctx,
					const unsigned char *data, int data_len,
					unsigned char *out)
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

		if (aad_fn != NULL)
			aad_fn(ctx, false, aad_ctx);

		if (EVP_DecryptUpdate(ctx, out, &outlen, data, data_len) != 1)
			bfe_openssl_error("EVP_DecryptUpdate");
		Assert(outlen == data_len);

		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
								BFE_TAG_LEN, (unsigned char *) tag) != 1)
			bfe_openssl_error("EVP_CTRL_GCM_SET_TAG");

		if (EVP_DecryptFinal_ex(ctx, out + outlen, &finallen) != 1)
			ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg("basic_file_encryption: authentication tag verification failed")));
		Assert(finallen == 0);
	}
	PG_FINALLY();
	{
		EVP_CIPHER_CTX_free(ctx);
	}
	PG_END_TRY();
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
	RecordAadCtx aad = {.path = path,.file_offset = file_offset};

	if (!pg_strong_random(data_key, sizeof(data_key)) ||
		!pg_strong_random(data_iv, sizeof(data_iv)) ||
		!pg_strong_random(wrap_iv, sizeof(wrap_iv)))
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("basic_file_encryption: could not generate encryption key material")));

	enlargeStringInfo(dst, body_len + BFE_OVERHEAD_SIZE);

	PG_TRY();
	{
		bfe_aes_gcm_encrypt(data_key, data_iv, record_aad_adapter, &aad,
							(const unsigned char *) data, body_len,
							(unsigned char *) dst->data + dst->len, data_tag);
		dst->len += body_len;

		memcpy(dst->data + dst->len, data_iv, BFE_IV_LEN);
		dst->len += BFE_IV_LEN;
		memcpy(dst->data + dst->len, data_tag, BFE_TAG_LEN);
		dst->len += BFE_TAG_LEN;
		memcpy(dst->data + dst->len, wrap_iv, BFE_IV_LEN);
		dst->len += BFE_IV_LEN;

		bfe_aes_gcm_encrypt(priv->kek, wrap_iv, record_aad_adapter, &aad,
							data_key, BFE_KEY_LEN,
							(unsigned char *) dst->data + dst->len, wrap_tag);
		dst->len += BFE_KEY_LEN;

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
	uint32		format;
	int			body_len;
	RecordAadCtx aad = {.path = path,.file_offset = file_offset};

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

	enlargeStringInfo(dst, body_len);

	PG_TRY();
	{
		bfe_aes_gcm_decrypt(priv->kek, wrap_iv, wrap_tag,
							record_aad_adapter, &aad,
							wrapped_key, BFE_KEY_LEN, data_key);
		bfe_aes_gcm_decrypt(data_key, data_iv, data_tag,
							record_aad_adapter, &aad,
							(const unsigned char *) data, body_len,
							(unsigned char *) dst->data + dst->len);
		dst->len += body_len;
	}
	PG_FINALLY();
	{
		explicit_bzero(data_key, sizeof(data_key));
	}
	PG_END_TRY();

	dst->data[dst->len] = '\0';
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
static void
bfe_generate_object_key(FileEncryptionModuleState *state,
						const RelFileLocator *locator,
						StringInfo dst)
{
	BasicFileEncryptionState *priv = bfe_require_kek(state);
	unsigned char dek[BFE_KEY_LEN];
	unsigned char wrap_iv[BFE_IV_LEN];
	unsigned char wrap_tag[BFE_TAG_LEN];
	uint32		format = BFE_OBJ_FORMAT_MAGIC;
	ObjectAadCtx aad = {.locator = locator};

	if (!pg_strong_random(dek, sizeof(dek)) ||
		!pg_strong_random(wrap_iv, sizeof(wrap_iv)))
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("basic_file_encryption: could not generate object key material")));

	enlargeStringInfo(dst, BFE_OBJ_WRAP_SIZE);

	PG_TRY();
	{
		memcpy(dst->data + dst->len, wrap_iv, BFE_IV_LEN);
		dst->len += BFE_IV_LEN;

		bfe_aes_gcm_encrypt(priv->kek, wrap_iv, object_aad_adapter, &aad,
							dek, BFE_KEY_LEN,
							(unsigned char *) dst->data + dst->len, wrap_tag);
		dst->len += BFE_KEY_LEN;

		memcpy(dst->data + dst->len, wrap_tag, BFE_TAG_LEN);
		dst->len += BFE_TAG_LEN;
		memcpy(dst->data + dst->len, &format, sizeof(format));
		dst->len += sizeof(format);

		Assert(dst->len == BFE_OBJ_WRAP_SIZE);
		dst->data[dst->len] = '\0';
	}
	PG_FINALLY();
	{
		explicit_bzero(dek, sizeof(dek));
		explicit_bzero(wrap_iv, sizeof(wrap_iv));
		explicit_bzero(wrap_tag, sizeof(wrap_tag));
	}
	PG_END_TRY();
}

static void *
bfe_object_open(FileEncryptionModuleState *state,
				const RelFileLocator *locator,
				const char *wrapped, Size wrapped_len)
{
	BasicFileEncryptionState *priv = bfe_require_kek(state);
	BFEObjectState *obj;
	const unsigned char *wrap_iv;
	const unsigned char *wrapped_dek;
	const unsigned char *wrap_tag;
	uint32		format;
	ObjectAadCtx aad = {.locator = locator};

	if (wrapped_len != BFE_OBJ_WRAP_SIZE)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("basic_file_encryption: wrapped object key has unexpected length %zu (want %zu)",
						wrapped_len, (Size) BFE_OBJ_WRAP_SIZE)));

	wrap_iv = (const unsigned char *) wrapped;
	wrapped_dek = wrap_iv + BFE_IV_LEN;
	wrap_tag = wrapped_dek + BFE_KEY_LEN;
	memcpy(&format, wrap_tag + BFE_TAG_LEN, sizeof(format));

	if (format != BFE_OBJ_FORMAT_MAGIC)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("basic_file_encryption: wrapped object key has unrecognized format 0x%08x",
						format)));

	obj = MemoryContextAllocZero(TopMemoryContext, sizeof(BFEObjectState));

	PG_TRY();
	{
		bfe_aes_gcm_decrypt(priv->kek, wrap_iv, wrap_tag,
							object_aad_adapter, &aad,
							wrapped_dek, BFE_KEY_LEN, obj->dek);
	}
	PG_CATCH();
	{
		explicit_bzero(obj->dek, sizeof(obj->dek));
		pfree(obj);
		PG_RE_THROW();
	}
	PG_END_TRY();

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
static void
bfe_encrypt_page(FileEncryptionModuleState *state,
				 void *object_state,
				 ForkNumber fork, BlockNumber blocknum,
				 const char *src, char *dst)
{
	BFEObjectState *obj = object_state;
	unsigned char data_iv[BFE_IV_LEN];
	unsigned char data_tag[BFE_TAG_LEN];
	uint32		format = BFE_PAGE_FORMAT_MAGIC;
	int			body_len = BLCKSZ - BFE_PAGE_OVERHEAD_SIZE;
	PageAadCtx	aad = {.fork = fork,.blocknum = blocknum};

	Assert(obj != NULL);

	if (!pg_strong_random(data_iv, sizeof(data_iv)))
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("basic_file_encryption: could not generate page IV")));

	PG_TRY();
	{
		bfe_aes_gcm_encrypt(obj->dek, data_iv, page_aad_adapter, &aad,
							(const unsigned char *) src, body_len,
							(unsigned char *) dst, data_tag);

		memcpy(dst + body_len, data_iv, BFE_IV_LEN);
		memcpy(dst + body_len + BFE_IV_LEN, data_tag, BFE_TAG_LEN);
		memcpy(dst + body_len + BFE_IV_LEN + BFE_TAG_LEN, &format, sizeof(format));
	}
	PG_FINALLY();
	{
		explicit_bzero(data_iv, sizeof(data_iv));
		explicit_bzero(data_tag, sizeof(data_tag));
	}
	PG_END_TRY();
}

static void
bfe_decrypt_page(FileEncryptionModuleState *state,
				 void *object_state,
				 ForkNumber fork, BlockNumber blocknum,
				 const char *src, char *dst)
{
	BFEObjectState *obj = object_state;
	const unsigned char *data_iv;
	const unsigned char *data_tag;
	uint32		format;
	int			body_len = BLCKSZ - BFE_PAGE_OVERHEAD_SIZE;
	PageAadCtx	aad = {.fork = fork,.blocknum = blocknum};

	Assert(obj != NULL);

	data_iv = (const unsigned char *) src + body_len;
	data_tag = data_iv + BFE_IV_LEN;
	memcpy(&format, data_tag + BFE_TAG_LEN, sizeof(format));

	if (format != BFE_PAGE_FORMAT_MAGIC)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("basic_file_encryption: encrypted page has unrecognized format 0x%08x",
						format)));

	bfe_aes_gcm_decrypt(obj->dek, data_iv, data_tag,
						page_aad_adapter, &aad,
						(const unsigned char *) src, body_len,
						(unsigned char *) dst);

	/* Zero the plaintext trailer so pd_checksum verifies (the writer's
	 * trailer is zeros per PageInit, and the decrypt output must match). */
	memset(dst + body_len, 0, BFE_PAGE_OVERHEAD_SIZE);
}
