/*-------------------------------------------------------------------------
 *
 * provider_file_encryption_impl.h
 *	  OpenSSL-provider-backed reference file encryption module implementation.
 *
 * This file is included by small module-specific wrappers that define:
 * PFEM_MODULE_NAME, PFEM_GUC_PREFIX, PFEM_CIPHER_DEFAULT,
 * PFEM_DIGEST_DEFAULT, PFEM_KEY_LEN, PFEM_FORMAT_MAGIC,
 * PFEM_OVERHEAD_SIZE, and PFEM_PROVIDER_HINT.
 *
 * Two encryption flows share the same configured KEK:
 *
 *   * Record-stream encryption (BufFile, reorderbuffer spill) uses a fresh
 *     DEK + MAC key pair per call.  Both are wrapped under the KEK and
 *     stored in the trailer.  Per-call overhead: PFEM_OVERHEAD_SIZE.
 *
 *   * Per-relation page encryption uses one (DEK, MAC key) pair per
 *     RelFileLocator, generated at relation-create time and wrapped under
 *     the KEK into the relation's KEY fork.  Each page's trailer holds
 *     only the per-page IV, HMAC tag, and a format marker.  Per-page
 *     overhead: 56 bytes (uniform across modules using this impl).
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * contrib/file_encryption_provider_common/provider_file_encryption_impl.h
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/provider.h>
#define PFEM_OPENSSL3 1
#else
#define PFEM_OPENSSL3 0
#endif

#include "access/xlog.h"
#include "fmgr.h"
#include "lib/stringinfo.h"
#include "port.h"
#include "storage/file_encryption.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/memutils.h"

PG_MODULE_MAGIC;

#define PFEM_IV_SLOT_LEN	16
#define PFEM_TAG_LEN		32
#define PFEM_KEY_MATERIAL_LEN	(PFEM_KEY_LEN * 2)
#define PFEM_FORMAT_LEN		sizeof(uint32)
#define PFEM_PAD_SIZE		(PFEM_OVERHEAD_SIZE - \
							 (2 * PFEM_IV_SLOT_LEN) - \
							 (2 * PFEM_TAG_LEN) - \
							 PFEM_KEY_MATERIAL_LEN - \
							 PFEM_FORMAT_LEN)

StaticAssertDecl(PFEM_KEY_LEN > 0, "invalid provider module key length");
StaticAssertDecl(PFEM_PAD_SIZE >= 0, "invalid provider module overhead");

/*
 * Per-page overhead: IV slot + HMAC tag + format marker.  The DEK and MAC
 * key for a page come from the per-relation state cached on SMgrRelation,
 * so the trailer doesn't carry a wrapped key.  Uniform 56 bytes across
 * modules using this impl; cluster page_reserved_size must equal this.
 */
#define PFEM_PAGE_OVERHEAD_SIZE	56
#define PFEM_PAGE_PAD_SIZE	(PFEM_PAGE_OVERHEAD_SIZE - PFEM_IV_SLOT_LEN - \
							 PFEM_TAG_LEN - PFEM_FORMAT_LEN)
StaticAssertDecl(PFEM_PAGE_PAD_SIZE >= 0, "invalid provider page overhead");

#define PFEM_KEY_GUC		PFEM_GUC_PREFIX ".key"
#define PFEM_PROVIDER_GUC	PFEM_GUC_PREFIX ".provider"
#define PFEM_CIPHER_GUC		PFEM_GUC_PREFIX ".cipher"
#define PFEM_DIGEST_GUC		PFEM_GUC_PREFIX ".digest"

/*
 * Object-key wrap blob written to the KEY fork:
 *
 *	  [ wrap IV  PFEM_IV_SLOT_LEN ]
 *	  [ wrapped (data_key || mac_key)  PFEM_KEY_MATERIAL_LEN ]
 *	  [ HMAC tag  PFEM_TAG_LEN ]
 *	  [ format magic  4B ]
 *
 * Total: IV_SLOT + KEY_MATERIAL + TAG + 4.  The KEK never encrypts user
 * bytes; this is the only place it's used as a cipher key.
 */
#define PFEM_OBJ_WRAP_SIZE	(PFEM_IV_SLOT_LEN + PFEM_KEY_MATERIAL_LEN + \
							 PFEM_TAG_LEN + PFEM_FORMAT_LEN)

typedef struct ProviderFileEncryptionState
{
	unsigned char kek[PFEM_KEY_LEN];
	const EVP_CIPHER *cipher;
	const EVP_MD *digest;
#if PFEM_OPENSSL3
	EVP_MAC    *hmac;
	OSSL_PROVIDER *provider;
#endif
	int			iv_len;
} ProviderFileEncryptionState;

/* Per-relation state cached on SMgrRelation.encryption_object_state. */
typedef struct PFEObjectState
{
	unsigned char data_key[PFEM_KEY_LEN];
	unsigned char mac_key[PFEM_KEY_LEN];
} PFEObjectState;

static char *pfem_key = NULL;
static char *pfem_provider = NULL;
static char *pfem_cipher = NULL;
static char *pfem_digest = NULL;

static void pfem_startup(FileEncryptionModuleState *state);
static void pfem_shutdown(FileEncryptionModuleState *state);
static void pfem_encrypt(const FileEncryptionModuleState *state,
						 const char *path, uint64 file_offset,
						 const char *data, Size data_len,
						 StringInfo dst);
static void pfem_decrypt(const FileEncryptionModuleState *state,
						 const char *path, uint64 file_offset,
						 const char *data, Size data_len,
						 StringInfo dst);
static void pfem_generate_object_key(FileEncryptionModuleState *state,
									 const RelFileLocator *locator,
									 StringInfo dst);
static void *pfem_object_open(FileEncryptionModuleState *state,
							  const RelFileLocator *locator,
							  const char *wrapped, Size wrapped_len);
static void pfem_object_close(FileEncryptionModuleState *state,
							  void *object_state);
static void pfem_encrypt_page(FileEncryptionModuleState *state,
							  void *object_state,
							  ForkNumber fork, BlockNumber blocknum,
							  const char *src, char *dst);
static void pfem_decrypt_page(FileEncryptionModuleState *state,
							  void *object_state,
							  ForkNumber fork, BlockNumber blocknum,
							  const char *src, char *dst);

static inline ProviderFileEncryptionState *pfem_require_state(const FileEncryptionModuleState *state);
static pg_noreturn void pfem_openssl_error(const char *op);
static pg_noreturn void pfem_missing_algorithm(const char *kind,
											   const char *name);
static void pfem_load_crypto(ProviderFileEncryptionState *priv);
static void pfem_free_crypto(ProviderFileEncryptionState *priv);
static void pfem_cipher_crypt(const ProviderFileEncryptionState *priv,
							  bool encrypting,
							  const unsigned char *key,
							  const unsigned char iv[PFEM_IV_SLOT_LEN],
							  const unsigned char *data, int data_len,
							  StringInfo dst);
static void pfem_cipher_crypt_raw(const ProviderFileEncryptionState *priv,
								  bool encrypting,
								  const unsigned char *key,
								  const unsigned char iv[PFEM_IV_SLOT_LEN],
								  const unsigned char *data, int data_len,
								  unsigned char *out);
static void pfem_hmac_raw(const ProviderFileEncryptionState *priv,
						  const unsigned char *key, int key_len,
						  const unsigned char *aad, int aad_len,
						  const unsigned char *data, int data_len,
						  unsigned char tag[PFEM_TAG_LEN]);
static void pfem_hmac(const ProviderFileEncryptionState *priv,
					  const unsigned char *key, int key_len,
					  const char *path, uint64 file_offset,
					  const unsigned char *data, int data_len,
					  unsigned char tag[PFEM_TAG_LEN]);

static const FileEncryptionCallbacks provider_file_encryption_callbacks = {
	PG_FILE_ENCRYPTION_MAGIC,
	.overhead_size = PFEM_OVERHEAD_SIZE,
	.page_overhead_size = PFEM_PAGE_OVERHEAD_SIZE,

	.startup_cb = pfem_startup,
	.shutdown_cb = pfem_shutdown,
	.encrypt_cb = pfem_encrypt,
	.decrypt_cb = pfem_decrypt,

	.generate_object_key_cb = pfem_generate_object_key,
	.object_open_cb = pfem_object_open,
	.object_close_cb = pfem_object_close,
	.encrypt_page_cb = pfem_encrypt_page,
	.decrypt_page_cb = pfem_decrypt_page,
};

static bool
pfem_check_key(char **newval, void **extra, GucSource source)
{
	const char *str = *newval;

	if (str == NULL || *str == '\0')
		return true;

	if (strlen(str) != PFEM_KEY_LEN * 2)
	{
		GUC_check_errdetail("%s must be %d hex characters (got %zu).",
							PFEM_KEY_GUC, PFEM_KEY_LEN * 2, strlen(str));
		return false;
	}

	for (const char *p = str; *p; p++)
	{
		if (!isxdigit((unsigned char) *p))
		{
			GUC_check_errdetail("%s must contain only hexadecimal digits.",
								PFEM_KEY_GUC);
			return false;
		}
	}

	return true;
}

void
_PG_init(void)
{
	DefineCustomStringVariable(PFEM_KEY_GUC,
							   "Hex-encoded key-encryption key used to wrap file encryption keys.",
							   NULL,
							   &pfem_key,
							   "",
							   PGC_POSTMASTER,
							   GUC_SUPERUSER_ONLY,
							   pfem_check_key, NULL, NULL);

	DefineCustomStringVariable(PFEM_PROVIDER_GUC,
							   "OpenSSL provider to load before resolving the file encryption cipher and digest.",
							   NULL,
							   &pfem_provider,
							   "",
							   PGC_POSTMASTER,
							   GUC_SUPERUSER_ONLY,
							   NULL, NULL, NULL);

	DefineCustomStringVariable(PFEM_CIPHER_GUC,
							   "OpenSSL cipher name used for file encryption.",
							   NULL,
							   &pfem_cipher,
							   PFEM_CIPHER_DEFAULT,
							   PGC_POSTMASTER,
							   GUC_SUPERUSER_ONLY,
							   NULL, NULL, NULL);

	DefineCustomStringVariable(PFEM_DIGEST_GUC,
							   "OpenSSL digest name used with HMAC for file authentication.",
							   NULL,
							   &pfem_digest,
							   PFEM_DIGEST_DEFAULT,
							   PGC_POSTMASTER,
							   GUC_SUPERUSER_ONLY,
							   NULL, NULL, NULL);

	MarkGUCPrefixReserved(PFEM_GUC_PREFIX);
}

const FileEncryptionCallbacks *
_PG_file_encryption_module_init(void)
{
	return &provider_file_encryption_callbacks;
}

static void
pfem_startup(FileEncryptionModuleState *state)
{
	ProviderFileEncryptionState *priv;
	uint64		decoded;

	if (pfem_key == NULL || pfem_key[0] == '\0')
	{
		state->private_data = NULL;
		return;
	}

	priv = palloc0_object(ProviderFileEncryptionState);

	decoded = hex_decode(pfem_key, strlen(pfem_key), (char *) priv->kek);
	Assert(decoded == PFEM_KEY_LEN);
	(void) decoded;

	PG_TRY();
	{
		pfem_load_crypto(priv);
	}
	PG_CATCH();
	{
		explicit_bzero(priv->kek, sizeof(priv->kek));
		pfem_free_crypto(priv);
		pfree(priv);
		PG_RE_THROW();
	}
	PG_END_TRY();

	state->private_data = priv;
}

static void
pfem_shutdown(FileEncryptionModuleState *state)
{
	ProviderFileEncryptionState *priv = state->private_data;

	if (priv != NULL)
	{
		explicit_bzero(priv->kek, sizeof(priv->kek));
		pfem_free_crypto(priv);
		pfree(priv);
		state->private_data = NULL;
	}
}

static inline ProviderFileEncryptionState *
pfem_require_state(const FileEncryptionModuleState *state)
{
	ProviderFileEncryptionState *priv = state->private_data;

	if (priv == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("%s is not set", PFEM_KEY_GUC)));
	return priv;
}

static pg_noreturn void
pfem_openssl_error(const char *op)
{
	unsigned long e = ERR_get_error();
	char		buf[256];

	if (e == 0)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("%s: %s failed", PFEM_MODULE_NAME, op)));

	ERR_error_string_n(e, buf, sizeof(buf));
	ereport(ERROR,
			(errcode(ERRCODE_INTERNAL_ERROR),
			 errmsg("%s: %s failed: %s", PFEM_MODULE_NAME, op, buf)));
}

static pg_noreturn void
pfem_missing_algorithm(const char *kind, const char *name)
{
	ereport(ERROR,
			(errcode(ERRCODE_CONFIG_FILE_ERROR),
			 errmsg("%s: could not fetch OpenSSL %s \"%s\"",
					PFEM_MODULE_NAME, kind, name),
			 errhint("Install or activate an OpenSSL provider that implements it. "
					 "If needed, set %s to the provider name and adjust %s or %s to the provider's algorithm names.",
					 PFEM_PROVIDER_GUC, PFEM_CIPHER_GUC, PFEM_DIGEST_GUC),
			 errdetail("Common provider name for this module: \"%s\".",
					   PFEM_PROVIDER_HINT)));
}

static int
pfem_cipher_key_length(const EVP_CIPHER *cipher)
{
#if PFEM_OPENSSL3
	return EVP_CIPHER_get_key_length(cipher);
#else
	return EVP_CIPHER_key_length(cipher);
#endif
}

static int
pfem_cipher_iv_length(const EVP_CIPHER *cipher)
{
#if PFEM_OPENSSL3
	return EVP_CIPHER_get_iv_length(cipher);
#else
	return EVP_CIPHER_iv_length(cipher);
#endif
}

static int
pfem_cipher_mode(const EVP_CIPHER *cipher)
{
#if PFEM_OPENSSL3
	return EVP_CIPHER_get_mode(cipher);
#else
	return EVP_CIPHER_mode(cipher);
#endif
}

static void
pfem_load_crypto(ProviderFileEncryptionState *priv)
{
	int			key_len;
	int			mode;
	unsigned char tag[PFEM_TAG_LEN];

	if (pfem_cipher == NULL || pfem_cipher[0] == '\0')
		ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("%s must not be empty", PFEM_CIPHER_GUC)));
	if (pfem_digest == NULL || pfem_digest[0] == '\0')
		ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("%s must not be empty", PFEM_DIGEST_GUC)));

#if PFEM_OPENSSL3
	if (pfem_provider != NULL && pfem_provider[0] != '\0')
	{
		priv->provider = OSSL_PROVIDER_load(NULL, pfem_provider);
		if (priv->provider == NULL)
			pfem_missing_algorithm("provider", pfem_provider);
	}

	priv->cipher = EVP_CIPHER_fetch(NULL, pfem_cipher, NULL);
	if (priv->cipher == NULL)
		pfem_missing_algorithm("cipher", pfem_cipher);

	priv->digest = EVP_MD_fetch(NULL, pfem_digest, NULL);
	if (priv->digest == NULL)
		pfem_missing_algorithm("digest", pfem_digest);

	priv->hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	if (priv->hmac == NULL)
		pfem_missing_algorithm("MAC", "HMAC");
#else
	priv->cipher = EVP_get_cipherbyname(pfem_cipher);
	if (priv->cipher == NULL)
		pfem_missing_algorithm("cipher", pfem_cipher);

	priv->digest = EVP_get_digestbyname(pfem_digest);
	if (priv->digest == NULL)
		pfem_missing_algorithm("digest", pfem_digest);
#endif

	key_len = pfem_cipher_key_length(priv->cipher);
	if (key_len != PFEM_KEY_LEN)
		ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("%s: OpenSSL cipher \"%s\" has key length %d, expected %d",
						PFEM_MODULE_NAME, pfem_cipher, key_len, PFEM_KEY_LEN)));

	priv->iv_len = pfem_cipher_iv_length(priv->cipher);
	if (priv->iv_len <= 0 || priv->iv_len > PFEM_IV_SLOT_LEN)
		ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("%s: OpenSSL cipher \"%s\" has IV length %d, expected 1..%d",
						PFEM_MODULE_NAME, pfem_cipher, priv->iv_len,
						PFEM_IV_SLOT_LEN)));

	mode = pfem_cipher_mode(priv->cipher);
	if (mode != EVP_CIPH_CTR_MODE &&
		mode != EVP_CIPH_CFB_MODE &&
		mode != EVP_CIPH_OFB_MODE &&
		mode != EVP_CIPH_STREAM_CIPHER)
		ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("%s: OpenSSL cipher \"%s\" is not a streaming cipher mode",
						PFEM_MODULE_NAME, pfem_cipher),
				 errhint("Use a provider cipher in CTR, CFB, OFB, or stream mode.")));

	pfem_hmac_raw(priv, priv->kek, PFEM_KEY_LEN, NULL, 0, NULL, 0, tag);
}

static void
pfem_free_crypto(ProviderFileEncryptionState *priv)
{
#if PFEM_OPENSSL3
	if (priv->cipher != NULL)
		EVP_CIPHER_free(unconstify(EVP_CIPHER *, priv->cipher));
	if (priv->digest != NULL)
		EVP_MD_free(unconstify(EVP_MD *, priv->digest));
	if (priv->hmac != NULL)
		EVP_MAC_free(priv->hmac);
	if (priv->provider != NULL)
		OSSL_PROVIDER_unload(priv->provider);
#endif
	priv->cipher = NULL;
	priv->digest = NULL;
#if PFEM_OPENSSL3
	priv->hmac = NULL;
	priv->provider = NULL;
#endif
}

static const char *
pfem_basename(const char *path)
{
	const char *basename = strrchr(path, '/');

	return basename ? basename + 1 : path;
}

static void
pfem_store64_be(unsigned char *dst, uint64 v)
{
	for (int i = 0; i < 8; i++)
		dst[i] = (unsigned char) (v >> ((7 - i) * 8));
}

static void
pfem_store32_be(unsigned char *dst, uint32 v)
{
	for (int i = 0; i < 4; i++)
		dst[i] = (unsigned char) (v >> ((3 - i) * 8));
}

/*
 * HMAC-of-(AAD || data) under 'key'.  AAD is an arbitrary byte string; the
 * caller assembles the right shape for its flow:
 *
 *   * Record stream:   basename(path) || file_offset(be64)
 *   * Object key wrap: relNumber(be32)
 *   * Page:            fork(be32) || blocknum(be32)
 */
static void
pfem_hmac_raw(const ProviderFileEncryptionState *priv,
			  const unsigned char *key, int key_len,
			  const unsigned char *aad, int aad_len,
			  const unsigned char *data, int data_len,
			  unsigned char tag[PFEM_TAG_LEN])
{
	unsigned char fulltag[EVP_MAX_MD_SIZE];
	size_t		tag_len = 0;

#if PFEM_OPENSSL3
	{
		EVP_MAC_CTX *ctx;
		OSSL_PARAM	params[2];

		ctx = EVP_MAC_CTX_new(priv->hmac);
		if (ctx == NULL)
			pfem_openssl_error("EVP_MAC_CTX_new");

		params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
													 pfem_digest, 0);
		params[1] = OSSL_PARAM_construct_end();

		PG_TRY();
		{
			if (EVP_MAC_init(ctx, key, key_len, params) != 1 ||
				(aad_len > 0 &&
				 EVP_MAC_update(ctx, aad, aad_len) != 1) ||
				(data_len > 0 &&
				 EVP_MAC_update(ctx, data, data_len) != 1) ||
				EVP_MAC_final(ctx, fulltag, &tag_len, sizeof(fulltag)) != 1)
				pfem_openssl_error("HMAC");
		}
		PG_FINALLY();
		{
			EVP_MAC_CTX_free(ctx);
		}
		PG_END_TRY();
	}
#else
	{
		HMAC_CTX   *ctx;
		unsigned int outlen;

		ctx = HMAC_CTX_new();
		if (ctx == NULL)
			pfem_openssl_error("HMAC_CTX_new");

		PG_TRY();
		{
			if (HMAC_Init_ex(ctx, key, key_len, priv->digest, NULL) != 1 ||
				(aad_len > 0 &&
				 HMAC_Update(ctx, aad, aad_len) != 1) ||
				(data_len > 0 &&
				 HMAC_Update(ctx, data, data_len) != 1) ||
				HMAC_Final(ctx, fulltag, &outlen) != 1)
				pfem_openssl_error("HMAC");
			tag_len = outlen;
		}
		PG_FINALLY();
		{
			HMAC_CTX_free(ctx);
		}
		PG_END_TRY();
	}
#endif

	if (tag_len != PFEM_TAG_LEN)
		ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("%s: OpenSSL digest \"%s\" produces %zu-byte HMAC tags, expected %d",
						PFEM_MODULE_NAME, pfem_digest, tag_len, PFEM_TAG_LEN)));

	memcpy(tag, fulltag, PFEM_TAG_LEN);
	explicit_bzero(fulltag, sizeof(fulltag));
}

/*
 * Record-stream HMAC: AAD = basename(path) || file_offset(be64).
 */
static void
pfem_hmac(const ProviderFileEncryptionState *priv,
		  const unsigned char *key, int key_len,
		  const char *path, uint64 file_offset,
		  const unsigned char *data, int data_len,
		  unsigned char tag[PFEM_TAG_LEN])
{
	const char *basename = pfem_basename(path);
	size_t		baselen = strlen(basename);
	unsigned char *aad;
	int			aad_len;

	aad_len = (int) baselen + 8;
	aad = palloc(aad_len);
	memcpy(aad, basename, baselen);
	pfem_store64_be(aad + baselen, file_offset);

	PG_TRY();
	{
		pfem_hmac_raw(priv, key, key_len, aad, aad_len,
					  data, data_len, tag);
	}
	PG_FINALLY();
	{
		pfree(aad);
	}
	PG_END_TRY();
}

/*
 * StringInfo wrapper around pfem_cipher_crypt_raw.  Used by the
 * record-stream flow which builds variable-length output.
 */
static void
pfem_cipher_crypt(const ProviderFileEncryptionState *priv,
				  bool encrypting,
				  const unsigned char *key,
				  const unsigned char iv[PFEM_IV_SLOT_LEN],
				  const unsigned char *data, int data_len,
				  StringInfo dst)
{
	enlargeStringInfo(dst, data_len);
	pfem_cipher_crypt_raw(priv, encrypting, key, iv, data, data_len,
						  (unsigned char *) dst->data + dst->len);
	dst->len += data_len;
	dst->data[dst->len] = '\0';
}

static void
pfem_cipher_crypt_raw(const ProviderFileEncryptionState *priv,
					  bool encrypting,
					  const unsigned char *key,
					  const unsigned char iv[PFEM_IV_SLOT_LEN],
					  const unsigned char *data, int data_len,
					  unsigned char *out)
{
	EVP_CIPHER_CTX *ctx;
	int			outlen;
	int			finallen;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		pfem_openssl_error("EVP_CIPHER_CTX_new");

	PG_TRY();
	{
		if (EVP_CipherInit_ex(ctx, priv->cipher, NULL, NULL, NULL,
							  encrypting ? 1 : 0) != 1)
			pfem_openssl_error("EVP_CipherInit_ex");
		if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1)
			pfem_openssl_error("EVP_CIPHER_CTX_set_padding");
		if (EVP_CipherInit_ex(ctx, NULL, NULL, key, iv,
							  encrypting ? 1 : 0) != 1)
			pfem_openssl_error("EVP_CipherInit_ex (key/iv)");

		if (EVP_CipherUpdate(ctx, out, &outlen, data, data_len) != 1)
			pfem_openssl_error("EVP_CipherUpdate");
		if (outlen != data_len)
			ereport(ERROR,
					(errcode(ERRCODE_CONFIG_FILE_ERROR),
					 errmsg("%s: OpenSSL cipher \"%s\" produced %d bytes for %d input bytes",
							PFEM_MODULE_NAME, pfem_cipher, outlen, data_len),
					 errhint("Use a provider cipher in CTR, CFB, OFB, or stream mode.")));

		if (EVP_CipherFinal_ex(ctx, out + outlen, &finallen) != 1)
			pfem_openssl_error("EVP_CipherFinal_ex");
		if (finallen != 0)
			ereport(ERROR,
					(errcode(ERRCODE_CONFIG_FILE_ERROR),
					 errmsg("%s: OpenSSL cipher \"%s\" produced unexpected final output",
							PFEM_MODULE_NAME, pfem_cipher),
					 errhint("Use a provider cipher in CTR, CFB, OFB, or stream mode.")));
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
 */
static void
pfem_encrypt(const FileEncryptionModuleState *state,
			 const char *path, uint64 file_offset,
			 const char *data, Size data_len,
			 StringInfo dst)
{
	ProviderFileEncryptionState *priv = pfem_require_state(state);
	unsigned char data_enc_key[PFEM_KEY_LEN];
	unsigned char data_mac_key[PFEM_KEY_LEN];
	unsigned char key_material[PFEM_KEY_MATERIAL_LEN];
	unsigned char data_iv[PFEM_IV_SLOT_LEN] = {0};
	unsigned char wrap_iv[PFEM_IV_SLOT_LEN] = {0};
	unsigned char data_tag[PFEM_TAG_LEN];
	unsigned char wrap_tag[PFEM_TAG_LEN];
	uint32		format = PFEM_FORMAT_MAGIC;
	int			body_len = (int) data_len;
	int			ciphertext_start;
	int			wrapped_key_start;

	if (!pg_strong_random(data_enc_key, sizeof(data_enc_key)) ||
		!pg_strong_random(data_mac_key, sizeof(data_mac_key)) ||
		!pg_strong_random(data_iv, priv->iv_len) ||
		!pg_strong_random(wrap_iv, priv->iv_len))
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("%s: could not generate encryption key material",
						PFEM_MODULE_NAME)));

	memcpy(key_material, data_enc_key, PFEM_KEY_LEN);
	memcpy(key_material + PFEM_KEY_LEN, data_mac_key, PFEM_KEY_LEN);

	enlargeStringInfo(dst, body_len + PFEM_OVERHEAD_SIZE);

	PG_TRY();
	{
		ciphertext_start = dst->len;
		pfem_cipher_crypt(priv, true, data_enc_key, data_iv,
						  (const unsigned char *) data, body_len, dst);
		pfem_hmac(priv, data_mac_key, PFEM_KEY_LEN, path, file_offset,
				  (const unsigned char *) dst->data + ciphertext_start,
				  body_len, data_tag);

		memcpy(dst->data + dst->len, data_iv, PFEM_IV_SLOT_LEN);
		dst->len += PFEM_IV_SLOT_LEN;
		memcpy(dst->data + dst->len, data_tag, PFEM_TAG_LEN);
		dst->len += PFEM_TAG_LEN;
		memcpy(dst->data + dst->len, wrap_iv, PFEM_IV_SLOT_LEN);
		dst->len += PFEM_IV_SLOT_LEN;

		wrapped_key_start = dst->len;
		pfem_cipher_crypt(priv, true, priv->kek, wrap_iv,
						  key_material, PFEM_KEY_MATERIAL_LEN, dst);
		Assert(dst->len == wrapped_key_start + PFEM_KEY_MATERIAL_LEN);
		pfem_hmac(priv, priv->kek, PFEM_KEY_LEN, path, file_offset,
				  (const unsigned char *) dst->data + wrapped_key_start,
				  PFEM_KEY_MATERIAL_LEN, wrap_tag);

		memcpy(dst->data + dst->len, wrap_tag, PFEM_TAG_LEN);
		dst->len += PFEM_TAG_LEN;
		memcpy(dst->data + dst->len, &format, sizeof(format));
		dst->len += sizeof(format);
		memset(dst->data + dst->len, 0, PFEM_PAD_SIZE);
		dst->len += PFEM_PAD_SIZE;
		Assert(dst->len == body_len + PFEM_OVERHEAD_SIZE);
		dst->data[dst->len] = '\0';
	}
	PG_FINALLY();
	{
		explicit_bzero(data_enc_key, sizeof(data_enc_key));
		explicit_bzero(data_mac_key, sizeof(data_mac_key));
		explicit_bzero(key_material, sizeof(key_material));
		explicit_bzero(data_iv, sizeof(data_iv));
		explicit_bzero(wrap_iv, sizeof(wrap_iv));
		explicit_bzero(data_tag, sizeof(data_tag));
		explicit_bzero(wrap_tag, sizeof(wrap_tag));
	}
	PG_END_TRY();
}

static void
pfem_decrypt(const FileEncryptionModuleState *state,
			 const char *path, uint64 file_offset,
			 const char *data, Size data_len,
			 StringInfo dst)
{
	ProviderFileEncryptionState *priv = pfem_require_state(state);
	const unsigned char *data_iv;
	const unsigned char *data_tag;
	const unsigned char *wrap_iv;
	const unsigned char *wrapped_keys;
	const unsigned char *wrap_tag;
	unsigned char expected_tag[PFEM_TAG_LEN];
	unsigned char key_material[PFEM_KEY_MATERIAL_LEN];
	char		key_material_buf[PFEM_KEY_MATERIAL_LEN + 1];
	StringInfoData key_material_out;
	uint32		format;
	int			body_len;

	if (data_len < PFEM_OVERHEAD_SIZE)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("%s: encrypted blob is too short (%zu bytes)",
						PFEM_MODULE_NAME, data_len)));

	body_len = (int) (data_len - PFEM_OVERHEAD_SIZE);
	data_iv = (const unsigned char *) data + body_len;
	data_tag = data_iv + PFEM_IV_SLOT_LEN;
	wrap_iv = data_tag + PFEM_TAG_LEN;
	wrapped_keys = wrap_iv + PFEM_IV_SLOT_LEN;
	wrap_tag = wrapped_keys + PFEM_KEY_MATERIAL_LEN;
	memcpy(&format, wrap_tag + PFEM_TAG_LEN, sizeof(format));

	if (format != PFEM_FORMAT_MAGIC)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("%s: encrypted blob has an unrecognized format",
						PFEM_MODULE_NAME)));

	key_material_out.data = key_material_buf;
	key_material_out.len = 0;
	key_material_out.maxlen = sizeof(key_material_buf);
	key_material_out.cursor = 0;

	PG_TRY();
	{
		pfem_hmac(priv, priv->kek, PFEM_KEY_LEN, path, file_offset,
				  wrapped_keys, PFEM_KEY_MATERIAL_LEN, expected_tag);
		if (timingsafe_bcmp(expected_tag, wrap_tag, PFEM_TAG_LEN) != 0)
			ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg("%s: wrapped key authentication failed",
							PFEM_MODULE_NAME),
					 errdetail("Path \"%s\" offset %llu was tampered with, or the key has changed.",
							   path, (unsigned long long) file_offset)));

		pfem_cipher_crypt(priv, false, priv->kek, wrap_iv,
						  wrapped_keys, PFEM_KEY_MATERIAL_LEN,
						  &key_material_out);
		if (key_material_out.len != PFEM_KEY_MATERIAL_LEN)
			ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg("%s: wrapped key decrypted to %d bytes, expected %d",
							PFEM_MODULE_NAME, key_material_out.len,
							PFEM_KEY_MATERIAL_LEN)));
		memcpy(key_material, key_material_out.data, PFEM_KEY_MATERIAL_LEN);

		pfem_hmac(priv, key_material + PFEM_KEY_LEN, PFEM_KEY_LEN,
				  path, file_offset, (const unsigned char *) data,
				  body_len, expected_tag);
		if (timingsafe_bcmp(expected_tag, data_tag, PFEM_TAG_LEN) != 0)
			ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg("%s: authentication tag verification failed",
							PFEM_MODULE_NAME),
					 errdetail("Path \"%s\" offset %llu was tampered with, or the key has changed.",
							   path, (unsigned long long) file_offset)));

		pfem_cipher_crypt(priv, false, key_material, data_iv,
						  (const unsigned char *) data, body_len, dst);
		Assert(dst->len == body_len);
	}
	PG_FINALLY();
	{
		explicit_bzero(expected_tag, sizeof(expected_tag));
		explicit_bzero(key_material, sizeof(key_material));
		explicit_bzero(key_material_buf, sizeof(key_material_buf));
	}
	PG_END_TRY();

	dst->data[dst->len] = '\0';
}

/*
 * ============================================================
 *	  Per-relation page encryption
 * ============================================================
 */
static void
pfem_generate_object_key(FileEncryptionModuleState *state,
						 const RelFileLocator *locator,
						 StringInfo dst)
{
	ProviderFileEncryptionState *priv = pfem_require_state(state);
	unsigned char data_key[PFEM_KEY_LEN];
	unsigned char mac_key[PFEM_KEY_LEN];
	unsigned char key_material[PFEM_KEY_MATERIAL_LEN];
	unsigned char wrap_iv[PFEM_IV_SLOT_LEN] = {0};
	unsigned char wrap_tag[PFEM_TAG_LEN];
	unsigned char aad[4];
	uint32		format = PFEM_FORMAT_MAGIC;
	int			wrapped_keys_start;

	if (!pg_strong_random(data_key, sizeof(data_key)) ||
		!pg_strong_random(mac_key, sizeof(mac_key)) ||
		!pg_strong_random(wrap_iv, priv->iv_len))
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("%s: could not generate object key material",
						PFEM_MODULE_NAME)));

	memcpy(key_material, data_key, PFEM_KEY_LEN);
	memcpy(key_material + PFEM_KEY_LEN, mac_key, PFEM_KEY_LEN);
	pfem_store32_be(aad, locator->relNumber);

	enlargeStringInfo(dst, PFEM_OBJ_WRAP_SIZE);

	PG_TRY();
	{
		memcpy(dst->data + dst->len, wrap_iv, PFEM_IV_SLOT_LEN);
		dst->len += PFEM_IV_SLOT_LEN;

		wrapped_keys_start = dst->len;
		pfem_cipher_crypt(priv, true, priv->kek, wrap_iv,
						  key_material, PFEM_KEY_MATERIAL_LEN, dst);
		Assert(dst->len == wrapped_keys_start + PFEM_KEY_MATERIAL_LEN);

		pfem_hmac_raw(priv, priv->kek, PFEM_KEY_LEN, aad, sizeof(aad),
					  (const unsigned char *) dst->data + wrapped_keys_start,
					  PFEM_KEY_MATERIAL_LEN, wrap_tag);

		memcpy(dst->data + dst->len, wrap_tag, PFEM_TAG_LEN);
		dst->len += PFEM_TAG_LEN;
		memcpy(dst->data + dst->len, &format, sizeof(format));
		dst->len += sizeof(format);

		Assert(dst->len == PFEM_OBJ_WRAP_SIZE);
		dst->data[dst->len] = '\0';
	}
	PG_FINALLY();
	{
		explicit_bzero(data_key, sizeof(data_key));
		explicit_bzero(mac_key, sizeof(mac_key));
		explicit_bzero(key_material, sizeof(key_material));
		explicit_bzero(wrap_iv, sizeof(wrap_iv));
		explicit_bzero(wrap_tag, sizeof(wrap_tag));
	}
	PG_END_TRY();
}

static void *
pfem_object_open(FileEncryptionModuleState *state,
				 const RelFileLocator *locator,
				 const char *wrapped, Size wrapped_len)
{
	ProviderFileEncryptionState *priv = pfem_require_state(state);
	PFEObjectState *obj;
	const unsigned char *wrap_iv;
	const unsigned char *wrapped_keys;
	const unsigned char *wrap_tag;
	unsigned char expected_tag[PFEM_TAG_LEN];
	unsigned char key_material[PFEM_KEY_MATERIAL_LEN];
	unsigned char aad[4];
	uint32		format;

	if (wrapped_len != PFEM_OBJ_WRAP_SIZE)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("%s: wrapped object key has unexpected length %zu (want %zu)",
						PFEM_MODULE_NAME, wrapped_len, (Size) PFEM_OBJ_WRAP_SIZE)));

	wrap_iv = (const unsigned char *) wrapped;
	wrapped_keys = wrap_iv + PFEM_IV_SLOT_LEN;
	wrap_tag = wrapped_keys + PFEM_KEY_MATERIAL_LEN;
	memcpy(&format, wrap_tag + PFEM_TAG_LEN, sizeof(format));

	if (format != PFEM_FORMAT_MAGIC)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("%s: wrapped object key has unrecognized format 0x%08x",
						PFEM_MODULE_NAME, format)));

	pfem_store32_be(aad, locator->relNumber);

	obj = MemoryContextAllocZero(TopMemoryContext, sizeof(PFEObjectState));

	PG_TRY();
	{
		pfem_hmac_raw(priv, priv->kek, PFEM_KEY_LEN, aad, sizeof(aad),
					  wrapped_keys, PFEM_KEY_MATERIAL_LEN, expected_tag);
		if (timingsafe_bcmp(expected_tag, wrap_tag, PFEM_TAG_LEN) != 0)
			ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg("%s: object key authentication failed",
							PFEM_MODULE_NAME)));

		pfem_cipher_crypt_raw(priv, false, priv->kek, wrap_iv,
							  wrapped_keys, PFEM_KEY_MATERIAL_LEN,
							  key_material);
		memcpy(obj->data_key, key_material, PFEM_KEY_LEN);
		memcpy(obj->mac_key, key_material + PFEM_KEY_LEN, PFEM_KEY_LEN);
	}
	PG_CATCH();
	{
		explicit_bzero(obj->data_key, sizeof(obj->data_key));
		explicit_bzero(obj->mac_key, sizeof(obj->mac_key));
		explicit_bzero(expected_tag, sizeof(expected_tag));
		explicit_bzero(key_material, sizeof(key_material));
		pfree(obj);
		PG_RE_THROW();
	}
	PG_END_TRY();

	explicit_bzero(expected_tag, sizeof(expected_tag));
	explicit_bzero(key_material, sizeof(key_material));

	return obj;
}

static void
pfem_object_close(FileEncryptionModuleState *state, void *object_state)
{
	PFEObjectState *obj = object_state;

	if (obj == NULL)
		return;
	explicit_bzero(obj->data_key, sizeof(obj->data_key));
	explicit_bzero(obj->mac_key, sizeof(obj->mac_key));
	pfree(obj);
}

/*
 * Page layout (BLCKSZ bytes):
 *
 *	  dst[0 .. BLCKSZ - 56)              ciphertext (body)
 *	  dst[BLCKSZ - 56 .. BLCKSZ - 40)    page IV (16B)
 *	  dst[BLCKSZ - 40 .. BLCKSZ -  8)    HMAC tag (32B)
 *	  dst[BLCKSZ -  8 .. BLCKSZ -  4)    format magic (4B)
 *	  dst[BLCKSZ -  4 .. BLCKSZ)         padding (4B)
 */
static void
pfem_encrypt_page(FileEncryptionModuleState *state,
				  void *object_state,
				  ForkNumber fork, BlockNumber blocknum,
				  const char *src, char *dst)
{
	ProviderFileEncryptionState *priv = pfem_require_state(state);
	PFEObjectState *obj = object_state;
	unsigned char data_iv[PFEM_IV_SLOT_LEN] = {0};
	unsigned char data_tag[PFEM_TAG_LEN];
	unsigned char aad[8];
	uint32		format = PFEM_FORMAT_MAGIC;
	int			body_len = BLCKSZ - PFEM_PAGE_OVERHEAD_SIZE;

	Assert(obj != NULL);

	if (!pg_strong_random(data_iv, priv->iv_len))
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("%s: could not generate page IV", PFEM_MODULE_NAME)));

	pfem_store32_be(aad, (uint32) fork);
	pfem_store32_be(aad + 4, blocknum);

	PG_TRY();
	{
		pfem_cipher_crypt_raw(priv, true, obj->data_key, data_iv,
							  (const unsigned char *) src, body_len,
							  (unsigned char *) dst);

		pfem_hmac_raw(priv, obj->mac_key, PFEM_KEY_LEN, aad, sizeof(aad),
					  (const unsigned char *) dst, body_len, data_tag);

		memcpy(dst + body_len, data_iv, PFEM_IV_SLOT_LEN);
		memcpy(dst + body_len + PFEM_IV_SLOT_LEN, data_tag, PFEM_TAG_LEN);
		memcpy(dst + body_len + PFEM_IV_SLOT_LEN + PFEM_TAG_LEN,
			   &format, sizeof(format));
		if (PFEM_PAGE_PAD_SIZE > 0)
			memset(dst + body_len + PFEM_IV_SLOT_LEN + PFEM_TAG_LEN + sizeof(format),
				   0, PFEM_PAGE_PAD_SIZE);
	}
	PG_FINALLY();
	{
		explicit_bzero(data_iv, sizeof(data_iv));
		explicit_bzero(data_tag, sizeof(data_tag));
	}
	PG_END_TRY();
}

static void
pfem_decrypt_page(FileEncryptionModuleState *state,
				  void *object_state,
				  ForkNumber fork, BlockNumber blocknum,
				  const char *src, char *dst)
{
	ProviderFileEncryptionState *priv = pfem_require_state(state);
	PFEObjectState *obj = object_state;
	const unsigned char *data_iv;
	const unsigned char *data_tag;
	unsigned char expected_tag[PFEM_TAG_LEN];
	unsigned char aad[8];
	uint32		format;
	int			body_len = BLCKSZ - PFEM_PAGE_OVERHEAD_SIZE;

	Assert(obj != NULL);

	data_iv = (const unsigned char *) src + body_len;
	data_tag = data_iv + PFEM_IV_SLOT_LEN;
	memcpy(&format, data_tag + PFEM_TAG_LEN, sizeof(format));

	if (format != PFEM_FORMAT_MAGIC)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("%s: encrypted page has unrecognized format 0x%08x",
						PFEM_MODULE_NAME, format)));

	pfem_store32_be(aad, (uint32) fork);
	pfem_store32_be(aad + 4, blocknum);

	PG_TRY();
	{
		pfem_hmac_raw(priv, obj->mac_key, PFEM_KEY_LEN, aad, sizeof(aad),
					  (const unsigned char *) src, body_len, expected_tag);
		if (timingsafe_bcmp(expected_tag, data_tag, PFEM_TAG_LEN) != 0)
			ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg("%s: page authentication failed",
							PFEM_MODULE_NAME)));

		pfem_cipher_crypt_raw(priv, false, obj->data_key, data_iv,
							  (const unsigned char *) src, body_len,
							  (unsigned char *) dst);

		/* Zero the plaintext trailer so pd_checksum verifies. */
		memset(dst + body_len, 0, PFEM_PAGE_OVERHEAD_SIZE);
	}
	PG_FINALLY();
	{
		explicit_bzero(expected_tag, sizeof(expected_tag));
	}
	PG_END_TRY();
}
