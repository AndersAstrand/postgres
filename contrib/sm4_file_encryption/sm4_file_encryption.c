/*-------------------------------------------------------------------------
 *
 * sm4_file_encryption.c
 *	  Reference file_encryption_library module using SM4-CTR + SM3 HMAC.
 *
 * The hex-encoded key in the sm4_file_encryption.key GUC is a
 * key-encryption key (KEK).  It never encrypts user bytes directly; it
 * only wraps data-encryption keys (DEKs).
 *
 * Two encryption flows share the same KEK:
 *
 *   * Record-stream encryption (BufFile, reorderbuffer spill files) uses
 *     a fresh DEK + MAC key per call.  Both are wrapped under the KEK and
 *     stored in the per-record trailer.  Per-call overhead: 136 bytes.
 *
 *   * Per-relation page encryption uses one (DEK, MAC key) pair per
 *     RelFileLocator, generated at relation-create time and wrapped under
 *     the KEK into the relation's KEY fork.  Each page's trailer holds
 *     only the per-page IV, HMAC tag, and a format marker.  Per-page
 *     overhead: 56 bytes.
 *
 * AAD bindings:
 *
 *   * Record-stream encrypt/decrypt binds basename(path) || file_offset(be64).
 *     Using only the basename keeps CREATE DATABASE FILE_COPY and ALTER
 *     DATABASE SET TABLESPACE working -- both clone files into directories
 *     whose leading path components change.
 *
 *   * Object-key wrap (DEK ciphertext stored in the KEY fork) binds
 *     relNumber(be32).
 *
 *   * Page encrypt/decrypt binds fork(be32) || blocknum(be32).  The
 *     per-relation DEK already pins which relation we're in; the fork and
 *     blocknum prevent intra-relation page substitution -- including
 *     INIT-fork-to-MAIN-fork substitution.  reinit re-encrypts INIT bytes
 *     under MAIN's AAD on unlogged-relation reset.
 *
 * Defaults: SM4-CTR cipher, SM3 digest.  Both are in the OpenSSL default
 * provider on modern OpenSSL builds.  Operators who want to override the
 * algorithm (e.g. to test another provider) can set sm4_file_encryption.
 * {provider, cipher, digest} accordingly.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * contrib/sm4_file_encryption/sm4_file_encryption.c
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
#define SM4_OPENSSL3 1
#else
#define SM4_OPENSSL3 0
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

#define SM4_KEY_LEN				16
#define SM4_IV_SLOT_LEN			16
#define SM4_TAG_LEN				32
#define SM4_KEY_MATERIAL_LEN	(SM4_KEY_LEN * 2)
#define SM4_FORMAT_LEN			sizeof(uint32)
#define SM4_FORMAT_MAGIC		0x314d4653	/* "SFM1" in native byte order */

/*
 * Per-call (record-stream) on-disk overhead:
 *	[ data IV   ][ data tag ]
 *	[ wrap IV   ][ wrapped (DEK || MAC key) ][ wrap tag ]
 *	[ format ][ pad ]
 *
 * Sized to 136 bytes (132 used + 4 zero pad), a multiple of MAXIMUM_ALIGNOF.
 */
#define SM4_OVERHEAD_SIZE		136
#define SM4_PAD_SIZE			(SM4_OVERHEAD_SIZE - \
								 (2 * SM4_IV_SLOT_LEN) - \
								 (2 * SM4_TAG_LEN) - \
								 SM4_KEY_MATERIAL_LEN - \
								 SM4_FORMAT_LEN)
StaticAssertDecl(SM4_PAD_SIZE >= 0, "invalid sm4_file_encryption overhead");

/*
 * Per-page overhead.  The DEK lives in the KEY fork, so the page trailer
 * just carries the per-page IV, HMAC tag, and a format marker.
 */
#define SM4_PAGE_OVERHEAD_SIZE	56
#define SM4_PAGE_PAD_SIZE		(SM4_PAGE_OVERHEAD_SIZE - SM4_IV_SLOT_LEN - \
								 SM4_TAG_LEN - SM4_FORMAT_LEN)
StaticAssertDecl(SM4_PAGE_PAD_SIZE >= 0, "invalid sm4_file_encryption page overhead");

/*
 * Object-key wrap blob written to the KEY fork:
 *
 *	  [ wrap IV  16B ]
 *	  [ wrapped (data_key || mac_key)  32B ]
 *	  [ HMAC tag  32B ]
 *	  [ format magic  4B ]
 *
 * Total 84 bytes.
 */
#define SM4_OBJ_WRAP_SIZE		(SM4_IV_SLOT_LEN + SM4_KEY_MATERIAL_LEN + \
								 SM4_TAG_LEN + SM4_FORMAT_LEN)

#define SM4_DEFAULT_CIPHER	"SM4-CTR"
#define SM4_DEFAULT_DIGEST	"SM3"

typedef struct SM4FileEncryptionState
{
	unsigned char kek[SM4_KEY_LEN];
	const EVP_CIPHER *cipher;
	const EVP_MD *digest;
#if SM4_OPENSSL3
	EVP_MAC    *hmac;
	OSSL_PROVIDER *provider;
#endif
	int			iv_len;
} SM4FileEncryptionState;

/* Cached per-relation state, opaque to the core. */
typedef struct SM4ObjectState
{
	unsigned char data_key[SM4_KEY_LEN];
	unsigned char mac_key[SM4_KEY_LEN];
} SM4ObjectState;

/*
 * Module-static configuration parsed once from the config string handed
 * to _PG_file_encryption_module_init.  Inherited by forked backends via
 * copy-on-write; set once per frontend tool invocation.
 */
static unsigned char sm4_kek_static[SM4_KEY_LEN];
static bool sm4_kek_set = false;
static char *sm4_provider = NULL;
static char *sm4_cipher = NULL;
static char *sm4_digest = NULL;

static void sm4_startup(FileEncryptionModuleState *state);
static void sm4_shutdown(FileEncryptionModuleState *state);
static void sm4_encrypt(const FileEncryptionModuleState *state,
						const char *path, uint64 file_offset,
						const char *data, Size data_len,
						StringInfo dst);
static void sm4_decrypt(const FileEncryptionModuleState *state,
						const char *path, uint64 file_offset,
						const char *data, Size data_len,
						StringInfo dst);
static void sm4_generate_object_key(FileEncryptionModuleState *state,
									const RelFileLocator *locator,
									StringInfo dst);
static void *sm4_object_open(FileEncryptionModuleState *state,
							 const RelFileLocator *locator,
							 const char *wrapped, Size wrapped_len);
static void sm4_object_close(FileEncryptionModuleState *state,
							 void *object_state);
static void sm4_encrypt_page(FileEncryptionModuleState *state,
							 void *object_state,
							 ForkNumber fork, BlockNumber blocknum,
							 const char *src, char *dst);
static void sm4_decrypt_page(FileEncryptionModuleState *state,
							 void *object_state,
							 ForkNumber fork, BlockNumber blocknum,
							 const char *src, char *dst);

static inline SM4FileEncryptionState *sm4_require_state(const FileEncryptionModuleState *state);
static pg_noreturn void sm4_openssl_error(const char *op);
static pg_noreturn void sm4_missing_algorithm(const char *kind,
											  const char *name);
static void sm4_load_crypto(SM4FileEncryptionState *priv);
static void sm4_free_crypto(SM4FileEncryptionState *priv);
static void sm4_cipher_crypt(const SM4FileEncryptionState *priv,
							 bool encrypting,
							 const unsigned char *key,
							 const unsigned char iv[SM4_IV_SLOT_LEN],
							 const unsigned char *data, int data_len,
							 StringInfo dst);
static void sm4_cipher_crypt_raw(const SM4FileEncryptionState *priv,
								 bool encrypting,
								 const unsigned char *key,
								 const unsigned char iv[SM4_IV_SLOT_LEN],
								 const unsigned char *data, int data_len,
								 unsigned char *out);
static void sm4_hmac_raw(const SM4FileEncryptionState *priv,
						 const unsigned char *key, int key_len,
						 const unsigned char *aad, int aad_len,
						 const unsigned char *data, int data_len,
						 unsigned char tag[SM4_TAG_LEN]);
static void sm4_hmac(const SM4FileEncryptionState *priv,
					 const unsigned char *key, int key_len,
					 const char *path, uint64 file_offset,
					 const unsigned char *data, int data_len,
					 unsigned char tag[SM4_TAG_LEN]);

static const FileEncryptionCallbacks sm4_file_encryption_callbacks = {
	PG_FILE_ENCRYPTION_MAGIC,
	.overhead_size = SM4_OVERHEAD_SIZE,
	.page_overhead_size = SM4_PAGE_OVERHEAD_SIZE,

	.startup_cb = sm4_startup,
	.shutdown_cb = sm4_shutdown,
	.encrypt_cb = sm4_encrypt,
	.decrypt_cb = sm4_decrypt,

	.generate_object_key_cb = sm4_generate_object_key,
	.object_open_cb = sm4_object_open,
	.object_close_cb = sm4_object_close,
	.encrypt_page_cb = sm4_encrypt_page,
	.decrypt_page_cb = sm4_decrypt_page,
};

/*
 * Trim leading and trailing ASCII whitespace from a NUL-terminated string
 * in place.  Returns a pointer that may be advanced past the original
 * start; the caller is expected to copy out before mutating further.
 */
static char *
sm4_trim(char *s)
{
	char	   *end;

	while (*s == ' ' || *s == '\t' || *s == '\r')
		s++;
	end = s + strlen(s);
	while (end > s && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r'))
		end--;
	*end = '\0';
	return s;
}

/*
 * Hand-rolled parser for the module config string.
 *
 * Format: newline-separated "key=value" entries; blank lines and lines
 * starting with '#' are ignored; surrounding whitespace around the key
 * and value is stripped.  Recognised keys: "key" (required, 64 hex
 * characters), "provider", "cipher", "digest".  Returns true on success,
 * false on parse error with *errmsg set to a palloc'd description.
 */
static bool
sm4_parse_config(const char *config, char **errmsg)
{
	char	   *buf;
	char	   *saveptr = NULL;
	char	   *line;
	bool		have_key = false;

	if (config == NULL || config[0] == '\0')
	{
		*errmsg = pstrdup("sm4_file_encryption: 'config' is empty; expected at least a 'key=<hex>' line");
		return false;
	}

	if (sm4_provider != NULL)
	{
		pfree(sm4_provider);
		sm4_provider = NULL;
	}
	if (sm4_cipher != NULL)
	{
		pfree(sm4_cipher);
		sm4_cipher = NULL;
	}
	if (sm4_digest != NULL)
	{
		pfree(sm4_digest);
		sm4_digest = NULL;
	}

	buf = pstrdup(config);
	for (line = strtok_r(buf, "\n", &saveptr);
		 line != NULL;
		 line = strtok_r(NULL, "\n", &saveptr))
	{
		char	   *trimmed = sm4_trim(line);
		char	   *eq;
		char	   *key;
		char	   *val;

		if (trimmed[0] == '\0' || trimmed[0] == '#')
			continue;

		eq = strchr(trimmed, '=');
		if (eq == NULL)
		{
			*errmsg = psprintf("sm4_file_encryption: malformed config line (no '='): \"%s\"", trimmed);
			pfree(buf);
			return false;
		}

		*eq = '\0';
		key = sm4_trim(trimmed);
		val = sm4_trim(eq + 1);

		if (strcmp(key, "key") == 0)
		{
			uint64		decoded;

			if (strlen(val) != SM4_KEY_LEN * 2)
			{
				*errmsg = psprintf("sm4_file_encryption: 'key' must be %d hex characters (got %zu)",
								   SM4_KEY_LEN * 2, strlen(val));
				pfree(buf);
				return false;
			}
			for (const char *p = val; *p; p++)
			{
				if (!isxdigit((unsigned char) *p))
				{
					*errmsg = pstrdup("sm4_file_encryption: 'key' must contain only hexadecimal digits");
					pfree(buf);
					return false;
				}
			}
			decoded = hex_decode(val, strlen(val), (char *) sm4_kek_static);
			Assert(decoded == SM4_KEY_LEN);
			(void) decoded;
			have_key = true;
		}
		else if (strcmp(key, "provider") == 0)
			sm4_provider = MemoryContextStrdup(TopMemoryContext, val);
		else if (strcmp(key, "cipher") == 0)
			sm4_cipher = MemoryContextStrdup(TopMemoryContext, val);
		else if (strcmp(key, "digest") == 0)
			sm4_digest = MemoryContextStrdup(TopMemoryContext, val);
		else
		{
			*errmsg = psprintf("sm4_file_encryption: unknown config key \"%s\"", key);
			pfree(buf);
			return false;
		}
	}

	pfree(buf);

	if (!have_key)
	{
		*errmsg = pstrdup("sm4_file_encryption: required config key 'key' is missing");
		return false;
	}

	if (sm4_cipher == NULL)
		sm4_cipher = MemoryContextStrdup(TopMemoryContext, SM4_DEFAULT_CIPHER);
	if (sm4_digest == NULL)
		sm4_digest = MemoryContextStrdup(TopMemoryContext, SM4_DEFAULT_DIGEST);

	sm4_kek_set = true;
	return true;
}

bool
_PG_file_encryption_module_init(const char *config,
								const FileEncryptionCallbacks **callbacks_out,
								char **errmsg)
{
	if (!sm4_parse_config(config, errmsg))
		return false;

	*callbacks_out = &sm4_file_encryption_callbacks;
	return true;
}

static void
sm4_startup(FileEncryptionModuleState *state)
{
	SM4FileEncryptionState *priv;

	if (!sm4_kek_set)
	{
		state->private_data = NULL;
		return;
	}

	priv = palloc0_object(SM4FileEncryptionState);
	memcpy(priv->kek, sm4_kek_static, SM4_KEY_LEN);

	PG_TRY();
	{
		sm4_load_crypto(priv);
	}
	PG_CATCH();
	{
		explicit_bzero(priv->kek, sizeof(priv->kek));
		sm4_free_crypto(priv);
		pfree(priv);
		PG_RE_THROW();
	}
	PG_END_TRY();

	state->private_data = priv;
}

static void
sm4_shutdown(FileEncryptionModuleState *state)
{
	SM4FileEncryptionState *priv = state->private_data;

	if (priv != NULL)
	{
		explicit_bzero(priv->kek, sizeof(priv->kek));
		sm4_free_crypto(priv);
		pfree(priv);
		state->private_data = NULL;
	}
}

static inline SM4FileEncryptionState *
sm4_require_state(const FileEncryptionModuleState *state)
{
	SM4FileEncryptionState *priv = state->private_data;

	if (priv == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("sm4_file_encryption: module was loaded without a valid configuration")));
	return priv;
}

static pg_noreturn void
sm4_openssl_error(const char *op)
{
	unsigned long e = ERR_get_error();
	char		buf[256];

	if (e == 0)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("sm4_file_encryption: %s failed", op)));

	ERR_error_string_n(e, buf, sizeof(buf));
	ereport(ERROR,
			(errcode(ERRCODE_INTERNAL_ERROR),
			 errmsg("sm4_file_encryption: %s failed: %s", op, buf)));
}

static pg_noreturn void
sm4_missing_algorithm(const char *kind, const char *name)
{
	ereport(ERROR,
			(errcode(ERRCODE_CONFIG_FILE_ERROR),
			 errmsg("sm4_file_encryption: could not fetch OpenSSL %s \"%s\"",
					kind, name),
			 errhint("Install or activate an OpenSSL provider that implements it. "
					 "If needed, set 'provider=' in file_encryption_config to the provider name and adjust 'cipher=' or 'digest=' to the provider's algorithm names.")));
}

static int
sm4_cipher_key_length(const EVP_CIPHER *cipher)
{
#if SM4_OPENSSL3
	return EVP_CIPHER_get_key_length(cipher);
#else
	return EVP_CIPHER_key_length(cipher);
#endif
}

static int
sm4_cipher_iv_length(const EVP_CIPHER *cipher)
{
#if SM4_OPENSSL3
	return EVP_CIPHER_get_iv_length(cipher);
#else
	return EVP_CIPHER_iv_length(cipher);
#endif
}

static int
sm4_cipher_mode(const EVP_CIPHER *cipher)
{
#if SM4_OPENSSL3
	return EVP_CIPHER_get_mode(cipher);
#else
	return EVP_CIPHER_mode(cipher);
#endif
}

static void
sm4_load_crypto(SM4FileEncryptionState *priv)
{
	int			key_len;
	int			mode;
	unsigned char tag[SM4_TAG_LEN];

	if (sm4_cipher == NULL || sm4_cipher[0] == '\0')
		ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("sm4_file_encryption: 'cipher' must not be empty")));
	if (sm4_digest == NULL || sm4_digest[0] == '\0')
		ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("sm4_file_encryption: 'digest' must not be empty")));

#if SM4_OPENSSL3
	if (sm4_provider != NULL && sm4_provider[0] != '\0')
	{
		priv->provider = OSSL_PROVIDER_load(NULL, sm4_provider);
		if (priv->provider == NULL)
			sm4_missing_algorithm("provider", sm4_provider);
	}

	priv->cipher = EVP_CIPHER_fetch(NULL, sm4_cipher, NULL);
	if (priv->cipher == NULL)
		sm4_missing_algorithm("cipher", sm4_cipher);

	priv->digest = EVP_MD_fetch(NULL, sm4_digest, NULL);
	if (priv->digest == NULL)
		sm4_missing_algorithm("digest", sm4_digest);

	priv->hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	if (priv->hmac == NULL)
		sm4_missing_algorithm("MAC", "HMAC");
#else
	priv->cipher = EVP_get_cipherbyname(sm4_cipher);
	if (priv->cipher == NULL)
		sm4_missing_algorithm("cipher", sm4_cipher);

	priv->digest = EVP_get_digestbyname(sm4_digest);
	if (priv->digest == NULL)
		sm4_missing_algorithm("digest", sm4_digest);
#endif

	key_len = sm4_cipher_key_length(priv->cipher);
	if (key_len != SM4_KEY_LEN)
		ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("sm4_file_encryption: OpenSSL cipher \"%s\" has key length %d, expected %d",
						sm4_cipher, key_len, SM4_KEY_LEN)));

	priv->iv_len = sm4_cipher_iv_length(priv->cipher);
	if (priv->iv_len <= 0 || priv->iv_len > SM4_IV_SLOT_LEN)
		ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("sm4_file_encryption: OpenSSL cipher \"%s\" has IV length %d, expected 1..%d",
						sm4_cipher, priv->iv_len, SM4_IV_SLOT_LEN)));

	mode = sm4_cipher_mode(priv->cipher);
	if (mode != EVP_CIPH_CTR_MODE &&
		mode != EVP_CIPH_CFB_MODE &&
		mode != EVP_CIPH_OFB_MODE &&
		mode != EVP_CIPH_STREAM_CIPHER)
		ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("sm4_file_encryption: OpenSSL cipher \"%s\" is not a streaming cipher mode",
						sm4_cipher),
				 errhint("Use a cipher in CTR, CFB, OFB, or stream mode.")));

	/* Sanity check that the digest produces SM4_TAG_LEN-byte HMACs. */
	sm4_hmac_raw(priv, priv->kek, SM4_KEY_LEN, NULL, 0, NULL, 0, tag);
}

static void
sm4_free_crypto(SM4FileEncryptionState *priv)
{
#if SM4_OPENSSL3
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
#if SM4_OPENSSL3
	priv->hmac = NULL;
	priv->provider = NULL;
#endif
}

static const char *
sm4_basename(const char *path)
{
	const char *basename = strrchr(path, '/');

	return basename ? basename + 1 : path;
}

static void
sm4_store64_be(unsigned char *dst, uint64 v)
{
	for (int i = 0; i < 8; i++)
		dst[i] = (unsigned char) (v >> ((7 - i) * 8));
}

static void
sm4_store32_be(unsigned char *dst, uint32 v)
{
	for (int i = 0; i < 4; i++)
		dst[i] = (unsigned char) (v >> ((3 - i) * 8));
}

/*
 * HMAC-of-(AAD || data) under 'key'.  AAD is an arbitrary byte string;
 * the caller assembles the shape for its flow:
 *
 *   * Record stream:   basename(path) || file_offset(be64)
 *   * Object key wrap: relNumber(be32)
 *   * Page:            fork(be32) || blocknum(be32)
 */
static void
sm4_hmac_raw(const SM4FileEncryptionState *priv,
			 const unsigned char *key, int key_len,
			 const unsigned char *aad, int aad_len,
			 const unsigned char *data, int data_len,
			 unsigned char tag[SM4_TAG_LEN])
{
	unsigned char fulltag[EVP_MAX_MD_SIZE];
	size_t		tag_len = 0;

#if SM4_OPENSSL3
	{
		EVP_MAC_CTX *ctx;
		OSSL_PARAM	params[2];

		ctx = EVP_MAC_CTX_new(priv->hmac);
		if (ctx == NULL)
			sm4_openssl_error("EVP_MAC_CTX_new");

		params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
													 sm4_digest, 0);
		params[1] = OSSL_PARAM_construct_end();

		PG_TRY();
		{
			if (EVP_MAC_init(ctx, key, key_len, params) != 1 ||
				(aad_len > 0 &&
				 EVP_MAC_update(ctx, aad, aad_len) != 1) ||
				(data_len > 0 &&
				 EVP_MAC_update(ctx, data, data_len) != 1) ||
				EVP_MAC_final(ctx, fulltag, &tag_len, sizeof(fulltag)) != 1)
				sm4_openssl_error("HMAC");
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
			sm4_openssl_error("HMAC_CTX_new");

		PG_TRY();
		{
			if (HMAC_Init_ex(ctx, key, key_len, priv->digest, NULL) != 1 ||
				(aad_len > 0 &&
				 HMAC_Update(ctx, aad, aad_len) != 1) ||
				(data_len > 0 &&
				 HMAC_Update(ctx, data, data_len) != 1) ||
				HMAC_Final(ctx, fulltag, &outlen) != 1)
				sm4_openssl_error("HMAC");
			tag_len = outlen;
		}
		PG_FINALLY();
		{
			HMAC_CTX_free(ctx);
		}
		PG_END_TRY();
	}
#endif

	if (tag_len != SM4_TAG_LEN)
		ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("sm4_file_encryption: OpenSSL digest \"%s\" produces %zu-byte HMAC tags, expected %d",
						sm4_digest, tag_len, SM4_TAG_LEN)));

	memcpy(tag, fulltag, SM4_TAG_LEN);
	explicit_bzero(fulltag, sizeof(fulltag));
}

/*
 * Record-stream HMAC: AAD = basename(path) || file_offset(be64).
 */
static void
sm4_hmac(const SM4FileEncryptionState *priv,
		 const unsigned char *key, int key_len,
		 const char *path, uint64 file_offset,
		 const unsigned char *data, int data_len,
		 unsigned char tag[SM4_TAG_LEN])
{
	const char *basename = sm4_basename(path);
	size_t		baselen = strlen(basename);
	unsigned char *aad;
	int			aad_len;

	aad_len = (int) baselen + 8;
	aad = palloc(aad_len);
	memcpy(aad, basename, baselen);
	sm4_store64_be(aad + baselen, file_offset);

	PG_TRY();
	{
		sm4_hmac_raw(priv, key, key_len, aad, aad_len,
					 data, data_len, tag);
	}
	PG_FINALLY();
	{
		pfree(aad);
	}
	PG_END_TRY();
}

/*
 * StringInfo wrapper around sm4_cipher_crypt_raw.  Used by the record-
 * stream flow which builds variable-length output.
 */
static void
sm4_cipher_crypt(const SM4FileEncryptionState *priv,
				 bool encrypting,
				 const unsigned char *key,
				 const unsigned char iv[SM4_IV_SLOT_LEN],
				 const unsigned char *data, int data_len,
				 StringInfo dst)
{
	enlargeStringInfo(dst, data_len);
	sm4_cipher_crypt_raw(priv, encrypting, key, iv, data, data_len,
						 (unsigned char *) dst->data + dst->len);
	dst->len += data_len;
	dst->data[dst->len] = '\0';
}

static void
sm4_cipher_crypt_raw(const SM4FileEncryptionState *priv,
					 bool encrypting,
					 const unsigned char *key,
					 const unsigned char iv[SM4_IV_SLOT_LEN],
					 const unsigned char *data, int data_len,
					 unsigned char *out)
{
	EVP_CIPHER_CTX *ctx;
	int			outlen;
	int			finallen;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		sm4_openssl_error("EVP_CIPHER_CTX_new");

	PG_TRY();
	{
		if (EVP_CipherInit_ex(ctx, priv->cipher, NULL, NULL, NULL,
							  encrypting ? 1 : 0) != 1)
			sm4_openssl_error("EVP_CipherInit_ex");
		if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1)
			sm4_openssl_error("EVP_CIPHER_CTX_set_padding");
		if (EVP_CipherInit_ex(ctx, NULL, NULL, key, iv,
							  encrypting ? 1 : 0) != 1)
			sm4_openssl_error("EVP_CipherInit_ex (key/iv)");

		if (EVP_CipherUpdate(ctx, out, &outlen, data, data_len) != 1)
			sm4_openssl_error("EVP_CipherUpdate");
		if (outlen != data_len)
			ereport(ERROR,
					(errcode(ERRCODE_CONFIG_FILE_ERROR),
					 errmsg("sm4_file_encryption: OpenSSL cipher \"%s\" produced %d bytes for %d input bytes",
							sm4_cipher, outlen, data_len),
					 errhint("Use a cipher in CTR, CFB, OFB, or stream mode.")));

		if (EVP_CipherFinal_ex(ctx, out + outlen, &finallen) != 1)
			sm4_openssl_error("EVP_CipherFinal_ex");
		if (finallen != 0)
			ereport(ERROR,
					(errcode(ERRCODE_CONFIG_FILE_ERROR),
					 errmsg("sm4_file_encryption: OpenSSL cipher \"%s\" produced unexpected final output",
							sm4_cipher),
					 errhint("Use a cipher in CTR, CFB, OFB, or stream mode.")));
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
sm4_encrypt(const FileEncryptionModuleState *state,
			const char *path, uint64 file_offset,
			const char *data, Size data_len,
			StringInfo dst)
{
	SM4FileEncryptionState *priv = sm4_require_state(state);
	unsigned char data_enc_key[SM4_KEY_LEN];
	unsigned char data_mac_key[SM4_KEY_LEN];
	unsigned char key_material[SM4_KEY_MATERIAL_LEN];
	unsigned char data_iv[SM4_IV_SLOT_LEN] = {0};
	unsigned char wrap_iv[SM4_IV_SLOT_LEN] = {0};
	unsigned char data_tag[SM4_TAG_LEN];
	unsigned char wrap_tag[SM4_TAG_LEN];
	uint32		format = SM4_FORMAT_MAGIC;
	int			body_len = (int) data_len;
	int			ciphertext_start;
	int			wrapped_key_start;

	if (!pg_strong_random(data_enc_key, sizeof(data_enc_key)) ||
		!pg_strong_random(data_mac_key, sizeof(data_mac_key)) ||
		!pg_strong_random(data_iv, priv->iv_len) ||
		!pg_strong_random(wrap_iv, priv->iv_len))
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("sm4_file_encryption: could not generate encryption key material")));

	memcpy(key_material, data_enc_key, SM4_KEY_LEN);
	memcpy(key_material + SM4_KEY_LEN, data_mac_key, SM4_KEY_LEN);

	enlargeStringInfo(dst, body_len + SM4_OVERHEAD_SIZE);

	PG_TRY();
	{
		ciphertext_start = dst->len;
		sm4_cipher_crypt(priv, true, data_enc_key, data_iv,
						 (const unsigned char *) data, body_len, dst);
		sm4_hmac(priv, data_mac_key, SM4_KEY_LEN, path, file_offset,
				 (const unsigned char *) dst->data + ciphertext_start,
				 body_len, data_tag);

		memcpy(dst->data + dst->len, data_iv, SM4_IV_SLOT_LEN);
		dst->len += SM4_IV_SLOT_LEN;
		memcpy(dst->data + dst->len, data_tag, SM4_TAG_LEN);
		dst->len += SM4_TAG_LEN;
		memcpy(dst->data + dst->len, wrap_iv, SM4_IV_SLOT_LEN);
		dst->len += SM4_IV_SLOT_LEN;

		wrapped_key_start = dst->len;
		sm4_cipher_crypt(priv, true, priv->kek, wrap_iv,
						 key_material, SM4_KEY_MATERIAL_LEN, dst);
		Assert(dst->len == wrapped_key_start + SM4_KEY_MATERIAL_LEN);
		sm4_hmac(priv, priv->kek, SM4_KEY_LEN, path, file_offset,
				 (const unsigned char *) dst->data + wrapped_key_start,
				 SM4_KEY_MATERIAL_LEN, wrap_tag);

		memcpy(dst->data + dst->len, wrap_tag, SM4_TAG_LEN);
		dst->len += SM4_TAG_LEN;
		memcpy(dst->data + dst->len, &format, sizeof(format));
		dst->len += sizeof(format);
		memset(dst->data + dst->len, 0, SM4_PAD_SIZE);
		dst->len += SM4_PAD_SIZE;
		Assert(dst->len == body_len + SM4_OVERHEAD_SIZE);
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
sm4_decrypt(const FileEncryptionModuleState *state,
			const char *path, uint64 file_offset,
			const char *data, Size data_len,
			StringInfo dst)
{
	SM4FileEncryptionState *priv = sm4_require_state(state);
	const unsigned char *data_iv;
	const unsigned char *data_tag;
	const unsigned char *wrap_iv;
	const unsigned char *wrapped_keys;
	const unsigned char *wrap_tag;
	unsigned char expected_tag[SM4_TAG_LEN];
	unsigned char key_material[SM4_KEY_MATERIAL_LEN];
	char		key_material_buf[SM4_KEY_MATERIAL_LEN + 1];
	StringInfoData key_material_out;
	uint32		format;
	int			body_len;

	if (data_len < SM4_OVERHEAD_SIZE)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("sm4_file_encryption: encrypted blob is too short (%zu bytes)",
						data_len)));

	body_len = (int) (data_len - SM4_OVERHEAD_SIZE);
	data_iv = (const unsigned char *) data + body_len;
	data_tag = data_iv + SM4_IV_SLOT_LEN;
	wrap_iv = data_tag + SM4_TAG_LEN;
	wrapped_keys = wrap_iv + SM4_IV_SLOT_LEN;
	wrap_tag = wrapped_keys + SM4_KEY_MATERIAL_LEN;
	memcpy(&format, wrap_tag + SM4_TAG_LEN, sizeof(format));

	if (format != SM4_FORMAT_MAGIC)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("sm4_file_encryption: encrypted blob has an unrecognized format")));

	key_material_out.data = key_material_buf;
	key_material_out.len = 0;
	key_material_out.maxlen = sizeof(key_material_buf);
	key_material_out.cursor = 0;

	PG_TRY();
	{
		sm4_hmac(priv, priv->kek, SM4_KEY_LEN, path, file_offset,
				 wrapped_keys, SM4_KEY_MATERIAL_LEN, expected_tag);
		if (timingsafe_bcmp(expected_tag, wrap_tag, SM4_TAG_LEN) != 0)
			ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg("sm4_file_encryption: wrapped key authentication failed"),
					 errdetail("Path \"%s\" offset %llu was tampered with, or the key has changed.",
							   path, (unsigned long long) file_offset)));

		sm4_cipher_crypt(priv, false, priv->kek, wrap_iv,
						 wrapped_keys, SM4_KEY_MATERIAL_LEN,
						 &key_material_out);
		if (key_material_out.len != SM4_KEY_MATERIAL_LEN)
			ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg("sm4_file_encryption: wrapped key decrypted to %d bytes, expected %d",
							key_material_out.len, SM4_KEY_MATERIAL_LEN)));
		memcpy(key_material, key_material_out.data, SM4_KEY_MATERIAL_LEN);

		sm4_hmac(priv, key_material + SM4_KEY_LEN, SM4_KEY_LEN,
				 path, file_offset, (const unsigned char *) data,
				 body_len, expected_tag);
		if (timingsafe_bcmp(expected_tag, data_tag, SM4_TAG_LEN) != 0)
			ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg("sm4_file_encryption: authentication tag verification failed"),
					 errdetail("Path \"%s\" offset %llu was tampered with, or the key has changed.",
							   path, (unsigned long long) file_offset)));

		sm4_cipher_crypt(priv, false, key_material, data_iv,
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
sm4_generate_object_key(FileEncryptionModuleState *state,
						const RelFileLocator *locator,
						StringInfo dst)
{
	SM4FileEncryptionState *priv = sm4_require_state(state);
	unsigned char data_key[SM4_KEY_LEN];
	unsigned char mac_key[SM4_KEY_LEN];
	unsigned char key_material[SM4_KEY_MATERIAL_LEN];
	unsigned char wrap_iv[SM4_IV_SLOT_LEN] = {0};
	unsigned char wrap_tag[SM4_TAG_LEN];
	unsigned char aad[4];
	uint32		format = SM4_FORMAT_MAGIC;
	int			wrapped_keys_start;

	if (!pg_strong_random(data_key, sizeof(data_key)) ||
		!pg_strong_random(mac_key, sizeof(mac_key)) ||
		!pg_strong_random(wrap_iv, priv->iv_len))
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("sm4_file_encryption: could not generate object key material")));

	memcpy(key_material, data_key, SM4_KEY_LEN);
	memcpy(key_material + SM4_KEY_LEN, mac_key, SM4_KEY_LEN);
	sm4_store32_be(aad, locator->relNumber);

	enlargeStringInfo(dst, SM4_OBJ_WRAP_SIZE);

	PG_TRY();
	{
		memcpy(dst->data + dst->len, wrap_iv, SM4_IV_SLOT_LEN);
		dst->len += SM4_IV_SLOT_LEN;

		wrapped_keys_start = dst->len;
		sm4_cipher_crypt(priv, true, priv->kek, wrap_iv,
						 key_material, SM4_KEY_MATERIAL_LEN, dst);
		Assert(dst->len == wrapped_keys_start + SM4_KEY_MATERIAL_LEN);

		sm4_hmac_raw(priv, priv->kek, SM4_KEY_LEN, aad, sizeof(aad),
					 (const unsigned char *) dst->data + wrapped_keys_start,
					 SM4_KEY_MATERIAL_LEN, wrap_tag);

		memcpy(dst->data + dst->len, wrap_tag, SM4_TAG_LEN);
		dst->len += SM4_TAG_LEN;
		memcpy(dst->data + dst->len, &format, sizeof(format));
		dst->len += sizeof(format);

		Assert(dst->len == SM4_OBJ_WRAP_SIZE);
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
sm4_object_open(FileEncryptionModuleState *state,
				const RelFileLocator *locator,
				const char *wrapped, Size wrapped_len)
{
	SM4FileEncryptionState *priv = sm4_require_state(state);
	SM4ObjectState *obj;
	const unsigned char *wrap_iv;
	const unsigned char *wrapped_keys;
	const unsigned char *wrap_tag;
	unsigned char expected_tag[SM4_TAG_LEN];
	unsigned char key_material[SM4_KEY_MATERIAL_LEN];
	unsigned char aad[4];
	uint32		format;

	if (wrapped_len != SM4_OBJ_WRAP_SIZE)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("sm4_file_encryption: wrapped object key has unexpected length %zu (want %zu)",
						wrapped_len, (Size) SM4_OBJ_WRAP_SIZE)));

	wrap_iv = (const unsigned char *) wrapped;
	wrapped_keys = wrap_iv + SM4_IV_SLOT_LEN;
	wrap_tag = wrapped_keys + SM4_KEY_MATERIAL_LEN;
	memcpy(&format, wrap_tag + SM4_TAG_LEN, sizeof(format));

	if (format != SM4_FORMAT_MAGIC)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("sm4_file_encryption: wrapped object key has unrecognized format 0x%08x",
						format)));

	sm4_store32_be(aad, locator->relNumber);

	obj = MemoryContextAllocZero(TopMemoryContext, sizeof(SM4ObjectState));

	PG_TRY();
	{
		sm4_hmac_raw(priv, priv->kek, SM4_KEY_LEN, aad, sizeof(aad),
					 wrapped_keys, SM4_KEY_MATERIAL_LEN, expected_tag);
		if (timingsafe_bcmp(expected_tag, wrap_tag, SM4_TAG_LEN) != 0)
			ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg("sm4_file_encryption: object key authentication failed")));

		sm4_cipher_crypt_raw(priv, false, priv->kek, wrap_iv,
							 wrapped_keys, SM4_KEY_MATERIAL_LEN,
							 key_material);
		memcpy(obj->data_key, key_material, SM4_KEY_LEN);
		memcpy(obj->mac_key, key_material + SM4_KEY_LEN, SM4_KEY_LEN);
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
sm4_object_close(FileEncryptionModuleState *state, void *object_state)
{
	SM4ObjectState *obj = object_state;

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
sm4_encrypt_page(FileEncryptionModuleState *state,
				 void *object_state,
				 ForkNumber fork, BlockNumber blocknum,
				 const char *src, char *dst)
{
	SM4FileEncryptionState *priv = sm4_require_state(state);
	SM4ObjectState *obj = object_state;
	unsigned char data_iv[SM4_IV_SLOT_LEN] = {0};
	unsigned char data_tag[SM4_TAG_LEN];
	unsigned char aad[8];
	uint32		format = SM4_FORMAT_MAGIC;
	int			body_len = BLCKSZ - SM4_PAGE_OVERHEAD_SIZE;

	Assert(obj != NULL);

	if (!pg_strong_random(data_iv, priv->iv_len))
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("sm4_file_encryption: could not generate page IV")));

	/*
	 * AAD = fork(be32) || blocknum(be32).  Including the fork
	 * distinguishes MAIN block N from INIT block N so neither can be
	 * substituted for the other on disk; reinit re-encrypts INIT bytes
	 * under MAIN's AAD when copying INIT into MAIN on unlogged-relation
	 * reset.
	 */
	sm4_store32_be(aad, (uint32) fork);
	sm4_store32_be(aad + 4, blocknum);

	PG_TRY();
	{
		sm4_cipher_crypt_raw(priv, true, obj->data_key, data_iv,
							 (const unsigned char *) src, body_len,
							 (unsigned char *) dst);

		sm4_hmac_raw(priv, obj->mac_key, SM4_KEY_LEN, aad, sizeof(aad),
					 (const unsigned char *) dst, body_len, data_tag);

		memcpy(dst + body_len, data_iv, SM4_IV_SLOT_LEN);
		memcpy(dst + body_len + SM4_IV_SLOT_LEN, data_tag, SM4_TAG_LEN);
		memcpy(dst + body_len + SM4_IV_SLOT_LEN + SM4_TAG_LEN,
			   &format, sizeof(format));
		if (SM4_PAGE_PAD_SIZE > 0)
			memset(dst + body_len + SM4_IV_SLOT_LEN + SM4_TAG_LEN + sizeof(format),
				   0, SM4_PAGE_PAD_SIZE);
	}
	PG_FINALLY();
	{
		explicit_bzero(data_iv, sizeof(data_iv));
		explicit_bzero(data_tag, sizeof(data_tag));
	}
	PG_END_TRY();
}

static void
sm4_decrypt_page(FileEncryptionModuleState *state,
				 void *object_state,
				 ForkNumber fork, BlockNumber blocknum,
				 const char *src, char *dst)
{
	SM4FileEncryptionState *priv = sm4_require_state(state);
	SM4ObjectState *obj = object_state;
	const unsigned char *data_iv;
	const unsigned char *data_tag;
	unsigned char expected_tag[SM4_TAG_LEN];
	unsigned char aad[8];
	uint32		format;
	int			body_len = BLCKSZ - SM4_PAGE_OVERHEAD_SIZE;

	Assert(obj != NULL);

	data_iv = (const unsigned char *) src + body_len;
	data_tag = data_iv + SM4_IV_SLOT_LEN;
	memcpy(&format, data_tag + SM4_TAG_LEN, sizeof(format));

	if (format != SM4_FORMAT_MAGIC)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("sm4_file_encryption: encrypted page has unrecognized format 0x%08x",
						format)));

	/* AAD = fork(be32) || blocknum(be32) -- see comment in sm4_encrypt_page. */
	sm4_store32_be(aad, (uint32) fork);
	sm4_store32_be(aad + 4, blocknum);

	PG_TRY();
	{
		sm4_hmac_raw(priv, obj->mac_key, SM4_KEY_LEN, aad, sizeof(aad),
					 (const unsigned char *) src, body_len, expected_tag);
		if (timingsafe_bcmp(expected_tag, data_tag, SM4_TAG_LEN) != 0)
			ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg("sm4_file_encryption: page authentication failed")));

		sm4_cipher_crypt_raw(priv, false, obj->data_key, data_iv,
							 (const unsigned char *) src, body_len,
							 (unsigned char *) dst);

		/* Zero the plaintext trailer so pd_checksum verifies. */
		memset(dst + body_len, 0, SM4_PAGE_OVERHEAD_SIZE);
	}
	PG_FINALLY();
	{
		explicit_bzero(expected_tag, sizeof(expected_tag));
	}
	PG_END_TRY();
}
