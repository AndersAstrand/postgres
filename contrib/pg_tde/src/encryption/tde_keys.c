#include "postgres.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "utils/resowner.h"

#include "encryption/enc_aes.h"
#include "encryption/tde_keys.h"

#ifdef FRONTEND
#include "pg_tde_fe.h"
#endif

static void uint8_to_hex(const uint8 in[16], char out[33]) {
	char *hex = "0123456789abcdef";

	for (int i = 0; i < 16; i++) {
		out[i << 1] = hex[in[i] >> 4];
		out[(i << 1) + 1] = hex[in[i] & 0x0F];
	}
	out[33] = 0;
}

void log_decrypted_key(const DecryptedTdeKey *decrypted_key) {
	char data[33];
	char iv[33];

	uint8_to_hex(decrypted_key->data, data);
	uint8_to_hex(decrypted_key->iv, iv);

	elog(LOG, "DecryptedTdeKey\n\tdata: %s\n\tiv: %s", data, iv);
}

void log_encrypted_key(const EncryptedTdeKey *encrypted_key) {
	char key_data[33];
	char key_iv[33];
	char iv[33];
	char aead_tag[33];

	uint8_to_hex(encrypted_key->key_data, key_data);
	uint8_to_hex(encrypted_key->key_iv, key_iv);
	uint8_to_hex(encrypted_key->iv, iv);
	uint8_to_hex(encrypted_key->aead_tag, aead_tag);

	elog(LOG, "EncryptedTdeKey\n\tkey_data: %s\n\tkey_iv: %s\n\tiv: %s\n\taead_tag: %s", key_data, key_iv, iv, aead_tag);
}

static void ResourceOwnerReleaseDecryptedTdeKey(Datum resource);
static DecryptedTdeKey *tde_keys_alloc_decrypted_key(void);

static const ResourceOwnerDesc tde_keys_resource_owner_desc =
{
	.name = "pg_tde decrypted key",
	.release_phase = RESOURCE_RELEASE_BEFORE_LOCKS,
	.release_priority = RELEASE_PRIO_FIRST,
	.ReleaseResource = ResourceOwnerReleaseDecryptedTdeKey,
	.DebugPrint = NULL,
};

EncryptedTdeKey *
tde_keys_encrypt_key(const DecryptedTdeKey *decrypted_key,
					 const uint8 *encryption_key,
					 const uint8 *additional_authentication_data,
					 int additional_authentication_data_size)
{
	EncryptedTdeKey *encrypted_key = palloc0_object(EncryptedTdeKey);

	// elog(LOG, "tde_keys_encrypt_key");
	// log_decrypted_key(decrypted_key);

	memcpy(encrypted_key->key_iv, decrypted_key->iv, TDE_KEY_IV_SIZE);

	if (!RAND_bytes(encrypted_key->iv, TDE_KEY_ENCRYPTION_IV_SIZE))
		ereport(ERROR,
				errmsg("could not generate iv for key encryption: %s",
					   ERR_error_string(ERR_get_error(), NULL)));

	AesGcmEncrypt(encryption_key,

				  encrypted_key->iv,
				  TDE_KEY_ENCRYPTION_IV_SIZE,

				  additional_authentication_data,
				  additional_authentication_data_size,

				  decrypted_key->data,
				  TDE_KEY_SIZE,

				  encrypted_key->key_data,

				  encrypted_key->aead_tag,
				  TDE_KEY_ENCRYPTION_AEAD_TAG_SIZE);

	// log_encrypted_key(encrypted_key);

	return encrypted_key;
}

DecryptedTdeKey *
tde_keys_decrypt_key(EncryptedTdeKey *encrypted_key,
					 const uint8 *decryption_key,
					 const uint8 *additional_authentication_data,
					 int additional_authentication_data_size)
{
	DecryptedTdeKey *decrypted_key;

	Assert(encrypted_key);
	Assert(decryption_key);

	// elog(LOG, "tde_keys_decrypt_key");
	// log_encrypted_key(encrypted_key);

	decrypted_key = tde_keys_alloc_decrypted_key();

	if (!AesGcmDecrypt(decryption_key,

					   encrypted_key->iv,
					   TDE_KEY_ENCRYPTION_IV_SIZE,

					   additional_authentication_data,
					   additional_authentication_data_size,

					   encrypted_key->key_data,
					   TDE_KEY_SIZE,

					   decrypted_key->data,

					   encrypted_key->aead_tag,
					   TDE_KEY_ENCRYPTION_AEAD_TAG_SIZE))
	{
		tde_keys_free_decrypted_key(decrypted_key);
		return NULL;
	}

	memcpy(decrypted_key->iv, encrypted_key->key_iv, TDE_KEY_IV_SIZE);

	// log_decrypted_key(decrypted_key);

	return decrypted_key;
}

void
tde_keys_free_decrypted_key(DecryptedTdeKey *decrypted_key)
{
	Assert(decrypted_key->owner);

	ResourceOwnerForget(decrypted_key->owner,
						PointerGetDatum(decrypted_key),
						&tde_keys_resource_owner_desc);
	OPENSSL_secure_clear_free(decrypted_key, sizeof(DecryptedTdeKey));
}

DecryptedTdeKey *
tde_keys_generate_decrypted_key(void)
{
	DecryptedTdeKey *decrypted_key = tde_keys_alloc_decrypted_key();

	if (!RAND_bytes(decrypted_key->data, TDE_KEY_SIZE))
		ereport(ERROR,
				errmsg("could not generate key: %s",
					   ERR_error_string(ERR_get_error(), NULL)));

	if (!RAND_bytes(decrypted_key->iv, TDE_KEY_IV_SIZE))
		ereport(ERROR,
				errmsg("could not generate iv: %s",
					   ERR_error_string(ERR_get_error(), NULL)));

	return decrypted_key;
}

static void
ResourceOwnerReleaseDecryptedTdeKey(Datum resource)
{
	OPENSSL_secure_clear_free(DatumGetPointer(resource), sizeof(DecryptedTdeKey));
}

static DecryptedTdeKey *
tde_keys_alloc_decrypted_key(void)
{
	DecryptedTdeKey *decrypted_key;

	ResourceOwnerEnlarge(CurrentResourceOwner);

	decrypted_key = OPENSSL_secure_zalloc(sizeof(DecryptedTdeKey));

	decrypted_key->owner = CurrentResourceOwner;
	ResourceOwnerRemember(decrypted_key->owner,
						  PointerGetDatum(decrypted_key),
						  &tde_keys_resource_owner_desc);

	return decrypted_key;
}

EncryptedTdeKey *
tde_keys_new_encrypted_key(const uint8 *encryption_key,
	 const uint8 *additional_authentication_data,
	 int additional_authentication_data_size)
{
	DecryptedTdeKey *decrypted_key;
	EncryptedTdeKey *encrypted_key;

	decrypted_key = tde_keys_generate_decrypted_key();
	encrypted_key = tde_keys_encrypt_key(decrypted_key,
										encryption_key,
										additional_authentication_data,
										additional_authentication_data_size);
	tde_keys_free_decrypted_key(decrypted_key);

	return encrypted_key;
}
