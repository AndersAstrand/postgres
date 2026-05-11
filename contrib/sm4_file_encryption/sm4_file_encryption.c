/*-------------------------------------------------------------------------
 *
 * sm4_file_encryption.c
 *	  Reference file encryption module using OpenSSL's SM4 provider cipher.
 *
 * The configured key is a key-encryption key.  Each encryption call uses
 * fresh data encryption and authentication keys, which are wrapped under the
 * configured key and stored in the trailer.
 *
 * Default algorithms:
 *	  cipher: SM4-CTR
 *	  digest: SM3 (used with HMAC)
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * contrib/sm4_file_encryption/sm4_file_encryption.c
 *
 *-------------------------------------------------------------------------
 */

#define PFEM_MODULE_NAME		"sm4_file_encryption"
#define PFEM_GUC_PREFIX			"sm4_file_encryption"
#define PFEM_CIPHER_DEFAULT		"SM4-CTR"
#define PFEM_DIGEST_DEFAULT		"SM3"
#define PFEM_PROVIDER_HINT		"default"
#define PFEM_KEY_LEN			16
#define PFEM_FORMAT_MAGIC		0x314d4653	/* "SFM1" in native byte order */
#define PFEM_OVERHEAD_SIZE		136

#include "../file_encryption_provider_common/provider_file_encryption_impl.h"
