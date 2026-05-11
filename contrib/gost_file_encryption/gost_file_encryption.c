/*-------------------------------------------------------------------------
 *
 * gost_file_encryption.c
 *	  Reference file encryption module using an OpenSSL GOST provider cipher.
 *
 * The configured key is a key-encryption key.  Each encryption call uses
 * fresh data encryption and authentication keys, which are wrapped under the
 * configured key and stored in the trailer.
 *
 * Default algorithms:
 *	  cipher: kuznyechik-ctr
 *	  digest: md_gost12_256 (used with HMAC)
 *
 * Provider packages differ in algorithm naming.  If your provider exposes a
 * different name, set gost_file_encryption.provider,
 * gost_file_encryption.cipher, and gost_file_encryption.digest in
 * postgresql.conf.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * contrib/gost_file_encryption/gost_file_encryption.c
 *
 *-------------------------------------------------------------------------
 */

#define PFEM_MODULE_NAME		"gost_file_encryption"
#define PFEM_GUC_PREFIX			"gost_file_encryption"
#define PFEM_CIPHER_DEFAULT		"kuznyechik-ctr"
#define PFEM_DIGEST_DEFAULT		"md_gost12_256"
#define PFEM_PROVIDER_HINT		"gostprov"
#define PFEM_KEY_LEN			32
#define PFEM_FORMAT_MAGIC		0x31474647	/* "GFG1" in native byte order */
#define PFEM_OVERHEAD_SIZE		168

#include "../file_encryption_provider_common/provider_file_encryption_impl.h"
