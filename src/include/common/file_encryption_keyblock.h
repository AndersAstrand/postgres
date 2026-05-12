/*-------------------------------------------------------------------------
 *
 * file_encryption_keyblock.h
 *	  Layout of the KEY-fork block produced by FileEncryptionGenerateObjectKey.
 *
 * The KEY fork holds one BLCKSZ block per relation, formatted as a normal
 * PostgreSQL page (PageInit'd with no special area, pd_checksum populated)
 * so it travels through the buffer manager and survives a future data-
 * checksums-on transition.  The encryption-specific payload lives in the
 * otherwise-empty data area between pd_lower and pd_upper:
 *
 *	  [ PageHeaderData (SizeOfPageHeaderData bytes)                   ]
 *	  [ FEKeyBlockHeader { magic, version, wrapped_len, reserved }    ]
 *	  [ wrapped DEK ... wrapped_len bytes ...                         ]
 *	  [ zero padding up to pd_upper                                   ]
 *	  [ encryption trailer (zero; KEY fork is exempt from encryption) ]
 *
 * The wrapped DEK is opaque to the core; the encryption module owns its
 * format and verification.  The layout itself is shared between the
 * backend (which writes it via FileEncryptionGenerateObjectKey and reads
 * it via FileEncryptionOpenObject) and any frontend tool that needs to
 * locate the wrapped DEK to hand to a module's object_open_cb.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/common/file_encryption_keyblock.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef FILE_ENCRYPTION_KEYBLOCK_H
#define FILE_ENCRYPTION_KEYBLOCK_H

#include "storage/bufpage.h"

#define FE_KEY_BLOCK_MAGIC		0x46454B42	/* "FEKB" */
#define FE_KEY_BLOCK_VERSION	1

typedef struct FEKeyBlockHeader
{
	uint32		magic;
	uint32		version;
	uint32		wrapped_len;
	uint32		reserved;
} FEKeyBlockHeader;

#define FE_KEY_BLOCK_HEADER_OFFSET	SizeOfPageHeaderData
#define FE_KEY_BLOCK_PAYLOAD_OFFSET (FE_KEY_BLOCK_HEADER_OFFSET + \
									 sizeof(FEKeyBlockHeader))
#define FE_KEY_BLOCK_MAX_WRAPPED	(BLCKSZ - FE_KEY_BLOCK_PAYLOAD_OFFSET)

#endif							/* FILE_ENCRYPTION_KEYBLOCK_H */
