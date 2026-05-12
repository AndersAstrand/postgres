/*-------------------------------------------------------------------------
 *
 * file_encryption.h
 *	  Backend wrappers around the file_encryption module ABI.
 *
 * The ABI itself lives in common/file_encryption_module.h so that
 * frontend tools (pg_checksums, pg_basebackup, ...) can dlopen the same
 * shared library and call the same callbacks.  This header layers the
 * backend-only conveniences (SMgrRelation, GUC, ereport-based wrappers)
 * on top.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/storage/file_encryption.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef FILE_ENCRYPTION_H
#define FILE_ENCRYPTION_H

#include "common/file_encryption_module.h"

/* SMgrRelation is forward-declared to avoid pulling in smgr.h here. */
struct SMgrRelationData;
typedef struct SMgrRelationData *SMgrRelation;

/*
 * GUC.  file_encryption_config is the opaque, module-defined configuration
 * string passed verbatim to _PG_file_encryption_module_init.  The library
 * NAME isn't a GUC: it lives in pg_control (set at initdb time and
 * immutable afterwards) and is read by the backend at startup.
 */
extern PGDLLIMPORT char *file_encryption_config;

extern bool FileEncryptionEnabled(void);

/* Per-call ciphertext overhead size declared by the loaded module. */
extern Size FileEncryptionOverheadSize(void);

extern void FileEncryptionEncrypt(const char *path, uint64 file_offset,
								  const char *data, Size data_len,
								  StringInfo dst);
extern void FileEncryptionDecrypt(const char *path, uint64 file_offset,
								  const char *data, Size data_len,
								  StringInfo dst);

/*
 * Page-level encryption is always engaged when a file encryption module is
 * configured -- relation pages are routed through the module, with the
 * module's declared page_overhead_size carved off the tail of every page
 * for its per-page metadata (may be zero for modes like AES-XTS).  The
 * helpers below wrap encrypt_page_cb / decrypt_page_cb with the BLCKSZ-in /
 * BLCKSZ-out contract that md.c needs.
 */
extern Size FileEncryptionPageReservedSize(void);

/*
 * Generate a fresh per-relation wrapped DEK and write it as a BLCKSZ-sized
 * page-formatted block into 'dst'.  Called once per relation at create time
 * by storage.c.
 */
extern void FileEncryptionGenerateObjectKey(const RelFileLocator *locator,
											char *dst);

/*
 * Read the relation's KEY fork (block 0) and unwrap the DEK into a
 * per-relation state pointer cached on SMgrRelation.  Idempotent.  Must be
 * called before the first FileEncryptionEncryptPage / DecryptPage call for
 * this relation; the page helpers below call it lazily on first use.
 */
extern void FileEncryptionOpenObject(SMgrRelation reln);

/*
 * Release per-relation state cached on SMgrRelation.  Called from
 * smgrclose() when the SMgrRelation is torn down.
 */
extern void FileEncryptionCloseObject(SMgrRelation reln);

extern void FileEncryptionEncryptPage(SMgrRelation reln, ForkNumber fork,
									  BlockNumber blocknum,
									  const char *src, char *dst);
extern void FileEncryptionDecryptPage(SMgrRelation reln, ForkNumber fork,
									  BlockNumber blocknum,
									  const char *src, char *dst);

extern void process_file_encryption_library(const char *libname);

/*
 * Eagerly run the module's per-process startup callback and register its
 * shutdown callback for the current process.  Must be called outside any
 * critical section (the startup callback may palloc) and before any code
 * path that touches encryption from within a critical section, such as
 * the AIO read/write completion callbacks in md.c.
 */
extern void FileEncryptionEnsureInit(void);

#endif							/* FILE_ENCRYPTION_H */
