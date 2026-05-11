/*-------------------------------------------------------------------------
 *
 * file_encryption.h
 *	  Exports for file encryption modules.
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

#include "common/relpath.h"
#include "lib/stringinfo.h"
#include "storage/block.h"
#include "storage/relfilelocator.h"

/* SMgrRelation is forward-declared to avoid pulling in smgr.h here. */
struct SMgrRelationData;
typedef struct SMgrRelationData *SMgrRelation;

/*
 * The value of the file_encryption_library GUC.
 */
extern PGDLLIMPORT char *file_encryption_library;

typedef struct FileEncryptionModuleState
{
	/* Holds the server's PG_VERSION_NUM. Reserved for future extensibility. */
	int			sversion;

	/*
	 * Private data pointer for use by a file encryption module. This can be
	 * used to store state for the module that will be passed to each callback.
	 */
	void	   *private_data;
} FileEncryptionModuleState;

/*
 * Optional per-process lifecycle callbacks.  startup_cb runs once when the
 * module's per-process state is first needed (or eagerly at postmaster
 * startup); shutdown_cb runs once at process exit.  Both may be NULL.
 */
typedef void (*FileEncryptionStartupCB) (FileEncryptionModuleState *state);
typedef void (*FileEncryptionShutdownCB) (FileEncryptionModuleState *state);

/*
 * Record-stream encryption callbacks (BufFile, reorderbuffer spill files).
 *
 * The module encrypts data_len plaintext bytes at "data" into dst, producing
 * exactly data_len + overhead_size output bytes (with the overhead at the
 * tail of dst).  The (path, file_offset) pair identifies where the bytes
 * will live on disk and is the natural AAD-derivation context.  Each call
 * is independent — modules typically generate a fresh data-encryption key
 * per call and wrap it under the module's configured KEK in the overhead.
 */
typedef void (*FileEncryptionEncryptCB) (const FileEncryptionModuleState *state,
										 const char *path, uint64 file_offset,
										 const char *data, Size data_len,
										 StringInfo dst);
typedef void (*FileEncryptionDecryptCB) (const FileEncryptionModuleState *state,
										 const char *path, uint64 file_offset,
										 const char *data, Size data_len,
										 StringInfo dst);

/*
 * Per-relation page-encryption callbacks.
 *
 * Page encryption uses one data-encryption key per relation (per
 * RelFileLocator), shared by all forks and all segment files of that
 * relation.  The wrapped DEK lives in the relation's KEY_FORKNUM, one
 * BLCKSZ block at position 0.
 *
 * generate_object_key_cb: called at relation-create time.  The module
 *   generates a fresh DEK, wraps it under its configured KEK, and writes
 *   the wrapped bytes (plus any per-relation metadata) into dst.  The
 *   bytes go verbatim into the KEY fork block.
 *
 * object_open_cb: called the first time md.c needs to encrypt or decrypt
 *   any page of the relation.  Receives the wrapped bytes the core read
 *   from KEY_FORKNUM block 0.  The module unwraps the DEK and returns a
 *   pointer to a per-relation state struct it owns.  The core caches the
 *   returned pointer on SMgrRelation.encryption_object_state and passes
 *   it back to every encrypt_page_cb / decrypt_page_cb for that relation.
 *
 * object_close_cb: called from smgrclose() when the SMgrRelation is
 *   destroyed.  The module frees its per-relation state.
 *
 * encrypt_page_cb / decrypt_page_cb: BLCKSZ-in / BLCKSZ-out page
 *   encryption.  The module uses the cached DEK; (fork, blocknum) serve
 *   as the IV-derivation context.
 *
 * All five must be set if any is.  Modules without page-encryption support
 * leave all five NULL.
 */
typedef void (*FileEncryptionGenerateObjectKeyCB) (FileEncryptionModuleState *state,
												   const RelFileLocator *locator,
												   StringInfo dst);
typedef void *(*FileEncryptionObjectOpenCB) (FileEncryptionModuleState *state,
											 const RelFileLocator *locator,
											 const char *wrapped, Size wrapped_len);
typedef void (*FileEncryptionObjectCloseCB) (FileEncryptionModuleState *state,
											 void *object_state);
typedef void (*FileEncryptionEncryptPageCB) (FileEncryptionModuleState *state,
											 void *object_state,
											 ForkNumber fork, BlockNumber blocknum,
											 const char *src, char *dst);
typedef void (*FileEncryptionDecryptPageCB) (FileEncryptionModuleState *state,
											 void *object_state,
											 ForkNumber fork, BlockNumber blocknum,
											 const char *src, char *dst);

/*
 * Identifies the compiled ABI version of the file encryption module.
 *
 * Bump this whenever FileEncryptionCallbacks or any of the callback
 * signatures change in an incompatible way.
 */
#define PG_FILE_ENCRYPTION_MAGIC 0x46454D36		/* "FEM6" */

typedef struct FileEncryptionCallbacks
{
	uint32		magic;			/* must be set to PG_FILE_ENCRYPTION_MAGIC */

	/*
	 * Number of bytes the module appends to every encrypt_cb output (per-call
	 * overhead, e.g. IV + auth tag + wrapped data key).  May be 0 for
	 * size-preserving modes.  Only relevant for record-stream encryption
	 * (BufFile, reorderbuffer spill).
	 */
	Size		overhead_size;

	/*
	 * Number of bytes the module reserves at the tail of every relation page
	 * for per-page metadata (IV, auth tag, ...).  Must match the cluster's
	 * page_reserved_size for page encryption to engage.  Smaller than
	 * overhead_size because the per-relation DEK lives in KEY_FORKNUM, not
	 * in each page's trailer.
	 */
	Size		page_overhead_size;

	/* Per-process lifecycle. */
	FileEncryptionStartupCB startup_cb;
	FileEncryptionShutdownCB shutdown_cb;

	/* Record-stream encryption (BufFile, reorderbuffer spill). */
	FileEncryptionEncryptCB encrypt_cb;
	FileEncryptionDecryptCB decrypt_cb;

	/* Per-relation page encryption.  All five must be set if any is. */
	FileEncryptionGenerateObjectKeyCB generate_object_key_cb;
	FileEncryptionObjectOpenCB object_open_cb;
	FileEncryptionObjectCloseCB object_close_cb;
	FileEncryptionEncryptPageCB encrypt_page_cb;
	FileEncryptionDecryptPageCB decrypt_page_cb;
} FileEncryptionCallbacks;

/*
 * Type of the shared library symbol _PG_file_encryption_module_init that is
 * required for all file encryption modules. This function will be invoked
 * during module loading.
 */
typedef const FileEncryptionCallbacks *(*FileEncryptionModuleInit) (void);
extern PGDLLEXPORT const FileEncryptionCallbacks *_PG_file_encryption_module_init(void);

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
 * Page-level encryption.  FileEncryptionPagesEnabled() is true when the
 * configured module's page_overhead_size matches the cluster's
 * page_reserved_size (i.e. relation pages are routed through the module).
 * The helpers below wrap encrypt_page_cb / decrypt_page_cb with the
 * BLCKSZ-in / BLCKSZ-out contract that md.c needs.
 */
extern bool FileEncryptionPagesEnabled(void);
extern Size FileEncryptionPageReservedSize(void);

/*
 * Generate a fresh per-relation wrapped DEK and write it as a BLCKSZ-sized
 * block of bytes into 'dst'.  The format is:
 *
 *   [ uint32 magic = "FKEB" ][ uint32 version = 1 ]
 *   [ uint32 wrapped_len   ][ uint32 reserved  = 0 ]
 *   [ wrapped DEK ... wrapped_len bytes ... ][ zero padding to BLCKSZ ]
 *
 * Called once per relation at create time by storage.c.
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

extern void process_file_encryption_library(void);

/*
 * Eagerly run the module's per-process startup callback and register its
 * shutdown callback for the current process.  Must be called outside any
 * critical section (the startup callback may palloc) and before any code
 * path that touches encryption from within a critical section, such as
 * the AIO read/write completion callbacks in md.c.
 */
extern void FileEncryptionEnsureInit(void);

#endif							/* FILE_ENCRYPTION_H */
