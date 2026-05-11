/*-------------------------------------------------------------------------
 *
 * file_encryption_module.h
 *	  Public ABI for pluggable file encryption modules.
 *
 * Modules implement a single symbol, _PG_file_encryption_module_init, which
 * the host (the backend or a frontend tool such as pg_checksums) calls at
 * load time.  The host passes an opaque, module-defined configuration
 * string; the module parses it, sets up whatever state it needs in *state,
 * and returns a pointer to its FileEncryptionCallbacks via *callbacks_out.
 *
 * The callback signatures and the state struct intentionally use only
 * types available to libpgcommon (RelFileLocator, ForkNumber, BlockNumber,
 * raw byte pointers, StringInfo).  This lets the same compiled .so be
 * loaded by both the backend and any libpgcommon-based frontend tool.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/common/file_encryption_module.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef FILE_ENCRYPTION_MODULE_H
#define FILE_ENCRYPTION_MODULE_H

#include "common/relpath.h"
#include "lib/stringinfo.h"
#include "storage/block.h"
#include "storage/relfilelocator.h"

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
 * Per-relation page-encryption callbacks.  See storage/file_encryption.h
 * for the backend-side wrappers.  Modules without page-encryption support
 * leave all five page callbacks NULL.
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
#define PG_FILE_ENCRYPTION_MAGIC 0x46454D37		/* "FEM7" */

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
 * Type of the shared library symbol _PG_file_encryption_module_init that
 * every file encryption module exports.
 *
 * 'config' is a module-defined opaque string (passed verbatim from the
 * file_encryption_config GUC in the backend, or from --encryption-config /
 * env in a frontend tool).  May be NULL or empty if the host has nothing
 * to provide; modules that need configuration should signal that as an
 * error via *errmsg.
 *
 * On success, the module returns true and populates *callbacks_out with a
 * pointer to its (typically static) callback table.  Modules that need to
 * carry parsed configuration into their callbacks should stash it in module
 * statics: init runs once per host process (per postmaster in the backend,
 * per tool invocation in the frontend), and fork()ed children inherit the
 * statics via copy-on-write.  Per-process state proper is built lazily by
 * the optional startup_cb.
 *
 * On failure, the module returns false and sets *errmsg to a host-allocated
 * (palloc-compatible) error string describing the problem.  The host frees
 * the string.  *callbacks_out is left untouched on failure.
 */
typedef bool (*FileEncryptionModuleInit) (const char *config,
										  const FileEncryptionCallbacks **callbacks_out,
										  char **errmsg);
extern PGDLLEXPORT bool _PG_file_encryption_module_init(const char *config,
														const FileEncryptionCallbacks **callbacks_out,
														char **errmsg);

#endif							/* FILE_ENCRYPTION_MODULE_H */
