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
 * raw byte pointers).  This lets the same compiled .so be loaded by both
 * the backend and any libpgcommon-based frontend tool.
 *
 * Error reporting follows the same return-value-plus-errmsg pattern as
 * _PG_file_encryption_module_init: every fallible callback returns false
 * (or NULL for object_open_cb) on failure and writes a palloc'd
 * description into *errmsg.  The host decides how to surface the error
 * -- the backend wraps each callback with ereport(ERROR); frontend
 * callers print and exit via pg_fatal.  Modules never call ereport or
 * pg_fatal directly, which keeps the same .so usable from both contexts.
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
 * module's per-process state is first needed (eagerly at postmaster startup
 * and again in each forked backend); shutdown_cb runs once at process exit.
 * Both may be NULL.  On failure startup_cb returns false and writes a
 * palloc'd description into *errmsg.
 */
typedef bool (*FileEncryptionStartupCB) (FileEncryptionModuleState *state,
										 char **errmsg);
typedef void (*FileEncryptionShutdownCB) (FileEncryptionModuleState *state);

/*
 * Record-stream encryption callbacks (BufFile, reorderbuffer spill files).
 *
 * The module encrypts data_len plaintext bytes at "data" into the
 * caller-allocated "dst" buffer, producing exactly data_len + overhead_size
 * output bytes (with the overhead at the tail of dst).  Decrypt is the
 * symmetric operation: data_len ciphertext bytes (including trailing
 * overhead) produce exactly data_len - overhead_size plaintext bytes.  The
 * caller sizes dst to the contractual output length; the module never
 * shortens or extends it.
 *
 * The (path, file_offset) pair identifies where the bytes will live on
 * disk; modules bind it into their per-call key/IV/MAC derivation however
 * they see fit (as AEAD AAD, HMAC input, an XTS-style tweak, ...) so
 * substituting one record for another at decrypt time fails.  Each call is
 * otherwise independent -- modules typically generate a fresh data-
 * encryption key per call and wrap it under the module's configured KEK in
 * the overhead.
 *
 * Returns true on success.  On failure returns false and writes a palloc'd
 * error description into *errmsg; the caller frees it via pfree().  The
 * contents of dst on failure are unspecified.
 */
typedef bool (*FileEncryptionEncryptCB) (const FileEncryptionModuleState *state,
										 const char *path, uint64 file_offset,
										 const char *data, Size data_len,
										 char *dst, char **errmsg);
typedef bool (*FileEncryptionDecryptCB) (const FileEncryptionModuleState *state,
										 const char *path, uint64 file_offset,
										 const char *data, Size data_len,
										 char *dst, char **errmsg);

/*
 * Per-relation page-encryption callbacks.  See storage/file_encryption.h
 * for the backend-side wrappers.  Return-value semantics match the
 * record-stream callbacks above.
 *
 * Per-page binding context: the host supplies (fork, blocknum) on every
 * encrypt/decrypt call (and the relation's RelFileLocator at object-open
 * time); the per-relation DEK is otherwise the same across all pages and
 * forks of the relation.  Modules use these inputs however they like --
 * as AEAD AAD, HMAC input, an XTS-style tweak -- so an attacker with
 * disk write access can't shuffle blocks between forks or block numbers
 * within a relation without the swap being detected at decrypt time.
 *
 * generate_object_key_cb writes its wrapped DEK into dst (caller-owned,
 * dst_max bytes) and stores the number of bytes used in *wrapped_len.
 * dst_max is the module-side cap on wrapped-DEK size; modules that need
 * more must fail with an *errmsg explaining why.  object_open_cb returns a
 * non-NULL pointer to module-owned state on success and NULL on failure
 * (with *errmsg populated).  The lifetime of the returned pointer must
 * outlive any encrypt/decrypt call referring to the same relation; the
 * host arranges for the allocator's lifetime to match.
 */
typedef bool (*FileEncryptionGenerateObjectKeyCB) (FileEncryptionModuleState *state,
												   const RelFileLocator *locator,
												   char *dst, Size dst_max,
												   Size *wrapped_len,
												   char **errmsg);
typedef void *(*FileEncryptionObjectOpenCB) (FileEncryptionModuleState *state,
											 const RelFileLocator *locator,
											 const char *wrapped, Size wrapped_len,
											 char **errmsg);
typedef void (*FileEncryptionObjectCloseCB) (FileEncryptionModuleState *state,
											 void *object_state);
typedef bool (*FileEncryptionEncryptPageCB) (FileEncryptionModuleState *state,
											 void *object_state,
											 ForkNumber fork, BlockNumber blocknum,
											 const char *src, char *dst,
											 char **errmsg);
typedef bool (*FileEncryptionDecryptPageCB) (FileEncryptionModuleState *state,
											 void *object_state,
											 ForkNumber fork, BlockNumber blocknum,
											 const char *src, char *dst,
											 char **errmsg);

/*
 * Identifies the compiled ABI version of the file encryption module.
 *
 * Bump this whenever FileEncryptionCallbacks or any of the callback
 * signatures change in an incompatible way.
 */
#define PG_FILE_ENCRYPTION_MAGIC 0x46454D39		/* "FEM9" */

typedef struct FileEncryptionCallbacks
{
	uint32		magic;			/* must be set to PG_FILE_ENCRYPTION_MAGIC */

	/*
	 * Number of bytes the module appends to every encrypt_cb output for its
	 * own per-call metadata.  The layout is fully module-defined; common
	 * elements include an IV, an authentication tag, and a per-call wrapped
	 * key, but a size-preserving mode is free to declare 0.  Only relevant
	 * for record-stream encryption (BufFile, reorderbuffer spill).
	 */
	Size		overhead_size;

	/*
	 * Number of bytes the module reserves at the tail of every relation
	 * page for its own per-page metadata.  Module-defined layout (typically
	 * IV plus authentication tag, but length-preserving modes like AES-XTS
	 * declare 0).  Must match the cluster's page_reserved_size for the
	 * module to load.  Smaller than overhead_size in the typical case
	 * because the per-relation DEK lives in KEY_FORKNUM, not in each
	 * page's trailer.
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
