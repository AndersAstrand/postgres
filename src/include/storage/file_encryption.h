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
 * Encrypt / decrypt callbacks.  The module sees a single uniform call
 * shape: encrypt the data_len plaintext bytes at "data" into dst,
 * producing exactly data_len + overhead_size output bytes (with the
 * overhead bytes laid out at the tail of dst).  The (path, file_offset)
 * pair identifies where the bytes will live on disk and is the natural
 * AAD-derivation context for AEAD modules.
 *
 * The caller is responsible for slicing data and dst to the right
 * boundaries; the module never has to know whether the call came from a
 * BufFile, a reorderbuffer spill file, or an md.c relation-page write.
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
 * Identifies the compiled ABI version of the file encryption module.
 *
 * Bump this whenever FileEncryptionCallbacks or any of the callback
 * signatures change in an incompatible way.
 */
#define PG_FILE_ENCRYPTION_MAGIC 0x46454D35		/* "FEM5" */

typedef struct FileEncryptionCallbacks
{
	uint32		magic;			/* must be set to PG_FILE_ENCRYPTION_MAGIC */

	/*
	 * Number of bytes the module appends to every encrypt_cb output (per-call
	 * overhead, e.g. IV + auth tag).  May be 0 for size-preserving modes.
	 *
	 * For relation-page encryption this also serves as the cluster's
	 * page_reserved_size: pg_control records the value at initdb time, every
	 * page on disk reserves that many bytes at its tail, and the module's
	 * declared overhead_size must match the cluster's page_reserved_size.
	 */
	Size		overhead_size;

	FileEncryptionStartupCB startup_cb;
	FileEncryptionShutdownCB shutdown_cb;
	FileEncryptionEncryptCB encrypt_cb;
	FileEncryptionDecryptCB decrypt_cb;
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
 * configured module's overhead_size matches the cluster's page_reserved_size
 * (i.e. relation pages are routed through the module).  The helpers below
 * wrap encrypt_cb / decrypt_cb with the BLCKSZ-in / BLCKSZ-out contract
 * that md.c needs.
 */
extern bool FileEncryptionPagesEnabled(void);
extern Size FileEncryptionPageReservedSize(void);
extern void FileEncryptionEncryptPage(const RelFileLocator *locator,
									  ForkNumber fork, BlockNumber blocknum,
									  const char *src, char *dst);
extern void FileEncryptionDecryptPage(const RelFileLocator *locator,
									  ForkNumber fork, BlockNumber blocknum,
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
