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
 * Per-file state.  Each opened encrypted file gets one of these; the module
 * owns ->private_data and is responsible for releasing it from
 * close_file_cb (if any).
 */
typedef struct FileEncryptionFileState
{
	void	   *private_data;
} FileEncryptionFileState;

/*
 * File encryption module callbacks.
 *
 * The file_offset argument to encrypt_cb / decrypt_cb identifies where the
 * encrypted record will be stored in the underlying file (offsets are
 * inclusive of any per-file header reserved by the core code).  Modules
 * can use it, together with the path and the per-file state, to derive
 * per-record IVs or nonces.
 */
typedef void (*FileEncryptionStartupCB) (FileEncryptionModuleState *state);
typedef void (*FileEncryptionShutdownCB) (FileEncryptionModuleState *state);

/*
 * Per-file callbacks.  init_file_cb is called once when a brand-new file is
 * being created; the module fills "header" with file_header_size bytes of
 * metadata that the core code writes verbatim at the start of the file,
 * and stows whatever per-file state it needs in fstate->private_data.
 *
 * open_file_cb is called once when an existing file is opened; the module
 * receives the file_header_size bytes the core code already read from
 * disk and reconstructs fstate->private_data.
 *
 * close_file_cb is called when the file is no longer needed; the module
 * releases anything it allocated for fstate->private_data.
 *
 * If file_header_size is 0, init_file_cb / open_file_cb may still be
 * supplied to set up per-file state derived from the path alone, and
 * "header" is then unused.
 */
typedef void (*FileEncryptionInitFileCB) (const FileEncryptionModuleState *state,
										  FileEncryptionFileState *fstate,
										  const char *path,
										  char *header);
typedef void (*FileEncryptionOpenFileCB) (const FileEncryptionModuleState *state,
										  FileEncryptionFileState *fstate,
										  const char *path,
										  const char *header);
typedef void (*FileEncryptionCloseFileCB) (const FileEncryptionModuleState *state,
										   FileEncryptionFileState *fstate);

typedef void (*FileEncryptionEncryptCB) (const FileEncryptionModuleState *state,
										 FileEncryptionFileState *fstate,
										 const char *path, uint64 file_offset,
										 const char *data, Size data_len,
										 StringInfo dst);
typedef void (*FileEncryptionDecryptCB) (const FileEncryptionModuleState *state,
										 FileEncryptionFileState *fstate,
										 const char *path, uint64 file_offset,
										 const char *data, Size data_len,
										 StringInfo dst);

/*
 * Page-level callbacks for relation files.  These run on a fixed-size
 * BLCKSZ buffer: src holds the page (including the trailing
 * page_reserved_size bytes), dst is a caller-allocated BLCKSZ buffer that
 * the module fills with the encrypted page (including its own use of the
 * trailing page_reserved_size bytes for IV, auth tag, key version, ...).
 * The cluster-wide page_reserved_size is fixed at initdb time and is
 * checked against the module's value at server start.
 *
 * The (RelFileLocator, fork, blocknum) tuple uniquely identifies the
 * page on disk and is the natural AAD / IV-derivation context.  pd_lsn
 * within the page can also be used (it advances on every WAL-logged
 * modification), but is not passed separately because it's already
 * inside src.
 */
typedef void (*FileEncryptionEncryptPageCB) (const FileEncryptionModuleState *state,
											 const RelFileLocator *locator,
											 ForkNumber fork,
											 BlockNumber blocknum,
											 const char *src, char *dst);
typedef void (*FileEncryptionDecryptPageCB) (const FileEncryptionModuleState *state,
											 const RelFileLocator *locator,
											 ForkNumber fork,
											 BlockNumber blocknum,
											 const char *src, char *dst);

/*
 * Identifies the compiled ABI version of the file encryption module.
 *
 * Bump this whenever FileEncryptionCallbacks or any of the callback
 * signatures change in an incompatible way.
 */
#define PG_FILE_ENCRYPTION_MAGIC 0x46454D33		/* "FEM3" */

typedef struct FileEncryptionCallbacks
{
	uint32		magic;			/* must be set to PG_FILE_ENCRYPTION_MAGIC */

	/*
	 * Number of bytes the core code reserves at the start of every encrypted
	 * file for the module's per-file header.  May be 0 (no header).  When
	 * non-zero, init_file_cb and open_file_cb must both be supplied.
	 */
	Size		file_header_size;

	/*
	 * Number of bytes the module needs at the tail of every relation page
	 * for its per-page metadata (e.g. IV, auth tag, key version).  May be
	 * 0 (no page-level encryption).  When non-zero, encrypt_page_cb and
	 * decrypt_page_cb must both be supplied, and the cluster's
	 * page_reserved_size in pg_control must match this value.
	 */
	Size		page_reserved_size;

	FileEncryptionStartupCB startup_cb;
	FileEncryptionShutdownCB shutdown_cb;
	FileEncryptionInitFileCB init_file_cb;
	FileEncryptionOpenFileCB open_file_cb;
	FileEncryptionCloseFileCB close_file_cb;
	FileEncryptionEncryptCB encrypt_cb;
	FileEncryptionDecryptCB decrypt_cb;
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

/*
 * Number of header bytes the configured module reserves per file.  Callers
 * that physically lay out encrypted files use this to skip past the header
 * when computing record offsets.
 */
extern Size FileEncryptionFileHeaderSize(void);

/*
 * Per-file lifecycle.  Callers do the actual file I/O for the header bytes;
 * these helpers just drive the module callbacks.
 *
 *	- FileEncryptionFileCreate is for a brand-new file.  On return,
 *	  header_buf has been populated with FileEncryptionFileHeaderSize() bytes
 *	  the caller must persist at offset 0.
 *	- FileEncryptionFileOpen is for an existing file.  Caller supplies the
 *	  FileEncryptionFileHeaderSize() bytes already read from offset 0.
 *	- FileEncryptionFileClose releases per-file state.
 */
extern FileEncryptionFileState *FileEncryptionFileCreate(const char *path,
														 char *header_buf);
extern FileEncryptionFileState *FileEncryptionFileOpen(const char *path,
													   const char *header_buf);
extern void FileEncryptionFileClose(FileEncryptionFileState *fstate);

extern void FileEncryptionEncrypt(FileEncryptionFileState *fstate,
								  const char *path, uint64 file_offset,
								  const char *data, Size data_len,
								  StringInfo dst);
extern void FileEncryptionDecrypt(FileEncryptionFileState *fstate,
								  const char *path, uint64 file_offset,
								  const char *data, Size data_len,
								  StringInfo dst);

/*
 * Page-level encryption.  FileEncryptionPagesEnabled() is true when a
 * configured module also registered the page callbacks.  The reserved
 * size returned here is authoritative at runtime; callers laying out
 * page contents must use it instead of FileEncryptionCallbacks-> to
 * remain agnostic to which module is loaded.
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

#endif							/* FILE_ENCRYPTION_H */
