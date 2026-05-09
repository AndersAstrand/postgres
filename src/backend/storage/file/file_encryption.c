/*-------------------------------------------------------------------------
 *
 * file_encryption.c
 *	  Support for pluggable file encryption modules.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/backend/storage/file/file_encryption.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/xlog.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "storage/file_encryption.h"
#include "storage/ipc.h"
#include "utils/memutils.h"

/* GUC */
char	   *file_encryption_library = NULL;

/*
 * Module-level callbacks.  Set during process_file_encryption_library() so
 * the postmaster has them at startup; fork()ed children inherit, and
 * EXEC_BACKEND children re-establish them via the same call from
 * launch_backend.c.
 */
static const FileEncryptionCallbacks *LoadedFileEncryptionCallbacks = NULL;

/* Per-process state, initialized lazily on first encrypt/decrypt. */
static FileEncryptionModuleState *file_encryption_module_state = NULL;
static bool file_encryption_per_process_initialized = false;

static void load_and_validate_module(void);
static void ensure_per_process_init(void);
static void file_encryption_shutdown_cb(int code, Datum arg);

/*
 * Returns true if a file encryption module is configured.
 */
bool
FileEncryptionEnabled(void)
{
	return file_encryption_library != NULL &&
		file_encryption_library[0] != '\0';
}

/*
 * Number of header bytes the configured module reserves at the start of
 * every encrypted file.  Returns 0 when no module is configured or the
 * module doesn't request a header.
 */
Size
FileEncryptionFileHeaderSize(void)
{
	if (!FileEncryptionEnabled())
		return 0;

	ensure_per_process_init();
	return LoadedFileEncryptionCallbacks->file_header_size;
}

/*
 * Allocate a per-file FileEncryptionFileState, with private_data zeroed.
 * Lives in TopMemoryContext so its lifetime is independent of whatever
 * transient context the caller happens to be in.
 */
static FileEncryptionFileState *
allocate_file_state(void)
{
	return MemoryContextAllocZero(TopMemoryContext,
								  sizeof(FileEncryptionFileState));
}

/*
 * Drive init_file_cb for a brand-new encrypted file and return the
 * per-file state.  header_buf must point at a buffer of at least
 * FileEncryptionFileHeaderSize() bytes; on return it holds the bytes the
 * caller must persist at the start of the file.
 */
FileEncryptionFileState *
FileEncryptionFileCreate(const char *path, char *header_buf)
{
	FileEncryptionFileState *fstate;

	if (!FileEncryptionEnabled())
		elog(ERROR, "file encryption module is not configured");

	ensure_per_process_init();

	fstate = allocate_file_state();

	if (LoadedFileEncryptionCallbacks->init_file_cb != NULL)
	{
		MemoryContext oldcontext = MemoryContextSwitchTo(TopMemoryContext);

		PG_TRY();
		{
			LoadedFileEncryptionCallbacks->init_file_cb(file_encryption_module_state,
														fstate, path, header_buf);
		}
		PG_FINALLY();
		{
			MemoryContextSwitchTo(oldcontext);
		}
		PG_END_TRY();
	}

	return fstate;
}

/*
 * Drive open_file_cb for an existing encrypted file.  header_buf must hold
 * the FileEncryptionFileHeaderSize() bytes the caller already read from
 * offset 0 of the file.
 */
FileEncryptionFileState *
FileEncryptionFileOpen(const char *path, const char *header_buf)
{
	FileEncryptionFileState *fstate;

	if (!FileEncryptionEnabled())
		elog(ERROR, "file encryption module is not configured");

	ensure_per_process_init();

	fstate = allocate_file_state();

	if (LoadedFileEncryptionCallbacks->open_file_cb != NULL)
	{
		MemoryContext oldcontext = MemoryContextSwitchTo(TopMemoryContext);

		PG_TRY();
		{
			LoadedFileEncryptionCallbacks->open_file_cb(file_encryption_module_state,
														fstate, path, header_buf);
		}
		PG_FINALLY();
		{
			MemoryContextSwitchTo(oldcontext);
		}
		PG_END_TRY();
	}

	return fstate;
}

/*
 * Release per-file state.  Safe to pass NULL.
 */
void
FileEncryptionFileClose(FileEncryptionFileState *fstate)
{
	if (fstate == NULL)
		return;

	if (LoadedFileEncryptionCallbacks != NULL &&
		LoadedFileEncryptionCallbacks->close_file_cb != NULL)
		LoadedFileEncryptionCallbacks->close_file_cb(file_encryption_module_state,
													 fstate);
	pfree(fstate);
}

/*
 * Encrypt a record for storage on disk.
 */
void
FileEncryptionEncrypt(FileEncryptionFileState *fstate,
					  const char *path, uint64 file_offset,
					  const char *data, Size data_len, StringInfo dst)
{
	if (!FileEncryptionEnabled())
		elog(ERROR, "file encryption module is not configured");

	ensure_per_process_init();
	resetStringInfo(dst);
	LoadedFileEncryptionCallbacks->encrypt_cb(file_encryption_module_state,
											  fstate,
											  path, file_offset, data, data_len,
											  dst);
}

/*
 * Decrypt a record read from disk.
 */
void
FileEncryptionDecrypt(FileEncryptionFileState *fstate,
					  const char *path, uint64 file_offset,
					  const char *data, Size data_len, StringInfo dst)
{
	if (!FileEncryptionEnabled())
		elog(ERROR, "file encryption module is not configured");

	ensure_per_process_init();
	resetStringInfo(dst);
	LoadedFileEncryptionCallbacks->decrypt_cb(file_encryption_module_state,
											  fstate,
											  path, file_offset, data, data_len,
											  dst);
}

/*
 * Returns true when a configured module also registered page callbacks.
 */
bool
FileEncryptionPagesEnabled(void)
{
	if (!FileEncryptionEnabled())
		return false;
	return LoadedFileEncryptionCallbacks->encrypt_page_cb != NULL;
}

/*
 * Number of bytes the configured module reserves at the tail of every
 * relation page.  Returns 0 when no page-level module is configured.
 */
Size
FileEncryptionPageReservedSize(void)
{
	if (!FileEncryptionPagesEnabled())
		return 0;
	return LoadedFileEncryptionCallbacks->page_reserved_size;
}

/*
 * Encrypt a relation page.  src and dst are both BLCKSZ-sized buffers; the
 * module fills dst with the encrypted page (consuming the trailing
 * page_reserved_size bytes for its own metadata).
 */
void
FileEncryptionEncryptPage(const RelFileLocator *locator,
						  ForkNumber fork, BlockNumber blocknum,
						  const char *src, char *dst)
{
	if (!FileEncryptionPagesEnabled())
		elog(ERROR, "page encryption is not configured");
	ensure_per_process_init();
	LoadedFileEncryptionCallbacks->encrypt_page_cb(file_encryption_module_state,
												   locator, fork, blocknum,
												   src, dst);
}

/*
 * Decrypt a relation page.  src and dst are both BLCKSZ-sized buffers; the
 * module reads the trailing page_reserved_size bytes of src to recover
 * IV/tag/key material before producing dst.
 */
void
FileEncryptionDecryptPage(const RelFileLocator *locator,
						  ForkNumber fork, BlockNumber blocknum,
						  const char *src, char *dst)
{
	if (!FileEncryptionPagesEnabled())
		elog(ERROR, "page encryption is not configured");
	ensure_per_process_init();
	LoadedFileEncryptionCallbacks->decrypt_page_cb(file_encryption_module_state,
												   locator, fork, blocknum,
												   src, dst);
}

/*
 * Load the configured file encryption library and validate its callbacks.
 *
 * Called at the same point as process_shared_preload_libraries() so that
 * the module's _PG_init runs early enough to define PGC_POSTMASTER GUCs,
 * and so misconfigurations surface at server start instead of at the first
 * encrypt/decrypt.
 */
void
process_file_encryption_library(void)
{
	bool		save_in_progress;

	if (!FileEncryptionEnabled())
		return;

	/*
	 * Pretend we're inside shared_preload_libraries processing for the
	 * duration of the load so that the module's _PG_init can define
	 * PGC_POSTMASTER GUCs.  Save and restore in case we're nested under
	 * an actual shared_preload_libraries pass.
	 */
	save_in_progress = process_shared_preload_libraries_in_progress;
	process_shared_preload_libraries_in_progress = true;
	PG_TRY();
	{
		load_and_validate_module();
	}
	PG_FINALLY();
	{
		process_shared_preload_libraries_in_progress = save_in_progress;
	}
	PG_END_TRY();
}

static void
load_and_validate_module(void)
{
	FileEncryptionModuleInit init;
	const FileEncryptionCallbacks *callbacks;

	/*
	 * Idempotent: in fork()ed backends we've already inherited the
	 * postmaster's callback pointer, and EXEC_BACKEND children only invoke
	 * this from launch_backend once.
	 */
	if (LoadedFileEncryptionCallbacks != NULL)
		return;

	init = (FileEncryptionModuleInit)
		load_external_function(file_encryption_library,
							   "_PG_file_encryption_module_init",
							   false, NULL);

	if (init == NULL)
		ereport(ERROR,
				(errmsg("file encryption modules have to define the symbol %s",
						"_PG_file_encryption_module_init")));

	callbacks = (*init) ();

	if (callbacks == NULL)
		ereport(ERROR,
				(errmsg("file encryption module \"%s\" returned no callbacks",
						file_encryption_library)));

	if (callbacks->magic != PG_FILE_ENCRYPTION_MAGIC)
		ereport(ERROR,
				(errmsg("file encryption module \"%s\" has incompatible ABI",
						file_encryption_library),
				 errdetail("Server expects %u, module provides %u.",
						   PG_FILE_ENCRYPTION_MAGIC,
						   callbacks->magic)));

	if (callbacks->encrypt_cb == NULL ||
		callbacks->decrypt_cb == NULL)
		ereport(ERROR,
				(errmsg("file encryption modules must register encrypt and decrypt callbacks")));

	/*
	 * If the module reserves a per-file header, init/open are mandatory; the
	 * core code can't write or parse the header on its own.  When no header
	 * is requested either both or neither may be supplied, depending on
	 * whether the module wants per-file state derived from the path.
	 */
	if (callbacks->file_header_size > 0 &&
		(callbacks->init_file_cb == NULL ||
		 callbacks->open_file_cb == NULL))
		ereport(ERROR,
				(errmsg("file encryption module \"%s\" reserves %zu header bytes per file but did not register init_file_cb and open_file_cb",
						file_encryption_library,
						callbacks->file_header_size)));
	if ((callbacks->init_file_cb == NULL) !=
		(callbacks->open_file_cb == NULL))
		ereport(ERROR,
				(errmsg("file encryption modules must register init_file_cb and open_file_cb together")));

	/*
	 * Page-level callbacks: encrypt/decrypt come together, and any non-zero
	 * page_reserved_size requires both.  The reservation must also match the
	 * cluster-wide value chosen at initdb time, since pages on disk already
	 * have that many bytes carved off.
	 */
	if ((callbacks->encrypt_page_cb == NULL) !=
		(callbacks->decrypt_page_cb == NULL))
		ereport(ERROR,
				(errmsg("file encryption modules must register encrypt_page_cb and decrypt_page_cb together")));
	if (callbacks->page_reserved_size > 0 &&
		callbacks->encrypt_page_cb == NULL)
		ereport(ERROR,
				(errmsg("file encryption module \"%s\" reserves %zu page bytes but did not register page callbacks",
						file_encryption_library,
						callbacks->page_reserved_size)));
	if (callbacks->encrypt_page_cb != NULL &&
		callbacks->page_reserved_size != GetPageReservedSize())
		ereport(ERROR,
				(errmsg("file encryption module \"%s\" requires %zu page-reserved bytes, but the cluster was initialized with %u",
						file_encryption_library,
						callbacks->page_reserved_size,
						GetPageReservedSize())));

	LoadedFileEncryptionCallbacks = callbacks;
}

/*
 * Allocate this process's FileEncryptionModuleState, run the module's
 * startup callback, and register the matching shutdown callback.  Idempotent.
 *
 * The state outlives the current memory context (it must survive until
 * backend exit, when the shutdown callback runs), so allocate from
 * TopMemoryContext.  The same context is used for the startup callback so
 * that whatever the module stows in private_data is durable.
 */
static void
ensure_per_process_init(void)
{
	if (file_encryption_per_process_initialized)
		return;

	/*
	 * Should already have run from process_file_encryption_library at
	 * startup; fall back to loading on demand for safety.
	 */
	if (LoadedFileEncryptionCallbacks == NULL)
		load_and_validate_module();

	file_encryption_module_state =
		MemoryContextAllocZero(TopMemoryContext,
							   sizeof(FileEncryptionModuleState));
	file_encryption_module_state->sversion = PG_VERSION_NUM;

	if (LoadedFileEncryptionCallbacks->startup_cb != NULL)
	{
		MemoryContext oldcontext = MemoryContextSwitchTo(TopMemoryContext);

		PG_TRY();
		{
			LoadedFileEncryptionCallbacks->startup_cb(file_encryption_module_state);
		}
		PG_CATCH();
		{
			MemoryContextSwitchTo(oldcontext);
			pfree(file_encryption_module_state);
			file_encryption_module_state = NULL;
			PG_RE_THROW();
		}
		PG_END_TRY();

		MemoryContextSwitchTo(oldcontext);
	}

	file_encryption_per_process_initialized = true;
	before_shmem_exit(file_encryption_shutdown_cb, 0);
}

/*
 * Call the shutdown callback of the loaded module, if defined.
 */
static void
file_encryption_shutdown_cb(int code, Datum arg)
{
	if (LoadedFileEncryptionCallbacks != NULL &&
		LoadedFileEncryptionCallbacks->shutdown_cb != NULL)
		LoadedFileEncryptionCallbacks->shutdown_cb(file_encryption_module_state);
}
