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
#include "storage/md.h"
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

/*
 * Per-process state.  Initialized eagerly from process_file_encryption_library
 * (which all top-level startup paths call) and re-initialized after fork()
 * when MyProcPid differs from the value stored at allocation time — fork()
 * inherits the pointer but on_exit_reset() (called early in every backend)
 * clears the before_shmem_exit registration, so we have to register again.
 */
static FileEncryptionModuleState *file_encryption_module_state = NULL;
static int	file_encryption_init_pid = 0;

/*
 * Page-level scratch StringInfo buffer.  Pages need a BLCKSZ-sized output
 * but StringInfo writes a trailing null at data[len], so the backing
 * buffer is BLCKSZ + 1.  Reused across calls in the current process.
 */
static char *page_scratch_buffer = NULL;

static inline void
ensure_page_scratch(void)
{
	if (page_scratch_buffer == NULL)
		page_scratch_buffer = MemoryContextAlloc(TopMemoryContext, BLCKSZ + 1);
}

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
 * Eager wrapper for ensure_per_process_init() and the page-scratch
 * allocation.  Called from mdinit() in each backend so that the
 * per-process module state, shutdown registration, and BLCKSZ-sized
 * scratch buffer are all in place before AIO completion callbacks
 * (which run inside critical sections and can't allocate) fire.
 *
 * No-op when the module hasn't been loaded yet — that's the bootstrap
 * case, where BaseInit() runs before process_file_encryption_library(),
 * and we'd otherwise try to dlopen the module and run its _PG_init too
 * early (PGC_POSTMASTER GUCs can't be defined after startup is complete).
 * The bootstrap process_file_encryption_library() call will reach back
 * via md_init_enc_workspace() to do the eager init once the module IS
 * loaded.
 */
void
FileEncryptionEnsureInit(void)
{
	if (!FileEncryptionEnabled())
		return;
	if (LoadedFileEncryptionCallbacks == NULL)
		return;
	ensure_per_process_init();
	if (LoadedFileEncryptionCallbacks->page_reserved_size > 0)
		ensure_page_scratch();
}

/*
 * Returns true when the configured module declares non-zero
 * page_reserved_size, i.e. it knows how to encrypt relation pages.
 *
 * mdinit() (called from smgrinit() in BaseInit()) consults this before
 * process_file_encryption_library() has run, so we must tolerate a NULL
 * LoadedFileEncryptionCallbacks: the answer in that case is "not yet, but
 * we'll be asked again after the module loads".
 */
bool
FileEncryptionPagesEnabled(void)
{
	if (!FileEncryptionEnabled())
		return false;
	if (LoadedFileEncryptionCallbacks == NULL)
		return false;
	return LoadedFileEncryptionCallbacks->page_reserved_size > 0;
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
 * Encrypt a relation page.  src and dst are both BLCKSZ-sized buffers;
 * the module fills dst with the encrypted page (consuming the trailing
 * page_reserved_size bytes for its own metadata).
 *
 * Internally this drives encrypt_cb with fstate == NULL so the module's
 * page-mode branch runs.  The path string is built on the fly from the
 * relfilelocator + fork; callers that already have a path string can
 * skip this helper and call FileEncryptionEncrypt directly.
 */
void
FileEncryptionEncryptPage(const RelFileLocator *locator,
						  ForkNumber fork, BlockNumber blocknum,
						  const char *src, char *dst)
{
	StringInfoData si;
	RelPathStr	relpath_str;

	if (!FileEncryptionPagesEnabled())
		elog(ERROR, "page encryption is not configured");
	ensure_per_process_init();
	ensure_page_scratch();

	relpath_str = relpathbackend(*locator, INVALID_PROC_NUMBER, fork);

	/*
	 * Wrap the per-process page scratch buffer as a fixed-size StringInfo.
	 * The module fills BLCKSZ bytes; we then memcpy out to dst.  We can't
	 * use dst directly because StringInfo writes a trailing null terminator
	 * one byte past dst->len, which would overflow a strict BLCKSZ buffer.
	 */
	si.data = page_scratch_buffer;
	si.len = 0;
	si.maxlen = BLCKSZ + 1;
	si.cursor = 0;

	LoadedFileEncryptionCallbacks->encrypt_cb(file_encryption_module_state,
											  NULL, /* page mode */
											  relpath_str.str,
											  (uint64) blocknum * BLCKSZ,
											  src, BLCKSZ, &si);
	if (si.len != BLCKSZ)
		elog(ERROR,
			 "page encryption module produced %d bytes, expected %d",
			 si.len, BLCKSZ);
	memcpy(dst, page_scratch_buffer, BLCKSZ);
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
	StringInfoData si;
	RelPathStr	relpath_str;

	if (!FileEncryptionPagesEnabled())
		elog(ERROR, "page encryption is not configured");
	ensure_per_process_init();
	ensure_page_scratch();

	relpath_str = relpathbackend(*locator, INVALID_PROC_NUMBER, fork);

	si.data = page_scratch_buffer;
	si.len = 0;
	si.maxlen = BLCKSZ + 1;
	si.cursor = 0;

	LoadedFileEncryptionCallbacks->decrypt_cb(file_encryption_module_state,
											  NULL, /* page mode */
											  relpath_str.str,
											  (uint64) blocknum * BLCKSZ,
											  src, BLCKSZ, &si);
	if (si.len != BLCKSZ)
		elog(ERROR,
			 "page decryption module produced %d bytes, expected %d",
			 si.len, BLCKSZ);
	memcpy(dst, page_scratch_buffer, BLCKSZ);
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

	/*
	 * Eagerly run the per-process startup callback now, while we're still
	 * outside any critical section.  AIO completion callbacks invoke
	 * encrypt/decrypt from within a critical section and can't tolerate
	 * the lazy palloc that ensure_per_process_init() would otherwise do
	 * on first use.  For the same reason, ask md.c to allocate its
	 * page-encryption workspace now: in bootstrap mode, mdinit() ran
	 * before this function and saw FileEncryptionPagesEnabled() == false,
	 * so the workspace is still NULL.
	 */
	ensure_per_process_init();
	md_init_enc_workspace();
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
	 * Page-level encryption is signalled by a non-zero page_reserved_size
	 * (the cluster's reservation in pg_control must match exactly).
	 * Modules that opt in are then expected to handle encrypt_cb /
	 * decrypt_cb calls with fstate == NULL.
	 */
	if (callbacks->page_reserved_size > 0 &&
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
	bool		state_inherited;

	/*
	 * Already initialized for this process?  fork()ed children inherit our
	 * file_encryption_module_state pointer (and the module's per-process
	 * private_data via COW), but on_exit_reset() in the child has already
	 * cleared the inherited before_shmem_exit list — so we still need to
	 * register the shutdown callback in the child.  Detect the
	 * fork-but-not-yet-registered case by comparing MyProcPid to the pid
	 * recorded when the state was first allocated.
	 */
	if (file_encryption_module_state != NULL &&
		file_encryption_init_pid == MyProcPid)
		return;

	state_inherited = (file_encryption_module_state != NULL);

	/*
	 * Should already have run from process_file_encryption_library at
	 * startup; fall back to loading on demand for safety.
	 */
	if (LoadedFileEncryptionCallbacks == NULL)
		load_and_validate_module();

	if (!state_inherited)
	{
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
	}

	file_encryption_init_pid = MyProcPid;
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
