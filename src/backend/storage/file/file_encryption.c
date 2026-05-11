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

/*
 * Per-process state.  Initialized eagerly from process_file_encryption_library
 * (which all top-level startup paths call) and re-initialized after fork()
 * when MyProcPid differs from the value stored at allocation time — fork()
 * inherits the pointer but on_exit_reset() (called early in every backend)
 * clears the before_shmem_exit registration, so we have to register again.
 */
static FileEncryptionModuleState *file_encryption_module_state = NULL;
static int	file_encryption_init_pid = 0;

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
 * Per-call ciphertext overhead the configured module declares.  Returns 0
 * when no module is configured.
 */
Size
FileEncryptionOverheadSize(void)
{
	if (!FileEncryptionEnabled())
		return 0;
	if (LoadedFileEncryptionCallbacks == NULL)
		return 0;
	return LoadedFileEncryptionCallbacks->overhead_size;
}

/*
 * Encrypt data_len plaintext bytes into dst.  On success, dst contains
 * exactly data_len + overhead_size bytes (the module appends its overhead
 * at the tail).
 */
void
FileEncryptionEncrypt(const char *path, uint64 file_offset,
					  const char *data, Size data_len, StringInfo dst)
{
	if (!FileEncryptionEnabled())
		elog(ERROR, "file encryption module is not configured");

	ensure_per_process_init();
	resetStringInfo(dst);
	LoadedFileEncryptionCallbacks->encrypt_cb(file_encryption_module_state,
											  path, file_offset, data, data_len,
											  dst);
}

/*
 * Decrypt data_len bytes (which the module produced via encrypt_cb,
 * including its trailing overhead) into dst.
 */
void
FileEncryptionDecrypt(const char *path, uint64 file_offset,
					  const char *data, Size data_len, StringInfo dst)
{
	if (!FileEncryptionEnabled())
		elog(ERROR, "file encryption module is not configured");

	ensure_per_process_init();
	resetStringInfo(dst);
	LoadedFileEncryptionCallbacks->decrypt_cb(file_encryption_module_state,
											  path, file_offset, data, data_len,
											  dst);
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
	 * outside any critical section.
	 */
	ensure_per_process_init();
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
