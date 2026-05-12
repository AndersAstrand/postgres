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
#include "common/file_encryption_keyblock.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "storage/bufpage.h"
#include "storage/checksum.h"
#include "storage/file_encryption.h"
#include "storage/ipc.h"
#include "storage/md.h"
#include "storage/smgr.h"
#include "utils/memutils.h"

/* GUC */
char	   *file_encryption_config = NULL;

/*
 * Library name in effect for this process.  In bootstrap mode this is set
 * by process_file_encryption_library() (which receives the name from the
 * bootstrap command line); at runtime it points at the field in
 * ControlFile, which postmaster populated via LocalProcessControlFile().
 * The two paths converge on the same loader.
 */
static const char *active_file_encryption_library = NULL;

/*
 * Module-level callbacks.  Set during process_file_encryption_library() so
 * the postmaster has them at startup; fork()ed children inherit, and
 * EXEC_BACKEND children re-establish them via the same call from
 * launch_backend.c.
 */
static const FileEncryptionCallbacks *LoadedFileEncryptionCallbacks = NULL;

/*
 * Per-process state.  Initialized eagerly from process_file_encryption_library
 * (which all top-level startup paths call) and re-initialized after fork().
 * Forked children inherit the postmaster's pointer, but they must not reuse
 * it: crash recovery can run the postmaster's shutdown callback and clear the
 * module private_data before later backends are forked.
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

static void load_and_validate_module(const char *libname);
static void ensure_per_process_init(void);
static void file_encryption_shutdown_cb(int code, Datum arg);

/*
 * Returns true if a file encryption module is configured for this cluster.
 * At runtime the library name lives in pg_control (stamped there at initdb
 * time); during bootstrap it's whatever process_file_encryption_library()
 * was handed on the command line.
 */
bool
FileEncryptionEnabled(void)
{
	return active_file_encryption_library != NULL &&
		active_file_encryption_library[0] != '\0';
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
 * Encrypt data_len plaintext bytes into dst.  dst must have
 * data_len + overhead_size bytes allocated by the caller; the module
 * appends its overhead at the tail.  Errors from the module are surfaced
 * as ereport(ERROR).
 */
void
FileEncryptionEncrypt(const char *path, uint64 file_offset,
					  const char *data, Size data_len, char *dst)
{
	char	   *module_errmsg = NULL;

	if (!FileEncryptionEnabled())
		elog(ERROR, "file encryption module is not configured");

	ensure_per_process_init();
	if (!LoadedFileEncryptionCallbacks->encrypt_cb(file_encryption_module_state,
												   path, file_offset, data, data_len,
												   dst, &module_errmsg))
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("file encryption module encrypt callback failed"),
				 module_errmsg ? errdetail("%s", module_errmsg) : 0));
}

/*
 * Decrypt data_len bytes (which the module produced via encrypt_cb,
 * including its trailing overhead) into dst.  dst must have
 * data_len - overhead_size bytes allocated by the caller.
 */
void
FileEncryptionDecrypt(const char *path, uint64 file_offset,
					  const char *data, Size data_len, char *dst)
{
	char	   *module_errmsg = NULL;

	if (!FileEncryptionEnabled())
		elog(ERROR, "file encryption module is not configured");

	ensure_per_process_init();
	if (!LoadedFileEncryptionCallbacks->decrypt_cb(file_encryption_module_state,
												   path, file_offset, data, data_len,
												   dst, &module_errmsg))
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("file encryption module decrypt callback failed"),
				 module_errmsg ? errdetail("%s", module_errmsg) : 0));
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
	ensure_page_scratch();
}

/*
 * Number of bytes the configured module reserves at the tail of every
 * relation page.  May be zero — a module that doesn't need a per-page
 * trailer (e.g. AES-XTS, or a stream cipher with a deterministic IV
 * derived from (relNumber, fork, blocknum)) is fully supported.  Returns
 * 0 when no module is configured.
 */
Size
FileEncryptionPageReservedSize(void)
{
	if (!FileEncryptionEnabled())
		return 0;
	if (LoadedFileEncryptionCallbacks == NULL)
		return 0;
	return LoadedFileEncryptionCallbacks->page_overhead_size;
}

/*
 * Generate a fresh per-relation wrapped DEK and write it as a BLCKSZ block
 * into 'dst'.  The block layout is:
 *
 *	  [ FEKeyBlockHeader ] [ wrapped DEK ... ] [ zero padding to BLCKSZ ]
 *
 * Called from storage.c when an encrypted relation is created; the result
 * is written to KEY_FORKNUM block 0.  The module writes the wrapped DEK
 * directly into the payload area of dst and reports how many bytes it
 * used; we then frame it with the FEKeyBlockHeader above.
 */
void
FileEncryptionGenerateObjectKey(const RelFileLocator *locator, char *dst)
{
	FEKeyBlockHeader hdr;
	Size		wrapped_len = 0;
	char	   *module_errmsg = NULL;

	if (!FileEncryptionEnabled())
		elog(ERROR, "file encryption module is not configured");

	ensure_per_process_init();

	/*
	 * Format the block as a PostgreSQL page so it passes PageIsVerified and
	 * travels through the buffer manager like any other block.  PageInit
	 * zeroes the whole BLCKSZ region (including the cluster-wide
	 * page-reserved trailer) and sets pd_lower/pd_upper/pd_special such
	 * that the entire area between the page header and pd_upper is
	 * available data space; we embed our header and the wrapped DEK there.
	 *
	 * We compute pd_checksum eagerly via pg_checksum_page rather than going
	 * through PageSetChecksum: PageSetChecksum is a no-op while
	 * data_checksums is "off", but the block must remain verifiable across
	 * a future data-checksums-on transition (we never let the
	 * data-checksums worker rewrite the KEY fork — see datachecksum_state).
	 * Computing the checksum at write time once means the block is
	 * permanently self-consistent regardless of the cluster's current
	 * checksum state.
	 */
	PageInit((Page) dst, BLCKSZ, 0);

	if (!LoadedFileEncryptionCallbacks->generate_object_key_cb(file_encryption_module_state,
															   locator,
															   dst + FE_KEY_BLOCK_PAYLOAD_OFFSET,
															   FE_KEY_BLOCK_MAX_WRAPPED,
															   &wrapped_len,
															   &module_errmsg))
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("file encryption module generate_object_key callback failed"),
				 module_errmsg ? errdetail("%s", module_errmsg) : 0));
	if (wrapped_len == 0)
		elog(ERROR, "file encryption module generated an empty wrapped key");
	if (wrapped_len > FE_KEY_BLOCK_MAX_WRAPPED)
		elog(ERROR,
			 "file encryption module generated %zu bytes of wrapped key, exceeds limit %zu",
			 wrapped_len, FE_KEY_BLOCK_MAX_WRAPPED);

	hdr.magic = FE_KEY_BLOCK_MAGIC;
	hdr.version = FE_KEY_BLOCK_VERSION;
	hdr.wrapped_len = (uint32) wrapped_len;
	hdr.reserved = 0;
	memcpy(dst + FE_KEY_BLOCK_HEADER_OFFSET, &hdr, sizeof(hdr));
	((PageHeader) dst)->pd_checksum = pg_checksum_page(dst, 0);
}

/*
 * Read the KEY fork block for 'reln' and ask the module to unwrap the
 * stored DEK into a per-relation state pointer cached on reln.  Idempotent
 * — no-op when the state is already populated.
 */
void
FileEncryptionOpenObject(SMgrRelation reln)
{
	PGIOAlignedBlock buf;
	FEKeyBlockHeader hdr;
	void	   *object_state;
	char	   *module_errmsg = NULL;
	MemoryContext oldcontext;

	if (reln->encryption_object_state != NULL)
		return;
	if (!FileEncryptionEnabled())
		elog(ERROR, "file encryption module is not configured");

	ensure_per_process_init();
	ensure_page_scratch();

	/*
	 * KEY fork is exempt from encryption (md_fork_is_encrypted returns
	 * false), so smgrread hands us the raw on-disk bytes.  We can read
	 * directly from disk because the KEY fork's content is forced to disk
	 * during relation creation -- on the primary by smgrextend +
	 * smgrimmedsync, on a standby by the dedicated smgr WAL record whose
	 * redo also goes directly to disk (see XLOG_SMGR_KEY_FORK_CREATE in
	 * storage.c).  This avoids reading through the buffer manager, which
	 * would risk recursive AIO inside an in-flight smgr write.
	 */
	smgrread(reln, KEY_FORKNUM, 0, buf.data);

	memcpy(&hdr, buf.data + FE_KEY_BLOCK_HEADER_OFFSET, sizeof(hdr));
	if (hdr.magic != FE_KEY_BLOCK_MAGIC)
		ereport(ERROR,
				(errmsg("invalid file-encryption key block on relation %u/%u/%u: bad magic 0x%08x",
						reln->smgr_rlocator.locator.spcOid,
						reln->smgr_rlocator.locator.dbOid,
						reln->smgr_rlocator.locator.relNumber,
						hdr.magic)));
	if (hdr.version != FE_KEY_BLOCK_VERSION)
		ereport(ERROR,
				(errmsg("unsupported file-encryption key block version %u on relation %u/%u/%u",
						hdr.version,
						reln->smgr_rlocator.locator.spcOid,
						reln->smgr_rlocator.locator.dbOid,
						reln->smgr_rlocator.locator.relNumber)));
	if (hdr.wrapped_len == 0 || hdr.wrapped_len > FE_KEY_BLOCK_MAX_WRAPPED)
		ereport(ERROR,
				(errmsg("invalid file-encryption key block on relation %u/%u/%u: wrapped_len %u out of range",
						reln->smgr_rlocator.locator.spcOid,
						reln->smgr_rlocator.locator.dbOid,
						reln->smgr_rlocator.locator.relNumber,
						hdr.wrapped_len)));

	/*
	 * The per-relation state has to outlive every catalog-scoped or
	 * transaction-scoped memory context that the module's palloc would
	 * otherwise pick up: it's cached on SMgrRelation and freed only when
	 * smgrdestroy() calls object_close_cb.  Switch to TopMemoryContext so
	 * the module can just palloc without thinking about lifetimes.
	 */
	oldcontext = MemoryContextSwitchTo(TopMemoryContext);
	object_state =
		LoadedFileEncryptionCallbacks->object_open_cb(file_encryption_module_state,
													  &reln->smgr_rlocator.locator,
													  buf.data + FE_KEY_BLOCK_PAYLOAD_OFFSET,
													  hdr.wrapped_len,
													  &module_errmsg);
	MemoryContextSwitchTo(oldcontext);
	if (object_state == NULL)
		ereport(ERROR,
				(errmsg("file encryption module could not open object state for relation %u/%u/%u",
						reln->smgr_rlocator.locator.spcOid,
						reln->smgr_rlocator.locator.dbOid,
						reln->smgr_rlocator.locator.relNumber),
				 module_errmsg ? errdetail("%s", module_errmsg) : 0));

	reln->encryption_object_state = object_state;
}

/*
 * Release any per-relation file-encryption state cached on 'reln'.  Called
 * from smgrdestroy() (and tolerates a NULL state, so it's safe from any
 * teardown path).
 */
void
FileEncryptionCloseObject(SMgrRelation reln)
{
	if (reln->encryption_object_state == NULL)
		return;
	if (LoadedFileEncryptionCallbacks != NULL &&
		LoadedFileEncryptionCallbacks->object_close_cb != NULL)
		LoadedFileEncryptionCallbacks->object_close_cb(file_encryption_module_state,
													   reln->encryption_object_state);
	reln->encryption_object_state = NULL;
}

/*
 * Encrypt a relation page.  src and dst are both BLCKSZ-sized buffers; the
 * module fills dst with the encrypted page (the trailing page_overhead_size
 * bytes are its own metadata).  Uses the per-relation DEK cached on
 * SMgrRelation, loading it lazily on first call.
 */
void
FileEncryptionEncryptPage(SMgrRelation reln, ForkNumber fork,
						  BlockNumber blocknum,
						  const char *src, char *dst)
{
	char	   *module_errmsg = NULL;

	if (!FileEncryptionEnabled())
		elog(ERROR, "file encryption module is not configured");

	FileEncryptionOpenObject(reln);

	if (!LoadedFileEncryptionCallbacks->encrypt_page_cb(file_encryption_module_state,
														reln->encryption_object_state,
														fork, blocknum, src, dst,
														&module_errmsg))
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("file encryption module encrypt_page callback failed for fork %d block %u of relation %u/%u/%u",
						fork, blocknum,
						reln->smgr_rlocator.locator.spcOid,
						reln->smgr_rlocator.locator.dbOid,
						reln->smgr_rlocator.locator.relNumber),
				 module_errmsg ? errdetail("%s", module_errmsg) : 0));
}

/*
 * Decrypt a relation page.  src and dst are both BLCKSZ-sized buffers; the
 * module reads the trailing page_overhead_size bytes of src for its own
 * per-page metadata (if any) before producing dst.  Module contract: the
 * trailing page_overhead_size bytes of dst must be zero on return, so
 * that pd_checksum (which covers the full BLCKSZ) verifies against the
 * writer's plaintext, which also has a zero trailer.
 */
void
FileEncryptionDecryptPage(SMgrRelation reln, ForkNumber fork,
						  BlockNumber blocknum,
						  const char *src, char *dst)
{
	char	   *module_errmsg = NULL;

	if (!FileEncryptionEnabled())
		elog(ERROR, "file encryption module is not configured");

	FileEncryptionOpenObject(reln);

	if (!LoadedFileEncryptionCallbacks->decrypt_page_cb(file_encryption_module_state,
														reln->encryption_object_state,
														fork, blocknum, src, dst,
														&module_errmsg))
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("file encryption module decrypt_page callback failed for fork %d block %u of relation %u/%u/%u",
						fork, blocknum,
						reln->smgr_rlocator.locator.spcOid,
						reln->smgr_rlocator.locator.dbOid,
						reln->smgr_rlocator.locator.relNumber),
				 module_errmsg ? errdetail("%s", module_errmsg) : 0));
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
process_file_encryption_library(const char *libname)
{
	bool		save_in_progress;

	/*
	 * If the caller didn't pass a libname (the normal runtime case), pull
	 * it from the control file via the xlog accessor.  Bootstrap passes
	 * the name explicitly because pg_control hasn't been populated yet at
	 * that point.
	 */
	if (libname == NULL || libname[0] == '\0')
		libname = GetFileEncryptionLibrary();

	if (libname == NULL || libname[0] == '\0')
	{
		active_file_encryption_library = NULL;
		return;
	}

	active_file_encryption_library = libname;

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
		load_and_validate_module(libname);
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
	 * before this function and saw FileEncryptionEnabled() == false, so
	 * the workspace is still NULL.
	 */
	ensure_per_process_init();
	md_init_enc_workspace();
}

static void
load_and_validate_module(const char *libname)
{
	FileEncryptionModuleInit init;
	const FileEncryptionCallbacks *callbacks = NULL;
	char	   *init_errmsg = NULL;
	MemoryContext oldcontext;
	bool		init_ok;

	/*
	 * Idempotent: in fork()ed backends we've already inherited the
	 * postmaster's callback pointer, and EXEC_BACKEND children only invoke
	 * this from launch_backend once.
	 */
	if (LoadedFileEncryptionCallbacks != NULL)
		return;

	init = (FileEncryptionModuleInit)
		load_external_function(libname,
							   "_PG_file_encryption_module_init",
							   false, NULL);

	if (init == NULL)
		ereport(ERROR,
				(errmsg("file encryption modules have to define the symbol %s",
						"_PG_file_encryption_module_init")));

	/*
	 * Modules typically stash parsed configuration into module statics
	 * via pstrdup/palloc, so any allocation done inside init must come
	 * from a long-lived context.  Switch to TopMemoryContext for the
	 * duration of the call -- the host has no way to know what the
	 * caller's current context is otherwise.  Frontend tools have only
	 * one heap and don't need this.
	 */
	oldcontext = MemoryContextSwitchTo(TopMemoryContext);
	init_ok = (*init) (file_encryption_config, &callbacks, &init_errmsg);
	MemoryContextSwitchTo(oldcontext);

	if (!init_ok)
	{
		char	   *detail = init_errmsg ? pstrdup(init_errmsg) : NULL;

		if (init_errmsg)
			pfree(init_errmsg);
		if (detail != NULL)
			ereport(ERROR,
					(errmsg("file encryption module \"%s\" failed to initialize",
							libname),
					 errdetail("%s", detail)));
		else
			ereport(ERROR,
					(errmsg("file encryption module \"%s\" failed to initialize",
							libname)));
	}

	if (callbacks == NULL)
		ereport(ERROR,
				(errmsg("file encryption module \"%s\" returned no callbacks",
						libname)));

	if (callbacks->magic != PG_FILE_ENCRYPTION_MAGIC)
		ereport(ERROR,
				(errmsg("file encryption module \"%s\" has incompatible ABI",
						libname),
				 errdetail("Server expects %u, module provides %u.",
						   PG_FILE_ENCRYPTION_MAGIC,
						   callbacks->magic)));

	/*
	 * A loaded module must implement every callback: encrypt_cb / decrypt_cb
	 * for record streams (BufFile, reorderbuffer spill), plus the five
	 * page-encryption callbacks.  Configuring an encryption library is an
	 * all-or-nothing choice -- there is no partial mode in which only some
	 * I/O is encrypted.
	 */
	if (callbacks->encrypt_cb == NULL ||
		callbacks->decrypt_cb == NULL ||
		callbacks->generate_object_key_cb == NULL ||
		callbacks->object_open_cb == NULL ||
		callbacks->object_close_cb == NULL ||
		callbacks->encrypt_page_cb == NULL ||
		callbacks->decrypt_page_cb == NULL)
		ereport(ERROR,
				(errmsg("file encryption module \"%s\" did not register the full callback set",
						libname),
				 errdetail("All of encrypt_cb, decrypt_cb, generate_object_key_cb, object_open_cb, object_close_cb, encrypt_page_cb, and decrypt_page_cb must be set.")));

	/*
	 * If the cluster's pg_control already has a page_reserved_size (i.e. we
	 * are starting up an existing cluster, not running BootStrapXLOG for
	 * the first time), the module's page_overhead_size must match it
	 * exactly.  A mismatch means the module was changed or replaced after
	 * initdb, which would silently corrupt every page on the next write.
	 *
	 * In bootstrap mode GetPageReservedSize() returns 0 because pg_control
	 * hasn't been populated yet; we accept the module unconditionally and
	 * BootStrapXLOG will copy page_overhead_size into pg_control.  Note
	 * that page_overhead_size = 0 is a valid declaration for modules that
	 * don't need a per-page trailer (e.g. AES-XTS, or a stream cipher with
	 * a deterministic IV derived from the binding context); it just means
	 * the cluster uses the full BLCKSZ for AM data.
	 */
	if (GetPageReservedSize() != 0 &&
		callbacks->page_overhead_size != GetPageReservedSize())
		ereport(ERROR,
				(errmsg("file encryption module \"%s\" declares page_overhead_size %zu, but the cluster was initialized with page_reserved_size %u",
						libname,
						callbacks->page_overhead_size,
						GetPageReservedSize()),
				 errdetail("The cluster's page_reserved_size is stamped at initdb time from the module's declared per-page overhead; the module appears to have been changed since.")));

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
	 * Already initialized for this process?
	 */
	if (file_encryption_module_state != NULL &&
		file_encryption_init_pid == MyProcPid)
		return;

	/*
	 * Should already have run from process_file_encryption_library at
	 * startup; fall back to loading on demand for safety, using whichever
	 * library name our caller already arranged in active_*.
	 */
	if (LoadedFileEncryptionCallbacks == NULL)
		load_and_validate_module(active_file_encryption_library);

	state_inherited = (file_encryption_module_state != NULL);
	if (state_inherited)
		file_encryption_module_state = NULL;

	file_encryption_module_state =
		MemoryContextAllocZero(TopMemoryContext,
							   sizeof(FileEncryptionModuleState));
	file_encryption_module_state->sversion = PG_VERSION_NUM;

	if (LoadedFileEncryptionCallbacks->startup_cb != NULL)
	{
		MemoryContext oldcontext = MemoryContextSwitchTo(TopMemoryContext);
		char	   *module_errmsg = NULL;
		bool		startup_ok;

		PG_TRY();
		{
			startup_ok = LoadedFileEncryptionCallbacks->startup_cb(file_encryption_module_state,
																   &module_errmsg);
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

		if (!startup_ok)
		{
			pfree(file_encryption_module_state);
			file_encryption_module_state = NULL;
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("file encryption module startup callback failed"),
					 module_errmsg ? errdetail("%s", module_errmsg) : 0));
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
	file_encryption_init_pid = 0;
}
