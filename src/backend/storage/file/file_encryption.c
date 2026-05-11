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
 * KEY fork block format.  One BLCKSZ block at position 0 of every encrypted
 * relation's KEY_FORKNUM.  The block is a fully-initialized PostgreSQL page
 * (PageInit'd with no special area and a populated pd_checksum) so it can
 * travel through the buffer manager and pass PageIsVerified just like any
 * other block, including after a data-checksums transition.  The
 * encryption-specific payload lives in the otherwise-empty data area
 * between pd_lower and pd_upper:
 *
 *	  [ PageHeaderData (SizeOfPageHeaderData bytes)                   ]
 *	  [ FEKeyBlockHeader { magic, version, wrapped_len, reserved }    ]
 *	  [ wrapped DEK ... wrapped_len bytes ...                         ]
 *	  [ zero padding up to pd_upper                                   ]
 *	  [ encryption trailer (zero; KEY fork is exempt from encryption) ]
 *
 * The wrapped DEK is opaque to the core; the encryption module owns its
 * format and verification.
 */
#define FE_KEY_BLOCK_MAGIC		0x46454B42	/* "FEKB" */
#define FE_KEY_BLOCK_VERSION	1

typedef struct FEKeyBlockHeader
{
	uint32		magic;
	uint32		version;
	uint32		wrapped_len;
	uint32		reserved;
} FEKeyBlockHeader;

/*
 * Wrapped DEK lives after the PageHeaderData + FEKeyBlockHeader, and must
 * stay within the page's normal data area (pd_lower..pd_upper).  pd_upper
 * is BLCKSZ - reserved_size for a freshly PageInit'd block; the largest
 * possible reserved size yields the most pessimistic bound, so size
 * conservatively against BLCKSZ.
 */
#define FE_KEY_BLOCK_HEADER_OFFSET	SizeOfPageHeaderData
#define FE_KEY_BLOCK_PAYLOAD_OFFSET (FE_KEY_BLOCK_HEADER_OFFSET + \
									 sizeof(FEKeyBlockHeader))
#define FE_KEY_BLOCK_MAX_WRAPPED	(BLCKSZ - FE_KEY_BLOCK_PAYLOAD_OFFSET)

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
 * Returns true if a file encryption module is configured for this cluster
 * (the library name was supplied at initdb time and now lives in
 * ControlFile, or has been provisionally set on the bootstrap path).
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
	if (FileEncryptionPagesEnabled())
		ensure_page_scratch();
}

/*
 * Returns true when the configured module's page_overhead_size matches the
 * cluster's page_reserved_size, i.e. relation pages are routed through the
 * module.
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
	return LoadedFileEncryptionCallbacks->page_overhead_size > 0;
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
	return LoadedFileEncryptionCallbacks->page_overhead_size;
}

/*
 * Generate a fresh per-relation wrapped DEK and write it as a BLCKSZ block
 * into 'dst'.  The block layout is:
 *
 *	  [ FEKeyBlockHeader ] [ wrapped DEK ... ] [ zero padding to BLCKSZ ]
 *
 * Called from storage.c when an encrypted relation is created; the result
 * is written to KEY_FORKNUM block 0.  Module ownership starts here: the
 * generate_object_key_cb writes the wrapped DEK into a StringInfo that we
 * then frame with the header above.
 */
void
FileEncryptionGenerateObjectKey(const RelFileLocator *locator, char *dst)
{
	StringInfoData si;
	FEKeyBlockHeader hdr;

	if (!FileEncryptionPagesEnabled())
		elog(ERROR, "page encryption is not configured");
	if (LoadedFileEncryptionCallbacks->generate_object_key_cb == NULL)
		elog(ERROR, "file encryption module does not implement generate_object_key_cb");

	ensure_per_process_init();

	initStringInfo(&si);
	LoadedFileEncryptionCallbacks->generate_object_key_cb(file_encryption_module_state,
														  locator, &si);
	if (si.len == 0)
		elog(ERROR, "file encryption module generated an empty wrapped key");
	if ((Size) si.len > FE_KEY_BLOCK_MAX_WRAPPED)
		elog(ERROR,
			 "file encryption module generated %d bytes of wrapped key, exceeds limit %zu",
			 si.len, FE_KEY_BLOCK_MAX_WRAPPED);

	hdr.magic = FE_KEY_BLOCK_MAGIC;
	hdr.version = FE_KEY_BLOCK_VERSION;
	hdr.wrapped_len = (uint32) si.len;
	hdr.reserved = 0;

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
	memcpy(dst + FE_KEY_BLOCK_HEADER_OFFSET, &hdr, sizeof(hdr));
	memcpy(dst + FE_KEY_BLOCK_PAYLOAD_OFFSET, si.data, si.len);
	((PageHeader) dst)->pd_checksum = pg_checksum_page(dst, 0);

	pfree(si.data);
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

	if (reln->encryption_object_state != NULL)
		return;
	if (!FileEncryptionPagesEnabled())
		elog(ERROR, "page encryption is not configured");
	if (LoadedFileEncryptionCallbacks->object_open_cb == NULL)
		elog(ERROR, "file encryption module does not implement object_open_cb");

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

	object_state =
		LoadedFileEncryptionCallbacks->object_open_cb(file_encryption_module_state,
													  &reln->smgr_rlocator.locator,
													  buf.data + FE_KEY_BLOCK_PAYLOAD_OFFSET,
													  hdr.wrapped_len);
	if (object_state == NULL)
		ereport(ERROR,
				(errmsg("file encryption module returned no object state for relation %u/%u/%u",
						reln->smgr_rlocator.locator.spcOid,
						reln->smgr_rlocator.locator.dbOid,
						reln->smgr_rlocator.locator.relNumber)));

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
	if (!FileEncryptionPagesEnabled())
		elog(ERROR, "page encryption is not configured");

	FileEncryptionOpenObject(reln);

	LoadedFileEncryptionCallbacks->encrypt_page_cb(file_encryption_module_state,
												   reln->encryption_object_state,
												   fork, blocknum, src, dst);
}

/*
 * Decrypt a relation page.  src and dst are both BLCKSZ-sized buffers; the
 * module reads the trailing page_overhead_size bytes of src to recover
 * IV/tag material before producing dst.  The module's contract zeros its
 * own page_overhead_size trailing bytes in dst.
 *
 * When the cluster's page_reserved_size is larger than the module's
 * page_overhead_size, the bytes between the two -- inside the cluster's
 * "trailer" view but outside the module's -- might carry decrypted body
 * content (typically zero, since PageInit wrote zeros there at encrypt
 * time, but we don't want to rely on that round-trip).  Zero the full
 * cluster-reserved tail so the plaintext seen by the buffer manager has
 * the trailer all-zero regardless of what the module wrote.  This is
 * what makes the writer's pd_checksum verify on read in the headroom
 * case.
 */
void
FileEncryptionDecryptPage(SMgrRelation reln, ForkNumber fork,
						  BlockNumber blocknum,
						  const char *src, char *dst)
{
	Size		cluster_reserved;

	if (!FileEncryptionPagesEnabled())
		elog(ERROR, "page encryption is not configured");

	FileEncryptionOpenObject(reln);

	LoadedFileEncryptionCallbacks->decrypt_page_cb(file_encryption_module_state,
												   reln->encryption_object_state,
												   fork, blocknum, src, dst);

	cluster_reserved = GetPageReservedSize();
	if (cluster_reserved > LoadedFileEncryptionCallbacks->page_overhead_size)
		memset(dst + BLCKSZ - cluster_reserved, 0, cluster_reserved);
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
	 * before this function and saw FileEncryptionPagesEnabled() == false,
	 * so the workspace is still NULL.
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
	bool		has_any_page_cb;
	bool		has_all_page_cb;

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

	if (!(*init) (file_encryption_config, &callbacks, &init_errmsg))
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

	if (callbacks->encrypt_cb == NULL ||
		callbacks->decrypt_cb == NULL)
		ereport(ERROR,
				(errmsg("file encryption modules must register encrypt and decrypt callbacks")));

	/*
	 * Page-encryption callbacks come as a group of five (generate / open /
	 * close / encrypt_page / decrypt_page).  Modules either register all of
	 * them or none — the core won't try to mix-and-match.
	 */
	has_any_page_cb =
		(callbacks->generate_object_key_cb != NULL) ||
		(callbacks->object_open_cb != NULL) ||
		(callbacks->object_close_cb != NULL) ||
		(callbacks->encrypt_page_cb != NULL) ||
		(callbacks->decrypt_page_cb != NULL);
	has_all_page_cb =
		(callbacks->generate_object_key_cb != NULL) &&
		(callbacks->object_open_cb != NULL) &&
		(callbacks->object_close_cb != NULL) &&
		(callbacks->encrypt_page_cb != NULL) &&
		(callbacks->decrypt_page_cb != NULL);

	if (has_any_page_cb && !has_all_page_cb)
		ereport(ERROR,
				(errmsg("file encryption module \"%s\" registered an incomplete set of page callbacks",
						libname),
				 errdetail("All of generate_object_key_cb, object_open_cb, object_close_cb, encrypt_page_cb, and decrypt_page_cb must be set.")));

	if (has_all_page_cb && callbacks->page_overhead_size == 0)
		ereport(ERROR,
				(errmsg("file encryption module \"%s\" registered page callbacks but declared page_overhead_size = 0",
						libname)));

	if (!has_all_page_cb && callbacks->page_overhead_size != 0)
		ereport(ERROR,
				(errmsg("file encryption module \"%s\" declared page_overhead_size %zu but did not register page callbacks",
						libname, callbacks->page_overhead_size)));

	/*
	 * If the cluster's pg_control already has a page_reserved_size (i.e. we
	 * are starting up an existing cluster, not running BootStrapXLOG for
	 * the first time), the module's page_overhead_size must match it
	 * exactly.  A mismatch means the module was changed or replaced after
	 * initdb, which would silently corrupt every page on the next write.
	 *
	 * In bootstrap mode GetPageReservedSize() returns 0 because pg_control
	 * hasn't been populated yet; we accept the module unconditionally and
	 * BootStrapXLOG will copy page_overhead_size into pg_control.
	 */
	if (callbacks->page_overhead_size > 0 &&
		GetPageReservedSize() != 0 &&
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
