/*-------------------------------------------------------------------------
 *
 * pg_checksums.c
 *	  Checks, enables or disables page level checksums for an offline
 *	  cluster
 *
 * Copyright (c) 2010-2026, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/bin/pg_checksums/pg_checksums.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres_fe.h"

#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "catalog/pg_tablespace_d.h"
#include "common/controldata_utils.h"
#include "common/file_encryption_keyblock.h"
#include "common/file_encryption_load.h"
#include "common/file_encryption_module.h"
#include "common/file_utils.h"
#include "common/logging.h"
#include "common/relpath.h"
#include "fe_utils/option_utils.h"
#include "fe_utils/version.h"
#include "getopt_long.h"
#include "pg_getopt.h"
#include "storage/bufpage.h"
#include "storage/checksum.h"
#include "storage/checksum_impl.h"


static int64 files_scanned = 0;
static int64 files_written = 0;
static int64 blocks_scanned = 0;
static int64 blocks_written = 0;
static int64 badblocks = 0;
static ControlFileData *ControlFile;

static char *only_filenode = NULL;
static bool do_sync = true;
static bool verbose = false;
static bool showprogress = false;
static DataDirSyncMethod sync_method = DATA_DIR_SYNC_METHOD_FSYNC;

/*
 * File encryption module state.  Populated in main() after ControlFile is
 * read if the cluster was initdb'd with --file-encryption-library; NULL
 * otherwise.  scan_file consults fe_callbacks to decide whether to
 * decrypt blocks before checksum verification.
 */
static const FileEncryptionCallbacks *fe_callbacks = NULL;
static FileEncryptionModuleState fe_module_state = {0};
static void *fe_module_handle = NULL;

/*
 * One-entry-per-relation cache of unwrapped DEK state.  Built lazily on
 * first MAIN/INIT block seen for each relation; freed at exit.  A simple
 * linked list is sufficient -- pg_checksums walks files sequentially and
 * we only revisit a relation across its segment boundary.
 */
typedef struct EncryptedRelEntry
{
	RelFileLocator locator;
	void	   *object_state;
	struct EncryptedRelEntry *next;
} EncryptedRelEntry;

static EncryptedRelEntry *encrypted_rels = NULL;

static char *file_encryption_config = NULL;

typedef enum
{
	PG_MODE_CHECK,
	PG_MODE_DISABLE,
	PG_MODE_ENABLE,
} PgChecksumMode;

static PgChecksumMode mode = PG_MODE_CHECK;

static const char *progname;

/*
 * Progress status information.
 */
static int64 total_size = 0;
static int64 current_size = 0;
static pg_time_t last_progress_report = 0;

static void
usage(void)
{
	printf(_("%s enables, disables, or verifies data checksums in a PostgreSQL database cluster.\n\n"), progname);
	printf(_("Usage:\n"));
	printf(_("  %s [OPTION]... [DATADIR]\n"), progname);
	printf(_("\nOptions:\n"));
	printf(_(" [-D, --pgdata=]DATADIR    data directory\n"));
	printf(_("  -c, --check              check data checksums (default)\n"));
	printf(_("  -d, --disable            disable data checksums\n"));
	printf(_("  -e, --enable             enable data checksums\n"));
	printf(_("  -f, --filenode=FILENODE  check only relation with specified filenode\n"));
	printf(_("      --file-encryption-config=STRING\n"
			 "                           configuration blob for the encryption module\n"
			 "                           named in the cluster's pg_control; may also be\n"
			 "                           supplied via the PGFILEENCRYPTIONCONFIG env var\n"));
	printf(_("  -N, --no-sync            do not wait for changes to be written safely to disk\n"));
	printf(_("  -P, --progress           show progress information\n"));
	printf(_("      --sync-method=METHOD set method for syncing files to disk\n"));
	printf(_("  -v, --verbose            output verbose messages\n"));
	printf(_("  -V, --version            output version information, then exit\n"));
	printf(_("  -?, --help               show this help, then exit\n"));
	printf(_("\nIf no data directory (DATADIR) is specified, "
			 "the environment variable PGDATA\nis used.\n\n"));
	printf(_("Report bugs to <%s>.\n"), PACKAGE_BUGREPORT);
	printf(_("%s home page: <%s>\n"), PACKAGE_NAME, PACKAGE_URL);
}

/*
 * Definition of one element part of an exclusion list, used for files
 * to exclude from checksum validation.  "name" is the name of the file
 * or path to check for exclusion.  If "match_prefix" is true, any items
 * matching the name as prefix are excluded.
 */
struct exclude_list_item
{
	const char *name;
	bool		match_prefix;
};

/*
 * List of files excluded from checksum validation.
 *
 * Note: this list should be kept in sync with what basebackup.c includes.
 */
static const struct exclude_list_item skip[] = {
	{"pg_control", false},
	{"pg_filenode.map", false},
	{"pg_internal.init", true},
	{"PG_VERSION", false},
#ifdef EXEC_BACKEND
	{"config_exec_params", true},
#endif
	{NULL, false}
};

/*
 * Report current progress status.  Parts borrowed from
 * src/bin/pg_basebackup/pg_basebackup.c.
 */
static void
progress_report(bool finished)
{
	int			percent;
	pg_time_t	now;

	Assert(showprogress);

	now = time(NULL);
	if (now == last_progress_report && !finished)
		return;					/* Max once per second */

	/* Save current time */
	last_progress_report = now;

	/* Adjust total size if current_size is larger */
	if (current_size > total_size)
		total_size = current_size;

	/* Calculate current percentage of size done */
	percent = total_size ? (int) ((current_size) * 100 / total_size) : 0;

	fprintf(stderr, _("%" PRId64 "/%" PRId64 " MB (%d%%) computed"),
			(current_size / (1024 * 1024)),
			(total_size / (1024 * 1024)),
			percent);

	/*
	 * Stay on the same line if reporting to a terminal and we're not done
	 * yet.
	 */
	fputc((!finished && isatty(fileno(stderr))) ? '\r' : '\n', stderr);
}

static bool
skipfile(const char *fn)
{
	int			excludeIdx;

	for (excludeIdx = 0; skip[excludeIdx].name != NULL; excludeIdx++)
	{
		int			cmplen = strlen(skip[excludeIdx].name);

		if (!skip[excludeIdx].match_prefix)
			cmplen++;
		if (strncmp(skip[excludeIdx].name, fn, cmplen) == 0)
			return true;
	}

	return false;
}

/*
 * Resolve the per-relation object_state for an encrypted relation,
 * loading + caching it on first lookup.  Reads the KEY fork from
 * '<dirpath>/<relNumber>_key', validates its header, and hands the
 * wrapped DEK to the module's object_open_cb.
 */
static void *
get_encryption_object_state(RelFileLocator locator, const char *dirpath)
{
	EncryptedRelEntry *entry;
	char		keypath[MAXPGPATH];
	int			f;
	PGIOAlignedBlock keybuf;
	FEKeyBlockHeader hdr;
	int			r;
	char	   *module_errmsg = NULL;
	void	   *obj_state;

	for (entry = encrypted_rels; entry != NULL; entry = entry->next)
	{
		if (entry->locator.spcOid == locator.spcOid &&
			entry->locator.dbOid == locator.dbOid &&
			entry->locator.relNumber == locator.relNumber)
			return entry->object_state;
	}

	snprintf(keypath, sizeof(keypath), "%s/%u_key", dirpath, locator.relNumber);
	f = open(keypath, O_RDONLY | PG_BINARY, 0);
	if (f < 0)
		pg_fatal("could not open KEY fork \"%s\": %m", keypath);
	r = read(f, keybuf.data, BLCKSZ);
	if (r != BLCKSZ)
	{
		if (r < 0)
			pg_fatal("could not read KEY fork \"%s\": %m", keypath);
		pg_fatal("short read on KEY fork \"%s\": read %d of %d", keypath, r, BLCKSZ);
	}
	close(f);

	memcpy(&hdr, keybuf.data + FE_KEY_BLOCK_HEADER_OFFSET, sizeof(hdr));
	if (hdr.magic != FE_KEY_BLOCK_MAGIC)
		pg_fatal("invalid KEY fork \"%s\": bad magic 0x%08x", keypath, hdr.magic);
	if (hdr.version != FE_KEY_BLOCK_VERSION)
		pg_fatal("unsupported KEY-fork version %u in \"%s\"", hdr.version, keypath);
	if (hdr.wrapped_len == 0 || hdr.wrapped_len > FE_KEY_BLOCK_MAX_WRAPPED)
		pg_fatal("invalid KEY fork \"%s\": wrapped_len %u out of range",
				 keypath, hdr.wrapped_len);

	obj_state = fe_callbacks->object_open_cb(&fe_module_state, &locator,
											 keybuf.data + FE_KEY_BLOCK_PAYLOAD_OFFSET,
											 hdr.wrapped_len, &module_errmsg);
	if (obj_state == NULL)
		pg_fatal("could not unwrap KEY for relation %u/%u/%u: %s",
				 locator.spcOid, locator.dbOid, locator.relNumber,
				 module_errmsg ? module_errmsg : "no detail");

	entry = pg_malloc(sizeof(*entry));
	entry->locator = locator;
	entry->object_state = obj_state;
	entry->next = encrypted_rels;
	encrypted_rels = entry;
	return obj_state;
}

/*
 * Decrypt a single block in place using the loaded module.  Caller has
 * already determined that the relation+fork is encrypted (i.e. fe_callbacks
 * is non-NULL and the fork is MAIN or INIT).  All-zero blocks are passed
 * through unchanged so PageIsNew() still recognises fresh-from-extend pages.
 */
static void
decrypt_block_in_place(PGIOAlignedBlock *buf, RelFileLocator locator,
					   ForkNumber forknum, BlockNumber blocknum,
					   const char *dirpath)
{
	void	   *obj_state;
	PGIOAlignedBlock plaintext;
	char	   *module_errmsg = NULL;

	/* Pass through fresh pages without trying to decrypt zeros. */
	{
		const uint64 *p = (const uint64 *) buf->data;
		bool		all_zero = true;

		for (Size i = 0; i < BLCKSZ / sizeof(uint64); i++)
			if (p[i] != 0)
			{
				all_zero = false;
				break;
			}
		if (all_zero)
			return;
	}

	obj_state = get_encryption_object_state(locator, dirpath);
	if (!fe_callbacks->decrypt_page_cb(&fe_module_state, obj_state,
									   forknum, blocknum,
									   buf->data, plaintext.data,
									   &module_errmsg))
		pg_fatal("could not decrypt fork %d block %u of relation %u/%u/%u: %s",
				 forknum, blocknum,
				 locator.spcOid, locator.dbOid, locator.relNumber,
				 module_errmsg ? module_errmsg : "no detail");

	memcpy(buf->data, plaintext.data, BLCKSZ);
}

/*
 * Re-encrypt a plaintext block in place after we've adjusted pd_checksum
 * in --enable mode.  Mirrors decrypt_block_in_place: same gating, same
 * cached object state, just the opposite direction.
 */
static void
encrypt_block_in_place(PGIOAlignedBlock *buf, RelFileLocator locator,
					   ForkNumber forknum, BlockNumber blocknum,
					   const char *dirpath)
{
	void	   *obj_state;
	PGIOAlignedBlock ciphertext;
	char	   *module_errmsg = NULL;

	obj_state = get_encryption_object_state(locator, dirpath);
	if (!fe_callbacks->encrypt_page_cb(&fe_module_state, obj_state,
									   forknum, blocknum,
									   buf->data, ciphertext.data,
									   &module_errmsg))
		pg_fatal("could not encrypt fork %d block %u of relation %u/%u/%u: %s",
				 forknum, blocknum,
				 locator.spcOid, locator.dbOid, locator.relNumber,
				 module_errmsg ? module_errmsg : "no detail");

	memcpy(buf->data, ciphertext.data, BLCKSZ);
}

static void
scan_file(const char *fn, int segmentno, RelFileLocator locator,
		  ForkNumber forknum, const char *dirpath)
{
	PGIOAlignedBlock buf;
	PageHeader	header = (PageHeader) buf.data;
	int			f;
	BlockNumber blockno;
	int			flags;
	int64		blocks_written_in_file = 0;
	bool		do_decrypt;

	Assert(mode == PG_MODE_ENABLE ||
		   mode == PG_MODE_CHECK);

	/*
	 * MAIN and INIT forks of relations in an encrypted cluster are routed
	 * through the module on every read/write; FSM, VM, and KEY forks are
	 * passed through plaintext per md_fork_is_encrypted() in the backend.
	 */
	do_decrypt = (fe_callbacks != NULL &&
				  (forknum == MAIN_FORKNUM || forknum == INIT_FORKNUM));

	flags = (mode == PG_MODE_ENABLE) ? O_RDWR : O_RDONLY;
	f = open(fn, PG_BINARY | flags, 0);

	if (f < 0)
		pg_fatal("could not open file \"%s\": %m", fn);

	files_scanned++;

	for (blockno = 0;; blockno++)
	{
		uint16		csum;
		BlockNumber abs_blocknum = blockno + (BlockNumber) segmentno * RELSEG_SIZE;
		int			r = read(f, buf.data, BLCKSZ);

		if (r == 0)
			break;
		if (r != BLCKSZ)
		{
			if (r < 0)
				pg_fatal("could not read block %u in file \"%s\": %m",
						 blockno, fn);
			else
				pg_fatal("could not read block %u in file \"%s\": read %d of %d",
						 blockno, fn, r, BLCKSZ);
		}
		blocks_scanned++;

		/*
		 * Since the file size is counted as total_size for progress status
		 * information, the sizes of all pages including new ones in the file
		 * should be counted as current_size. Otherwise the progress reporting
		 * calculated using those counters may not reach 100%.
		 */
		current_size += r;

		if (do_decrypt)
			decrypt_block_in_place(&buf, locator, forknum, abs_blocknum, dirpath);

		/* New pages have no checksum yet */
		if (PageIsNew(buf.data))
			continue;

		csum = pg_checksum_page(buf.data, abs_blocknum);
		if (mode == PG_MODE_CHECK)
		{
			if (csum != header->pd_checksum)
			{
				if (ControlFile->data_checksum_version == PG_DATA_CHECKSUM_VERSION)
					pg_log_error("checksum verification failed in file \"%s\", block %u: calculated checksum %X but block contains %X",
								 fn, blockno, csum, header->pd_checksum);
				badblocks++;
			}
		}
		else if (mode == PG_MODE_ENABLE)
		{
			int			w;

			/*
			 * Do not rewrite if the checksum is already set to the expected
			 * value.
			 */
			if (header->pd_checksum == csum)
				continue;

			blocks_written_in_file++;

			/* Set checksum in page header */
			header->pd_checksum = csum;

			/*
			 * Re-encrypt before writing back if this fork was encrypted on
			 * read.  Both directions use the same object state, so we
			 * never have to worry about wrap/unwrap mismatches.
			 */
			if (do_decrypt)
				encrypt_block_in_place(&buf, locator, forknum, abs_blocknum,
									   dirpath);

			/* Seek back to beginning of block */
			if (lseek(f, -BLCKSZ, SEEK_CUR) < 0)
				pg_fatal("seek failed for block %u in file \"%s\": %m", blockno, fn);

			/* Write block with checksum */
			w = write(f, buf.data, BLCKSZ);
			if (w != BLCKSZ)
			{
				if (w < 0)
					pg_fatal("could not write block %u in file \"%s\": %m",
							 blockno, fn);
				else
					pg_fatal("could not write block %u in file \"%s\": wrote %d of %d",
							 blockno, fn, w, BLCKSZ);
			}
		}

		if (showprogress)
			progress_report(false);
	}

	if (verbose)
	{
		if (mode == PG_MODE_CHECK)
			pg_log_info("checksums verified in file \"%s\"", fn);
		if (mode == PG_MODE_ENABLE)
			pg_log_info("checksums enabled in file \"%s\"", fn);
	}

	/* Update write counters if any write activity has happened */
	if (blocks_written_in_file > 0)
	{
		files_written++;
		blocks_written += blocks_written_in_file;
	}

	close(f);
}

/*
 * Scan the given directory for items which can be checksummed and
 * operate on each one of them.  If "sizeonly" is true, the size of
 * all the items which have checksums is computed and returned back
 * to the caller without operating on the files.  This is used to compile
 * the total size of the data directory for progress reports.
 *
 * spcOid / dbOid are the OIDs implied by the directory path (e.g. when
 * scanning base/16384/, dbOid=16384 and spcOid=DEFAULTTABLESPACE_OID).
 * spcOid=0 means the OID isn't known yet -- we're either at the top of
 * pg_tblspc and the next-level subdir name is the tablespace OID, or
 * we're at the version-dir level and the next-level subdir name is the
 * database OID.  These are passed to scan_file so it can construct the
 * RelFileLocator for encrypted relations.
 */
static int64
scan_directory(const char *basedir, const char *subdir, bool sizeonly,
			   Oid spcOid, Oid dbOid)
{
	int64		dirsize = 0;
	char		path[MAXPGPATH];
	DIR		   *dir;
	struct dirent *de;

	snprintf(path, sizeof(path), "%s/%s", basedir, subdir);
	dir = opendir(path);
	if (!dir)
		pg_fatal("could not open directory \"%s\": %m", path);
	while ((de = readdir(dir)) != NULL)
	{
		char		fn[MAXPGPATH];
		struct stat st;

		if (strcmp(de->d_name, ".") == 0 ||
			strcmp(de->d_name, "..") == 0)
			continue;

		/* Skip temporary files */
		if (strncmp(de->d_name,
					PG_TEMP_FILE_PREFIX,
					strlen(PG_TEMP_FILE_PREFIX)) == 0)
			continue;

		/* Skip temporary folders */
		if (strncmp(de->d_name,
					PG_TEMP_FILES_DIR,
					strlen(PG_TEMP_FILES_DIR)) == 0)
			continue;

		/* Skip macOS system files */
		if (strcmp(de->d_name, ".DS_Store") == 0)
			continue;

		snprintf(fn, sizeof(fn), "%s/%s", path, de->d_name);
		if (lstat(fn, &st) < 0)
			pg_fatal("could not stat file \"%s\": %m", fn);
		if (S_ISREG(st.st_mode))
		{
			char		fnonly[MAXPGPATH];
			char	   *forkpath,
					   *segmentpath;
			int			segmentno = 0;
			ForkNumber	forknum = MAIN_FORKNUM;
			RelFileLocator locator;

			if (skipfile(de->d_name))
				continue;

			/*
			 * Cut off at the segment boundary (".") to get the segment number
			 * in order to mix it into the checksum. Then also cut off at the
			 * fork boundary, to get the filenode the file belongs to for
			 * filtering.
			 */
			strlcpy(fnonly, de->d_name, sizeof(fnonly));
			segmentpath = strchr(fnonly, '.');
			if (segmentpath != NULL)
			{
				*segmentpath++ = '\0';
				segmentno = atoi(segmentpath);
				if (segmentno == 0)
					pg_fatal("invalid segment number %d in file name \"%s\"",
							 segmentno, fn);
			}

			forkpath = strchr(fnonly, '_');
			if (forkpath != NULL)
			{
				*forkpath++ = '\0';
				forknum = forkname_to_number(forkpath);
				if (forknum == InvalidForkNumber)
				{
					/*
					 * Something unparseable; treat as a non-relation file
					 * and don't try to decrypt it.  pg_checksums isn't in
					 * the business of strictly validating filenames.
					 */
					forknum = MAIN_FORKNUM;
				}
			}

			if (only_filenode && strcmp(only_filenode, fnonly) != 0)
				/* filenode not to be included */
				continue;

			/*
			 * In --enable mode the KEY fork's checksum was already set
			 * at relation-create time via pg_checksum_page (see
			 * FileEncryptionGenerateObjectKey); the backend's data-
			 * checksum worker skips the KEY fork on enable, and so do we.
			 * Checksum verification (--check) still runs for the KEY fork
			 * normally.
			 */
			if (forknum == KEY_FORKNUM && mode == PG_MODE_ENABLE)
				continue;

			dirsize += st.st_size;

			/*
			 * No need to work on the file when calculating only the size of
			 * the items in the data folder.
			 */
			if (!sizeonly)
			{
				locator.spcOid = spcOid;
				locator.dbOid = dbOid;
				locator.relNumber = (RelFileNumber) strtoul(fnonly, NULL, 10);
				scan_file(fn, segmentno, locator, forknum, path);
			}
		}
		else if (S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode))
		{
			Oid			sub_spc = spcOid;
			Oid			sub_db = dbOid;
			char	   *endp;

			/*
			 * Subdirectory names are OIDs at three levels: in base/<dboid>/
			 * the d_name is the dbOid; at the top of pg_tblspc the d_name
			 * is the tablespace OID; and inside a tablespace's
			 * TABLESPACE_VERSION_DIRECTORY the d_name is again the dbOid.
			 * dbOid==0 (unset) is the "next numeric subdir is the dbOid"
			 * signal; spcOid==0 is the same signal at the top of pg_tblspc.
			 */
			if (spcOid == 0)
				sub_spc = (Oid) strtoul(de->d_name, &endp, 10);
			else if (dbOid == 0 && spcOid != GLOBALTABLESPACE_OID)
				sub_db = (Oid) strtoul(de->d_name, &endp, 10);

			/*
			 * If going through the entries of pg_tblspc, we assume to operate
			 * on tablespace locations where only TABLESPACE_VERSION_DIRECTORY
			 * is valid, resolving the linked locations and dive into them
			 * directly.
			 */
			if (strncmp(PG_TBLSPC_DIR, subdir, strlen(PG_TBLSPC_DIR)) == 0)
			{
				char		tblspc_path[MAXPGPATH];
				struct stat tblspc_st;

				/*
				 * Resolve tablespace location path and check whether
				 * TABLESPACE_VERSION_DIRECTORY exists.  Not finding a valid
				 * location is unexpected, since there should be no orphaned
				 * links and no links pointing to something else than a
				 * directory.
				 */
				snprintf(tblspc_path, sizeof(tblspc_path), "%s/%s/%s",
						 path, de->d_name, TABLESPACE_VERSION_DIRECTORY);

				if (lstat(tblspc_path, &tblspc_st) < 0)
					pg_fatal("could not stat file \"%s\": %m",
							 tblspc_path);

				/*
				 * Move backwards once as the scan needs to happen for the
				 * contents of TABLESPACE_VERSION_DIRECTORY.
				 */
				snprintf(tblspc_path, sizeof(tblspc_path), "%s/%s",
						 path, de->d_name);

				/* Looks like a valid tablespace location */
				dirsize += scan_directory(tblspc_path,
										  TABLESPACE_VERSION_DIRECTORY,
										  sizeonly, sub_spc, sub_db);
			}
			else
			{
				dirsize += scan_directory(path, de->d_name, sizeonly,
										  sub_spc, sub_db);
			}
		}
	}
	closedir(dir);
	return dirsize;
}

int
main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{"check", no_argument, NULL, 'c'},
		{"pgdata", required_argument, NULL, 'D'},
		{"disable", no_argument, NULL, 'd'},
		{"enable", no_argument, NULL, 'e'},
		{"filenode", required_argument, NULL, 'f'},
		{"no-sync", no_argument, NULL, 'N'},
		{"progress", no_argument, NULL, 'P'},
		{"verbose", no_argument, NULL, 'v'},
		{"sync-method", required_argument, NULL, 1},
		{"file-encryption-config", required_argument, NULL, 2},
		{NULL, 0, NULL, 0}
	};

	char	   *DataDir = NULL;
	int			c;
	int			option_index;
	bool		crc_ok;
	uint32		major_version;
	char	   *version_str;

	pg_logging_init(argv[0]);
	set_pglocale_pgservice(argv[0], PG_TEXTDOMAIN("pg_checksums"));
	progname = get_progname(argv[0]);

	if (argc > 1)
	{
		if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-?") == 0)
		{
			usage();
			exit(0);
		}
		if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0)
		{
			puts("pg_checksums (PostgreSQL) " PG_VERSION);
			exit(0);
		}
	}

	while ((c = getopt_long(argc, argv, "cdD:ef:NPv", long_options, &option_index)) != -1)
	{
		switch (c)
		{
			case 'c':
				mode = PG_MODE_CHECK;
				break;
			case 'd':
				mode = PG_MODE_DISABLE;
				break;
			case 'D':
				DataDir = optarg;
				break;
			case 'e':
				mode = PG_MODE_ENABLE;
				break;
			case 'f':
				if (!option_parse_int(optarg, "-f/--filenode", 0,
									  INT_MAX,
									  NULL))
					exit(1);
				only_filenode = pstrdup(optarg);
				break;
			case 'N':
				do_sync = false;
				break;
			case 'P':
				showprogress = true;
				break;
			case 'v':
				verbose = true;
				break;
			case 1:
				if (!parse_sync_method(optarg, &sync_method))
					exit(1);
				break;
			case 2:
				file_encryption_config = pg_strdup(optarg);
				break;
			default:
				/* getopt_long already emitted a complaint */
				pg_log_error_hint("Try \"%s --help\" for more information.", progname);
				exit(1);
		}
	}

	if (DataDir == NULL)
	{
		if (optind < argc)
			DataDir = argv[optind++];
		else
			DataDir = getenv("PGDATA");

		/* If no DataDir was specified, and none could be found, error out */
		if (DataDir == NULL)
		{
			pg_log_error("no data directory specified");
			pg_log_error_hint("Try \"%s --help\" for more information.", progname);
			exit(1);
		}
	}

	/* Complain if any arguments remain */
	if (optind < argc)
	{
		pg_log_error("too many command-line arguments (first is \"%s\")",
					 argv[optind]);
		pg_log_error_hint("Try \"%s --help\" for more information.", progname);
		exit(1);
	}

	/* filenode checking only works in --check mode */
	if (mode != PG_MODE_CHECK && only_filenode)
	{
		pg_log_error("option -f/--filenode can only be used with --check");
		pg_log_error_hint("Try \"%s --help\" for more information.", progname);
		exit(1);
	}

	/*
	 * Retrieve the contents of this cluster's PG_VERSION.  We require
	 * compatibility with the same major version as the one this tool is
	 * compiled with.
	 */
	major_version = GET_PG_MAJORVERSION_NUM(get_pg_version(DataDir, &version_str));
	if (major_version != PG_MAJORVERSION_NUM)
	{
		pg_log_error("data directory is of wrong version");
		pg_log_error_detail("File \"%s\" contains \"%s\", which is not compatible with this program's version \"%s\".",
							"PG_VERSION", version_str, PG_MAJORVERSION);
		exit(1);
	}

	/* Read the control file and check compatibility */
	ControlFile = get_controlfile(DataDir, &crc_ok);
	if (!crc_ok)
		pg_fatal("pg_control CRC value is incorrect");

	if (ControlFile->pg_control_version != PG_CONTROL_VERSION)
		pg_fatal("cluster is not compatible with this version of pg_checksums");

	if (ControlFile->blcksz != BLCKSZ)
	{
		pg_log_error("database cluster is not compatible");
		pg_log_error_detail("The database cluster was initialized with block size %u, but pg_checksums was compiled with block size %u.",
							ControlFile->blcksz, BLCKSZ);
		exit(1);
	}

	/*
	 * Check if cluster is running.  A clean shutdown is required to avoid
	 * random checksum failures caused by torn pages.  Note that this doesn't
	 * guard against someone starting the cluster concurrently.
	 */
	if (ControlFile->state != DB_SHUTDOWNED &&
		ControlFile->state != DB_SHUTDOWNED_IN_RECOVERY)
		pg_fatal("cluster must be shut down");

	if (ControlFile->data_checksum_version != PG_DATA_CHECKSUM_VERSION &&
		mode == PG_MODE_CHECK)
		pg_fatal("data checksums are not enabled in cluster");

	if (ControlFile->data_checksum_version == PG_DATA_CHECKSUM_OFF &&
		mode == PG_MODE_DISABLE)
		pg_fatal("data checksums are already disabled in cluster");

	if (ControlFile->data_checksum_version == PG_DATA_CHECKSUM_VERSION &&
		mode == PG_MODE_ENABLE)
		pg_fatal("data checksums are already enabled in cluster");

	/*
	 * Load the file-encryption module, if the cluster was initialized with
	 * one.  Module errors abort via pg_fatal; on success fe_callbacks is
	 * non-NULL and scan_file routes MAIN/INIT blocks through it.
	 */
	if (ControlFile->file_encryption_library[0] != '\0')
	{
		char	   *load_errmsg = NULL;

		if (file_encryption_config == NULL)
		{
			const char *env = getenv("PGFILEENCRYPTIONCONFIG");

			if (env != NULL)
				file_encryption_config = pg_strdup(env);
		}
		if (file_encryption_config == NULL || file_encryption_config[0] == '\0')
		{
			pg_log_error("cluster was initialized with file encryption but no configuration was supplied");
			pg_log_error_hint("Use --file-encryption-config=STRING or set the PGFILEENCRYPTIONCONFIG environment variable.");
			exit(1);
		}

		if (!load_file_encryption_module(argv[0],
										 ControlFile->file_encryption_library,
										 file_encryption_config,
										 &fe_module_handle,
										 &fe_callbacks,
										 &load_errmsg))
			pg_fatal("%s", load_errmsg ? load_errmsg : "could not load file encryption module");

		fe_module_state.sversion = PG_VERSION_NUM;
		if (fe_callbacks->startup_cb != NULL)
			fe_callbacks->startup_cb(&fe_module_state);
		if (fe_callbacks->page_overhead_size != ControlFile->page_reserved_size)
			pg_fatal("module's page_overhead_size %zu does not match cluster's page_reserved_size %u",
					 fe_callbacks->page_overhead_size,
					 ControlFile->page_reserved_size);
	}

	/* Operate on all files if checking or enabling checksums */
	if (mode == PG_MODE_CHECK || mode == PG_MODE_ENABLE)
	{
		/*
		 * If progress status information is requested, we need to scan the
		 * directory tree twice: once to know how much total data needs to be
		 * processed and once to do the real work.
		 */
		if (showprogress)
		{
			total_size = scan_directory(DataDir, "global", true,
										GLOBALTABLESPACE_OID, 0);
			total_size += scan_directory(DataDir, "base", true,
										 DEFAULTTABLESPACE_OID, 0);
			total_size += scan_directory(DataDir, PG_TBLSPC_DIR, true, 0, 0);
		}

		(void) scan_directory(DataDir, "global", false,
							  GLOBALTABLESPACE_OID, 0);
		(void) scan_directory(DataDir, "base", false,
							  DEFAULTTABLESPACE_OID, 0);
		(void) scan_directory(DataDir, PG_TBLSPC_DIR, false, 0, 0);

		if (showprogress)
			progress_report(true);

		printf(_("Checksum operation completed\n"));
		printf(_("Files scanned:   %" PRId64 "\n"), files_scanned);
		printf(_("Blocks scanned:  %" PRId64 "\n"), blocks_scanned);
		if (mode == PG_MODE_CHECK)
		{
			printf(_("Bad checksums:  %" PRId64 "\n"), badblocks);
			printf(_("Data checksum version: %u\n"), ControlFile->data_checksum_version);

			if (badblocks > 0)
				exit(1);
		}
		else if (mode == PG_MODE_ENABLE)
		{
			printf(_("Files written:  %" PRId64 "\n"), files_written);
			printf(_("Blocks written: %" PRId64 "\n"), blocks_written);
		}
	}

	/*
	 * Finally make the data durable on disk if enabling or disabling
	 * checksums.  Flush first the data directory for safety, and then update
	 * the control file to keep the switch consistent.
	 */
	if (mode == PG_MODE_ENABLE || mode == PG_MODE_DISABLE)
	{
		ControlFile->data_checksum_version =
			(mode == PG_MODE_ENABLE) ? PG_DATA_CHECKSUM_VERSION : PG_DATA_CHECKSUM_OFF;

		if (do_sync)
		{
			pg_log_info("syncing data directory");
			sync_pgdata(DataDir, PG_VERSION_NUM, sync_method, true);
		}

		pg_log_info("updating control file");
		update_controlfile(DataDir, ControlFile, do_sync);

		if (verbose)
			printf(_("Data checksum version: %u\n"), ControlFile->data_checksum_version);
		if (mode == PG_MODE_ENABLE)
			printf(_("Checksums enabled in cluster\n"));
		else
			printf(_("Checksums disabled in cluster\n"));
	}

	/*
	 * Release per-relation encryption state and the module's per-process
	 * state in module-friendly order.
	 */
	if (fe_callbacks != NULL)
	{
		EncryptedRelEntry *entry,
				   *next;

		for (entry = encrypted_rels; entry != NULL; entry = next)
		{
			next = entry->next;
			if (fe_callbacks->object_close_cb != NULL)
				fe_callbacks->object_close_cb(&fe_module_state,
											  entry->object_state);
			pg_free(entry);
		}
		encrypted_rels = NULL;

		if (fe_callbacks->shutdown_cb != NULL)
			fe_callbacks->shutdown_cb(&fe_module_state);
	}

	return 0;
}
