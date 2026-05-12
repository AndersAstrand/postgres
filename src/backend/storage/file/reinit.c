/*-------------------------------------------------------------------------
 *
 * reinit.c
 *	  Reinitialization of unlogged relations
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/storage/file/reinit.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "catalog/pg_tablespace_d.h"
#include "common/relpath.h"
#include "postmaster/startup.h"
#include "storage/copydir.h"
#include "storage/fd.h"
#include "storage/file_encryption.h"
#include "storage/reinit.h"
#include "storage/relfilelocator.h"
#include "storage/smgr.h"
#include "utils/hsearch.h"
#include "utils/memutils.h"

static void ResetUnloggedRelationsInTablespaceDir(Oid spcOid,
												  const char *tsdirname,
												  int op);
static void ResetUnloggedRelationsInDbspaceDir(Oid spcOid, Oid dbOid,
											   const char *dbspacedirname,
											   int op);
static void reencrypt_init_segment(RelFileLocator rlocator, unsigned segno,
								   const char *srcpath, const char *dstpath);

typedef struct
{
	RelFileNumber relnumber;	/* hash key */
} unlogged_relation_entry;

/*
 * Reset unlogged relations from before the last restart.
 *
 * If op includes UNLOGGED_RELATION_CLEANUP, we remove all forks of any
 * relation with an "init" fork, except for the "init" fork itself.
 *
 * If op includes UNLOGGED_RELATION_INIT, we copy the "init" fork to the main
 * fork.
 */
void
ResetUnloggedRelations(int op)
{
	char		temp_path[MAXPGPATH + sizeof(PG_TBLSPC_DIR) + sizeof(TABLESPACE_VERSION_DIRECTORY)];
	DIR		   *spc_dir;
	struct dirent *spc_de;
	MemoryContext tmpctx,
				oldctx;

	/* Log it. */
	elog(DEBUG1, "resetting unlogged relations: cleanup %d init %d",
		 (op & UNLOGGED_RELATION_CLEANUP) != 0,
		 (op & UNLOGGED_RELATION_INIT) != 0);

	/*
	 * Just to be sure we don't leak any memory, let's create a temporary
	 * memory context for this operation.
	 */
	tmpctx = AllocSetContextCreate(CurrentMemoryContext,
								   "ResetUnloggedRelations",
								   ALLOCSET_DEFAULT_SIZES);
	oldctx = MemoryContextSwitchTo(tmpctx);

	/* Prepare to report progress resetting unlogged relations. */
	begin_startup_progress_phase();

	/*
	 * First process unlogged files in pg_default ($PGDATA/base)
	 */
	ResetUnloggedRelationsInTablespaceDir(DEFAULTTABLESPACE_OID, "base", op);

	/*
	 * Cycle through directories for all non-default tablespaces.
	 */
	spc_dir = AllocateDir(PG_TBLSPC_DIR);

	while ((spc_de = ReadDir(spc_dir, PG_TBLSPC_DIR)) != NULL)
	{
		Oid			spcOid;
		char	   *endp;

		if (strcmp(spc_de->d_name, ".") == 0 ||
			strcmp(spc_de->d_name, "..") == 0)
			continue;

		/*
		 * Each entry under pg_tblspc is a symlink whose name is the
		 * tablespace OID.  Skip anything that doesn't parse as one.
		 */
		spcOid = strtoul(spc_de->d_name, &endp, 10);
		if (*endp != '\0')
			continue;

		snprintf(temp_path, sizeof(temp_path), "%s/%s/%s",
				 PG_TBLSPC_DIR, spc_de->d_name, TABLESPACE_VERSION_DIRECTORY);
		ResetUnloggedRelationsInTablespaceDir(spcOid, temp_path, op);
	}

	FreeDir(spc_dir);

	/*
	 * Restore memory context.
	 */
	MemoryContextSwitchTo(oldctx);
	MemoryContextDelete(tmpctx);
}

/*
 * Process one tablespace directory for ResetUnloggedRelations
 */
static void
ResetUnloggedRelationsInTablespaceDir(Oid spcOid, const char *tsdirname,
									  int op)
{
	DIR		   *ts_dir;
	struct dirent *de;
	char		dbspace_path[MAXPGPATH * 2];

	ts_dir = AllocateDir(tsdirname);

	/*
	 * If we get ENOENT on a tablespace directory, log it and return.  This
	 * can happen if a previous DROP TABLESPACE crashed between removing the
	 * tablespace directory and removing the symlink in pg_tblspc.  We don't
	 * really want to prevent database startup in that scenario, so let it
	 * pass instead.  Any other type of error will be reported by ReadDir
	 * (causing a startup failure).
	 */
	if (ts_dir == NULL && errno == ENOENT)
	{
		ereport(LOG,
				(errcode_for_file_access(),
				 errmsg("could not open directory \"%s\": %m",
						tsdirname)));
		return;
	}

	while ((de = ReadDir(ts_dir, tsdirname)) != NULL)
	{
		Oid			dbOid;
		char	   *endp;

		/*
		 * We're only interested in the per-database directories, which have
		 * numeric names.  Note that this code will also (properly) ignore "."
		 * and "..".
		 */
		if (strspn(de->d_name, "0123456789") != strlen(de->d_name))
			continue;
		dbOid = strtoul(de->d_name, &endp, 10);
		Assert(*endp == '\0');

		snprintf(dbspace_path, sizeof(dbspace_path), "%s/%s",
				 tsdirname, de->d_name);

		if (op & UNLOGGED_RELATION_INIT)
			ereport_startup_progress("resetting unlogged relations (init), elapsed time: %ld.%02d s, current path: %s",
									 dbspace_path);
		else if (op & UNLOGGED_RELATION_CLEANUP)
			ereport_startup_progress("resetting unlogged relations (cleanup), elapsed time: %ld.%02d s, current path: %s",
									 dbspace_path);

		ResetUnloggedRelationsInDbspaceDir(spcOid, dbOid, dbspace_path, op);
	}

	FreeDir(ts_dir);
}

/*
 * Process one per-dbspace directory for ResetUnloggedRelations
 */
static void
ResetUnloggedRelationsInDbspaceDir(Oid spcOid, Oid dbOid,
								   const char *dbspacedirname, int op)
{
	DIR		   *dbspace_dir;
	struct dirent *de;
	char		rm_path[MAXPGPATH * 2];

	/* Caller must specify at least one operation. */
	Assert((op & (UNLOGGED_RELATION_CLEANUP | UNLOGGED_RELATION_INIT)) != 0);

	/*
	 * Cleanup is a two-pass operation.  First, we go through and identify all
	 * the files with init forks.  Then, we go through again and nuke
	 * everything with the same OID except the init fork.
	 */
	if ((op & UNLOGGED_RELATION_CLEANUP) != 0)
	{
		HTAB	   *hash;
		HASHCTL		ctl;

		/*
		 * It's possible that someone could create a ton of unlogged relations
		 * in the same database & tablespace, so we'd better use a hash table
		 * rather than an array or linked list to keep track of which files
		 * need to be reset.  Otherwise, this cleanup operation would be
		 * O(n^2).
		 */
		ctl.keysize = sizeof(Oid);
		ctl.entrysize = sizeof(unlogged_relation_entry);
		ctl.hcxt = CurrentMemoryContext;
		hash = hash_create("unlogged relation OIDs", 32, &ctl,
						   HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);

		/* Scan the directory. */
		dbspace_dir = AllocateDir(dbspacedirname);
		while ((de = ReadDir(dbspace_dir, dbspacedirname)) != NULL)
		{
			ForkNumber	forkNum;
			unsigned	segno;
			unlogged_relation_entry ent;

			/* Skip anything that doesn't look like a relation data file. */
			if (!parse_filename_for_nontemp_relation(de->d_name,
													 &ent.relnumber,
													 &forkNum, &segno))
				continue;

			/* Also skip it unless this is the init fork. */
			if (forkNum != INIT_FORKNUM)
				continue;

			/*
			 * Put the RelFileNumber into the hash table, if it isn't already.
			 */
			(void) hash_search(hash, &ent, HASH_ENTER, NULL);
		}

		/* Done with the first pass. */
		FreeDir(dbspace_dir);

		/*
		 * If we didn't find any init forks, there's no point in continuing;
		 * we can bail out now.
		 */
		if (hash_get_num_entries(hash) == 0)
		{
			hash_destroy(hash);
			return;
		}

		/*
		 * Now, make a second pass and remove anything that matches.
		 */
		dbspace_dir = AllocateDir(dbspacedirname);
		while ((de = ReadDir(dbspace_dir, dbspacedirname)) != NULL)
		{
			ForkNumber	forkNum;
			unsigned	segno;
			unlogged_relation_entry ent;

			/* Skip anything that doesn't look like a relation data file. */
			if (!parse_filename_for_nontemp_relation(de->d_name,
													 &ent.relnumber,
													 &forkNum, &segno))
				continue;

			/*
			 * We never remove the init fork.  We also keep the key fork:
			 * its wrapped DEK belongs to the relation as a unit (the data
			 * we're about to wipe was encrypted under it; new data after
			 * reset re-encrypts under the same DEK).  Re-creating it would
			 * require module-side wrap, which we don't do during reinit.
			 */
			if (forkNum == INIT_FORKNUM || forkNum == KEY_FORKNUM)
				continue;

			/*
			 * See whether the OID portion of the name shows up in the hash
			 * table.  If so, nuke it!
			 */
			if (hash_search(hash, &ent, HASH_FIND, NULL))
			{
				snprintf(rm_path, sizeof(rm_path), "%s/%s",
						 dbspacedirname, de->d_name);
				if (unlink(rm_path) < 0)
					ereport(ERROR,
							(errcode_for_file_access(),
							 errmsg("could not remove file \"%s\": %m",
									rm_path)));
				else
					elog(DEBUG2, "unlinked file \"%s\"", rm_path);
			}
		}

		/* Cleanup is complete. */
		FreeDir(dbspace_dir);
		hash_destroy(hash);
	}

	/*
	 * Initialization happens after cleanup is complete: we copy each init
	 * fork file to the corresponding main fork file.  Note that if we are
	 * asked to do both cleanup and init, we may never get here: if the
	 * cleanup code determines that there are no init forks in this dbspace,
	 * it will return before we get to this point.
	 */
	if ((op & UNLOGGED_RELATION_INIT) != 0)
	{
		/* Scan the directory. */
		dbspace_dir = AllocateDir(dbspacedirname);
		while ((de = ReadDir(dbspace_dir, dbspacedirname)) != NULL)
		{
			ForkNumber	forkNum;
			RelFileNumber relNumber;
			unsigned	segno;
			char		srcpath[MAXPGPATH * 2];
			char		dstpath[MAXPGPATH];

			/* Skip anything that doesn't look like a relation data file. */
			if (!parse_filename_for_nontemp_relation(de->d_name, &relNumber,
													 &forkNum, &segno))
				continue;

			/* Also skip it unless this is the init fork. */
			if (forkNum != INIT_FORKNUM)
				continue;

			/* Construct source pathname. */
			snprintf(srcpath, sizeof(srcpath), "%s/%s",
					 dbspacedirname, de->d_name);

			/* Construct destination pathname. */
			if (segno == 0)
				snprintf(dstpath, sizeof(dstpath), "%s/%u",
						 dbspacedirname, relNumber);
			else
				snprintf(dstpath, sizeof(dstpath), "%s/%u.%u",
						 dbspacedirname, relNumber, segno);

			/*
			 * If page encryption is configured, the INIT-fork ciphertext
			 * was produced under a (fork=INIT_FORKNUM, blocknum) binding
			 * context and a raw byte copy into the MAIN fork would not
			 * decrypt later (the read path supplies fork=MAIN_FORKNUM as
			 * binding context).  Decrypt INIT-side and re-encrypt
			 * MAIN-side instead so the context matches at read time.
			 */
			if (FileEncryptionEnabled())
			{
				RelFileLocator rlocator = {.spcOid = spcOid,
				.dbOid = dbOid,.relNumber = relNumber};

				elog(DEBUG2, "re-encrypting %s into %s", srcpath, dstpath);
				reencrypt_init_segment(rlocator, segno, srcpath, dstpath);
			}
			else
			{
				/* OK, we're ready to perform the actual copy. */
				elog(DEBUG2, "copying %s to %s", srcpath, dstpath);
				copy_file(srcpath, dstpath);
			}
		}

		FreeDir(dbspace_dir);

		/*
		 * copy_file() above has already called pg_flush_data() on the files
		 * it created. Now we need to fsync those files, because a checkpoint
		 * won't do it for us while we're in recovery. We do this in a
		 * separate pass to allow the kernel to perform all the flushes
		 * (especially the metadata ones) at once.
		 */
		dbspace_dir = AllocateDir(dbspacedirname);
		while ((de = ReadDir(dbspace_dir, dbspacedirname)) != NULL)
		{
			RelFileNumber relNumber;
			ForkNumber	forkNum;
			unsigned	segno;
			char		mainpath[MAXPGPATH];

			/* Skip anything that doesn't look like a relation data file. */
			if (!parse_filename_for_nontemp_relation(de->d_name, &relNumber,
													 &forkNum, &segno))
				continue;

			/* Also skip it unless this is the init fork. */
			if (forkNum != INIT_FORKNUM)
				continue;

			/* Construct main fork pathname. */
			if (segno == 0)
				snprintf(mainpath, sizeof(mainpath), "%s/%u",
						 dbspacedirname, relNumber);
			else
				snprintf(mainpath, sizeof(mainpath), "%s/%u.%u",
						 dbspacedirname, relNumber, segno);

			fsync_fname(mainpath, false);
		}

		FreeDir(dbspace_dir);

		/*
		 * Lastly, fsync the database directory itself, ensuring the
		 * filesystem remembers the file creations and deletions we've done.
		 * We don't bother with this during a call that does only
		 * UNLOGGED_RELATION_CLEANUP, because if recovery crashes before we
		 * get to doing UNLOGGED_RELATION_INIT, we'll redo the cleanup step
		 * too at the next startup attempt.
		 */
		fsync_fname(dbspacedirname, true);
	}
}

/*
 * INIT-fork-to-MAIN-fork copy for an encrypted unlogged relation.
 *
 * Each INIT-fork page was encrypted with a binding context that included
 * fork=INIT_FORKNUM; a raw byte copy into MAIN would not decrypt afterwards
 * because the encryption layer supplies fork=MAIN_FORKNUM on read.  Decrypt
 * each block of the INIT segment file and re-encrypt under the MAIN context
 * using the relation's existing DEK (read from the KEY fork), producing a
 * MAIN segment file that the running cluster can read normally.
 *
 * The plaintext never leaves this process's memory.  The DEK is unchanged.
 */
static void
reencrypt_init_segment(RelFileLocator rlocator, unsigned segno,
					   const char *srcpath, const char *dstpath)
{
	SMgrRelation reln;
	int			src_fd;
	int			dst_fd;
	struct stat st;
	BlockNumber nblocks;
	BlockNumber block_in_seg;
	PGIOAlignedBlock encrypted;
	PGIOAlignedBlock plaintext;
	PGIOAlignedBlock reencrypted;

	/*
	 * smgropen + FileEncryptionOpenObject load the relation's DEK by
	 * reading the KEY fork.  Both palloc; we're outside any critical
	 * section here.
	 */
	reln = smgropen(rlocator, INVALID_PROC_NUMBER);
	FileEncryptionOpenObject(reln);

	src_fd = OpenTransientFile(srcpath, O_RDONLY | PG_BINARY);
	if (src_fd < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not open file \"%s\": %m", srcpath)));

	if (fstat(src_fd, &st) < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not stat file \"%s\": %m", srcpath)));
	if (st.st_size % BLCKSZ != 0)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("INIT fork file \"%s\" has size %lld, not a multiple of BLCKSZ",
						srcpath, (long long) st.st_size)));
	nblocks = st.st_size / BLCKSZ;

	dst_fd = OpenTransientFile(dstpath,
							   O_WRONLY | O_CREAT | O_TRUNC | PG_BINARY);
	if (dst_fd < 0)
	{
		CloseTransientFile(src_fd);
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not create file \"%s\": %m", dstpath)));
	}

	for (block_in_seg = 0; block_in_seg < nblocks; block_in_seg++)
	{
		BlockNumber blocknum = segno * RELSEG_SIZE + block_in_seg;
		off_t		off = (off_t) block_in_seg * BLCKSZ;

		if (pg_pread(src_fd, encrypted.data, BLCKSZ, off) != BLCKSZ)
			ereport(ERROR,
					(errcode_for_file_access(),
					 errmsg("could not read block %u in file \"%s\": %m",
							block_in_seg, srcpath)));

		FileEncryptionDecryptPage(reln, INIT_FORKNUM, blocknum,
								  encrypted.data, plaintext.data);
		FileEncryptionEncryptPage(reln, MAIN_FORKNUM, blocknum,
								  plaintext.data, reencrypted.data);

		if (pg_pwrite(dst_fd, reencrypted.data, BLCKSZ, off) != BLCKSZ)
			ereport(ERROR,
					(errcode_for_file_access(),
					 errmsg("could not write block %u in file \"%s\": %m",
							block_in_seg, dstpath)));
	}

	if (pg_fsync(dst_fd) != 0)
	{
		CloseTransientFile(src_fd);
		CloseTransientFile(dst_fd);
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not fsync file \"%s\": %m", dstpath)));
	}

	CloseTransientFile(src_fd);
	if (CloseTransientFile(dst_fd) != 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not close file \"%s\": %m", dstpath)));
}

/*
 * Basic parsing of putative relation filenames.
 *
 * This function returns true if the file appears to be in the correct format
 * for a non-temporary relation and false otherwise.
 *
 * If it returns true, it sets *relnumber, *fork, and *segno to the values
 * extracted from the filename. If it returns false, these values are set to
 * InvalidRelFileNumber, InvalidForkNumber, and 0, respectively.
 */
bool
parse_filename_for_nontemp_relation(const char *name, RelFileNumber *relnumber,
									ForkNumber *fork, unsigned *segno)
{
	unsigned long n,
				s;
	ForkNumber	f;
	char	   *endp;

	*relnumber = InvalidRelFileNumber;
	*fork = InvalidForkNumber;
	*segno = 0;

	/*
	 * Relation filenames should begin with a digit that is not a zero. By
	 * rejecting cases involving leading zeroes, the caller can assume that
	 * there's only one possible string of characters that could have produced
	 * any given value for *relnumber.
	 *
	 * (To be clear, we don't expect files with names like 0017.3 to exist at
	 * all -- but if 0017.3 does exist, it's a non-relation file, not part of
	 * the main fork for relfilenode 17.)
	 */
	if (name[0] < '1' || name[0] > '9')
		return false;

	/*
	 * Parse the leading digit string. If the value is out of range, we
	 * conclude that this isn't a relation file at all.
	 */
	errno = 0;
	n = strtoul(name, &endp, 10);
	if (errno || name == endp || n <= 0 || n > PG_UINT32_MAX)
		return false;
	name = endp;

	/* Check for a fork name. */
	if (*name != '_')
		f = MAIN_FORKNUM;
	else
	{
		int			forkchar;

		forkchar = forkname_chars(name + 1, &f);
		if (forkchar <= 0)
			return false;
		name += forkchar + 1;
	}

	/* Check for a segment number. */
	if (*name != '.')
		s = 0;
	else
	{
		/* Reject leading zeroes, just like we do for RelFileNumber. */
		if (name[1] < '1' || name[1] > '9')
			return false;

		errno = 0;
		s = strtoul(name + 1, &endp, 10);
		if (errno || name + 1 == endp || s <= 0 || s > PG_UINT32_MAX)
			return false;
		name = endp;
	}

	/* Now we should be at the end. */
	if (*name != '\0')
		return false;

	/* Set out parameters and return. */
	*relnumber = (RelFileNumber) n;
	*fork = f;
	*segno = (unsigned) s;
	return true;
}
