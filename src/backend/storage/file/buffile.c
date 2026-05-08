/*-------------------------------------------------------------------------
 *
 * buffile.c
 *	  Management of large buffered temporary files.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/storage/file/buffile.c
 *
 * NOTES:
 *
 * BufFiles provide a very incomplete emulation of stdio atop virtual Files
 * (as managed by fd.c).  Currently, we only support the buffered-I/O
 * aspect of stdio: a read or write of the low-level File occurs only
 * when the buffer is filled or emptied.  This is an even bigger win
 * for virtual Files than for ordinary kernel files, since reducing the
 * frequency with which a virtual File is touched reduces "thrashing"
 * of opening/closing file descriptors.
 *
 * Note that BufFile structs are allocated with palloc(), and therefore
 * will go away automatically at query/transaction end.  Since the underlying
 * virtual Files are made with OpenTemporaryFile, all resources for
 * the file are certain to be cleaned up even if processing is aborted
 * by ereport(ERROR).  The data structures required are made in the
 * palloc context that was current when the BufFile was created, and
 * any external resources such as temp files are owned by the ResourceOwner
 * that was current at that time.
 *
 * BufFile also supports temporary files that exceed the OS file size limit
 * (by opening multiple fd.c temporary files).  This is an essential feature
 * for sorts and hashjoins on large amounts of data.
 *
 * BufFile supports temporary files that can be shared with other backends, as
 * infrastructure for parallel execution.  Such files need to be created as a
 * member of a SharedFileSet that all participants are attached to.
 *
 * BufFile also supports temporary files that can be used by the single backend
 * when the corresponding files need to be survived across the transaction and
 * need to be opened and closed multiple times.  Such files need to be created
 * as a member of a FileSet.
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "commands/tablespace.h"
#include "executor/instrument.h"
#include "lib/stringinfo.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "storage/buffile.h"
#include "storage/bufmgr.h"
#include "storage/fd.h"
#include "storage/file_encryption.h"
#include "utils/memutils.h"
#include "utils/resowner.h"
#include "utils/wait_event.h"

/*
 * We break BufFiles into gigabyte-sized segments, regardless of RELSEG_SIZE.
 * The reason is that we'd like large BufFiles to be spread across multiple
 * tablespaces when available.
 */
#define MAX_PHYSICAL_FILESIZE	0x40000000
#define BUFFILE_SEG_SIZE		(MAX_PHYSICAL_FILESIZE / BLCKSZ)

/*
 * When file encryption is enabled, each BLCKSZ plaintext block becomes one
 * fixed-size physical block on disk:
 *
 *	  [ uint32 plaintext_len ] [ uint32 ciphertext_len ] [ ciphertext... ]
 *
 * with the rest of the physical block left as unspecified slack.  Fixing
 * the physical block size lets us seek to logical block N at a known
 * physical offset without an offset map.
 *
 * BUFFILE_ENC_OVERHEAD bounds the room available for the 8-byte header plus
 * any per-record overhead the encryption module wants to add (e.g. an IV
 * and/or auth tag).  Modules that need more than (OVERHEAD - HEADER) bytes
 * of overhead per BLCKSZ plaintext cannot be used for BufFile.
 */
#define BUFFILE_ENC_OVERHEAD			64
#define BUFFILE_ENC_HEADER_SIZE			8
#define BUFFILE_PHYSICAL_BLOCK_SIZE		(BLCKSZ + BUFFILE_ENC_OVERHEAD)
#define BUFFILE_MAX_CIPHERTEXT			(BUFFILE_PHYSICAL_BLOCK_SIZE - BUFFILE_ENC_HEADER_SIZE)
#define BUFFILE_ENC_PLAINTEXT_PER_FILE	\
	(((MAX_PHYSICAL_FILESIZE) / BUFFILE_PHYSICAL_BLOCK_SIZE) * BLCKSZ)

/*
 * This data structure represents a buffered file that consists of one or
 * more physical files (each accessed through a virtual file descriptor
 * managed by fd.c).
 */
struct BufFile
{
	int			numFiles;		/* number of physical files in set */
	/* all files except the last have length exactly MAX_PHYSICAL_FILESIZE */
	File	   *files;			/* palloc'd array with numFiles entries */
	/*
	 * Per-physical-file encryption state (parallel to "files"); NULL when
	 * encryption is disabled, otherwise one entry per physical file.
	 */
	FileEncryptionFileState **fstates;
	/* Bytes the encryption module reserves at the start of each file. */
	Size		enc_header_size;

	bool		isInterXact;	/* keep open over transactions? */
	bool		dirty;			/* does buffer need to be written? */
	bool		readOnly;		/* has the file been set to read only? */
	bool		encrypted;		/* snapshot of FileEncryptionEnabled() at create */

	/*
	 * Encrypted-mode bookkeeping.  buffer_from_disk is true when the current
	 * buffer reflects what's on disk for its block; it goes false after
	 * BufFileSeek invalidates the buffer.  highest_dumped_offset is the
	 * plaintext-space high-water mark across all physical files, used to
	 * distinguish fresh appends from writes that must first load and preserve
	 * existing block contents.
	 */
	bool		buffer_from_disk;
	int64		highest_dumped_offset;

	FileSet    *fileset;		/* space for fileset based segment files */
	const char *name;			/* name of fileset based BufFile */

	/*
	 * Reusable encryption-side buffers; lazily initialized on first
	 * encrypted I/O so non-encrypted BufFiles pay no allocator cost.
	 */
	StringInfoData enc_ciphertext;
	StringInfoData enc_plaintext;

	/*
	 * resowner is the ResourceOwner to use for underlying temp files.  (We
	 * don't need to remember the memory context we're using explicitly,
	 * because after creation we only repalloc our arrays larger.)
	 */
	ResourceOwner resowner;

	/*
	 * "current pos" is position of start of buffer within the logical file.
	 * Position as seen by user of BufFile is (curFile, curOffset + pos).
	 */
	int			curFile;		/* file index (0..n) part of current pos */
	pgoff_t		curOffset;		/* offset part of current pos */
	int64		pos;			/* next read/write position in buffer */
	int64		nbytes;			/* total # of valid bytes in buffer */

	/*
	 * XXX Should ideally use PGIOAlignedBlock, but might need a way to avoid
	 * wasting per-file alignment padding when some users create many files.
	 */
	PGAlignedBlock buffer;
};

static BufFile *makeBufFileCommon(int nfiles);
static BufFile *makeBufFile(File firstfile);
static void extendBufFile(BufFile *file);
static void BufFileLoadBuffer(BufFile *file);
static void BufFileDumpBuffer(BufFile *file);
static void BufFileFlush(BufFile *file);
static File MakeNewFileSetSegment(BufFile *buffile, int segment);
static int	BufFileReadEncryptedBlock(BufFile *file, int fileno,
									  pgoff_t block_start, bool missing_ok);
static pgoff_t BufFileWriteEncryptedBlock(BufFile *file, int fileno,
										  pgoff_t block_start,
										  const char *data,
										  uint32 plaintext_len);
static bool BufFileLoadEncryptedBlock(BufFile *file, bool for_write);
static void BufFilePrepareEncryptedWrite(BufFile *file);

/*
 * Create BufFile and perform the common initialization.
 */
static BufFile *
makeBufFileCommon(int nfiles)
{
	BufFile    *file = palloc_object(BufFile);

	file->numFiles = nfiles;
	file->isInterXact = false;
	file->dirty = false;
	file->encrypted = FileEncryptionEnabled();
	file->enc_header_size = file->encrypted ? FileEncryptionFileHeaderSize() : 0;
	file->fstates = NULL;
	file->buffer_from_disk = false;
	file->highest_dumped_offset = 0;
	file->resowner = CurrentResourceOwner;
	file->curFile = 0;
	file->curOffset = 0;
	file->pos = 0;
	file->nbytes = 0;
	file->enc_ciphertext.data = NULL;
	file->enc_plaintext.data = NULL;

	return file;
}

/*
 * Maximum logical (plaintext) bytes that fit in one physical component file.
 *
 * For the no-encryption path this is MAX_PHYSICAL_FILESIZE, exactly matching
 * upstream so the on-disk layout is unchanged.  For encrypted BufFiles each
 * physical file holds:
 *
 *	  enc_header_size bytes of module-owned per-file metadata, followed by
 *	  N fixed-size BUFFILE_PHYSICAL_BLOCK_SIZE blocks
 *
 * so the available plaintext space shrinks by both the header and any
 * partial trailing block.
 */
static inline pgoff_t
BufFilePlaintextPerFile(const BufFile *file)
{
	if (!file->encrypted)
		return (pgoff_t) MAX_PHYSICAL_FILESIZE;
	return ((pgoff_t) (MAX_PHYSICAL_FILESIZE - file->enc_header_size) /
			BUFFILE_PHYSICAL_BLOCK_SIZE) * BLCKSZ;
}

static inline int64
BufFilePlaintextBlocksPerFile(const BufFile *file)
{
	if (!file->encrypted)
		return (int64) BUFFILE_SEG_SIZE;
	return ((int64) (MAX_PHYSICAL_FILESIZE - file->enc_header_size) /
			BUFFILE_PHYSICAL_BLOCK_SIZE);
}

/*
 * Translate a plaintext offset within a physical file to the physical
 * offset where its encrypted representation begins.
 */
static inline pgoff_t
BufFilePhysicalOffset(const BufFile *file, pgoff_t plaintext_offset)
{
	Assert((plaintext_offset % BLCKSZ) == 0);
	return (pgoff_t) file->enc_header_size +
		(plaintext_offset / BLCKSZ) * BUFFILE_PHYSICAL_BLOCK_SIZE;
}

/*
 * Lazily set up the per-BufFile reusable encryption staging buffers.
 */
static inline void
BufFileEnsureEncBuffers(BufFile *file)
{
	if (file->enc_ciphertext.data == NULL)
	{
		MemoryContext oldcontext;

		oldcontext = MemoryContextSwitchTo(GetMemoryChunkContext(file));
		initStringInfo(&file->enc_ciphertext);
		initStringInfo(&file->enc_plaintext);
		MemoryContextSwitchTo(oldcontext);
	}
}

/*
 * Allocate fstate and write/read the per-file encryption header for one
 * physical file.  Pass create=true for a brand-new file (the module
 * produces a header which we persist) and false for an existing file
 * (we hand the on-disk header to the module).  Returns NULL when
 * encryption is disabled.
 */
static FileEncryptionFileState *
BufFileInitPhysFile(BufFile *file, File pfile, bool create)
{
	FileEncryptionFileState *fstate;
	char	   *header = NULL;

	if (!file->encrypted)
		return NULL;

	if (file->enc_header_size > 0)
		header = palloc(file->enc_header_size);

	if (create)
	{
		fstate = FileEncryptionFileCreate(FilePathName(pfile), header);
		if (file->enc_header_size > 0)
		{
			int			n;

			n = FileWrite(pfile, header, file->enc_header_size, 0,
						  WAIT_EVENT_BUFFILE_WRITE);
			if (n != (int) file->enc_header_size)
				ereport(ERROR,
						(errcode_for_file_access(),
						 errmsg("could not write encryption header to file \"%s\": %m",
								FilePathName(pfile))));
		}
	}
	else
	{
		if (file->enc_header_size > 0)
		{
			int			n;

			n = FileRead(pfile, header, file->enc_header_size, 0,
						 WAIT_EVENT_BUFFILE_READ);
			if (n != (int) file->enc_header_size)
				ereport(ERROR,
						(errcode_for_file_access(),
						 errmsg("could not read encryption header from file \"%s\": %m",
								FilePathName(pfile))));
		}
		fstate = FileEncryptionFileOpen(FilePathName(pfile), header);
	}

	if (header != NULL)
		pfree(header);

	return fstate;
}

/*
 * Compute the logical (plaintext) size of one physical component file.
 *
 * For unencrypted BufFiles, this is just FileSize().  For encrypted ones,
 * we count full physical blocks and probe the trailing partial block (if
 * any) to read its plaintext length out of the on-disk header.
 */
static int64
BufFileLogicalSize(BufFile *file, int fileno)
{
	int64		phys_size;
	int64		full_blocks;
	int64		remainder;
	char		header[BUFFILE_ENC_HEADER_SIZE];
	uint32		plaintext_len;
	int			hdr_read;

	phys_size = FileSize(file->files[fileno]);
	if (phys_size < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not determine size of temporary file \"%s\" from BufFile \"%s\": %m",
						FilePathName(file->files[fileno]),
						file->name)));
	if (!file->encrypted)
		return phys_size;

	/* Subtract the per-file encryption header. */
	if (phys_size <= file->enc_header_size)
		return 0;
	phys_size -= file->enc_header_size;

	full_blocks = phys_size / BUFFILE_PHYSICAL_BLOCK_SIZE;
	remainder = phys_size - full_blocks * BUFFILE_PHYSICAL_BLOCK_SIZE;

	if (remainder == 0)
		return full_blocks * BLCKSZ;

	hdr_read = FileRead(file->files[fileno], header, sizeof(header),
						file->enc_header_size +
						full_blocks * BUFFILE_PHYSICAL_BLOCK_SIZE,
						WAIT_EVENT_BUFFILE_READ);
	if (hdr_read != sizeof(header))
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("could not read encrypted BufFile header for size of \"%s\"",
						FilePathName(file->files[fileno]))));
	memcpy(&plaintext_len, header, sizeof(plaintext_len));
	if (plaintext_len > BLCKSZ)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("invalid encrypted BufFile header in \"%s\"",
						FilePathName(file->files[fileno]))));

	return full_blocks * BLCKSZ + plaintext_len;
}

static int
BufFileReadEncryptedBlock(BufFile *file, int fileno, pgoff_t block_start,
						  bool missing_ok)
{
	File		thisfile;
	char		header[BUFFILE_ENC_HEADER_SIZE];
	uint32		plaintext_len;
	uint32		ciphertext_len;
	pgoff_t		phys_offset;
	int			hdr_read;
	int			ct_read;
	instr_time	io_start;
	instr_time	io_time;

	Assert(file->encrypted);
	Assert((block_start % BLCKSZ) == 0);

	BufFileEnsureEncBuffers(file);

	thisfile = file->files[fileno];
	phys_offset = BufFilePhysicalOffset(file, block_start);

	if (track_io_timing)
		INSTR_TIME_SET_CURRENT(io_start);
	else
		INSTR_TIME_SET_ZERO(io_start);

	hdr_read = FileRead(thisfile, header, sizeof(header), phys_offset,
						WAIT_EVENT_BUFFILE_READ);
	if (hdr_read == 0 && missing_ok)
	{
		if (track_io_timing)
		{
			INSTR_TIME_SET_CURRENT(io_time);
			INSTR_TIME_ACCUM_DIFF(pgBufferUsage.temp_blk_read_time,
								  io_time, io_start);
		}
		return 0;
	}
	if (hdr_read < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not read file \"%s\": %m",
						FilePathName(thisfile))));
	if (hdr_read != sizeof(header))
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("short read of encrypted BufFile header in \"%s\"",
						FilePathName(thisfile))));

	memcpy(&plaintext_len, header, sizeof(uint32));
	memcpy(&ciphertext_len, header + sizeof(uint32), sizeof(uint32));

	if (plaintext_len > BLCKSZ ||
		ciphertext_len > BUFFILE_MAX_CIPHERTEXT)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("invalid encrypted BufFile block header in \"%s\"",
						FilePathName(thisfile))));

	resetStringInfo(&file->enc_ciphertext);
	enlargeStringInfo(&file->enc_ciphertext, (int) ciphertext_len);

	ct_read = FileRead(thisfile, file->enc_ciphertext.data,
					   ciphertext_len, phys_offset + sizeof(header),
					   WAIT_EVENT_BUFFILE_READ);
	if (ct_read < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not read file \"%s\": %m",
						FilePathName(thisfile))));
	if ((uint32) ct_read != ciphertext_len)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("short read of encrypted BufFile body in \"%s\"",
						FilePathName(thisfile))));

	file->enc_ciphertext.len = ct_read;
	file->enc_ciphertext.data[ct_read] = '\0';

	FileEncryptionDecrypt(file->fstates[fileno],
						  FilePathName(thisfile), phys_offset,
						  file->enc_ciphertext.data, ciphertext_len,
						  &file->enc_plaintext);

	if ((uint32) file->enc_plaintext.len != plaintext_len)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("decrypted plaintext size %d does not match header %u in \"%s\"",
						file->enc_plaintext.len, plaintext_len,
						FilePathName(thisfile))));

	if (track_io_timing)
	{
		INSTR_TIME_SET_CURRENT(io_time);
		INSTR_TIME_ACCUM_DIFF(pgBufferUsage.temp_blk_read_time,
							  io_time, io_start);
	}

	if (plaintext_len > 0)
		pgBufferUsage.temp_blks_read++;

	return plaintext_len;
}

static pgoff_t
BufFileWriteEncryptedBlock(BufFile *file, int fileno, pgoff_t block_start,
						   const char *data, uint32 plaintext_len)
{
	File		thisfile;
	pgoff_t		phys_offset;
	uint32		ciphertext_len;
	char		header[BUFFILE_ENC_HEADER_SIZE];
	instr_time	io_start;
	instr_time	io_time;

	Assert(file->encrypted);
	Assert((block_start % BLCKSZ) == 0);
	Assert(plaintext_len <= BLCKSZ);

	BufFileEnsureEncBuffers(file);

	thisfile = file->files[fileno];
	phys_offset = BufFilePhysicalOffset(file, block_start);

	resetStringInfo(&file->enc_ciphertext);
	FileEncryptionEncrypt(file->fstates[fileno],
						  FilePathName(thisfile), phys_offset,
						  data, plaintext_len,
						  &file->enc_ciphertext);
	ciphertext_len = (uint32) file->enc_ciphertext.len;

	if (ciphertext_len > BUFFILE_MAX_CIPHERTEXT)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("encryption module produced %u ciphertext bytes, exceeds BufFile limit %d",
						ciphertext_len, BUFFILE_MAX_CIPHERTEXT)));

	memcpy(header, &plaintext_len, sizeof(uint32));
	memcpy(header + sizeof(uint32), &ciphertext_len, sizeof(uint32));

	if (track_io_timing)
		INSTR_TIME_SET_CURRENT(io_start);
	else
		INSTR_TIME_SET_ZERO(io_start);

	if (FileWrite(thisfile, header, sizeof(header), phys_offset,
				  WAIT_EVENT_BUFFILE_WRITE) != sizeof(header))
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not write to file \"%s\": %m",
						FilePathName(thisfile))));
	if ((uint32) FileWrite(thisfile, file->enc_ciphertext.data,
						   ciphertext_len,
						   phys_offset + sizeof(header),
						   WAIT_EVENT_BUFFILE_WRITE) != ciphertext_len)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not write to file \"%s\": %m",
						FilePathName(thisfile))));

	if (track_io_timing)
	{
		INSTR_TIME_SET_CURRENT(io_time);
		INSTR_TIME_ACCUM_DIFF(pgBufferUsage.temp_blk_write_time,
							  io_time, io_start);
	}
	pgBufferUsage.temp_blks_written++;

	return phys_offset + sizeof(header) + ciphertext_len;
}

static bool
BufFileLoadEncryptedBlock(BufFile *file, bool for_write)
{
	pgoff_t		logical;
	pgoff_t		block_start;
	int			intra;
	pgoff_t		max_per_file;
	int			plaintext_len;

	Assert(file->encrypted);
	Assert(!file->dirty);

	logical = file->curOffset + file->pos;
	max_per_file = BufFilePlaintextPerFile(file);

	if (logical >= max_per_file && file->curFile + 1 < file->numFiles)
	{
		file->curFile++;
		logical -= max_per_file;
	}

	block_start = (logical / BLCKSZ) * BLCKSZ;
	intra = (int) (logical - block_start);

	file->curOffset = block_start;
	file->pos = intra;
	file->nbytes = 0;
	file->buffer_from_disk = false;

	plaintext_len = BufFileReadEncryptedBlock(file, file->curFile,
											  block_start, true);
	if (plaintext_len > 0)
	{
		memcpy(file->buffer.data, file->enc_plaintext.data, plaintext_len);
		file->nbytes = plaintext_len;
		file->buffer_from_disk = true;
	}

	if (for_write)
	{
		if (intra > file->nbytes)
		{
			MemSet(file->buffer.data + file->nbytes, 0,
				   intra - file->nbytes);
			file->nbytes = intra;
		}
	}
	else if (intra >= file->nbytes)
	{
		file->nbytes = 0;
		file->pos = 0;
	}

	return file->nbytes > 0;
}

static void
BufFilePrepareEncryptedWrite(BufFile *file)
{
	int			fileno;
	pgoff_t		max_per_file;
	pgoff_t		local_offset;
	pgoff_t		block_start;
	int			intra;
	int64		block_total;

	Assert(file->encrypted);
	Assert(!file->dirty);

	fileno = file->curFile;
	max_per_file = BufFilePlaintextPerFile(file);
	local_offset = file->curOffset + file->pos;

	if (local_offset >= max_per_file && fileno + 1 < file->numFiles)
	{
		fileno++;
		local_offset -= max_per_file;
	}

	block_start = (local_offset / BLCKSZ) * BLCKSZ;
	intra = (int) (local_offset - block_start);
	block_total = (int64) fileno * max_per_file + block_start;

	if (file->curFile == fileno &&
		file->curOffset == block_start &&
		file->pos == intra &&
		file->buffer_from_disk &&
		intra <= file->nbytes)
		return;

	if (intra != 0 || block_total < file->highest_dumped_offset)
		BufFileLoadEncryptedBlock(file, true);
}

/*
 * Create a BufFile given the first underlying physical file.
 * NOTE: caller must set isInterXact if appropriate.
 */
static BufFile *
makeBufFile(File firstfile)
{
	BufFile    *file = makeBufFileCommon(1);

	file->files = palloc_object(File);
	file->files[0] = firstfile;
	file->readOnly = false;
	file->fileset = NULL;
	file->name = NULL;

	if (file->encrypted)
	{
		file->fstates = palloc_object(FileEncryptionFileState *);
		file->fstates[0] = BufFileInitPhysFile(file, firstfile, true);
	}

	return file;
}

/*
 * Add another component temp file.
 */
static void
extendBufFile(BufFile *file)
{
	File		pfile;
	ResourceOwner oldowner;

	/* Be sure to associate the file with the BufFile's resource owner */
	oldowner = CurrentResourceOwner;
	CurrentResourceOwner = file->resowner;

	if (file->fileset == NULL)
		pfile = OpenTemporaryFile(file->isInterXact);
	else
		pfile = MakeNewFileSetSegment(file, file->numFiles);

	Assert(pfile >= 0);

	CurrentResourceOwner = oldowner;

	file->files = (File *) repalloc(file->files,
									(file->numFiles + 1) * sizeof(File));
	file->files[file->numFiles] = pfile;
	if (file->encrypted)
	{
		file->fstates = (FileEncryptionFileState **)
			repalloc(file->fstates,
					 (file->numFiles + 1) * sizeof(FileEncryptionFileState *));
		file->fstates[file->numFiles] = BufFileInitPhysFile(file, pfile, true);
	}
	file->numFiles++;
}

/*
 * Create a BufFile for a new temporary file (which will expand to become
 * multiple temporary files if more than MAX_PHYSICAL_FILESIZE bytes are
 * written to it).
 *
 * If interXact is true, the temp file will not be automatically deleted
 * at end of transaction.
 *
 * Note: if interXact is true, the caller had better be calling us in a
 * memory context, and with a resource owner, that will survive across
 * transaction boundaries.
 */
BufFile *
BufFileCreateTemp(bool interXact)
{
	BufFile    *file;
	File		pfile;

	/*
	 * Ensure that temp tablespaces are set up for OpenTemporaryFile to use.
	 * Possibly the caller will have done this already, but it seems useful to
	 * double-check here.  Failure to do this at all would result in the temp
	 * files always getting placed in the default tablespace, which is a
	 * pretty hard-to-detect bug.  Callers may prefer to do it earlier if they
	 * want to be sure that any required catalog access is done in some other
	 * resource context.
	 */
	PrepareTempTablespaces();

	pfile = OpenTemporaryFile(interXact);
	Assert(pfile >= 0);

	file = makeBufFile(pfile);
	file->isInterXact = interXact;

	return file;
}

/*
 * Build the name for a given segment of a given BufFile.
 */
static void
FileSetSegmentName(char *name, const char *buffile_name, int segment)
{
	snprintf(name, MAXPGPATH, "%s.%d", buffile_name, segment);
}

/*
 * Create a new segment file backing a fileset based BufFile.
 */
static File
MakeNewFileSetSegment(BufFile *buffile, int segment)
{
	char		name[MAXPGPATH];
	File		file;

	/*
	 * It is possible that there are files left over from before a crash
	 * restart with the same name.  In order for BufFileOpenFileSet() not to
	 * get confused about how many segments there are, we'll unlink the next
	 * segment number if it already exists.
	 */
	FileSetSegmentName(name, buffile->name, segment + 1);
	FileSetDelete(buffile->fileset, name, true);

	/* Create the new segment. */
	FileSetSegmentName(name, buffile->name, segment);
	file = FileSetCreate(buffile->fileset, name);

	/* FileSetCreate would've errored out */
	Assert(file > 0);

	return file;
}

/*
 * Create a BufFile that can be discovered and opened read-only by other
 * backends that are attached to the same SharedFileSet using the same name.
 *
 * The naming scheme for fileset based BufFiles is left up to the calling code.
 * The name will appear as part of one or more filenames on disk, and might
 * provide clues to administrators about which subsystem is generating
 * temporary file data.  Since each SharedFileSet object is backed by one or
 * more uniquely named temporary directory, names don't conflict with
 * unrelated SharedFileSet objects.
 */
BufFile *
BufFileCreateFileSet(FileSet *fileset, const char *name)
{
	BufFile    *file;

	file = makeBufFileCommon(1);
	file->fileset = fileset;
	file->name = pstrdup(name);
	file->files = palloc_object(File);
	file->files[0] = MakeNewFileSetSegment(file, 0);
	file->readOnly = false;

	if (file->encrypted)
	{
		file->fstates = palloc_object(FileEncryptionFileState *);
		file->fstates[0] = BufFileInitPhysFile(file, file->files[0], true);
	}

	return file;
}

/*
 * Open a file that was previously created in another backend (or this one)
 * with BufFileCreateFileSet in the same FileSet using the same name.
 * The backend that created the file must have called BufFileClose() or
 * BufFileExportFileSet() to make sure that it is ready to be opened by other
 * backends and render it read-only.  If missing_ok is true, which indicates
 * that missing files can be safely ignored, then return NULL if the BufFile
 * with the given name is not found, otherwise, throw an error.
 */
BufFile *
BufFileOpenFileSet(FileSet *fileset, const char *name, int mode,
				   bool missing_ok)
{
	BufFile    *file;
	char		segment_name[MAXPGPATH];
	Size		capacity = 16;
	File	   *files;
	int			nfiles = 0;

	files = palloc_array(File, capacity);

	/*
	 * We don't know how many segments there are, so we'll probe the
	 * filesystem to find out.
	 */
	for (;;)
	{
		/* See if we need to expand our file segment array. */
		if (nfiles + 1 > capacity)
		{
			capacity *= 2;
			files = repalloc_array(files, File, capacity);
		}
		/* Try to load a segment. */
		FileSetSegmentName(segment_name, name, nfiles);
		files[nfiles] = FileSetOpen(fileset, segment_name, mode);
		if (files[nfiles] <= 0)
			break;
		++nfiles;

		CHECK_FOR_INTERRUPTS();
	}

	/*
	 * If we didn't find any files at all, then no BufFile exists with this
	 * name.
	 */
	if (nfiles == 0)
	{
		/* free the memory */
		pfree(files);

		if (missing_ok)
			return NULL;

		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not open temporary file \"%s\" from BufFile \"%s\": %m",
						segment_name, name)));
	}

	file = makeBufFileCommon(nfiles);
	file->files = files;
	file->readOnly = (mode == O_RDONLY);
	file->fileset = fileset;
	file->name = pstrdup(name);

	if (file->encrypted)
	{
		file->fstates = palloc_array(FileEncryptionFileState *, nfiles);
		for (int i = 0; i < nfiles; i++)
			file->fstates[i] = BufFileInitPhysFile(file, file->files[i], false);
	}

	/*
	 * Track the existing logical extent so later writes can distinguish
	 * appending past EOF from overwriting an existing block that must be
	 * loaded first.
	 */
	file->highest_dumped_offset = BufFileSize(file);

	return file;
}

/*
 * Delete a BufFile that was created by BufFileCreateFileSet in the given
 * FileSet using the given name.
 *
 * It is not necessary to delete files explicitly with this function.  It is
 * provided only as a way to delete files proactively, rather than waiting for
 * the FileSet to be cleaned up.
 *
 * Only one backend should attempt to delete a given name, and should know
 * that it exists and has been exported or closed otherwise missing_ok should
 * be passed true.
 */
void
BufFileDeleteFileSet(FileSet *fileset, const char *name, bool missing_ok)
{
	char		segment_name[MAXPGPATH];
	int			segment = 0;
	bool		found = false;

	/*
	 * We don't know how many segments the file has.  We'll keep deleting
	 * until we run out.  If we don't manage to find even an initial segment,
	 * raise an error.
	 */
	for (;;)
	{
		FileSetSegmentName(segment_name, name, segment);
		if (!FileSetDelete(fileset, segment_name, true))
			break;
		found = true;
		++segment;

		CHECK_FOR_INTERRUPTS();
	}

	if (!found && !missing_ok)
		elog(ERROR, "could not delete unknown BufFile \"%s\"", name);
}

/*
 * BufFileExportFileSet --- flush and make read-only, in preparation for sharing.
 */
void
BufFileExportFileSet(BufFile *file)
{
	/* Must be a file belonging to a FileSet. */
	Assert(file->fileset != NULL);

	/* It's probably a bug if someone calls this twice. */
	Assert(!file->readOnly);

	BufFileFlush(file);
	file->readOnly = true;
}

/*
 * Close a BufFile
 *
 * Like fclose(), this also implicitly FileCloses the underlying File.
 */
void
BufFileClose(BufFile *file)
{
	int			i;

	/* flush any unwritten data */
	BufFileFlush(file);
	/* close and delete the underlying file(s) */
	for (i = 0; i < file->numFiles; i++)
		FileClose(file->files[i]);
	if (file->fstates != NULL)
	{
		for (i = 0; i < file->numFiles; i++)
			FileEncryptionFileClose(file->fstates[i]);
		pfree(file->fstates);
	}
	/* release the buffer space */
	pfree(file->files);
	if (file->enc_ciphertext.data != NULL)
	{
		pfree(file->enc_ciphertext.data);
		pfree(file->enc_plaintext.data);
	}
	pfree(file);
}

/*
 * BufFileLoadBuffer
 *
 * Load some data into buffer, if possible, starting from curOffset.
 * At call, must have dirty = false.  In the non-encrypted path callers
 * additionally guarantee pos and nbytes = 0; the encrypted path tolerates
 * any (curOffset + pos) combination and normalizes them to point at the
 * start of the loaded block.
 *
 * On exit, nbytes is the number of bytes loaded into the buffer.
 */
static void
BufFileLoadBuffer(BufFile *file)
{
	File		thisfile;
	instr_time	io_start;
	instr_time	io_time;

	if (file->encrypted)
	{
		(void) BufFileLoadEncryptedBlock(file, false);
		return;
	}

	/*
	 * Advance to next component file if necessary and possible.
	 */
	if (file->curOffset >= MAX_PHYSICAL_FILESIZE &&
		file->curFile + 1 < file->numFiles)
	{
		file->curFile++;
		file->curOffset = 0;
	}

	thisfile = file->files[file->curFile];

	if (track_io_timing)
		INSTR_TIME_SET_CURRENT(io_start);
	else
		INSTR_TIME_SET_ZERO(io_start);

	/*
	 * Read whatever we can get, up to a full bufferload.
	 */
	file->nbytes = FileRead(thisfile,
							file->buffer.data,
							sizeof(file->buffer.data),
							file->curOffset,
							WAIT_EVENT_BUFFILE_READ);
	if (file->nbytes < 0)
	{
		file->nbytes = 0;
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not read file \"%s\": %m",
						FilePathName(thisfile))));
	}

	if (track_io_timing)
	{
		INSTR_TIME_SET_CURRENT(io_time);
		INSTR_TIME_ACCUM_DIFF(pgBufferUsage.temp_blk_read_time, io_time, io_start);
	}

	/* we choose not to advance curOffset here */

	if (file->nbytes > 0)
		pgBufferUsage.temp_blks_read++;
}

/*
 * BufFileDumpBuffer
 *
 * Dump buffer contents starting at curOffset.
 * At call, should have dirty = true, nbytes > 0.
 * On exit, dirty is cleared if successful write, and curOffset is advanced.
 */
static void
BufFileDumpBuffer(BufFile *file)
{
	int64		wpos = 0;
	int64		bytestowrite;
	File		thisfile;

	if (file->encrypted)
	{
		pgoff_t		max_per_file = BufFilePlaintextPerFile(file);
		uint32		plaintext_len;

		/*
		 * Encrypted BufFiles encrypt one BLCKSZ-aligned block at a time.
		 * BufFileWrite() prepares dirty buffers by loading the current
		 * block first when needed, so partial writes still preserve any
		 * existing bytes before or after the write range.
		 */
		Assert((file->curOffset % BLCKSZ) == 0);

		/* Roll over to next physical file if this block doesn't fit. */
		if (file->curOffset >= max_per_file)
		{
			while (file->curFile + 1 >= file->numFiles)
				extendBufFile(file);
			file->curFile++;
			file->curOffset = 0;
		}

		plaintext_len = (uint32) file->nbytes;
		(void) BufFileWriteEncryptedBlock(file, file->curFile,
										  file->curOffset,
										  file->buffer.data,
										  plaintext_len);

		file->dirty = false;

		/*
		 * Track the new highest plaintext-end so later writes can distinguish
		 * fresh extension from read-modify-write.
		 */
		{
			int64		dump_end_total =
				(int64) file->curFile * max_per_file +
				file->curOffset + plaintext_len;

			if (dump_end_total > file->highest_dumped_offset)
				file->highest_dumped_offset = dump_end_total;
		}

		/*
		 * Mirror the upstream post-dump bookkeeping: advance curOffset by
		 * the plaintext we wrote, then back up to the user's logical
		 * position (curOffset + pos).  LoadBuffer handles re-aligning the
		 * resulting curOffset to a block boundary, so we don't enforce
		 * alignment here.
		 */
		file->curOffset += plaintext_len;
		file->curOffset -= (file->nbytes - file->pos);
		if (file->curOffset < 0)
		{
			file->curFile--;
			Assert(file->curFile >= 0);
			file->curOffset += BufFilePlaintextPerFile(file);
		}
		file->pos = 0;
		file->nbytes = 0;
		/* Buffer is empty now; further writes need their own load or extend. */
		file->buffer_from_disk = false;
		return;
	}

	/*
	 * Unlike BufFileLoadBuffer, we must dump the whole buffer even if it
	 * crosses a component-file boundary; so we need a loop.
	 */
	while (wpos < file->nbytes)
	{
		int64		availbytes;
		instr_time	io_start;
		instr_time	io_time;

		/*
		 * Advance to next component file if necessary and possible.
		 */
		if (file->curOffset >= MAX_PHYSICAL_FILESIZE)
		{
			while (file->curFile + 1 >= file->numFiles)
				extendBufFile(file);
			file->curFile++;
			file->curOffset = 0;
		}

		/*
		 * Determine how much we need to write into this file.
		 */
		bytestowrite = file->nbytes - wpos;
		availbytes = MAX_PHYSICAL_FILESIZE - file->curOffset;

		if (bytestowrite > availbytes)
			bytestowrite = availbytes;

		thisfile = file->files[file->curFile];

		if (track_io_timing)
			INSTR_TIME_SET_CURRENT(io_start);
		else
			INSTR_TIME_SET_ZERO(io_start);

		bytestowrite = FileWrite(thisfile,
								 file->buffer.data + wpos,
								 bytestowrite,
								 file->curOffset,
								 WAIT_EVENT_BUFFILE_WRITE);
		if (bytestowrite <= 0)
			ereport(ERROR,
					(errcode_for_file_access(),
					 errmsg("could not write to file \"%s\": %m",
							FilePathName(thisfile))));

		if (track_io_timing)
		{
			INSTR_TIME_SET_CURRENT(io_time);
			INSTR_TIME_ACCUM_DIFF(pgBufferUsage.temp_blk_write_time, io_time, io_start);
		}

		file->curOffset += bytestowrite;
		wpos += bytestowrite;

		pgBufferUsage.temp_blks_written++;
	}
	file->dirty = false;

	/*
	 * At this point, curOffset has been advanced to the end of the buffer,
	 * ie, its original value + nbytes.  We need to make it point to the
	 * logical file position, ie, original value + pos, in case that is less
	 * (as could happen due to a small backwards seek in a dirty buffer!)
	 */
	file->curOffset -= (file->nbytes - file->pos);
	if (file->curOffset < 0)	/* handle possible segment crossing */
	{
		file->curFile--;
		Assert(file->curFile >= 0);
		file->curOffset += MAX_PHYSICAL_FILESIZE;
	}

	/*
	 * Now we can set the buffer empty without changing the logical position
	 */
	file->pos = 0;
	file->nbytes = 0;
}

/*
 * BufFileRead variants
 *
 * Like fread() except we assume 1-byte element size and report I/O errors via
 * ereport().
 *
 * If 'exact' is true, then an error is also raised if the number of bytes
 * read is not exactly 'size' (no short reads).  If 'exact' and 'eofOK' are
 * true, then reading zero bytes is ok.
 */
static size_t
BufFileReadCommon(BufFile *file, void *ptr, size_t size, bool exact, bool eofOK)
{
	size_t		start_size = size;
	size_t		nread = 0;
	size_t		nthistime;

	BufFileFlush(file);

	while (size > 0)
	{
		if (file->pos >= file->nbytes)
		{
			/* Try to load more data into buffer. */
			file->curOffset += file->pos;
			file->pos = 0;
			file->nbytes = 0;
			BufFileLoadBuffer(file);
			if (file->nbytes <= 0)
				break;			/* no more data available */
		}

		nthistime = file->nbytes - file->pos;
		if (nthistime > size)
			nthistime = size;
		Assert(nthistime > 0);

		memcpy(ptr, file->buffer.data + file->pos, nthistime);

		file->pos += nthistime;
		ptr = (char *) ptr + nthistime;
		size -= nthistime;
		nread += nthistime;
	}

	if (exact &&
		(nread != start_size && !(nread == 0 && eofOK)))
		ereport(ERROR,
				errcode_for_file_access(),
				file->name ?
				errmsg("could not read from file set \"%s\": read only %zu of %zu bytes",
					   file->name, nread, start_size) :
				errmsg("could not read from temporary file: read only %zu of %zu bytes",
					   nread, start_size));

	return nread;
}

/*
 * Legacy interface where the caller needs to check for end of file or short
 * reads.
 */
size_t
BufFileRead(BufFile *file, void *ptr, size_t size)
{
	return BufFileReadCommon(file, ptr, size, false, false);
}

/*
 * Require read of exactly the specified size.
 */
void
BufFileReadExact(BufFile *file, void *ptr, size_t size)
{
	BufFileReadCommon(file, ptr, size, true, false);
}

/*
 * Require read of exactly the specified size, but optionally allow end of
 * file (in which case 0 is returned).
 */
size_t
BufFileReadMaybeEOF(BufFile *file, void *ptr, size_t size, bool eofOK)
{
	return BufFileReadCommon(file, ptr, size, true, eofOK);
}

/*
 * BufFileWrite
 *
 * Like fwrite() except we assume 1-byte element size and report errors via
 * ereport().
 */
void
BufFileWrite(BufFile *file, const void *ptr, size_t size)
{
	size_t		nthistime;

	Assert(!file->readOnly);

	while (size > 0)
	{
		if (file->pos >= BLCKSZ)
		{
			/* Buffer full, dump it out */
			if (file->dirty)
				BufFileDumpBuffer(file);
			else
			{
				/* Hmm, went directly from reading to writing? */
				file->curOffset += file->pos;
				file->pos = 0;
				file->nbytes = 0;
				file->buffer_from_disk = false;
			}
		}

		if (file->encrypted && !file->dirty)
			BufFilePrepareEncryptedWrite(file);

		nthistime = BLCKSZ - file->pos;
		if (nthistime > size)
			nthistime = size;
		Assert(nthistime > 0);

		memcpy(file->buffer.data + file->pos, ptr, nthistime);

		file->dirty = true;
		file->pos += nthistime;
		if (file->nbytes < file->pos)
			file->nbytes = file->pos;
		ptr = (const char *) ptr + nthistime;
		size -= nthistime;
	}
}

/*
 * BufFileFlush
 *
 * Like fflush(), except that I/O errors are reported with ereport().
 */
static void
BufFileFlush(BufFile *file)
{
	if (file->dirty)
		BufFileDumpBuffer(file);

	Assert(!file->dirty);
}

/*
 * BufFileSeek
 *
 * Like fseek(), except that target position needs two values in order to
 * work when logical filesize exceeds maximum value representable by pgoff_t.
 * We do not support relative seeks across more than that, however.
 * I/O errors are reported by ereport().
 *
 * Result is 0 if OK, EOF if not.  Logical position is not moved if an
 * impossible seek is attempted.
 */
int
BufFileSeek(BufFile *file, int fileno, pgoff_t offset, int whence)
{
	int			newFile;
	pgoff_t		newOffset;
	pgoff_t		max_per_file = BufFilePlaintextPerFile(file);

	switch (whence)
	{
		case SEEK_SET:
			if (fileno < 0)
				return EOF;
			newFile = fileno;
			newOffset = offset;
			break;
		case SEEK_CUR:

			/*
			 * Relative seek considers only the signed offset, ignoring
			 * fileno.
			 */
			newFile = file->curFile;
			newOffset = (file->curOffset + file->pos) + offset;
			break;
		case SEEK_END:

			/*
			 * The file size of the last file gives us the end offset of that
			 * file (in plaintext bytes for encrypted BufFiles).
			 */
			newFile = file->numFiles - 1;
			newOffset = BufFileLogicalSize(file, file->numFiles - 1);
			break;
		default:
			elog(ERROR, "invalid whence: %d", whence);
			return EOF;
	}
	while (newOffset < 0)
	{
		if (--newFile < 0)
			return EOF;
		newOffset += max_per_file;
	}
	if (newFile == file->curFile &&
		newOffset >= file->curOffset &&
		newOffset <= file->curOffset + file->nbytes)
	{
		/*
		 * Seek is to a point within existing buffer; we can just adjust
		 * pos-within-buffer, without flushing buffer.  Note this is OK
		 * whether reading or writing, but buffer remains dirty if we were
		 * writing.
		 */
		file->pos = (int64) (newOffset - file->curOffset);
		return 0;
	}
	/* Otherwise, must reposition buffer, so flush any dirty data */
	BufFileFlush(file);

	/*
	 * At this point and no sooner, check for seek past last segment. The
	 * above flush could have created a new segment, so checking sooner would
	 * not work (at least not with this code).
	 */

	/* convert seek to "start of next seg" to "end of last seg" */
	if (newFile == file->numFiles && newOffset == 0)
	{
		newFile--;
		newOffset = max_per_file;
	}
	while (newOffset > max_per_file)
	{
		if (++newFile >= file->numFiles)
			return EOF;
		newOffset -= max_per_file;
	}
	if (newFile >= file->numFiles)
		return EOF;
	/* Seek is OK! */
	file->curFile = newFile;
	file->curOffset = newOffset;
	file->pos = 0;
	file->nbytes = 0;
	file->buffer_from_disk = false;
	return 0;
}

void
BufFileTell(BufFile *file, int *fileno, pgoff_t *offset)
{
	*fileno = file->curFile;
	*offset = file->curOffset + file->pos;
}

/*
 * BufFileSeekBlock --- block-oriented seek
 *
 * Performs absolute seek to the start of the n'th BLCKSZ-sized block of
 * the file.  Note that users of this interface will fail if their files
 * exceed BLCKSZ * PG_INT64_MAX bytes, but that is quite a lot; we don't
 * work with tables bigger than that, either...
 *
 * Result is 0 if OK, EOF if not.  Logical position is not moved if an
 * impossible seek is attempted.
 */
int
BufFileSeekBlock(BufFile *file, int64 blknum)
{
	int64		blocks_per_file = BufFilePlaintextBlocksPerFile(file);

	return BufFileSeek(file,
					   (int) (blknum / blocks_per_file),
					   (pgoff_t) (blknum % blocks_per_file) * BLCKSZ,
					   SEEK_SET);
}

/*
 * Returns the amount of data in the given BufFile, in bytes.
 *
 * Returned value includes the size of any holes left behind by BufFileAppend.
 * ereport()s on failure.
 */
int64
BufFileSize(BufFile *file)
{
	int64		lastFileSize = BufFileLogicalSize(file, file->numFiles - 1);

	return ((file->numFiles - 1) * (int64) BufFilePlaintextPerFile(file)) +
		lastFileSize;
}

/*
 * Append the contents of the source file to the end of the target file.
 *
 * Note that operation subsumes ownership of underlying resources from
 * "source".  Caller should never call BufFileClose against source having
 * called here first.  Resource owners for source and target must match,
 * too.
 *
 * This operation works by manipulating lists of segment files, so the
 * file content is always appended at a MAX_PHYSICAL_FILESIZE-aligned
 * boundary, typically creating empty holes before the boundary.  These
 * areas do not contain any interesting data, and cannot be read from by
 * caller.
 *
 * Returns the block number within target where the contents of source
 * begins.  Caller should apply this as an offset when working off block
 * positions that are in terms of the original BufFile space.
 */
int64
BufFileAppend(BufFile *target, BufFile *source)
{
	int64		startBlock = (int64) target->numFiles *
		BufFilePlaintextBlocksPerFile(target);
	int			newNumFiles = target->numFiles + source->numFiles;
	int			i;

	Assert(source->readOnly);
	Assert(!source->dirty);
	Assert(target->encrypted == source->encrypted);

	if (target->resowner != source->resowner)
		elog(ERROR, "could not append BufFile with non-matching resource owner");

	target->files = (File *)
		repalloc(target->files, sizeof(File) * newNumFiles);
	for (i = target->numFiles; i < newNumFiles; i++)
		target->files[i] = source->files[i - target->numFiles];

	if (target->encrypted)
	{
		target->fstates = (FileEncryptionFileState **)
			repalloc(target->fstates,
					 sizeof(FileEncryptionFileState *) * newNumFiles);
		for (i = target->numFiles; i < newNumFiles; i++)
		{
			target->fstates[i] = source->fstates[i - target->numFiles];
			source->fstates[i - target->numFiles] = NULL;
		}
	}
	target->numFiles = newNumFiles;
	if (target->encrypted)
		target->highest_dumped_offset = BufFileSize(target);

	return startBlock;
}

/*
 * Truncate a BufFile created by BufFileCreateFileSet up to the given fileno
 * and the offset.
 *
 * In encrypted mode, offset is a logical plaintext offset.  When the
 * truncation point lands inside an encrypted block, rewrite that block with
 * a shorter plaintext payload before truncating the physical file.
 */
void
BufFileTruncateFileSet(BufFile *file, int fileno, pgoff_t offset)
{
	int			numFiles = file->numFiles;
	int			newFile = fileno;
	pgoff_t		newOffset = file->curOffset;
	pgoff_t		max_per_file = BufFilePlaintextPerFile(file);
	char		segment_name[MAXPGPATH];
	int			i;
	pgoff_t		physical_offset = offset;

	if (file->encrypted)
	{
		pgoff_t		block_start = (offset / BLCKSZ) * BLCKSZ;
		int			intra = (int) (offset - block_start);

		if (intra == 0)
			physical_offset = BufFilePhysicalOffset(file, offset);
		else
		{
			int			plaintext_len;

			plaintext_len = BufFileReadEncryptedBlock(file, fileno,
													  block_start, false);
			if (plaintext_len < intra)
				ereport(ERROR,
						(errcode(ERRCODE_DATA_CORRUPTED),
						 errmsg("encrypted BufFile block in \"%s\" is shorter than requested truncation offset",
								FilePathName(file->files[fileno]))));

			physical_offset = BufFileWriteEncryptedBlock(file, fileno,
														 block_start,
														 file->enc_plaintext.data,
														 (uint32) intra);
		}
	}

	/*
	 * Loop over all the files up to the given fileno and remove the files
	 * that are greater than the fileno and truncate the given file up to the
	 * offset. Note that we also remove the given fileno if the offset is 0
	 * provided it is not the first file in which we truncate it.
	 */
	for (i = file->numFiles - 1; i >= fileno; i--)
	{
		if ((i != fileno || offset == 0) && i != 0)
		{
			FileSetSegmentName(segment_name, file->name, i);
			FileClose(file->files[i]);
			if (file->encrypted && file->fstates[i] != NULL)
			{
				FileEncryptionFileClose(file->fstates[i]);
				file->fstates[i] = NULL;
			}
			if (!FileSetDelete(file->fileset, segment_name, true))
				ereport(ERROR,
						(errcode_for_file_access(),
						 errmsg("could not delete fileset \"%s\": %m",
								segment_name)));
			numFiles--;
			newOffset = max_per_file;

			/*
			 * This is required to indicate that we have deleted the given
			 * fileno.
			 */
			if (i == fileno)
				newFile--;
		}
		else
		{
			if (FileTruncate(file->files[i], physical_offset,
							 WAIT_EVENT_BUFFILE_TRUNCATE) < 0)
				ereport(ERROR,
						(errcode_for_file_access(),
						 errmsg("could not truncate file \"%s\": %m",
								FilePathName(file->files[i]))));
			newOffset = offset;
		}
	}

	file->numFiles = numFiles;

	/*
	 * If the truncate point is within existing buffer then we can just adjust
	 * pos within buffer.
	 */
	if (newFile == file->curFile &&
		newOffset >= file->curOffset &&
		newOffset <= file->curOffset + file->nbytes)
	{
		/* No need to reset the current pos if the new pos is greater. */
		if (newOffset <= file->curOffset + file->pos)
			file->pos = (int64) newOffset - file->curOffset;

		/* Adjust the nbytes for the current buffer. */
		file->nbytes = (int64) newOffset - file->curOffset;
	}
	else if (newFile == file->curFile &&
			 newOffset < file->curOffset)
	{
		/*
		 * The truncate point is within the existing file but prior to the
		 * current position, so we can forget the current buffer and reset the
		 * current position.
		 */
		file->curOffset = newOffset;
		file->pos = 0;
		file->nbytes = 0;
	}
	else if (newFile < file->curFile)
	{
		/*
		 * The truncate point is prior to the current file, so need to reset
		 * the current position accordingly.
		 */
		file->curFile = newFile;
		file->curOffset = newOffset;
		file->pos = 0;
		file->nbytes = 0;
	}
	/* Nothing to do, if the truncate point is beyond current file. */

	/*
	 * Refresh the highest-dumped tracker so a subsequent write still
	 * recognizes a fresh extension past the truncation point.
	 */
	{
		int64		truncated_eof = (int64) newFile *
			BufFilePlaintextPerFile(file) + newOffset;

		if (truncated_eof < file->highest_dumped_offset)
			file->highest_dumped_offset = truncated_eof;
	}
}
