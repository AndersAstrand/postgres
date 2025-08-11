/*
 * Encrypted XLog storage manager
 */

#include "postgres.h"

#include "access/xlog.h"
#include "access/xlog_internal.h"
#include "access/xlog_smgr.h"
#include "access/xloginsert.h"
#include "storage/bufmgr.h"
#include "storage/shmem.h"
#include "utils/guc.h"
#include "utils/memutils.h"

#include "access/pg_tde_xlog_keys.h"
#include "access/pg_tde_xlog_smgr.h"
#include "catalog/tde_global_space.h"
#include "encryption/enc_tde.h"
#include "pg_tde.h"
#include "pg_tde_defines.h"

#ifdef FRONTEND
#include "pg_tde_fe.h"
#else
#include "pg_tde_guc.h"
#include "port/atomics.h"
#endif

static void CalcXLogPageIVPrefix(TimeLineID tli, XLogRecPtr lsn, const unsigned char *base_iv, char *iv_prefix);
static ssize_t tdeheap_xlog_seg_read(int fd, void *buf, size_t count, off_t offset,
									 TimeLineID tli, XLogSegNo segno, int segSize);
static ssize_t tdeheap_xlog_seg_write(int fd, const void *buf, size_t count,
									  off_t offset, TimeLineID tli,
									  XLogSegNo segno, int segSize);

static const XLogSmgr tde_xlog_smgr = {
	.seg_read = tdeheap_xlog_seg_read,
	.seg_write = tdeheap_xlog_seg_write,
};

static void *EncryptionCryptCtx = NULL;

/* TODO: can be swapped out to the disk */
WalEncryptionKey EncryptionKey =
{
	.type = WAL_KEY_TYPE_INVALID,
	.wal_start = {.tli = 0,.lsn = InvalidXLogRecPtr},
	.key = {0,}
};

static void
iv_prefix_debug(const char *iv_prefix, char *out_hex)
{
	for (int i = 0; i < 16; ++i)
	{
		sprintf(out_hex + i * 2, "%02x", (int) *(iv_prefix + i));
	}
	out_hex[32] = 0;
}

/*
 * Must be the same as in replication/walsender.c
 *
 * This is used to calculate the encryption buffer size.
 */
#define MAX_SEND_SIZE (XLOG_BLCKSZ * 16)

/*
 * Since the backend code needs to use atomics and shared memory while the
 * frotnend code cannot do that we provide two separate implementations of some
 * data structures and the functions which operate one them.
 */

#ifndef FRONTEND

typedef struct EncryptionStateData
{
	/*
	 * To sync with readers. We sync on LSN only and TLI here just to
	 * communicate its value to readers.
	 */
	pg_atomic_uint32 enc_key_tli;
	pg_atomic_uint64 enc_key_lsn;
	WalLocation LastReadOffset;
} EncryptionStateData;

static EncryptionStateData *EncryptionState = NULL;

static char *EncryptionBuf;

static XLogRecPtr
TDEXLogGetEncKeyLsn()
{
	return (XLogRecPtr) pg_atomic_read_u64(&EncryptionState->enc_key_lsn);
}

static TimeLineID
TDEXLogGetEncKeyTli()
{
	return (TimeLineID) pg_atomic_read_u32(&EncryptionState->enc_key_tli);
}

static void
TDEXLogSetEncKeyLocation(WalLocation loc)
{
	/*
	 * Write TLI first and then LSN. The barrier ensures writes won't be
	 * reordered. When reading, the opposite must be done (with a matching
	 * barrier in between), so we always see a valid TLI after observing a
	 * valid LSN.
	 */
	pg_atomic_write_u32(&EncryptionState->enc_key_tli, loc.tli);
	pg_write_barrier();
	pg_atomic_write_u64(&EncryptionState->enc_key_lsn, loc.lsn);
}

static Size TDEXLogEncryptBuffSize(void);

static int	XLOGChooseNumBuffers(void);

static int
XLOGChooseNumBuffers(void)
{
	int			xbuffers;

	xbuffers = NBuffers / 32;
	if (xbuffers > (wal_segment_size / XLOG_BLCKSZ))
		xbuffers = (wal_segment_size / XLOG_BLCKSZ);
	if (xbuffers < 8)
		xbuffers = 8;
	return xbuffers;
}

/*
 * Defines the size of the XLog encryption buffer
 */
static Size
TDEXLogEncryptBuffSize(void)
{
	int			xbuffers;

	xbuffers = (XLOGbuffers == -1) ? XLOGChooseNumBuffers() : XLOGbuffers;
	return Max(MAX_SEND_SIZE, mul_size(XLOG_BLCKSZ, xbuffers));
}

Size
TDEXLogEncryptStateSize(void)
{
	Size		sz;

	sz = sizeof(EncryptionStateData);
	if (EncryptXLog)
	{
		sz = add_size(sz, TDEXLogEncryptBuffSize());
		sz = add_size(sz, PG_IO_ALIGN_SIZE);
	}

	return sz;
}

/*
 * Alloc memory for the encryption buffer.
 *
 * It should fit XLog buffers (XLOG_BLCKSZ * wal_buffers). We can't
 * (re)alloc this buf in tdeheap_xlog_seg_write() based on the write size as
 * it's called in the CRIT section, hence no allocations are allowed.
 *
 * Access to this buffer happens during XLogWrite() call which should
 * be called with WALWriteLock held, hence no need in extra locks.
 */
void
TDEXLogShmemInit(void)
{
	bool		foundBuf;

	EncryptionState = (EncryptionStateData *)
		ShmemInitStruct("TDE XLog Encryption State",
						TDEXLogEncryptStateSize(),
						&foundBuf);

	if(!foundBuf) {
		memset(EncryptionState, 0, sizeof(EncryptionStateData));

		pg_atomic_init_u64(&EncryptionState->enc_key_lsn, 0);

		elog(DEBUG1, "pg_tde: initialized encryption buffer %lu bytes", TDEXLogEncryptStateSize());
	}

	if (EncryptXLog)
	{
		EncryptionBuf = (char *) TYPEALIGN(PG_IO_ALIGN_SIZE, ((char *) EncryptionState) + sizeof(EncryptionStateData));

		Assert((char *) EncryptionState + TDEXLogEncryptStateSize() >= (char *) EncryptionBuf + TDEXLogEncryptBuffSize());
	}
}

#else							/* !FRONTEND */

typedef struct EncryptionStateData
{
	TimeLineID	enc_key_tli;
	XLogRecPtr	enc_key_lsn;
	WalLocation LastReadOffset;
} EncryptionStateData;

static EncryptionStateData EncryptionStateD = {0};

static EncryptionStateData *EncryptionState = &EncryptionStateD;

static char EncryptionBuf[MAX_SEND_SIZE];

static XLogRecPtr
TDEXLogGetEncKeyLsn()
{
	return (XLogRecPtr) EncryptionState->enc_key_lsn;
}

static TimeLineID
TDEXLogGetEncKeyTli()
{
	return (TimeLineID) EncryptionState->enc_key_tli;
}

static void
TDEXLogSetEncKeyLocation(WalLocation loc)
{
	EncryptionState->enc_key_tli = loc.tli;
	EncryptionState->enc_key_lsn = loc.lsn;
}

#endif							/* FRONTEND */

void
TDEXLogSmgrInit()
{
	SetXLogSmgr(&tde_xlog_smgr);
}

void
TDEXLogSmgrInitWrite(bool encrypt_xlog)
{
	WalEncryptionKey *key = pg_tde_read_last_wal_key();

	/*
	 * Always generate a new key on starting PostgreSQL to protect against
	 * attacks on CTR ciphers based on comparing the WAL generated by two
	 * divergent copies of the same cluster.
	 */
	if (encrypt_xlog)
	{
		// TODO: if we crash between this method and when we update the current key,
		// do we end up floording wal_keys with invalid keys??
		pg_tde_create_wal_key(&EncryptionKey, WAL_KEY_TYPE_ENCRYPTED);
		
		// TODO WTF: if we read the key here, everything works properly
		// but if we comment this out, things will fail later with encryption key errors, even in
		// debug builds
		// synchronization error? gcc bug? ub?
		char		buf[33];
		iv_prefix_debug(buf, EncryptionKey.key);
	}
	else if (key && key->type == WAL_KEY_TYPE_ENCRYPTED)
	{
		pg_tde_create_wal_key(&EncryptionKey, WAL_KEY_TYPE_UNENCRYPTED);
	}
	else if (key)
	{
		EncryptionKey = *key;
		TDEXLogSetEncKeyLocation(EncryptionKey.wal_start);
	}

	{
		WalLocation start = {.tli = 1,.lsn = 0};
		pg_tde_fetch_wal_keys(start);
	}

	if (key)
		pfree(key);
}

void
TDEXLogSmgrInitWriteReuseKey()
{
	WalEncryptionKey *key = pg_tde_read_last_wal_key();

	if (key)
	{
		EncryptionKey = *key;
		TDEXLogSetEncKeyLocation(EncryptionKey.wal_start);
		pfree(key);
	}
}

/*
 * Encrypt XLog page(s) from the buf and write to the segment file.
 */
static ssize_t
TDEXLogWriteEncryptedPages(int fd, const void *buf, size_t count, off_t offset,
						   TimeLineID tli, XLogSegNo segno)
{
	char		iv_prefix[16];
	WalEncryptionKey *key = &EncryptionKey;
	char	   *enc_buff = EncryptionBuf;

#ifndef FRONTEND
	Assert(count <= TDEXLogEncryptBuffSize());
#endif

#ifdef TDE_XLOG_DEBUG
	elog(DEBUG1, "write encrypted WAL, size: %lu, offset: %ld [%lX], seg: %X/%X, key_start_lsn: %u_%X/%X",
		 count, offset, offset, LSN_FORMAT_ARGS(segno), key->wal_start.tli, LSN_FORMAT_ARGS(key->wal_start.lsn));
#endif

	CalcXLogPageIVPrefix(tli, segno, key->base_iv, iv_prefix);
	pg_tde_stream_crypt(iv_prefix,
						offset,
						(char *) buf,
						count,
						enc_buff,
						key->key,
						&EncryptionCryptCtx);

	return pg_pwrite(fd, enc_buff, count, offset);
}

/*
 * Encrypt XLog page(s) from the buf and write to the segment file.
 */
static ssize_t
TDEXLogWriteEncryptedPagesOldKeys(int fd, const void *buf, size_t count, off_t offset,
						   TimeLineID tli, XLogSegNo segno, int segSize)
{
	char	   *enc_buff = EncryptionBuf;

#ifndef FRONTEND
	Assert(count <= TDEXLogEncryptBuffSize());
#endif

	/* This method potentially allocates, but only in very early execution
	   Shouldn't happen in a write, where we are in a critical section */
	TDEXLogCryptBuffer(buf, enc_buff, count, offset, tli, segno, segSize);

	return pg_pwrite(fd, enc_buff, count, offset);
}

static ssize_t
tdeheap_xlog_seg_write(int fd, const void *buf, size_t count, off_t offset,
					   TimeLineID tli, XLogSegNo segno, int segSize)
{
	
	WalLocation write_loc = {.tli = tli,.lsn = offset};

	/*
	 * Set the last (most recent) key's start LSN if not set.
	 *
	 * This func called with WALWriteLock held, so no need in any extra sync.
	 */
	if (EncryptionKey.type != WAL_KEY_TYPE_INVALID && TDEXLogGetEncKeyLsn() == 0)
	{
		WalLocation loc = {.tli = tli};
		WALKeyCacheRec *keys = pg_tde_get_wal_cache_keys();

		XLogSegNoOffsetToRecPtr(segno, offset, segSize, loc.lsn);

		#ifndef FRONTEND
		if (EncryptionKey.type == WAL_KEY_TYPE_ENCRYPTED)
		{
			loc = ((EncryptionState->LastReadOffset.tli  == 0 && EncryptionState->LastReadOffset.lsn == 0) || !RecoveryInProgress()) ? loc : EncryptionState->LastReadOffset;
		}
		#endif

		pg_tde_wal_last_key_set_location(loc);
		EncryptionKey.wal_start = loc;
		TDEXLogSetEncKeyLocation(EncryptionKey.wal_start);

		// also update the cache
		if(keys) for (WALKeyCacheRec *curr_key = keys; curr_key != NULL; curr_key = curr_key->next)
		{
			if(!wal_location_valid(curr_key->start)) {
				curr_key-> start = EncryptionKey.wal_start;
			}
		}
	}
	if (EncryptionKey.type != WAL_KEY_TYPE_INVALID && EncryptionKey.wal_start.lsn == 0)
	{
		EncryptionKey.wal_start.lsn = TDEXLogGetEncKeyLsn();
		EncryptionKey.wal_start.tli = TDEXLogGetEncKeyTli();
	}

	// TODO: `EncryptionKey.type == WAL_KEY_TYPE_ENCRYPTED` is questionable
	// What's the correct behavior when the user turns off WAL encryption, and we rewrite the last page?
	// Should we write completely a unencrypted page like now?
	// Should we delete not required keys in this case? Otherwise if something tries to read it...
	// It would make more sense to keep the page partially encrypted, but we don't even initialize encryption code in that case
	if (EncryptionKey.type == WAL_KEY_TYPE_ENCRYPTED && unlikely(wal_location_cmp(write_loc, EncryptionState->LastReadOffset) < 0))
			return TDEXLogWriteEncryptedPagesOldKeys(fd, buf, count, offset, tli, segno, segSize);

	if (EncryptionKey.type == WAL_KEY_TYPE_ENCRYPTED)
	{
		return TDEXLogWriteEncryptedPages(fd, buf, count, offset, tli, segno);
	} else
		return pg_pwrite(fd, buf, count, offset);
}

/*
 * Read the XLog pages from the segment file and dectypt if need.
 */
static ssize_t
tdeheap_xlog_seg_read(int fd, void *buf, size_t count, off_t offset,
					  TimeLineID tli, XLogSegNo segno, int segSize)
{
	ssize_t		readsz;

#ifdef TDE_XLOG_DEBUG
	elog(DEBUG1, "read from a WAL segment, size: %lu offset: %ld [%lX], seg: %u_%X/%X",
		 count, offset, offset, tli, LSN_FORMAT_ARGS(segno));
#endif

	readsz = pg_pread(fd, buf, count, offset);

	if (readsz <= 0)
		return readsz;

	TDEXLogCryptBuffer(buf, buf, count, offset, tli, segno, segSize);

	XLogSegNoOffsetToRecPtr(segno, offset + readsz, segSize, EncryptionState->LastReadOffset.lsn);
	EncryptionState->LastReadOffset.tli = tli;

	return readsz;
}

/*
 * [De]Crypt buffer if needed based on provided segment offset, number and TLI
 */
void
TDEXLogCryptBuffer(const void *buf, void * out_buf, size_t count, off_t offset,
				   TimeLineID tli, XLogSegNo segno, int segSize)
{
	WALKeyCacheRec *keys = pg_tde_get_wal_cache_keys();
	WalLocation data_end = {.tli = tli};
	WalLocation data_start = {.tli = tli};

	if (!keys)
	{
		WalLocation start = {.tli = 1,.lsn = 0};

		/* cache is empty, try to read keys from disk */
		keys = pg_tde_fetch_wal_keys(start);
	}

	XLogSegNoOffsetToRecPtr(segno, offset, segSize, data_start.lsn);
	XLogSegNoOffsetToRecPtr(segno, offset + count, segSize, data_end.lsn);

	/*
	 * TODO: this is higly ineffective. We should get rid of linked list and
	 * search from the last key as this is what the walsender is useing.
	 */
	for (WALKeyCacheRec *curr_key = keys; curr_key != NULL; curr_key = curr_key->next)
	{
		// skip keys that weren't updated properly yet
		if(!wal_location_valid(curr_key->start)) continue;

#ifdef TDE_XLOG_DEBUG
		elog(DEBUG1, "WAL key %u_%X/%X - %u_%X/%X encrypted: %s",
			 curr_key->start.tli, LSN_FORMAT_ARGS(curr_key->start.lsn),
			 curr_key->end.tli, LSN_FORMAT_ARGS(curr_key->end.lsn),
			 curr_key->key.type == WAL_KEY_TYPE_ENCRYPTED ? "yes" : "no");
#endif

		if (wal_location_valid(curr_key->key.wal_start) &&
			curr_key->key.type == WAL_KEY_TYPE_ENCRYPTED)
		{
			/*
			 * Check if the key's range overlaps with the buffer's and (de)cypt
			 * the part that does.
			 */
			if (wal_location_cmp(data_start, curr_key->end) < 0 && wal_location_cmp(data_end, curr_key->start) > 0)
			{
				char		iv_prefix[16];
				size_t		minlsn = Min(data_end.lsn, curr_key->end.lsn);
				size_t		maxlsn = data_start.tli > curr_key->start.tli ? data_start.lsn : Max(data_start.lsn, curr_key->start.lsn);
				off_t		dec_off = XLogSegmentOffset(maxlsn, segSize);
				off_t		dec_end = XLogSegmentOffset(minlsn, segSize);
				size_t		dec_sz;
				const char	   *dec_buf = (const char *) buf + (dec_off - offset);
				char	   *decout_buf = (char *) out_buf + (dec_off - offset);

				Assert(dec_off >= offset);

				CalcXLogPageIVPrefix(tli, segno, curr_key->key.base_iv, iv_prefix);

				/* We have reached the end of the segment */
				if (dec_end < dec_off)
				{
					dec_end = dec_off + count;
				}

				dec_sz = dec_end - dec_off;

#ifdef TDE_XLOG_DEBUG
				elog(DEBUG1, "decrypt WAL, dec_off: %lu [buff_off %lu], sz: %lu | key %u_%X/%X",
					 dec_off, dec_off - offset, dec_sz, curr_key->key.wal_start.tli, LSN_FORMAT_ARGS(curr_key->key.wal_start.lsn));
#endif
				pg_tde_stream_crypt(iv_prefix,
									dec_off,
									dec_buf,
									dec_sz,
									decout_buf,
									curr_key->key.key,
									&curr_key->crypt_ctx);
			}
		}
	}
}

union u128cast
{
	char		a[16];
	unsigned	__int128 i;
};

/*
 * Calculate the start IV for an XLog segmenet.
 *
 * IV: (TLI(uint32) + XLogRecPtr(uint64)) + BaseIV(uint8[12])
 *
 * TODO: Make the calculation more like OpenSSL's CTR withot any gaps and
 * preferrably without zeroing the lowest bytes for the base IV.
 *
 * TODO: This code vectorizes poorly in both gcc and clang.
 */
static void
CalcXLogPageIVPrefix(TimeLineID tli, XLogRecPtr lsn, const unsigned char *base_iv, char *iv_prefix)
{
	union u128cast base;
	union u128cast iv;
	unsigned	__int128 offset;

	for (int i = 0; i < 16; i++)
#ifdef WORDS_BIGENDIAN
		base.a[i] = base_iv[i];
#else
		base.a[i] = base_iv[15 - i];
#endif

	/* We do not support wrapping addition in Aes128EncryptedZeroBlocks() */
	base.i &= ~(((unsigned __int128) 1) << 32);

	offset = (((unsigned __int128) tli) << 112) | (((unsigned __int128) lsn) << 32);

	iv.i = base.i + offset;

	for (int i = 0; i < 16; i++)
#ifdef WORDS_BIGENDIAN
		iv_prefix[i] = iv.a[i];
#else
		iv_prefix[i] = iv.a[15 - i];
#endif
}
