/*-------------------------------------------------------------------------
 *
 * storage_xlog.h
 *	  prototypes for XLog support for backend/catalog/storage.c
 *
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/catalog/storage_xlog.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef STORAGE_XLOG_H
#define STORAGE_XLOG_H

#include "access/xlogreader.h"
#include "lib/stringinfo.h"
#include "storage/block.h"
#include "storage/relfilelocator.h"

/*
 * Declarations for smgr-related XLOG records
 *
 * Note: we log file creation and truncation here, but logging of deletion
 * actions is handled by xact.c, because it is part of transaction commit.
 */

/* XLOG gives us high 4 bits */
#define XLOG_SMGR_CREATE			0x10
#define XLOG_SMGR_TRUNCATE			0x20
#define XLOG_SMGR_KEY_FORK_CREATE	0x30

typedef struct xl_smgr_create
{
	RelFileLocator rlocator;
	ForkNumber	forkNum;
} xl_smgr_create;

/* flags for xl_smgr_truncate */
#define SMGR_TRUNCATE_HEAP		0x0001
#define SMGR_TRUNCATE_VM		0x0002
#define SMGR_TRUNCATE_FSM		0x0004
#define SMGR_TRUNCATE_ALL		\
	(SMGR_TRUNCATE_HEAP|SMGR_TRUNCATE_VM|SMGR_TRUNCATE_FSM)

typedef struct xl_smgr_truncate
{
	BlockNumber blkno;
	RelFileLocator rlocator;
	int			flags;
} xl_smgr_truncate;

/*
 * XLOG_SMGR_KEY_FORK_CREATE: create the KEY fork and write its single block
 * directly to disk, bypassing the buffer pool.  The wrapped-DEK contents
 * follow the header in the WAL record and the redo writes them with
 * smgrwrite + smgrimmedsync so a subsequent encrypted write on the standby
 * can reliably read them back via smgrread, even when the redo loop hasn't
 * yet had a chance to flush dirty buffers.
 */
typedef struct xl_smgr_key_fork_create
{
	RelFileLocator rlocator;
	/* BLCKSZ bytes of page-formatted KEY fork data follow */
} xl_smgr_key_fork_create;

extern void log_smgrcreate(const RelFileLocator *rlocator, ForkNumber forkNum);
extern void log_smgr_key_fork_create(const RelFileLocator *rlocator,
									 const char *keyblock);

extern void smgr_redo(XLogReaderState *record);
extern void smgr_desc(StringInfo buf, XLogReaderState *record);
extern const char *smgr_identify(uint8 info);

#endif							/* STORAGE_XLOG_H */
