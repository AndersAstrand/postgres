/*-------------------------------------------------------------------------
 *
 * sibtree.h
 *	  Header file for secondary index btree access method.
 *
 * A secondary index stores (user_key_columns, pk_columns) in a custom
 * B-tree with no TID in the tuple.  Lookups go through the primary key
 * index to reach heap tuples.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 *
 * src/include/access/sibtree.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef SIBTREE_H
#define SIBTREE_H

#include "access/amapi.h"
#include "access/itup.h"
#include "access/sdir.h"
#include "access/genam.h"
#include "storage/bufmgr.h"
#include "storage/bufpage.h"
#include "storage/bulk_write.h"
#include "utils/relcache.h"

/*
 * On-disk tuple format for secondary index.
 *
 * Leaf tuples:   [si_info] [null bitmap?] [key cols data] [pk cols data]
 * Internal tuples: [si_info] [null bitmap?] [key cols data] [child BlockNumber]
 *
 * si_info layout (16 bits):
 *   bits 0-11:  tuple size in bytes (max 4095)
 *   bit  12:    has nulls
 *   bit  13:    unused
 *   bits 14-15: unused
 *
 * No TID anywhere.  PK values are the logical pointer for leaf tuples.
 * Child block number is the pointer for internal tuples.
 */
typedef struct SIBTupleData
{
	uint16		si_info;
	/* null bitmap and data follow */
} SIBTupleData;

typedef SIBTupleData *SIBTuple;

/* si_info masks */
#define SIBT_SIZE_MASK		0x0FFF	/* 12 bits for size */
#define SIBT_NULL_MASK		0x1000	/* has nulls */

/* Tuple accessors */
#define SIBTupleGetSize(itup)		((itup)->si_info & SIBT_SIZE_MASK)
#define SIBTupleHasNulls(itup)		(((itup)->si_info & SIBT_NULL_MASK) != 0)

/*
 * Data offset: where column data starts within the tuple.
 * Without nulls: MAXALIGN(sizeof(SIBTupleData)) = typically 2->8 with MAXALIGN
 * With nulls: MAXALIGN(sizeof(SIBTupleData) + sizeof(IndexAttributeBitMapData))
 */
static inline Size
SIBTupleDataOffset(uint16 si_info)
{
	if (!(si_info & SIBT_NULL_MASK))
		return MAXALIGN(sizeof(SIBTupleData));
	else
		return MAXALIGN(sizeof(SIBTupleData) + sizeof(IndexAttributeBitMapData));
}

/*
 * Get the null bitmap pointer (or NULL if no nulls).
 */
static inline bits8 *
SIBTupleGetNullBits(SIBTuple itup)
{
	if (!SIBTupleHasNulls(itup))
		return NULL;
	return (bits8 *) ((char *) itup + sizeof(SIBTupleData));
}

/*
 * For internal (non-leaf) tuples, the child block number is stored as the
 * last piece of data in the tuple.
 */
static inline BlockNumber
SIBTupleGetChildBlkno(SIBTuple itup)
{
	BlockNumber blkno;

	memcpy(&blkno,
		   (char *) itup + SIBTupleGetSize(itup) - sizeof(BlockNumber),
		   sizeof(BlockNumber));
	return blkno;
}

static inline void
SIBTupleSetChildBlkno(SIBTuple itup, BlockNumber blkno)
{
	memcpy((char *) itup + SIBTupleGetSize(itup) - sizeof(BlockNumber),
		   &blkno, sizeof(BlockNumber));
}

/*
 * Page opaque data — stored in the special space at the end of each page.
 */
typedef struct SIBTPageOpaqueData
{
	BlockNumber sibt_right;		/* right sibling, or InvalidBlockNumber */
	uint16		sibt_level;		/* 0 = leaf */
	uint16		sibt_flags;		/* flag bits, see below */
} SIBTPageOpaqueData;

typedef SIBTPageOpaqueData *SIBTPageOpaque;

/* Page flag bits */
#define SIBTP_LEAF				0x0001
#define SIBTP_ROOT				0x0002
#define SIBTP_META				0x0004
#define SIBTP_INCOMPLETE_SPLIT	0x0008

/* Page accessors */
#define SIBTPageGetOpaque(page) \
	((SIBTPageOpaque) PageGetSpecialPointer(page))

#define SIBTPageIsLeaf(page)	(SIBTPageGetOpaque(page)->sibt_flags & SIBTP_LEAF)
#define SIBTPageIsRoot(page)	(SIBTPageGetOpaque(page)->sibt_flags & SIBTP_ROOT)

/*
 * On internal pages, offset 1 is the "minus infinity" entry: it has no key
 * data, only a child block number.  Real data keys start at offset 2.
 */
#define SIBTP_FIRSTDATAKEY		2

/*
 * Meta page layout — page 0 is always the meta page.
 */
#define SIBT_METAPAGE		0
#define SIBT_MAGIC			0x53494254	/* "SIBT" */
#define SIBT_VERSION		1

typedef struct SIBTMetaPageData
{
	uint32		sibtm_magic;
	uint32		sibtm_version;
	BlockNumber sibtm_root;		/* root page, or InvalidBlockNumber */
	uint16		sibtm_level;	/* tree level of root (0 = leaf) */
} SIBTMetaPageData;

#define SIBTPageGetMeta(page) \
	((SIBTMetaPageData *) PageGetContents(page))

/*
 * Maximum tuple size that can fit on a page. We need at least 3 items
 * per page for splits to work.
 */
#define SIBTMaxItemSize \
	MAXALIGN_DOWN((BLCKSZ - \
				   MAXALIGN(SizeOfPageHeaderData + 3 * sizeof(ItemIdData)) - \
				   MAXALIGN(sizeof(SIBTPageOpaqueData))) / 3)

/*
 * Scan opaque data
 */
typedef struct SIBTScanOpaqueData
{
	/* Preprocessed scan keys and comparison support */
	bool		qual_ok;
	int			numberOfKeys;
	ScanKeyData *keyData;
	FmgrInfo   *orderProcs;		/* cmp functions for each key column */

	/* Current scan position */
	bool		started;
	bool		finished;
	Buffer		currBuf;		/* currently locked leaf page */
	OffsetNumber currOffset;	/* next offset to examine on page */
	ScanDirection currDir;

	/*
	 * Page read-ahead: we convert all matching tuples from the current page
	 * into IndexTuple format and cache them here.  This allows the executor's
	 * IndexNextSecondary() to use standard index_getattr() on xs_itup.
	 */
	int			numItems;
	int			currItem;
	IndexTuple *items;			/* palloc'd array of IndexTuples */
} SIBTScanOpaqueData;

typedef SIBTScanOpaqueData *SIBTScanOpaque;

/*
 * Stack frame for tree descent (used during insert to remember parent pages
 * for split propagation).
 */
typedef struct SIBTStack
{
	BlockNumber blkno;
	OffsetNumber offset;		/* where the child pointer was */
	struct SIBTStack *parent;
} SIBTStack;

/*
 * Build state for sorted bulk load.
 */
typedef struct SIBTBuildLevel
{
	BulkWriteBuffer buf;
	BlockNumber blkno;
	OffsetNumber lastoff;
	uint16		level;
	struct SIBTBuildLevel *parent;
} SIBTBuildLevel;

typedef struct SIBTBuildState
{
	Relation	heap;
	Relation	index;
	BulkWriteState *bulkstate;
	BlockNumber pages_alloced;
	SIBTBuildLevel *leaf;		/* current leaf level state */
	double		indtuples;		/* count of tuples indexed */
} SIBTBuildState;


/* ---- Function prototypes ---- */

/* sibtree.c — AM handler and main entry points */
extern Datum sibthandler(PG_FUNCTION_ARGS);

/* sibtpage.c — page and tuple operations */
extern void sibt_initpage(Page page, uint16 flags, uint16 level);
extern void sibt_initmetapage(Page page, BlockNumber root, uint16 level);
extern SIBTuple sibt_form_tuple(TupleDesc tupdesc, Datum *values, bool *isnull,
								int nattrs);
extern SIBTuple sibt_form_internal_tuple(TupleDesc tupdesc, Datum *values,
										 bool *isnull, int nkeyattrs,
										 BlockNumber child);
extern Datum sibt_getattr(SIBTuple itup, int attnum, TupleDesc tupdesc,
						  bool *isnull);
extern IndexTuple sibt_convert_to_itup(SIBTuple situp, TupleDesc tupdesc,
									   int natts);
extern int	sibt_compare_scankey(SIBTuple itup, ScanKey keys, int nkeys,
								 FmgrInfo *orderProcs, TupleDesc tupdesc);
extern int	sibt_compare_tuples(SIBTuple a, SIBTuple b, TupleDesc tupdesc,
								ScanKey keys, int nkeys, int natts);

/* sibtree.c — split helper (called recursively) */
extern void sibt_split_and_insert(Relation rel, Buffer buf, SIBTuple newtuple,
								  OffsetNumber newoff, ScanKey keys, int nkeys,
								  SIBTStack *stack);

/* sibtsearch.c — tree descent and scan */
extern Buffer sibt_search_leaf(Relation rel, ScanKey keys, int nkeys,
							   TupleDesc tupdesc, SIBTStack **stackp);
extern OffsetNumber sibt_binsrch_leaf(Page page, ScanKey keys, int nkeys,
									  TupleDesc tupdesc);
extern OffsetNumber sibt_binsrch_internal(Page page, ScanKey keys, int nkeys,
										  TupleDesc tupdesc);

/* sibtsort.c — sorted bulk build */
extern IndexBuildResult *sibt_build(Relation heap, Relation index,
									IndexInfo *indexInfo);
extern void sibt_buildempty(Relation index);

#endif							/* SIBTREE_H */
