/*-------------------------------------------------------------------------
 *
 * sibtree.c
 *	  AM handler, insert, scan, and vacuum stubs for secondary index btree.
 *
 * A secondary index is a B-tree that stores (user_key, pk_values) tuples
 * with no TID.  Heap tuples are reached via PK index lookup.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 *
 * src/backend/access/sibtree/sibtree.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/amapi.h"
#include "access/generic_xlog.h"
#include "access/genam.h"
#include "access/nbtree.h"
#include "access/reloptions.h"
#include "access/relscan.h"
#include "access/sibtree.h"
#include "catalog/index.h"
#include "miscadmin.h"
#include "nodes/pathnodes.h"
#include "optimizer/cost.h"
#include "optimizer/optimizer.h"
#include "storage/bufmgr.h"
#include "storage/lmgr.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/index_selfuncs.h"
#include "utils/selfuncs.h"


/* Forward declarations */
static bool sibt_insert(Relation rel, Datum *values, bool *isnull,
						ItemPointer ht_ctid, Relation heapRel,
						IndexUniqueCheck checkUnique, bool indexUnchanged,
						IndexInfo *indexInfo);
static IndexScanDesc sibt_beginscan(Relation rel, int nkeys, int norderbys);
static void sibt_rescan(IndexScanDesc scan, ScanKey keys, int nkeys,
						ScanKey orderbys, int norderbys);
static bool sibt_gettuple(IndexScanDesc scan, ScanDirection dir);
static void sibt_endscan(IndexScanDesc scan);
static IndexBulkDeleteResult *sibt_bulkdelete(IndexVacuumInfo *info,
											  IndexBulkDeleteResult *stats,
											  IndexBulkDeleteCallback callback,
											  void *callback_state);
static IndexBulkDeleteResult *sibt_vacuumcleanup(IndexVacuumInfo *info,
												  IndexBulkDeleteResult *stats);
static void sibt_costestimate(PlannerInfo *root, IndexPath *path,
							  double loop_count,
							  Cost *indexStartupCost,
							  Cost *indexTotalCost,
							  Selectivity *indexSelectivity,
							  double *indexCorrelation,
							  double *indexPages);
static bytea *sibt_options(Datum reloptions, bool validate);
static bool sibt_validate(Oid opclassoid);

/* ----------------------------------------------------------------
 *		AM handler
 * ----------------------------------------------------------------
 */
Datum
sibthandler(PG_FUNCTION_ARGS)
{
	IndexAmRoutine *amroutine = makeNode(IndexAmRoutine);

	amroutine->amstrategies = BTMaxStrategyNumber;
	amroutine->amsupport = BTNProcs;
	amroutine->amoptsprocnum = 0;
	amroutine->amcanorder = true;
	amroutine->amcanorderbyop = false;
	amroutine->amcanhash = false;
	amroutine->amconsistentequality = true;
	amroutine->amconsistentordering = true;
	amroutine->amcanbackward = false;	/* no left-links */
	amroutine->amcanunique = false;
	amroutine->amcanmulticol = true;
	amroutine->amoptionalkey = true;
	amroutine->amsearcharray = false;
	amroutine->amsearchnulls = true;
	amroutine->amstorage = false;
	amroutine->amclusterable = false;
	amroutine->ampredlocks = false;
	amroutine->amcanparallel = false;
	amroutine->amcanbuildparallel = false;
	amroutine->amcaninclude = false;
	amroutine->amusemaintenanceworkmem = true;
	amroutine->amsummarizing = false;
	amroutine->amparallelvacuumoptions = 0;
	amroutine->amkeytype = InvalidOid;

	amroutine->ambuild = sibt_build;
	amroutine->ambuildempty = sibt_buildempty;
	amroutine->aminsert = sibt_insert;
	amroutine->aminsertcleanup = NULL;
	amroutine->ambulkdelete = sibt_bulkdelete;
	amroutine->amvacuumcleanup = sibt_vacuumcleanup;
	amroutine->amcanreturn = NULL;
	amroutine->amcostestimate = sibt_costestimate;
	amroutine->amgettreeheight = NULL;
	amroutine->amoptions = sibt_options;
	amroutine->amproperty = NULL;
	amroutine->ambuildphasename = NULL;
	amroutine->amvalidate = sibt_validate;
	amroutine->amadjustmembers = NULL;
	amroutine->ambeginscan = sibt_beginscan;
	amroutine->amrescan = sibt_rescan;
	amroutine->amgettuple = sibt_gettuple;
	amroutine->amgetbitmap = NULL;
	amroutine->amendscan = sibt_endscan;
	amroutine->ammarkpos = NULL;
	amroutine->amrestrpos = NULL;
	amroutine->amestimateparallelscan = NULL;
	amroutine->aminitparallelscan = NULL;
	amroutine->amparallelrescan = NULL;
	amroutine->amtranslatestrategy = bttranslatestrategy;
	amroutine->amtranslatecmptype = bttranslatecmptype;

	PG_RETURN_POINTER(amroutine);
}

/* ----------------------------------------------------------------
 *		Insert
 * ----------------------------------------------------------------
 */

/*
 * Insert a new tuple into the sibtree index by descending to the correct
 * leaf page and inserting.  Handle page splits as needed.
 */
static void
sibt_do_insert(Relation rel, SIBTuple itup)
{
	Buffer		buf;
	Page		page;
	Size		itupsz;
	OffsetNumber off;
	TupleDesc	tupdesc = RelationGetDescr(rel);
	int			nkeys = IndexRelationGetNumberOfKeyAttributes(rel);
	SIBTStack  *stack = NULL;
	ScanKeyData *keys;
	int			i;

	/* Build scan keys from the tuple's key columns for tree descent */
	keys = (ScanKeyData *) palloc(sizeof(ScanKeyData) * nkeys);
	for (i = 0; i < nkeys; i++)
	{
		bool		isnull;
		Datum		val = sibt_getattr(itup, i + 1, tupdesc, &isnull);
		Oid			opfamily = rel->rd_opfamily[i];
		Oid			typid = TupleDescAttr(tupdesc, i)->atttypid;
		Oid			cmpfn;

		cmpfn = get_opfamily_proc(opfamily, typid, typid, BTORDER_PROC);
		if (isnull)
			ScanKeyEntryInitialize(&keys[i], SK_ISNULL | SK_SEARCHNULL,
								   i + 1, BTEqualStrategyNumber,
								   InvalidOid, InvalidOid, cmpfn,
								   (Datum) 0);
		else
			ScanKeyEntryInitialize(&keys[i], 0,
								   i + 1, BTEqualStrategyNumber,
								   InvalidOid,
								   TupleDescAttr(tupdesc, i)->attcollation,
								   cmpfn, val);
	}

	/* Find the leaf page */
	buf = sibt_search_leaf(rel, keys, nkeys, tupdesc, &stack);

	itupsz = MAXALIGN(SIBTupleGetSize(itup));

	if (!BufferIsValid(buf))
	{
		/*
		 * Empty tree — create root leaf page.
		 */
		GenericXLogState *xlogstate;
		Buffer		metabuf;
		Page		metapage;
		BlockNumber newblk;

		buf = ReadBuffer(rel, P_NEW);
		newblk = BufferGetBlockNumber(buf);
		LockBuffer(buf, BUFFER_LOCK_EXCLUSIVE);

		metabuf = ReadBuffer(rel, SIBT_METAPAGE);
		LockBuffer(metabuf, BUFFER_LOCK_EXCLUSIVE);

		xlogstate = GenericXLogStart(rel);
		page = GenericXLogRegisterBuffer(xlogstate, buf,
										 GENERIC_XLOG_FULL_IMAGE);
		sibt_initpage(page, SIBTP_LEAF | SIBTP_ROOT, 0);

		if (PageAddItemExtended(page, itup, itupsz,
								FirstOffsetNumber, PAI_OVERWRITE) == InvalidOffsetNumber)
			elog(ERROR, "failed to add item to new sibtree root page");

		metapage = GenericXLogRegisterBuffer(xlogstate, metabuf,
											 GENERIC_XLOG_FULL_IMAGE);
		sibt_initmetapage(metapage, newblk, 0);

		GenericXLogFinish(xlogstate);
		UnlockReleaseBuffer(metabuf);
		UnlockReleaseBuffer(buf);
		pfree(keys);
		return;
	}

	/*
	 * Normal case — insert into existing leaf page.
	 * We had a share lock; upgrade to exclusive.
	 */
	LockBuffer(buf, BUFFER_LOCK_UNLOCK);
	LockBuffer(buf, BUFFER_LOCK_EXCLUSIVE);
	page = BufferGetPage(buf);

	/* Re-check we're on the right page after re-locking */
	{
		SIBTPageOpaque opaque = SIBTPageGetOpaque(page);

		while (opaque->sibt_right != InvalidBlockNumber)
		{
			OffsetNumber maxoff = PageGetMaxOffsetNumber(page);

			if (maxoff >= FirstOffsetNumber)
			{
				SIBTuple	lasttup = (SIBTuple) PageGetItem(page,
															 PageGetItemId(page, maxoff));
				int			cmp = sibt_compare_scankey(lasttup, keys, nkeys, NULL, tupdesc);

				if (cmp >= 0)
					break;
			}

			/* Follow right link */
			{
				BlockNumber rightblk = opaque->sibt_right;

				UnlockReleaseBuffer(buf);
				buf = ReadBuffer(rel, rightblk);
				LockBuffer(buf, BUFFER_LOCK_EXCLUSIVE);
				page = BufferGetPage(buf);
				opaque = SIBTPageGetOpaque(page);
			}
		}
	}

	/* Find insert position */
	off = sibt_binsrch_leaf(page, keys, nkeys, tupdesc);

	/* Does the tuple fit on this page? */
	if (PageGetFreeSpace(page) >= itupsz + sizeof(ItemIdData))
	{
		/* Simple insert */
		GenericXLogState *xlogstate = GenericXLogStart(rel);

		page = GenericXLogRegisterBuffer(xlogstate, buf, 0);

		if (PageAddItemExtended(page, itup, itupsz,
								off, 0) == InvalidOffsetNumber)
			elog(ERROR, "failed to add item to sibtree leaf page");

		GenericXLogFinish(xlogstate);
		UnlockReleaseBuffer(buf);
	}
	else
	{
		/* Need to split the page */
		sibt_split_and_insert(rel, buf, itup, off, keys, nkeys, stack);
	}

	/* Free stack */
	while (stack)
	{
		SIBTStack  *parent = stack->parent;

		pfree(stack);
		stack = parent;
	}
	pfree(keys);
}

/*
 * Split a leaf page and insert the new tuple.
 * buf is exclusively locked on entry; released on exit.
 */
void
sibt_split_and_insert(Relation rel, Buffer buf, SIBTuple newtuple,
					  OffsetNumber newoff, ScanKey keys, int nkeys,
					  SIBTStack *stack)
{
	Page		oldpage = BufferGetPage(buf);
	Buffer		newbuf;
	Page		newpage;
	BlockNumber oldblk = BufferGetBlockNumber(buf);
	BlockNumber newblk;
	OffsetNumber maxoff = PageGetMaxOffsetNumber(oldpage);
	OffsetNumber splitoff;
	Size		totalsize = 0;
	Size		halfsize;
	OffsetNumber i;
	GenericXLogState *xlogstate;
	TupleDesc	tupdesc = RelationGetDescr(rel);
	SIBTPageOpaque oldopaque;
	SIBTPageOpaque newopaque;
	BlockNumber old_right;

	/* Compute split point: aim for half the total data */
	for (i = FirstOffsetNumber; i <= maxoff; i++)
	{
		ItemId		itemid = PageGetItemId(oldpage, i);

		totalsize += MAXALIGN(ItemIdGetLength(itemid)) + sizeof(ItemIdData);
	}
	totalsize += MAXALIGN(SIBTupleGetSize(newtuple)) + sizeof(ItemIdData);
	halfsize = totalsize / 2;

	{
		Size		accum = 0;

		splitoff = FirstOffsetNumber;
		for (i = FirstOffsetNumber; i <= maxoff + 1; i++)
		{
			Size		sz;

			if (i == newoff)
				sz = MAXALIGN(SIBTupleGetSize(newtuple)) + sizeof(ItemIdData);
			else if (i <= maxoff)
			{
				ItemId		itemid = PageGetItemId(oldpage,
												   (i > newoff) ? i - 1 : i);

				/* Adjust for the new tuple insertion shifting offsets */
				if (i > newoff)
					itemid = PageGetItemId(oldpage, i - 1);

				sz = MAXALIGN(ItemIdGetLength(itemid)) + sizeof(ItemIdData);
			}
			else
				break;

			accum += sz;
			if (accum >= halfsize)
			{
				splitoff = i + 1;
				break;
			}
		}
		if (splitoff < SIBTP_FIRSTDATAKEY)
			splitoff = SIBTP_FIRSTDATAKEY;
	}

	/* Allocate a new right page */
	newbuf = ReadBuffer(rel, P_NEW);
	newblk = BufferGetBlockNumber(newbuf);
	LockBuffer(newbuf, BUFFER_LOCK_EXCLUSIVE);

	/* Do the split under WAL */
	xlogstate = GenericXLogStart(rel);

	oldpage = GenericXLogRegisterBuffer(xlogstate, buf, 0);
	newpage = GenericXLogRegisterBuffer(xlogstate, newbuf,
										GENERIC_XLOG_FULL_IMAGE);

	oldopaque = SIBTPageGetOpaque(oldpage);
	old_right = oldopaque->sibt_right;

	/* Initialize new page as leaf at the same level */
	sibt_initpage(newpage, SIBTP_LEAF, oldopaque->sibt_level);
	newopaque = SIBTPageGetOpaque(newpage);
	newopaque->sibt_right = old_right;
	oldopaque->sibt_right = newblk;

	/* Clear the root flag on old page if it was root */
	oldopaque->sibt_flags &= ~SIBTP_ROOT;

	/*
	 * Rebuild: put tuples before splitoff on old page, rest on new page.
	 * We need to handle the inserted tuple too.
	 *
	 * Simplest approach: collect all tuples into a temporary array,
	 * then distribute.
	 */
	{
		int			totalcount = maxoff + 1;	/* existing + new */
		SIBTuple   *alltuples;
		Size	   *allsizes;
		int			idx = 0;

		alltuples = (SIBTuple *) palloc(sizeof(SIBTuple) * totalcount);
		allsizes = (Size *) palloc(sizeof(Size) * totalcount);

		for (i = FirstOffsetNumber; i <= maxoff + 1; i++)
		{
			if (i == newoff)
			{
				alltuples[idx] = newtuple;
				allsizes[idx] = MAXALIGN(SIBTupleGetSize(newtuple));
				idx++;
			}
			if (i <= maxoff)
			{
				SIBTuple	existing = (SIBTuple) PageGetItem(
								  BufferGetPage(buf),  /* use original page data */
								  PageGetItemId(BufferGetPage(buf), i));
				/* copy since we're going to rebuild the page */
				SIBTuple	copy = (SIBTuple) palloc(SIBTupleGetSize(existing));

				memcpy(copy, existing, SIBTupleGetSize(existing));
				alltuples[idx] = copy;
				allsizes[idx] = MAXALIGN(SIBTupleGetSize(existing));
				idx++;
			}
		}

		/* Clear old page data (keep header and opaque) */
		{
			SIBTPageOpaqueData saved_opaque = *oldopaque;

			PageInit(oldpage, BLCKSZ, sizeof(SIBTPageOpaqueData));
			*SIBTPageGetOpaque(oldpage) = saved_opaque;
		}

		/* Distribute tuples */
		{
			OffsetNumber offnum;

			/* Left page: tuples 0..splitoff-2 */
			offnum = FirstOffsetNumber;
			for (i = 0; i < splitoff - 1 && i < idx; i++)
			{
				if (PageAddItemExtended(oldpage, alltuples[i],
										allsizes[i], offnum, 0) == InvalidOffsetNumber)
					elog(ERROR, "failed to add item during sibtree split (left)");
				offnum++;
			}

			/* Right page: remaining tuples */
			offnum = FirstOffsetNumber;
			for (; i < idx; i++)
			{
				if (PageAddItemExtended(newpage, alltuples[i],
										allsizes[i], offnum, 0) == InvalidOffsetNumber)
					elog(ERROR, "failed to add item during sibtree split (right)");
				offnum++;
			}
		}

		/* Free copies */
		for (i = 0; i < idx; i++)
		{
			if (alltuples[i] != newtuple)
				pfree(alltuples[i]);
		}
		pfree(alltuples);
		pfree(allsizes);
	}

	GenericXLogFinish(xlogstate);
	UnlockReleaseBuffer(newbuf);
	UnlockReleaseBuffer(buf);

	/*
	 * Now insert the separator key (first key on the new right page) into
	 * the parent.  The separator is the first tuple's key columns on the
	 * new page.
	 */
	{
		Buffer		parentbuf;
		Page		parentpage;
		SIBTuple	sep;
		Datum	   *sepvalues;
		bool	   *sepisnull;
		int			nkeyatts = IndexRelationGetNumberOfKeyAttributes(rel);

		/* Read new page to get the separator key */
		newbuf = ReadBuffer(rel, newblk);
		LockBuffer(newbuf, BUFFER_LOCK_SHARE);
		newpage = BufferGetPage(newbuf);
		{
			SIBTuple	firsttup = (SIBTuple) PageGetItem(newpage,
														  PageGetItemId(newpage, FirstOffsetNumber));

			sepvalues = (Datum *) palloc(sizeof(Datum) * nkeyatts);
			sepisnull = (bool *) palloc(sizeof(bool) * nkeyatts);
			for (i = 0; i < nkeyatts; i++)
				sepvalues[i] = sibt_getattr(firsttup, i + 1, tupdesc,
											&sepisnull[i]);
		}
		UnlockReleaseBuffer(newbuf);

		/* Form internal tuple with separator key + pointer to new right page */
		sep = sibt_form_internal_tuple(tupdesc, sepvalues, sepisnull,
									   nkeyatts, newblk);
		pfree(sepvalues);
		pfree(sepisnull);

		if (stack != NULL)
		{
			/* Insert into parent page */
			parentbuf = ReadBuffer(rel, stack->blkno);
			LockBuffer(parentbuf, BUFFER_LOCK_EXCLUSIVE);
			parentpage = BufferGetPage(parentbuf);

			if (PageGetFreeSpace(parentpage) >=
				MAXALIGN(SIBTupleGetSize(sep)) + sizeof(ItemIdData))
			{
				GenericXLogState *pxlog = GenericXLogStart(rel);
				OffsetNumber parentoff = stack->offset + 1;

				parentpage = GenericXLogRegisterBuffer(pxlog, parentbuf, 0);

				if (PageAddItemExtended(parentpage, sep,
										MAXALIGN(SIBTupleGetSize(sep)),
										parentoff, 0) == InvalidOffsetNumber)
					elog(ERROR, "failed to add separator to parent during sibtree split");

				GenericXLogFinish(pxlog);
				UnlockReleaseBuffer(parentbuf);
			}
			else
			{
				/* Parent needs splitting too — recursive call */
				sibt_split_and_insert(rel, parentbuf, sep,
									  stack->offset + 1,
									  keys, nkeys, stack->parent);
			}
		}
		else
		{
			/*
			 * No parent — we split the root.  Create a new root page.
			 */
			Buffer		rootbuf;
			Buffer		metabuf;
			Page		rootpage;
			Page		metapage;
			BlockNumber rootblk;
			GenericXLogState *rxlog;
			SIBTuple	minf;
			Size		minfsize;

			rootbuf = ReadBuffer(rel, P_NEW);
			rootblk = BufferGetBlockNumber(rootbuf);
			LockBuffer(rootbuf, BUFFER_LOCK_EXCLUSIVE);

			metabuf = ReadBuffer(rel, SIBT_METAPAGE);
			LockBuffer(metabuf, BUFFER_LOCK_EXCLUSIVE);

			rxlog = GenericXLogStart(rel);

			rootpage = GenericXLogRegisterBuffer(rxlog, rootbuf,
												 GENERIC_XLOG_FULL_IMAGE);
			sibt_initpage(rootpage, SIBTP_ROOT, 1);	/* level = old level + 1 */

			metapage = GenericXLogRegisterBuffer(rxlog, metabuf, 0);
			{
				SIBTMetaPageData *meta = SIBTPageGetMeta(metapage);

				meta->sibtm_root = rootblk;
				meta->sibtm_level++;
			}

			/* First entry: minus-infinity pointing to old root (left child) */
			minfsize = MAXALIGN(sizeof(SIBTupleData)) + sizeof(BlockNumber);
			minf = (SIBTuple) palloc0(minfsize);
			minf->si_info = (uint16) minfsize;
			SIBTupleSetChildBlkno(minf, oldblk);

			if (PageAddItemExtended(rootpage, minf,
									MAXALIGN(minfsize),
									FirstOffsetNumber, 0) == InvalidOffsetNumber)
				elog(ERROR, "failed to add minus-infinity to new root");

			/* Second entry: separator key pointing to new right page */
			if (PageAddItemExtended(rootpage, sep,
									MAXALIGN(SIBTupleGetSize(sep)),
									FirstOffsetNumber + 1, 0) == InvalidOffsetNumber)
				elog(ERROR, "failed to add separator to new root");

			GenericXLogFinish(rxlog);
			UnlockReleaseBuffer(metabuf);
			UnlockReleaseBuffer(rootbuf);
			pfree(minf);
		}

		pfree(sep);
	}
}

static bool
sibt_insert(Relation rel, Datum *values, bool *isnull,
			ItemPointer ht_ctid, Relation heapRel,
			IndexUniqueCheck checkUnique, bool indexUnchanged,
			IndexInfo *indexInfo)
{
	SIBTuple	itup;
	TupleDesc	tupdesc = RelationGetDescr(rel);
	int			natts = tupdesc->natts;

	/* Form our custom tuple (all columns: key + PK) */
	itup = sibt_form_tuple(tupdesc, values, isnull, natts);

	/* Check size */
	if (SIBTupleGetSize(itup) > SIBTMaxItemSize)
		ereport(ERROR,
				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
				 errmsg("index row size %zu exceeds maximum %zu for index \"%s\"",
						(Size) SIBTupleGetSize(itup),
						(Size) SIBTMaxItemSize,
						RelationGetRelationName(rel))));

	sibt_do_insert(rel, itup);

	pfree(itup);
	return false;
}

/* ----------------------------------------------------------------
 *		Scan
 * ----------------------------------------------------------------
 */
static IndexScanDesc
sibt_beginscan(Relation rel, int nkeys, int norderbys)
{
	IndexScanDesc scan;
	SIBTScanOpaque so;

	scan = RelationGetIndexScan(rel, nkeys, norderbys);

	so = (SIBTScanOpaque) palloc0(sizeof(SIBTScanOpaqueData));
	so->qual_ok = true;
	so->currBuf = InvalidBuffer;
	so->started = false;
	so->finished = false;
	so->numItems = 0;
	so->currItem = 0;
	so->items = NULL;

	/* Set up btree comparison functions for each key column */
	{
		int			nkeyattrs = IndexRelationGetNumberOfKeyAttributes(rel);

		so->orderProcs = (FmgrInfo *) palloc(sizeof(FmgrInfo) * nkeyattrs);
		for (int i = 0; i < nkeyattrs; i++)
		{
			FmgrInfo   *procinfo = index_getprocinfo(rel, i + 1, BTORDER_PROC);

			fmgr_info_copy(&so->orderProcs[i], procinfo, CurrentMemoryContext);
		}
	}

	scan->opaque = so;

	return scan;
}

static void
sibt_rescan(IndexScanDesc scan, ScanKey keys, int nkeys,
			ScanKey orderbys, int norderbys)
{
	SIBTScanOpaque so = (SIBTScanOpaque) scan->opaque;

	/* Release any held buffer */
	if (BufferIsValid(so->currBuf))
	{
		ReleaseBuffer(so->currBuf);
		so->currBuf = InvalidBuffer;
	}

	/* Free cached items */
	if (so->items)
	{
		for (int i = 0; i < so->numItems; i++)
			pfree(so->items[i]);
		pfree(so->items);
		so->items = NULL;
	}

	so->started = false;
	so->finished = false;
	so->numItems = 0;
	so->currItem = 0;
	so->qual_ok = true;

	/* Copy scan keys and replace sk_func with btree comparison functions */
	if (keys && nkeys > 0)
	{
		memmove(scan->keyData, keys, nkeys * sizeof(ScanKeyData));
		so->numberOfKeys = nkeys;

		/*
		 * The executor provides scan keys with operator functions (e.g.
		 * int4eq for =).  We need btree comparison functions (BTORDER_PROC)
		 * that return -1/0/1 for our tree traversal and tuple comparison.
		 * Index orderProcs by column (sk_attno - 1).
		 */
		for (int i = 0; i < nkeys; i++)
		{
			AttrNumber	attno = scan->keyData[i].sk_attno;

			if (so->orderProcs && attno > 0)
				fmgr_info_copy(&scan->keyData[i].sk_func,
							   &so->orderProcs[attno - 1],
							   CurrentMemoryContext);
		}
	}
	else
		so->numberOfKeys = 0;
}

/*
 * Read all matching tuples from a leaf page, converting them to IndexTuples.
 * Returns the number of matching items stored.
 */
static int
sibt_readpage(IndexScanDesc scan, Page page, ScanDirection dir)
{
	SIBTScanOpaque so = (SIBTScanOpaque) scan->opaque;
	TupleDesc	tupdesc = RelationGetDescr(scan->indexRelation);
	int			natts = tupdesc->natts;
	OffsetNumber maxoff = PageGetMaxOffsetNumber(page);
	OffsetNumber off;
	int			count = 0;
	int			maxitems;
	MemoryContext oldcxt;

	/* Free previous items */
	if (so->items)
	{
		for (int i = 0; i < so->numItems; i++)
			pfree(so->items[i]);
		pfree(so->items);
	}

	maxitems = maxoff;
	so->items = (IndexTuple *) palloc(sizeof(IndexTuple) * maxitems);

	oldcxt = MemoryContextSwitchTo(CurTransactionContext);

	for (off = FirstOffsetNumber; off <= maxoff; off++)
	{
		SIBTuple	situp = (SIBTuple) PageGetItem(page,
												   PageGetItemId(page, off));
		bool		matches = true;
		bool		past_end = false;

		/*
		 * Check each scan key against the tuple.  We need to handle
		 * different strategies (=, <, <=, >=, >) correctly.
		 */
		for (int k = 0; k < so->numberOfKeys; k++)
		{
			ScanKey		key = &scan->keyData[k];
			Datum		val;
			bool		isnull;
			int32		cmp;

			if (key->sk_flags & SK_ISNULL)
			{
				/* NULL scan key: skip for now */
				matches = false;
				break;
			}

			val = sibt_getattr(situp, key->sk_attno, tupdesc, &isnull);
			if (isnull)
			{
				matches = false;
				break;
			}

			cmp = DatumGetInt32(FunctionCall2Coll(&key->sk_func,
												  key->sk_collation,
												  val,
												  key->sk_argument));

			switch (key->sk_strategy)
			{
				case BTLessStrategyNumber:		/* < */
					if (cmp >= 0)
					{
						matches = false;
						past_end = true;
					}
					break;
				case BTLessEqualStrategyNumber:	/* <= */
					if (cmp > 0)
					{
						matches = false;
						past_end = true;
					}
					break;
				case BTEqualStrategyNumber:		/* = */
					if (cmp != 0)
					{
						matches = false;
						if (cmp > 0)
							past_end = true;
					}
					break;
				case BTGreaterEqualStrategyNumber:	/* >= */
					if (cmp < 0)
						matches = false;
					break;
				case BTGreaterStrategyNumber:	/* > */
					if (cmp <= 0)
						matches = false;
					break;
				default:
					matches = false;
					break;
			}

			if (!matches)
				break;
		}

		if (past_end)
			break;

		if (!matches)
			continue;

		/* Convert to IndexTuple so executor can use index_getattr() */
		so->items[count] = sibt_convert_to_itup(situp, tupdesc, natts);
		count++;
	}

	MemoryContextSwitchTo(oldcxt);

	so->numItems = count;
	so->currItem = 0;
	return count;
}

static bool
sibt_gettuple(IndexScanDesc scan, ScanDirection dir)
{
	SIBTScanOpaque so = (SIBTScanOpaque) scan->opaque;
	TupleDesc	tupdesc = RelationGetDescr(scan->indexRelation);

	if (so->finished)
		return false;

	/* Only forward scans for now */
	if (!ScanDirectionIsForward(dir))
		elog(ERROR, "sibtree does not support backward scans");

	if (!so->started)
	{
		Buffer		buf;

		/* Find the starting leaf page */
		buf = sibt_search_leaf(scan->indexRelation,
							   scan->keyData, so->numberOfKeys,
							   tupdesc, NULL);

		if (!BufferIsValid(buf))
		{
			so->finished = true;
			return false;
		}

		/* Read matching tuples from this page */
		{
			Page		page = BufferGetPage(buf);

			sibt_readpage(scan, page, dir);
		}

		/* Keep the buffer pinned (but unlock) for navigating to next page */
		so->currBuf = buf;
		LockBuffer(buf, BUFFER_LOCK_UNLOCK);
		so->started = true;
	}

	/* Return next cached item */
	while (true)
	{
		if (so->currItem < so->numItems)
		{
			IndexTuple	itup = so->items[so->currItem];

			so->currItem++;

			/*
			 * Set xs_itup so IndexNextSecondary() can extract PK values
			 * using index_getattr().  Set xs_heaptid to a dummy valid
			 * value so index_getnext_tid() doesn't think scan is over.
			 */
			scan->xs_itup = itup;
			scan->xs_itupdesc = tupdesc;
			ItemPointerSet(&scan->xs_heaptid, 0, 1);
			scan->xs_recheck = false;
			return true;
		}

		/* Move to next leaf page via right-link */
		if (BufferIsValid(so->currBuf))
		{
			Page		page;
			SIBTPageOpaque opaque;
			BlockNumber rightblk;

			LockBuffer(so->currBuf, BUFFER_LOCK_SHARE);
			page = BufferGetPage(so->currBuf);
			opaque = SIBTPageGetOpaque(page);
			rightblk = opaque->sibt_right;
			LockBuffer(so->currBuf, BUFFER_LOCK_UNLOCK);

			if (rightblk == InvalidBlockNumber)
			{
				ReleaseBuffer(so->currBuf);
				so->currBuf = InvalidBuffer;
				so->finished = true;
				return false;
			}

			/* Release old buffer, read next page */
			ReleaseBuffer(so->currBuf);
			so->currBuf = ReadBuffer(scan->indexRelation, rightblk);
			LockBuffer(so->currBuf, BUFFER_LOCK_SHARE);

			{
				Page		nextpage = BufferGetPage(so->currBuf);
				int			n = sibt_readpage(scan, nextpage, dir);

				LockBuffer(so->currBuf, BUFFER_LOCK_UNLOCK);

				if (n == 0)
				{
					/* No more matching tuples */
					ReleaseBuffer(so->currBuf);
					so->currBuf = InvalidBuffer;
					so->finished = true;
					return false;
				}
			}
		}
		else
		{
			so->finished = true;
			return false;
		}
	}
}

static void
sibt_endscan(IndexScanDesc scan)
{
	SIBTScanOpaque so = (SIBTScanOpaque) scan->opaque;

	if (BufferIsValid(so->currBuf))
		ReleaseBuffer(so->currBuf);

	if (so->items)
	{
		for (int i = 0; i < so->numItems; i++)
			pfree(so->items[i]);
		pfree(so->items);
	}

	pfree(so);
}

/* ----------------------------------------------------------------
 *		Vacuum — no-ops for secondary indexes
 * ----------------------------------------------------------------
 */
static IndexBulkDeleteResult *
sibt_bulkdelete(IndexVacuumInfo *info, IndexBulkDeleteResult *stats,
				IndexBulkDeleteCallback callback, void *callback_state)
{
	/* Secondary indexes skip bulk deletion entirely */
	if (stats == NULL)
		stats = (IndexBulkDeleteResult *) palloc0(sizeof(IndexBulkDeleteResult));

	return stats;
}

static IndexBulkDeleteResult *
sibt_vacuumcleanup(IndexVacuumInfo *info, IndexBulkDeleteResult *stats)
{
	if (stats == NULL)
		stats = (IndexBulkDeleteResult *) palloc0(sizeof(IndexBulkDeleteResult));

	stats->num_pages = RelationGetNumberOfBlocks(info->index);
	stats->pages_free = 0;

	return stats;
}

/* ----------------------------------------------------------------
 *		Cost estimation — delegate to btcostestimate + PK overhead
 * ----------------------------------------------------------------
 */
static void
sibt_costestimate(PlannerInfo *root, IndexPath *path,
				  double loop_count,
				  Cost *indexStartupCost,
				  Cost *indexTotalCost,
				  Selectivity *indexSelectivity,
				  double *indexCorrelation,
				  double *indexPages)
{
	/* Use btree's cost estimator as base */
	btcostestimate(root, path, loop_count,
				   indexStartupCost, indexTotalCost,
				   indexSelectivity, indexCorrelation, indexPages);

	/*
	 * Add PK lookup cost per tuple: one extra btree descent per row
	 * retrieved through the secondary index.
	 */
	{
		double		tuples = *indexSelectivity * path->indexinfo->rel->rows;

		*indexTotalCost += tuples * (random_page_cost + cpu_index_tuple_cost * 3);
	}
}

/* ----------------------------------------------------------------
 *		Options and validation
 * ----------------------------------------------------------------
 */
static bytea *
sibt_options(Datum reloptions, bool validate)
{
	return default_reloptions(reloptions, validate, RELOPT_KIND_BTREE);
}

static bool
sibt_validate(Oid opclassoid)
{
	/* Accept any opclass that btree accepts */
	return btvalidate(opclassoid);
}
