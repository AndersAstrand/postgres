/*-------------------------------------------------------------------------
 *
 * sibtsort.c
 *	  Sorted bulk build for secondary index btree.
 *
 * Builds the index bottom-up: sort all tuples, write leaf pages
 * left-to-right, propagate separators to parent pages.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 *
 * src/backend/access/sibtree/sibtsort.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/sibtree.h"
#include "access/tableam.h"
#include "catalog/index.h"
#include "miscadmin.h"
#include "storage/bulk_write.h"
#include "utils/sortsupport.h"
#include "utils/tuplesort.h"

/* Fill factors */
#define SIBT_LEAF_FILLFACTOR	0.90
#define SIBT_INTERNAL_FILLFACTOR 0.70

/* Forward declarations */
static void sibt_build_callback(Relation index, ItemPointer tid,
								Datum *values, bool *isnull,
								bool tupleIsAlive, void *state);
static void sibt_load(SIBTBuildState *state, Tuplesortstate *sortstate);
static SIBTBuildLevel *sibt_pagestate_new(SIBTBuildState *state, uint16 level);
static void sibt_buildadd(SIBTBuildState *state, SIBTBuildLevel *lvl,
						  SIBTuple itup);
static void sibt_uppershutdown(SIBTBuildState *state);

/*
 * Main entry point for building a sibtree index.
 */
IndexBuildResult *
sibt_build(Relation heap, Relation index, IndexInfo *indexInfo)
{
	IndexBuildResult *result;
	SIBTBuildState buildstate;
	Tuplesortstate *sortstate;
	double		reltuples;
	int			natts = RelationGetDescr(index)->natts;

	buildstate.heap = heap;
	buildstate.index = index;
	buildstate.indtuples = 0;

	/*
	 * Sort phase: use tuplesort to sort index tuples by key columns.
	 * We use the standard btree tuplesort since our comparison order
	 * is the same.
	 */
	sortstate = tuplesort_begin_index_btree(heap, index, false, false,
											maintenance_work_mem, NULL, TUPLESORT_NONE);

	/* Scan the heap and spool tuples */
	reltuples = table_index_build_scan(heap, index, indexInfo, true, true,
									   sibt_build_callback,
									   (void *) sortstate, NULL);

	/* Sort */
	tuplesort_performsort(sortstate);

	/* Load sorted tuples into pages */
	buildstate.indtuples = 0;
	buildstate.bulkstate = smgr_bulk_start_rel(index, MAIN_FORKNUM);
	buildstate.pages_alloced = 0;
	buildstate.leaf = NULL;

	/* Reserve block 0 for meta page */
	buildstate.pages_alloced = 1;

	sibt_load(&buildstate, sortstate);

	tuplesort_end(sortstate);

	/* Write the meta page */
	{
		BulkWriteBuffer metabuf = smgr_bulk_get_buf(buildstate.bulkstate);
		BlockNumber root = InvalidBlockNumber;
		uint16		level = 0;

		/* Find the root from the build levels */
		if (buildstate.leaf != NULL)
		{
			SIBTBuildLevel *lvl = buildstate.leaf;

			while (lvl != NULL)
			{
				root = lvl->blkno;
				level = lvl->level;
				lvl = lvl->parent;
			}
		}

		sibt_initmetapage((Page) metabuf, root, level);
		smgr_bulk_write(buildstate.bulkstate, SIBT_METAPAGE, metabuf, true);
	}

	smgr_bulk_finish(buildstate.bulkstate);

	result = (IndexBuildResult *) palloc(sizeof(IndexBuildResult));
	result->heap_tuples = reltuples;
	result->index_tuples = buildstate.indtuples;

	return result;
}

/*
 * Build callback — called for each heap tuple.
 * Spools the tuple into tuplesort.
 */
static void
sibt_build_callback(Relation index, ItemPointer tid,
					Datum *values, bool *isnull,
					bool tupleIsAlive, void *state)
{
	Tuplesortstate *sortstate = (Tuplesortstate *) state;

	tuplesort_putindextuplevalues(sortstate, index, tid, values, isnull);
}

/*
 * Load sorted tuples from tuplesort into sibtree pages.
 */
static void
sibt_load(SIBTBuildState *state, Tuplesortstate *sortstate)
{
	IndexTuple	itup;
	TupleDesc	tupdesc = RelationGetDescr(state->index);
	int			natts = tupdesc->natts;

	/* Iterate through sorted tuples */
	while ((itup = tuplesort_getindextuple(sortstate, true)) != NULL)
	{
		Datum	   *values;
		bool	   *isnull;
		SIBTuple	situp;
		int			i;

		CHECK_FOR_INTERRUPTS();

		/* Deform the IndexTuple and form our SIBTuple */
		values = (Datum *) palloc(sizeof(Datum) * natts);
		isnull = (bool *) palloc(sizeof(bool) * natts);

		for (i = 0; i < natts; i++)
			values[i] = index_getattr(itup, i + 1, tupdesc, &isnull[i]);

		situp = sibt_form_tuple(tupdesc, values, isnull, natts);
		pfree(values);
		pfree(isnull);

		/* Ensure we have a leaf level */
		if (state->leaf == NULL)
			state->leaf = sibt_pagestate_new(state, 0);

		sibt_buildadd(state, state->leaf, situp);
		state->indtuples++;

		pfree(situp);
	}

	/* Finalize all levels */
	sibt_uppershutdown(state);
}

/*
 * Allocate and initialize a new build level.
 */
static SIBTBuildLevel *
sibt_pagestate_new(SIBTBuildState *state, uint16 level)
{
	SIBTBuildLevel *lvl;
	Page		page;

	lvl = (SIBTBuildLevel *) palloc0(sizeof(SIBTBuildLevel));
	lvl->level = level;
	lvl->parent = NULL;

	/* Allocate the first page for this level */
	lvl->buf = smgr_bulk_get_buf(state->bulkstate);
	lvl->blkno = state->pages_alloced++;
	lvl->lastoff = 0;

	page = (Page) lvl->buf;

	if (level == 0)
		sibt_initpage(page, SIBTP_LEAF, level);
	else
		sibt_initpage(page, 0, level);

	return lvl;
}

/*
 * Add a tuple to a build level page.  If the page is full, write it out,
 * propagate a separator to the parent, and start a new page.
 */
static void
sibt_buildadd(SIBTBuildState *state, SIBTBuildLevel *lvl, SIBTuple itup)
{
	Page		page = (Page) lvl->buf;
	Size		itupsz = MAXALIGN(SIBTupleGetSize(itup));
	Size		maxsize;
	TupleDesc	tupdesc = RelationGetDescr(state->index);
	int			nkeyattrs = IndexRelationGetNumberOfKeyAttributes(state->index);

	/* Compute page fill limit based on level */
	maxsize = BLCKSZ - MAXALIGN(SizeOfPageHeaderData) -
		MAXALIGN(sizeof(SIBTPageOpaqueData));
	if (lvl->level == 0)
		maxsize = (Size) (maxsize * SIBT_LEAF_FILLFACTOR);
	else
		maxsize = (Size) (maxsize * SIBT_INTERNAL_FILLFACTOR);

	/* Check if tuple fits on the current page */
	if (lvl->lastoff > 0 &&
		PageGetFreeSpace(page) < itupsz + sizeof(ItemIdData))
	{
		/*
		 * Page is full.  Write it out and propagate separator to parent.
		 */
		SIBTPageOpaque opaque;
		BlockNumber newblk = state->pages_alloced++;
		BulkWriteBuffer newbuf;
		Page		newpage;

		/* Set right-link to the new page */
		opaque = SIBTPageGetOpaque(page);
		opaque->sibt_right = newblk;

		/* Write the full page */
		smgr_bulk_write(state->bulkstate, lvl->blkno, lvl->buf, true);

		/* Propagate separator key to parent */
		{
			Datum	   *sepvalues;
			bool	   *sepisnull;
			SIBTuple	sep;
			int			i;

			/*
			 * The separator is the first key of the new page (i.e., the
			 * current tuple we're about to insert).
			 */
			sepvalues = (Datum *) palloc(sizeof(Datum) * nkeyattrs);
			sepisnull = (bool *) palloc(sizeof(bool) * nkeyattrs);
			for (i = 0; i < nkeyattrs; i++)
				sepvalues[i] = sibt_getattr(itup, i + 1, tupdesc,
											&sepisnull[i]);

			sep = sibt_form_internal_tuple(tupdesc, sepvalues, sepisnull,
										   nkeyattrs, newblk);
			pfree(sepvalues);
			pfree(sepisnull);

			/* Ensure parent level exists */
			if (lvl->parent == NULL)
			{
				lvl->parent = sibt_pagestate_new(state, lvl->level + 1);

				/*
				 * First entry on a new internal page is the minus-infinity
				 * entry pointing to the first page of this level.
				 *
				 * We need to use the OLD page's blkno here because the
				 * minus-infinity entry points to the leftmost child.
				 * But we've already written it.  We need to record the
				 * block of the very first page at this level.
				 */
				SIBTuple	minf;
				Size		minfsize;

				minfsize = MAXALIGN(sizeof(SIBTupleData)) + sizeof(BlockNumber);
				minf = (SIBTuple) palloc0(minfsize);
				minf->si_info = (uint16) minfsize;
				SIBTupleSetChildBlkno(minf, lvl->blkno);

				{
					Page		parentpage = (Page) lvl->parent->buf;

					if (PageAddItemExtended(parentpage, minf,
											MAXALIGN(minfsize),
											FirstOffsetNumber, 0) == InvalidOffsetNumber)
						elog(ERROR, "failed to add minus-infinity during sibtree build");
					lvl->parent->lastoff = FirstOffsetNumber;
				}
				pfree(minf);
			}

			sibt_buildadd(state, lvl->parent, sep);
			pfree(sep);
		}

		/* Start a new page at this level */
		newbuf = smgr_bulk_get_buf(state->bulkstate);
		newpage = (Page) newbuf;

		if (lvl->level == 0)
			sibt_initpage(newpage, SIBTP_LEAF, lvl->level);
		else
			sibt_initpage(newpage, 0, lvl->level);

		lvl->buf = newbuf;
		lvl->blkno = newblk;
		lvl->lastoff = 0;
		page = newpage;
	}

	/* Insert the tuple */
	{
		OffsetNumber off = lvl->lastoff + 1;

		if (PageAddItemExtended(page, itup, itupsz,
								off, 0) == InvalidOffsetNumber)
			elog(ERROR, "failed to add item during sibtree build at offset %u", off);
		lvl->lastoff = off;
	}
}

/*
 * Finalize the build: write out the last page at each level and
 * mark the topmost page as root.
 */
static void
sibt_uppershutdown(SIBTBuildState *state)
{
	SIBTBuildLevel *lvl = state->leaf;
	SIBTBuildLevel *rootlevel = NULL;

	if (lvl == NULL)
		return;					/* empty index */

	while (lvl != NULL)
	{
		Page		page = (Page) lvl->buf;

		/* If this level has a parent, propagate the last page */
		if (lvl->parent != NULL && lvl->parent->lastoff == 0)
		{
			/*
			 * Parent level has no entries yet (only one page at this level,
			 * so no separator was propagated).  The first entry should be
			 * the minus-infinity pointing to this page.
			 */
			SIBTuple	minf;
			Size		minfsize;
			Page		parentpage = (Page) lvl->parent->buf;

			minfsize = MAXALIGN(sizeof(SIBTupleData)) + sizeof(BlockNumber);
			minf = (SIBTuple) palloc0(minfsize);
			minf->si_info = (uint16) minfsize;
			SIBTupleSetChildBlkno(minf, lvl->blkno);

			if (PageAddItemExtended(parentpage, minf,
									MAXALIGN(minfsize),
									FirstOffsetNumber, 0) == InvalidOffsetNumber)
				elog(ERROR, "failed to add minus-infinity during sibtree finalize");
			lvl->parent->lastoff = FirstOffsetNumber;
			pfree(minf);
		}

		rootlevel = lvl;

		/* Write the final page at this level */
		if (lvl->parent == NULL)
		{
			/* This is the root */
			SIBTPageOpaque opaque = SIBTPageGetOpaque(page);

			opaque->sibt_flags |= SIBTP_ROOT;
		}

		smgr_bulk_write(state->bulkstate, lvl->blkno, lvl->buf, true);
		/* smgr_bulk_write takes ownership of buf */
		lvl->buf = NULL;

		lvl = lvl->parent;
	}
}

/*
 * Build an empty sibtree index (for unlogged relations).
 */
void
sibt_buildempty(Relation index)
{
	BulkWriteState *bulkstate;
	BulkWriteBuffer metabuf;

	bulkstate = smgr_bulk_start_rel(index, INIT_FORKNUM);
	metabuf = smgr_bulk_get_buf(bulkstate);

	sibt_initmetapage((Page) metabuf, InvalidBlockNumber, 0);
	smgr_bulk_write(bulkstate, SIBT_METAPAGE, metabuf, true);

	smgr_bulk_finish(bulkstate);
}
