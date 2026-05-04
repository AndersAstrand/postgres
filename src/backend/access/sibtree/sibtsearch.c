/*-------------------------------------------------------------------------
 *
 * sibtsearch.c
 *	  Tree descent, binary search, and scan for secondary index btree.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 *
 * src/backend/access/sibtree/sibtsearch.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/sibtree.h"
#include "storage/bufmgr.h"

/*
 * Binary search a leaf page for the first tuple >= scan keys.
 *
 * Returns the OffsetNumber of the first tuple that satisfies the scan keys,
 * or one past the max offset if all tuples are less than the keys.
 */
OffsetNumber
sibt_binsrch_leaf(Page page, ScanKey keys, int nkeys, TupleDesc tupdesc)
{
	OffsetNumber low,
				high,
				mid;

	low = FirstOffsetNumber;
	high = PageGetMaxOffsetNumber(page) + 1;

	while (low < high)
	{
		SIBTuple	itup;
		int			cmp;

		mid = low + (high - low) / 2;
		itup = (SIBTuple) PageGetItem(page, PageGetItemId(page, mid));
		cmp = sibt_compare_scankey(itup, keys, nkeys, NULL, tupdesc);

		if (cmp < 0)
			low = mid + 1;
		else
			high = mid;
	}

	return low;
}

/*
 * Binary search an internal page.
 *
 * Returns the OffsetNumber of the rightmost entry whose key <= scan key.
 * Offset 1 is the minus-infinity entry (always a valid result for leftmost).
 */
OffsetNumber
sibt_binsrch_internal(Page page, ScanKey keys, int nkeys, TupleDesc tupdesc)
{
	OffsetNumber low,
				high,
				result;
	OffsetNumber maxoff = PageGetMaxOffsetNumber(page);

	/*
	 * Offset 1 is minus-infinity (no key data, just child blkno).
	 * Real keys start at offset 2.
	 */
	if (maxoff < SIBTP_FIRSTDATAKEY)
		return FirstOffsetNumber;

	result = FirstOffsetNumber;	/* default: leftmost child */
	low = SIBTP_FIRSTDATAKEY;
	high = maxoff;

	while (low <= high)
	{
		OffsetNumber mid;
		SIBTuple	itup;
		int			cmp;

		mid = low + (high - low) / 2;
		itup = (SIBTuple) PageGetItem(page, PageGetItemId(page, mid));
		cmp = sibt_compare_scankey(itup, keys, nkeys, NULL, tupdesc);

		if (cmp <= 0)
		{
			/* tuple key <= search key: this child or one to the right */
			result = mid;
			low = mid + 1;
		}
		else
		{
			/* tuple key > search key: go left */
			high = mid - 1;
		}
	}

	return result;
}

/*
 * Descend the tree to find the correct leaf page for the given scan keys.
 *
 * Returns a buffer with a share lock on the leaf page.
 * If stackp is not NULL, builds a stack of parent pages for insert.
 */
Buffer
sibt_search_leaf(Relation rel, ScanKey keys, int nkeys, TupleDesc tupdesc,
				 SIBTStack **stackp)
{
	Buffer		buf;
	Page		page;
	SIBTMetaPageData *meta;
	BlockNumber blkno;
	uint16		level;

	/* Read meta page to find root */
	buf = ReadBuffer(rel, SIBT_METAPAGE);
	LockBuffer(buf, BUFFER_LOCK_SHARE);
	page = BufferGetPage(buf);
	meta = SIBTPageGetMeta(page);

	if (meta->sibtm_magic != SIBT_MAGIC)
		elog(ERROR, "sibtree index is not valid");

	blkno = meta->sibtm_root;
	level = meta->sibtm_level;
	UnlockReleaseBuffer(buf);

	if (blkno == InvalidBlockNumber)
		return InvalidBuffer;	/* empty tree */

	/* Read the root page */
	buf = ReadBuffer(rel, blkno);
	LockBuffer(buf, BUFFER_LOCK_SHARE);
	page = BufferGetPage(buf);

	/* Descend to leaf */
	while (!SIBTPageIsLeaf(page))
	{
		OffsetNumber off;
		SIBTuple	itup;
		BlockNumber child;

		off = sibt_binsrch_internal(page, keys, nkeys, tupdesc);
		itup = (SIBTuple) PageGetItem(page, PageGetItemId(page, off));
		child = SIBTupleGetChildBlkno(itup);

		/* Push to stack if requested */
		if (stackp)
		{
			SIBTStack  *s = (SIBTStack *) palloc(sizeof(SIBTStack));

			s->blkno = blkno;
			s->offset = off;
			s->parent = *stackp;
			*stackp = s;
		}

		/* Move to child */
		UnlockReleaseBuffer(buf);
		blkno = child;
		buf = ReadBuffer(rel, blkno);
		LockBuffer(buf, BUFFER_LOCK_SHARE);
		page = BufferGetPage(buf);
	}

	/*
	 * We're at a leaf.  Follow right-links if a concurrent split moved our
	 * target key to the right sibling.
	 */
	if (keys != NULL && nkeys > 0)
	{
		while (true)
		{
			SIBTPageOpaque opaque = SIBTPageGetOpaque(page);
			OffsetNumber maxoff = PageGetMaxOffsetNumber(page);

			if (maxoff < FirstOffsetNumber ||
				opaque->sibt_right == InvalidBlockNumber)
				break;

			/* Check if the rightmost tuple on this page is < our key */
			{
				SIBTuple	lasttup = (SIBTuple) PageGetItem(page,
															 PageGetItemId(page, maxoff));
				int			cmp = sibt_compare_scankey(lasttup, keys, nkeys, NULL, tupdesc);

				if (cmp >= 0)
					break;		/* key is on this page or earlier */
			}

			/* Move right */
			{
				BlockNumber rightblk = opaque->sibt_right;

				UnlockReleaseBuffer(buf);
				buf = ReadBuffer(rel, rightblk);
				LockBuffer(buf, BUFFER_LOCK_SHARE);
				page = BufferGetPage(buf);
				blkno = rightblk;
			}
		}
	}

	return buf;
}
