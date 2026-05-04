/*-------------------------------------------------------------------------
 *
 * sibtpage.c
 *	  Page and tuple operations for secondary index btree.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 *
 * src/backend/access/sibtree/sibtpage.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/nbtree.h"
#include "access/sibtree.h"
#include "access/tupmacs.h"
#include "catalog/pg_type.h"
#include "utils/datum.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"

/*
 * Initialize a sibtree page.
 */
void
sibt_initpage(Page page, uint16 flags, uint16 level)
{
	SIBTPageOpaque opaque;

	PageInit(page, BLCKSZ, sizeof(SIBTPageOpaqueData));
	opaque = SIBTPageGetOpaque(page);
	opaque->sibt_right = InvalidBlockNumber;
	opaque->sibt_level = level;
	opaque->sibt_flags = flags;
}

/*
 * Initialize the meta page.
 */
void
sibt_initmetapage(Page page, BlockNumber root, uint16 level)
{
	SIBTMetaPageData *meta;

	sibt_initpage(page, SIBTP_META, 0);
	meta = SIBTPageGetMeta(page);
	meta->sibtm_magic = SIBT_MAGIC;
	meta->sibtm_version = SIBT_VERSION;
	meta->sibtm_root = root;
	meta->sibtm_level = level;
}

/*
 * Form a leaf tuple from Datum values.
 *
 * nattrs includes both key columns and PK columns.
 */
SIBTuple
sibt_form_tuple(TupleDesc tupdesc, Datum *values, bool *isnull, int nattrs)
{
	Size		hoff;
	Size		data_size;
	Size		tuple_size;
	bool		hasnulls = false;
	SIBTuple	itup;
	char	   *tp;
	bits8	   *nullbits;
	int			i;

	/* Check for nulls */
	for (i = 0; i < nattrs; i++)
	{
		if (isnull[i])
		{
			hasnulls = true;
			break;
		}
	}

	/* Compute header offset */
	if (hasnulls)
		hoff = MAXALIGN(sizeof(SIBTupleData) + sizeof(IndexAttributeBitMapData));
	else
		hoff = MAXALIGN(sizeof(SIBTupleData));

	/* Compute data size */
	data_size = 0;
	for (i = 0; i < nattrs; i++)
	{
		CompactAttribute *attr = TupleDescCompactAttr(tupdesc, i);

		if (hasnulls && isnull[i])
			continue;

		data_size = att_nominal_alignby(data_size, attr->attalignby);

		if (attr->attlen < 0)
			data_size += datumGetSize(values[i], false, attr->attlen);
		else
			data_size += attr->attlen;
	}

	tuple_size = hoff + data_size;
	if (tuple_size > SIBT_SIZE_MASK)
		elog(ERROR, "secondary index tuple too large: %zu bytes", tuple_size);

	itup = (SIBTuple) palloc0(tuple_size);
	itup->si_info = (uint16) tuple_size;
	if (hasnulls)
		itup->si_info |= SIBT_NULL_MASK;

	/* Set null bitmap */
	if (hasnulls)
	{
		nullbits = SIBTupleGetNullBits(itup);
		memset(nullbits, 0, sizeof(IndexAttributeBitMapData));
		for (i = 0; i < nattrs; i++)
		{
			if (!isnull[i])
				nullbits[i >> 3] |= (1 << (i & 7));
		}
	}

	/* Copy data */
	tp = (char *) itup + hoff;
	{
		Size		off = 0;

		for (i = 0; i < nattrs; i++)
		{
			CompactAttribute *attr = TupleDescCompactAttr(tupdesc, i);

			if (hasnulls && isnull[i])
				continue;

			off = att_nominal_alignby(off, attr->attalignby);

			if (attr->attbyval)
				store_att_byval(tp + off, values[i], attr->attlen);
			else if (attr->attlen == -1)
			{
				/* varlena */
				Size		len = VARSIZE_ANY(DatumGetPointer(values[i]));

				memcpy(tp + off, DatumGetPointer(values[i]), len);
				off += len;
				continue;
			}
			else if (attr->attlen == -2)
			{
				/* cstring */
				Size		len = strlen(DatumGetCString(values[i])) + 1;

				memcpy(tp + off, DatumGetCString(values[i]), len);
				off += len;
				continue;
			}
			else
				memcpy(tp + off, DatumGetPointer(values[i]), attr->attlen);

			off += attr->attlen;
		}
	}

	return itup;
}

/*
 * Form an internal (non-leaf) tuple with key columns and a child block number.
 * The child blkno is appended after the key column data.
 */
SIBTuple
sibt_form_internal_tuple(TupleDesc tupdesc, Datum *values, bool *isnull,
						 int nkeyattrs, BlockNumber child)
{
	Size		hoff;
	Size		data_size;
	Size		tuple_size;
	bool		hasnulls = false;
	SIBTuple	itup;
	char	   *tp;
	bits8	   *nullbits;
	int			i;

	for (i = 0; i < nkeyattrs; i++)
	{
		if (isnull[i])
		{
			hasnulls = true;
			break;
		}
	}

	if (hasnulls)
		hoff = MAXALIGN(sizeof(SIBTupleData) + sizeof(IndexAttributeBitMapData));
	else
		hoff = MAXALIGN(sizeof(SIBTupleData));

	data_size = 0;
	for (i = 0; i < nkeyattrs; i++)
	{
		CompactAttribute *attr = TupleDescCompactAttr(tupdesc, i);

		if (hasnulls && isnull[i])
			continue;

		data_size = att_nominal_alignby(data_size, attr->attalignby);

		if (attr->attlen < 0)
			data_size += datumGetSize(values[i], false, attr->attlen);
		else
			data_size += attr->attlen;
	}

	/* Align before child blkno */
	data_size = MAXALIGN(data_size);
	tuple_size = hoff + data_size + sizeof(BlockNumber);

	if (tuple_size > SIBT_SIZE_MASK)
		elog(ERROR, "secondary index internal tuple too large: %zu bytes", tuple_size);

	itup = (SIBTuple) palloc0(tuple_size);
	itup->si_info = (uint16) tuple_size;
	if (hasnulls)
		itup->si_info |= SIBT_NULL_MASK;

	if (hasnulls)
	{
		nullbits = SIBTupleGetNullBits(itup);
		memset(nullbits, 0, sizeof(IndexAttributeBitMapData));
		for (i = 0; i < nkeyattrs; i++)
		{
			if (!isnull[i])
				nullbits[i >> 3] |= (1 << (i & 7));
		}
	}

	/* Copy key data */
	tp = (char *) itup + hoff;
	{
		Size		off = 0;

		for (i = 0; i < nkeyattrs; i++)
		{
			CompactAttribute *attr = TupleDescCompactAttr(tupdesc, i);

			if (hasnulls && isnull[i])
				continue;

			off = att_nominal_alignby(off, attr->attalignby);

			if (attr->attbyval)
				store_att_byval(tp + off, values[i], attr->attlen);
			else if (attr->attlen == -1)
			{
				Size		len = VARSIZE_ANY(DatumGetPointer(values[i]));

				memcpy(tp + off, DatumGetPointer(values[i]), len);
				off += len;
				continue;
			}
			else if (attr->attlen == -2)
			{
				Size		len = strlen(DatumGetCString(values[i])) + 1;

				memcpy(tp + off, DatumGetCString(values[i]), len);
				off += len;
				continue;
			}
			else
				memcpy(tp + off, DatumGetPointer(values[i]), attr->attlen);

			off += attr->attlen;
		}
	}

	/* Store child block number at the end */
	SIBTupleSetChildBlkno(itup, child);

	return itup;
}

/*
 * Extract an attribute value from a secondary index tuple.
 *
 * This is our equivalent of index_getattr() for the SIBTuple format.
 * It walks through the tuple data to find the requested attribute.
 */
Datum
sibt_getattr(SIBTuple itup, int attnum, TupleDesc tupdesc, bool *isnull)
{
	int			i;
	char	   *tp;
	bits8	   *bp;
	Size		off;
	CompactAttribute *attr;

	Assert(attnum > 0);
	*isnull = false;

	bp = SIBTupleGetNullBits(itup);

	/* Check for null */
	if (bp != NULL && att_isnull(attnum - 1, bp))
	{
		*isnull = true;
		return (Datum) 0;
	}

	tp = (char *) itup + SIBTupleDataOffset(itup->si_info);

	/* Walk attributes up to the one we want */
	off = 0;
	for (i = 0; i < attnum - 1; i++)
	{
		if (bp != NULL && att_isnull(i, bp))
			continue;

		attr = TupleDescCompactAttr(tupdesc, i);
		off = att_nominal_alignby(off, attr->attalignby);
		off = att_addlength_pointer(off, attr->attlen, tp + off);
	}

	attr = TupleDescCompactAttr(tupdesc, attnum - 1);
	off = att_nominal_alignby(off, attr->attalignby);

	return fetchatt(attr, tp + off);
}

/*
 * Convert a SIBTuple to a standard IndexTuple so the executor's
 * IndexNextSecondary() can use index_getattr() on xs_itup.
 *
 * This copies values out of our format and creates a standard IndexTuple.
 */
IndexTuple
sibt_convert_to_itup(SIBTuple situp, TupleDesc tupdesc, int natts)
{
	Datum	   *values;
	bool	   *isnull;
	IndexTuple	itup;
	int			i;

	values = (Datum *) palloc(sizeof(Datum) * natts);
	isnull = (bool *) palloc(sizeof(bool) * natts);

	for (i = 0; i < natts; i++)
		values[i] = sibt_getattr(situp, i + 1, tupdesc, &isnull[i]);

	itup = index_form_tuple(tupdesc, values, isnull);

	pfree(values);
	pfree(isnull);

	return itup;
}

/*
 * Compare a leaf tuple against scan keys using btree comparison functions.
 *
 * Returns <0 if tuple < keys, 0 if equal, >0 if tuple > keys.
 * Only compares key columns (not PK columns).
 *
 * orderProcs are the BTORDER_PROC comparison functions for each key column.
 */
int
sibt_compare_scankey(SIBTuple itup, ScanKey keys, int nkeys,
					 FmgrInfo *orderProcs, TupleDesc tupdesc)
{
	int			i;

	for (i = 0; i < nkeys; i++)
	{
		ScanKey		key = &keys[i];
		Datum		val;
		bool		isnull;
		int32		result;

		/* Only support simple column keys for now */
		if (key->sk_flags & SK_ISNULL)
		{
			/* NULL key: NULLs sort to the end */
			val = sibt_getattr(itup, key->sk_attno, tupdesc, &isnull);
			if (isnull)
				continue;		/* both null, equal for this column */
			return -1;			/* non-null tuple < null key (nulls last) */
		}

		val = sibt_getattr(itup, key->sk_attno, tupdesc, &isnull);
		if (isnull)
			return 1;			/* null tuple > non-null key (nulls last) */

		result = DatumGetInt32(FunctionCall2Coll(
			orderProcs ? &orderProcs[key->sk_attno - 1] : &key->sk_func,
			key->sk_collation,
			val,
			key->sk_argument));
		if (result != 0)
			return result;
	}

	return 0;					/* all keys equal */
}

/*
 * Compare two tuples by key columns, then PK columns for tiebreaking.
 *
 * keys provides the comparison functions for key columns.
 * natts is total attribute count (key + PK).
 */
int
sibt_compare_tuples(SIBTuple a, SIBTuple b, TupleDesc tupdesc,
					ScanKey keys, int nkeys, int natts)
{
	int			i;

	/* Compare key columns */
	for (i = 0; i < nkeys; i++)
	{
		Datum		va,
					vb;
		bool		na,
					nb;
		int32		result;

		va = sibt_getattr(a, keys[i].sk_attno, tupdesc, &na);
		vb = sibt_getattr(b, keys[i].sk_attno, tupdesc, &nb);

		if (na && nb)
			continue;
		if (na)
			return 1;
		if (nb)
			return -1;

		result = DatumGetInt32(FunctionCall2Coll(&keys[i].sk_func,
												 keys[i].sk_collation,
												 va, vb));
		if (result != 0)
			return result;
	}

	/* Tiebreak on PK columns (columns nkeys+1 through natts) */
	for (i = nkeys; i < natts; i++)
	{
		Datum		va,
					vb;
		bool		na,
					nb;
		int32		result;
		CompactAttribute *attr = TupleDescCompactAttr(tupdesc, i);
		Oid			typid = TupleDescAttr(tupdesc, i)->atttypid;
		Oid			cmpfn;

		va = sibt_getattr(a, i + 1, tupdesc, &na);
		vb = sibt_getattr(b, i + 1, tupdesc, &nb);

		if (na && nb)
			continue;
		if (na)
			return 1;
		if (nb)
			return -1;

		/*
		 * For PK tiebreaking we need a comparison function.  Use the default
		 * btree comparison operator for this type.
		 */
		cmpfn = get_opfamily_proc(get_opclass_family(
										GetDefaultOpClass(typid, BTREE_AM_OID)),
								  typid, typid, BTORDER_PROC);
		if (!OidIsValid(cmpfn))
			elog(ERROR, "could not find comparison function for type %u", typid);

		result = DatumGetInt32(OidFunctionCall2Coll(cmpfn,
													TupleDescAttr(tupdesc, i)->attcollation,
													va, vb));
		if (result != 0)
			return result;
	}

	return 0;
}
