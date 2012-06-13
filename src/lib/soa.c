/**************************************************************************************************
	$Id: soa.c,v 1.65 2005/12/18 19:16:41 bboy Exp $

	Copyright (C) 2002-2005  Don Moore <bboy@bboy.net>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at Your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
**************************************************************************************************/

#include "mydns.h"

char mydns_soa_table_name[PATH_MAX] = MYDNS_SOA_TABLE;
char *mydns_soa_where_clause = NULL;

/* Optional columns */
int mydns_soa_use_active = 0;
int mydns_soa_use_xfer = 0;
int mydns_soa_use_update_acl = 0;

/* Make this nonzero to enable debugging within this source file */
#define	DEBUG_LIB_SOA	0


/**************************************************************************************************
	MYDNS_SOA_COUNT
	Returns the number of zones in the soa table.
**************************************************************************************************/
long
mydns_soa_count(SQL *sqlConn)
{
	return sql_count(sqlConn, "SELECT COUNT(*) FROM %s", mydns_soa_table_name);
}
/*--- mydns_soa_count() -------------------------------------------------------------------------*/


/**************************************************************************************************
	MYDNS_SET_SOA_TABLE_NAME
**************************************************************************************************/
void
mydns_set_soa_table_name(char *name)
{
	if (!name)
		strncpy(mydns_soa_table_name, MYDNS_SOA_TABLE, sizeof(mydns_soa_table_name)-1);
	else
		strncpy(mydns_soa_table_name, name, sizeof(mydns_soa_table_name)-1);
}
/*--- mydns_set_soa_table_name() ----------------------------------------------------------------*/


/**************************************************************************************************
	MYDNS_SET_SOA_WHERE_CLAUSE
**************************************************************************************************/
void
mydns_set_soa_where_clause(char *where)
{
	if (where && strlen(where))
	{
		if (!(mydns_soa_where_clause = strdup(where)))
			Errx("out of memory");
	}
}
/*--- mydns_set_soa_where_clause() --------------------------------------------------------------*/


/**************************************************************************************************
	MYDNS_SOA_PARSE
**************************************************************************************************/
#if !PROFILING
inline
#endif
MYDNS_SOA *
mydns_soa_parse(SQL_ROW row)
{
	MYDNS_SOA *rv;
	int len;

	if ((rv = (MYDNS_SOA *)malloc(sizeof(MYDNS_SOA))))
	{
		rv->next = NULL;

		rv->id = atou(row[0]);
		strncpy(rv->origin, row[1], sizeof(rv->origin)-1);
		strncpy(rv->ns, row[2], sizeof(rv->ns)-1);
		if (!rv->ns[0])
			snprintf(rv->ns, sizeof(rv->ns), "ns.%s", rv->origin);
		strncpy(rv->mbox, row[3], sizeof(rv->mbox)-1);
		if (!rv->mbox[0])
			snprintf(rv->mbox, sizeof(rv->mbox), "hostmaster.%s", rv->origin);
		rv->serial = atou(row[4]);
		rv->refresh = atou(row[5]);
		rv->retry = atou(row[6]);
		rv->expire = atou(row[7]);
		rv->minimum = atou(row[8]);
		rv->ttl = atou(row[9]);

		/* If 'ns' or 'mbox' don't end in a dot, append the origin */
		len = strlen(rv->ns);
		if (rv->ns[len-1] != '.')
		{
			strncat(rv->ns, ".", sizeof(rv->ns) - len - 1);
			strncat(rv->ns, rv->origin, sizeof(rv->ns) - len - 2);
		}
		len = strlen(rv->mbox);
		if (rv->mbox[len-1] != '.')
		{
			strncat(rv->mbox, ".", sizeof(rv->mbox) - len - 1);
			strncat(rv->mbox, rv->origin, sizeof(rv->mbox) - len - 2);
		}

		/* Make sure TTL for SOA is at least the minimum */
		if (rv->ttl < rv->minimum)
			rv->ttl = rv->minimum;
	}
	return (rv);
}
/*--- mydns_soa_parse() -------------------------------------------------------------------------*/


/**************************************************************************************************
	MYDNS_SOA_DUP
	Create a duplicate copy of the record.
	Make and return a copy of a MYDNS_SOA record.  If 'recurse' is specified, copies all records
	in the list.
**************************************************************************************************/
MYDNS_SOA *
mydns_soa_dup(MYDNS_SOA *start, int recurse)
{
	register MYDNS_SOA *first = NULL, *last = NULL, *soa, *s, *tmp;

	for (s = start; s; s = tmp)
	{
		tmp = s->next;

		if (!(soa = (MYDNS_SOA *)calloc(1, sizeof(MYDNS_SOA))))
			Err(_("out of memory"));

		soa->id = s->id;
		strncpy(soa->origin, s->origin, sizeof(soa->origin)-1);
		strncpy(soa->ns, s->ns, sizeof(soa->ns)-1);
		strncpy(soa->mbox, s->mbox, sizeof(soa->mbox)-1);
		soa->serial = s->serial;
		soa->refresh = s->refresh;
		soa->retry = s->retry;
		soa->expire = s->expire;
		soa->minimum = s->minimum;
		soa->ttl = s->ttl;
		soa->next = NULL;
		if (recurse)
		{
			if (!first) first = soa;
			if (last) last->next = soa;
			last = soa;
		}
		else
			return (soa);
	}
	return (first);
}
/*--- mydns_soa_dup() ---------------------------------------------------------------------------*/


/**************************************************************************************************
	MYDNS_SOA_SIZE
**************************************************************************************************/
#if !PROFILING
inline
#endif
size_t
mydns_soa_size(MYDNS_SOA *first)
{
	register MYDNS_SOA *p;
	register size_t size = 0;

	for (p = first; p; p = p->next)
		size += sizeof(MYDNS_SOA);

	return (size);
}
/*--- mydns_soa_size() --------------------------------------------------------------------------*/


/**************************************************************************************************
	_MYDNS_SOA_FREE
	Frees the pointed-to structure.	Don't call this function directly, call the macro.
**************************************************************************************************/
#if !PROFILING
inline
#endif
void
_mydns_soa_free(MYDNS_SOA *first)
{
	register MYDNS_SOA *p, *tmp;

	for (p = first; p; p = tmp)
	{
		tmp = p->next;
		Free(p);
	}
}
/*--- mydns_soa_free() --------------------------------------------------------------------------*/


/**************************************************************************************************
	MYDNS_SOA_LOAD
	Returns 0 on success or nonzero if an error occurred.
**************************************************************************************************/
int
mydns_soa_load(SQL *sqlConn, MYDNS_SOA **rptr, char *origin)
{
	MYDNS_SOA		*first = NULL, *last = NULL;
	size_t			querylen;
	char				query[DNS_QUERYBUFSIZ];
	SQL_RES			*res;
	SQL_ROW			row;
	register char	*c;
#ifdef DN_COLUMN_NAMES
	int				originlen = strlen(origin);
#endif

	if (rptr) *rptr = NULL;

	/* Verify args */
	if (!sqlConn || !origin || !rptr)
	{
		errno = EINVAL;
		return (-1);
	}

	/* We're not escaping 'origin', so check it for illegal type chars */
	for (c = origin; *c; c++)
		if (SQL_BADCHAR(*c))
			return (0);

#ifdef DN_COLUMN_NAMES
	if (origin[originlen - 1] == '.')
		origin[originlen - 1] = '\0';							/* Remove dot from origin for DN */
	else
		originlen = 0;
#endif

	/* Construct query */
	if (mydns_soa_where_clause)
		querylen = snprintf(query, sizeof(query),
			"SELECT "MYDNS_SOA_FIELDS"%s FROM %s WHERE origin='%s' AND %s",
			(mydns_soa_use_active ? ",active" : ""),
			mydns_soa_table_name, origin, mydns_soa_where_clause);
	else
		querylen = snprintf(query, sizeof(query),
			"SELECT "MYDNS_SOA_FIELDS"%s FROM %s WHERE origin='%s'",
			(mydns_soa_use_active ? ",active" : ""),
			mydns_soa_table_name, origin);

#ifdef DN_COLUMN_NAMES
	if (originlen)
		origin[originlen - 1] = '.';							/* Readd dot to origin for DN */
#endif

	/* Submit query */
	if (!(res = sql_query(sqlConn, query, querylen)))
		return (-1);

#if DEBUG_ENABLED && DEBUG_LIB_SOA
	{
		int numresults = sql_num_rows(res);

		Debug("SOA query: %d row%s: %s", numresults, S(numresults), query);
	}
#endif

	/* Add results to list */
	while ((row = sql_getrow(res)))
	{
		MYDNS_SOA *new;

		if (mydns_soa_use_active && row[MYDNS_SOA_NUMFIELDS] && !GETBOOL(row[MYDNS_SOA_NUMFIELDS]))
			continue;

		if (!(new = mydns_soa_parse(row)))
		{
			sql_free(res);
			return (-1);
		}
		if (!first) first = new;
		if (last) last->next = new;
		last = new;
	}

	*rptr = first;
	sql_free(res);
	return (0);
}
/*--- mydns_soa_load() --------------------------------------------------------------------------*/

/* vi:set ts=3: */
