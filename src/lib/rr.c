/**************************************************************************************************
	$Id: rr.c,v 1.65 2005/04/29 16:10:27 bboy Exp $

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

char mydns_rr_table_name[PATH_MAX] = MYDNS_RR_TABLE;
char *mydns_rr_where_clause = NULL;

/* Optional columns */
int mydns_rr_use_active = 0;
int mydns_rr_use_stamp = 0;

/* Make this nonzero to enable debugging within this source file */
#define	DEBUG_LIB_RR	0


/**************************************************************************************************
	MYDNS_RR_COUNT
	Returns the number of records in the rr table.
**************************************************************************************************/
long
mydns_rr_count(SQL *sqlConn)
{
	return sql_count(sqlConn, "SELECT COUNT(*) FROM %s", mydns_rr_table_name);
}
/*--- mydns_rr_count() --------------------------------------------------------------------------*/


/**************************************************************************************************
	MYDNS_SET_RR_TABLE_NAME
**************************************************************************************************/
void
mydns_set_rr_table_name(char *name)
{
	if (!name)
		strncpy(mydns_rr_table_name, MYDNS_RR_TABLE, sizeof(mydns_rr_table_name)-1);
	else
		strncpy(mydns_rr_table_name, name, sizeof(mydns_rr_table_name)-1);
}
/*--- mydns_set_rr_table_name() -----------------------------------------------------------------*/


/**************************************************************************************************
	MYDNS_SET_RR_WHERE_CLAUSE
**************************************************************************************************/
void
mydns_set_rr_where_clause(char *where)
{
	if (where && strlen(where))
	{
		if (!(mydns_rr_where_clause = strdup(where)))
			Errx("out of memory");
	}
}
/*--- mydns_set_rr_where_clause() ---------------------------------------------------------------*/


/**************************************************************************************************
	MYDNS_RR_GET_TYPE
**************************************************************************************************/
inline dns_qtype_t
mydns_rr_get_type(char *type)
{
	register char *c;

	for (c = type; *c; c++)
		*c = toupper(*c);

	switch (type[0])
	{
		case 'A':
			if (!type[1])
				return DNS_QTYPE_A;

			if (type[1] == 'A' && type[2] == 'A' && type[3] == 'A' && !type[4])
				return DNS_QTYPE_AAAA;

#if ALIAS_ENABLED
			if (type[1] == 'L' && type[2] == 'I' && type[3] == 'A' && type[4] == 'S' && !type[5])
				return DNS_QTYPE_ALIAS;
#endif
			break;

		case 'C':
			if (type[1] == 'N' && type[2] == 'A' && type[3] == 'M' && type[4] == 'E' && !type[5])
				return DNS_QTYPE_CNAME;
			break;

		case 'H':
			if (type[1] == 'I' && type[2] == 'N' && type[3] == 'F' && type[4] == 'O' && !type[5])
				return DNS_QTYPE_HINFO;
			break;

		case 'M':
			if (type[1] == 'X' && !type[2])
				return DNS_QTYPE_MX;
			break;

		case 'N':
			if (type[1] == 'S' && !type[2])
				return DNS_QTYPE_NS;
			if (type[1] == 'A' && type[2] == 'P' && type[3] == 'T' && type[4] == 'R' && !type[5])
				return DNS_QTYPE_NAPTR;
			break;

		case 'T':
			if (type[1] == 'X' && type[2] == 'T' && !type[3])
				return DNS_QTYPE_TXT;
			break;

		case 'P':
			if (type[1] == 'T' && type[2] == 'R' && !type[3])
				return DNS_QTYPE_PTR;
			break;

		case 'R':
			if (type[1] == 'P' && !type[2])
				return DNS_QTYPE_RP;
			break;

		case 'S':
			if (type[1] == 'R' && type[2] == 'V' && !type[3])
				return DNS_QTYPE_SRV;
			break;
	}
	return 0;
}
/*--- mydns_rr_get_type() -----------------------------------------------------------------------*/


/**************************************************************************************************
	MYDNS_RR_PARSE_RP
	RP contains two names in 'data' -- the mbox and the txt.
	NUL-terminate mbox and fill 'rp_txt' with the txt part of the record.
**************************************************************************************************/
static inline void
mydns_rr_parse_rp(SQL_ROW row, const char *origin, MYDNS_RR *rr)
{
	char *c;

	/* If no space, set txt to '.' */
	if (!(c = strchr(rr->data, ' ')))
	{
		rr->rp_txt[0] = '.';
		rr->rp_txt[1] = '\0';
	}
	else
	{
		strncpy(rr->rp_txt, c+1, sizeof(rr->rp_txt)-1);
		*c = '\0';

		/* Append origin to rp_txt if necessary */
		{
			int namelen = strlen(rr->rp_txt);
			if (namelen && rr->rp_txt[namelen-1] != '.')
			{
				strncat(rr->rp_txt, ".", sizeof(rr->rp_txt) - namelen - 1);
				strncat(rr->rp_txt, origin, sizeof(rr->rp_txt) - namelen - 2);
			}
		}
	}
}
/*--- mydns_rr_parse_rp() -----------------------------------------------------------------------*/


/**************************************************************************************************
	MYDNS_RR_PARSE_SRV
	SRV records contain two unsigned 16-bit integers in the "data" field before the target,
	'srv_weight' and 'srv_port' - parse them and make "data" contain only the target.  Also, make
	sure 'aux' fits into 16 bits, clamping values above 65535.
**************************************************************************************************/
static inline void
mydns_rr_parse_srv(SQL_ROW row, const char *origin, MYDNS_RR *rr)
{
	char *weight, *port, *target;

	/* Clamp 'aux' if necessary */
	if (rr->aux > 65535)
		rr->aux = 65535;

	/* Parse weight (into srv_weight), port (into srv_port), and target */
	target = rr->data;
	if ((weight = strsep(&target, " \t")))
	{
		rr->srv_weight = atoi(weight);
		if ((port = strsep(&target, " \t")))
			rr->srv_port = atoi(port);
		memmove(rr->data, target, strlen(target)+1);
	}
}
/*--- mydns_rr_parse_srv() ----------------------------------------------------------------------*/


/**************************************************************************************************
	MYDNS_RR_PARSE_NAPTR
	Returns 0 on success, -1 on error.
**************************************************************************************************/
static inline int
mydns_rr_parse_naptr(SQL_ROW row, const char *origin, MYDNS_RR *rr)
{
	char int_tmp[12], data_copy[DNS_MAXNAMELEN * 2 + 2], *p;

	strncpy(data_copy, rr->data, sizeof(data_copy) - 1);
	p = data_copy;

	if (!strsep_quotes(&p, int_tmp, sizeof(int_tmp)))
		return (-1);
	rr->naptr_order = atoi(int_tmp);

	if (!strsep_quotes(&p, int_tmp, sizeof(int_tmp)))
		return (-1);
	rr->naptr_pref = atoi(int_tmp);

	if (!strsep_quotes(&p, rr->naptr_flags, sizeof(rr->naptr_flags)))
		return (-1);

	if (!strsep_quotes(&p, rr->naptr_service, sizeof(rr->naptr_service)))
		return (-1);

	if (!strsep_quotes(&p, rr->naptr_regex, sizeof(rr->naptr_regex)))
		return (-1);

	if (!strsep_quotes(&p, rr->naptr_replacement, sizeof(rr->naptr_replacement)))
		return (-1);

	return 0;
}
/*--- mydns_rr_parse_naptr() --------------------------------------------------------------------*/


/**************************************************************************************************
	MYDNS_RR_PARSE
	Given the SQL results with RR data, populates and returns a matching MYDNS_RR structure.
	Returns NULL on error.
**************************************************************************************************/
inline MYDNS_RR *
mydns_rr_parse(SQL_ROW row, const char *origin)
{
	MYDNS_RR *rr;

	if ((rr = (MYDNS_RR *)calloc(1, sizeof(MYDNS_RR))))
	{
		rr->next = NULL;

		rr->id = atou(row[0]);
		rr->zone = atou(row[1]);
		strncpy(rr->name, row[2], sizeof(rr->name)-1);
		strncpy(rr->data, row[3], sizeof(rr->data)-1);
		rr->class = DNS_CLASS_IN;
		rr->aux = atou(row[4]);
		rr->ttl = atou(row[5]);
		if (!(rr->type = mydns_rr_get_type(row[6])))
		{
			/* Ignore unknown RR type(s) */
			free(rr);
			return (NULL);
		}
#if ALIAS_ENABLED
		if (rr->type == DNS_QTYPE_ALIAS)
		{
			rr->type = DNS_QTYPE_A;
			rr->alias = 1;
		}
		else
			rr->alias = 0;
#endif

		/* Populate special fields for RP records */
		if (rr->type == DNS_QTYPE_RP)
			mydns_rr_parse_rp(row, origin, rr);

		/* Populate special fields for NAPTR records */
		if (rr->type == DNS_QTYPE_NAPTR)
		{
			if (mydns_rr_parse_naptr(row, origin, rr) < 0)
			{
				free(rr);
				return (NULL);
			}
		}

		/* Append origin to data if it's not there for these types: */
		if (origin)
			switch (rr->type)
			{
				case DNS_QTYPE_CNAME:
				case DNS_QTYPE_MX:
				case DNS_QTYPE_NS:
				case DNS_QTYPE_RP:
				case DNS_QTYPE_SRV:
#ifdef DN_COLUMN_NAMES
					/* Just append dot for DN */
					strncat(rr->data, ".", sizeof(rr->data) - strlen(rr->data) - 1);
#else
					{
						int namelen = strlen(rr->data);
						if (namelen && rr->data[namelen-1] != '.')
						{
							strncat(rr->data, ".", sizeof(rr->data) - namelen - 1);
							strncat(rr->data, origin, sizeof(rr->data) - namelen - 2);
						}
					}
#endif
					break;
				default: break;
			}

		if (rr->type == DNS_QTYPE_SRV)
			mydns_rr_parse_srv(row, origin, rr);
	}
	return (rr);
}
/*--- mydns_rr_parse() --------------------------------------------------------------------------*/


/**************************************************************************************************
	MYDNS_RR_DUP
	Make and return a copy of a MYDNS_RR record.  If 'recurse' is specified, copies all records
	in the RRset.
**************************************************************************************************/
MYDNS_RR *
mydns_rr_dup(MYDNS_RR *start, int recurse)
{
	register MYDNS_RR *first = NULL, *last = NULL, *rr, *s, *tmp;

	for (s = start; s; s = tmp)
	{
		tmp = s->next;

		if (!(rr = (MYDNS_RR *)calloc(1, sizeof(MYDNS_RR))))
			Err(_("out of memory"));

		rr->id = s->id;
		rr->zone = s->zone;
		strncpy(rr->name, s->name, sizeof(rr->name)-1);
		rr->type = s->type;
		rr->class = s->class;
		strncpy(rr->data, s->data, sizeof(rr->data)-1);
		rr->aux = s->aux;
		rr->ttl = s->ttl;
#if ALIAS_ENABLED
		rr->alias = s->alias;
#endif

		rr->srv_weight = s->srv_weight;
		rr->srv_port = s->srv_port;

		/* Copy rp_txt only for RP records */
		if (rr->type == DNS_QTYPE_RP)
			strncpy(rr->rp_txt, s->rp_txt, sizeof(rr->rp_txt) - 1);

		/* Copy naptr fields only for NAPTR records */
		if (rr->type == DNS_QTYPE_NAPTR)
		{
			rr->naptr_order = s->naptr_order;
			rr->naptr_pref = s->naptr_pref;
			strncpy(rr->naptr_flags, s->naptr_flags, sizeof(rr->naptr_flags) - 1);
			strncpy(rr->naptr_service, s->naptr_service, sizeof(rr->naptr_service) - 1);
			strncpy(rr->naptr_regex, s->naptr_regex, sizeof(rr->naptr_regex) - 1);
			strncpy(rr->naptr_replacement, s->naptr_replacement, sizeof(rr->naptr_replacement) - 1);
		}

		rr->next = NULL;
		if (recurse)
		{
			if (!first) first = rr;
			if (last) last->next = rr;
			last = rr;
		}
		else
			return (rr);
	}
	return (first);
}
/*--- mydns_rr_dup() ----------------------------------------------------------------------------*/


/**************************************************************************************************
	MYDNS_RR_SIZE
**************************************************************************************************/
inline size_t
mydns_rr_size(MYDNS_RR *first)
{
	register MYDNS_RR *p;
	register size_t size = 0;

	for (p = first; p; p = p->next)
		size += sizeof(MYDNS_RR);

	return (size);
}
/*--- mydns_rr_size() ---------------------------------------------------------------------------*/


/**************************************************************************************************
	_MYDNS_RR_FREE
	Frees the pointed-to structure.	Don't call this function directly, call the macro.
**************************************************************************************************/
inline void
_mydns_rr_free(MYDNS_RR *first)
{
	register MYDNS_RR *p, *tmp;

	for (p = first; p; p = tmp)
	{
		tmp = p->next;
		Free(p);
	}
}
/*--- _mydns_rr_free() --------------------------------------------------------------------------*/


/**************************************************************************************************
	MYDNS_RR_LOAD
	Returns 0 on success or nonzero if an error occurred.
	If "name" is NULL, all resource records for the zone will be loaded.
**************************************************************************************************/
int
mydns_rr_load(SQL *sqlConn, MYDNS_RR **rptr, uint32_t zone,
				  dns_qtype_t type, char *name, char *origin)
{
	MYDNS_RR *first = NULL, *last = NULL;
	size_t	querylen;
	uchar		query[DNS_QUERYBUFSIZ],
				namequery[DNS_MAXNAMELEN + DNS_MAXNAMELEN + DNS_MAXNAMELEN + 25] = "";
	uchar		*wheretype;
	register char *c, *cp;
	SQL_RES	*res;
	SQL_ROW	row;
#ifdef DN_COLUMN_NAMES
	int		originlen = origin ? strlen(origin) : 0;
	int		namelen = name ? strlen(name) : 0;
#endif

#if DEBUG_ENABLED && DEBUG_LIB_RR
	Debug("mydns_rr_load(zone=%u, type='%s', name='%s', origin='%s')",
			zone, mydns_qtype_str(type), name ?: "NULL", origin ?: "NULL");
#endif

	if (rptr) *rptr = NULL;

	/* Verify args */
	if (!sqlConn || !rptr)
	{
		errno = EINVAL;
		return (-1);
	}

	/* Get the type='XX' part of the WHERE clause */
	switch (type)
	{
#if ALIAS_ENABLED
		case DNS_QTYPE_A:			wheretype = " AND (type='A' OR type='ALIAS')"; break;
#else
		case DNS_QTYPE_A:			wheretype = " AND type='A'"; break;
#endif
		case DNS_QTYPE_AAAA:		wheretype = " AND type='AAAA'"; break;
		case DNS_QTYPE_CNAME:	wheretype = " AND type='CNAME'"; break;
		case DNS_QTYPE_HINFO:	wheretype = " AND type='HINFO'"; break;
		case DNS_QTYPE_MX:		wheretype = " AND type='MX'"; break;
		case DNS_QTYPE_NAPTR:	wheretype = " AND type='NAPTR'"; break;
		case DNS_QTYPE_NS:		wheretype = " AND type='NS'"; break;
		case DNS_QTYPE_PTR:		wheretype = " AND type='PTR'"; break;
		case DNS_QTYPE_SOA:		wheretype = " AND type='SOA'"; break;
		case DNS_QTYPE_SRV:		wheretype = " AND type='SRV'"; break;
		case DNS_QTYPE_TXT:		wheretype = " AND type='TXT'"; break;
		case DNS_QTYPE_ANY:		wheretype = ""; break;
		default:
			errno = EINVAL;
			return (-1);
	}

	/* Make sure 'name' and 'origin' (if present) are valid */
	if (name)
	{
		for (c = name; *c; c++)
			if (SQL_BADCHAR(*c))
				return (0);
	}
	if (origin)
	{
		for (c = origin; *c; c++)
			if (SQL_BADCHAR(*c))
				return (0);
	}

#ifdef DN_COLUMN_NAMES
	/* Remove dot from origin and name for DN */
	if (originlen && origin[originlen - 1] == '.')
		origin[originlen-1] = '\0';
	else
		originlen = 0;

	if (name)
	{
		if (namelen && name[namelen - 1] == '.')
			name[namelen-1] = '\0';
		else
			namelen = 0;
	}
#endif

	/* Construct query */
	if (name)
	{
		if (origin)
		{
			if (!name[0])
				snprintf(namequery, sizeof(namequery), "(name='' OR name='%s')", origin);
			else
			{
#ifdef DN_COLUMN_NAMES
				snprintf(namequery, sizeof(namequery), "name='%s'", name);
#else
				snprintf(namequery, sizeof(namequery), "(name='%s' OR name='%s.%s')", name, name, origin);
#endif
			}
		}
		else
			snprintf(namequery, sizeof(namequery), "name='%s'", name);
	}

#ifdef DN_COLUMN_NAMES
	if (originlen)
		origin[originlen - 1] = '.';							/* Readd dot to origin for DN */

	if (name)
	{
		if (namelen)
			name[namelen - 1] = '.';
	}
#endif

	querylen = snprintf(query, sizeof(query),
		"SELECT "MYDNS_RR_FIELDS"%s FROM %s WHERE "
#ifdef DN_COLUMN_NAMES
			"zone_id=%u%s"
#else
			"zone=%u%s"
#endif
			"%s%s%s%s",
			(mydns_rr_use_active ? ",active" : ""),
			mydns_rr_table_name,
			zone, wheretype,
			(namequery[0]) ? " AND " : "",
			namequery,
			(mydns_rr_where_clause) ? " AND " : "",
			(mydns_rr_where_clause) ? mydns_rr_where_clause : "");

	/* Submit query */
	if (!(res = sql_query(sqlConn, query, querylen)))
		return (-1);

#if DEBUG_ENABLED && DEBUG_LIB_RR
	{
		int numresults = sql_num_rows(res);

		Debug("RR query: %d row%s: %s", numresults, S(numresults), query);
	}
#endif

	/* Add results to list */
	while ((row = sql_getrow(res)))
	{
		MYDNS_RR *new;

		/* Obey "active" column */
		if (mydns_rr_use_active && row[MYDNS_RR_NUMFIELDS] && !GETBOOL(row[MYDNS_RR_NUMFIELDS]))
			continue;

		if (!(new = mydns_rr_parse(row, origin)))
			continue;

		/* Always trim origin from name (XXX: Why? When did I add this?) */
		/* Apparently removing this code breaks RRs where the name IS the origin */
		/* But trim only where the name is exactly the origin */
		if (origin && (cp = strstr(new->name, origin)) && !(cp - new->name))
			*cp = '\0';

		if (!first) first = new;
		if (last) last->next = new;
		last = new;
	}

	*rptr = first;
	sql_free(res);
	return (0);
}
/*--- mydns_rr_load() ---------------------------------------------------------------------------*/

/* vi:set ts=3: */
