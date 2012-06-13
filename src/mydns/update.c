/**************************************************************************************************
	$Id: update.c,v 1.10 2005/12/18 19:16:41 bboy Exp $
	update.c: Code to implement RFC 2136 (DNS UPDATE)

	Copyright (C) 2005  Don Moore <bboy@bboy.net>

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

#include "named.h"

/* Make this nonzero to enable debugging for this source file */
#define	DEBUG_UPDATE	1

#define	DEBUG_UPDATE_SQL	0


typedef struct _update_query_rr
{
	char				name[DNS_MAXNAMELEN];
	dns_qtype_t		type;
	dns_class_t		class;
	uint32_t			ttl;
	uint16_t			rdlength;
	unsigned char	rdata[DNS_MAXPACKETLEN_UDP + 1];
} UQRR;


/* This is the temporary RRset described in RFC 2136, 3.2.3 */
typedef struct _update_temp_rrset
{
	char			name[DNS_MAXNAMELEN];
	dns_qtype_t	type;
	char			data[DNS_MAXPACKETLEN_UDP + 1];
	uint32_t		aux;

	int			checked;											/* Have we checked this unique name/type? */
} TMPRR;


typedef struct _update_query
{
	/* Zone section */
	char			name[DNS_MAXNAMELEN];						/* The zone name */
	dns_qtype_t	type;												/* Must be DNS_QTYPE_SOA */
	dns_class_t	class;											/* The zone's class */

	UQRR			*PR;												/* Prerequisite section RRs */
	int			numPR;											/* Number of items in 'PR' */

	UQRR			*UP;												/* Update section RRs */
	int			numUP;											/* Number of items in 'UP' */

	UQRR			*AD;												/* Additional data section RRs */
	int			numAD;											/* Number of items in 'AD' */

	TMPRR			**tmprr;											/* Temporary RR list for prerequisite */
	int			num_tmprr;										/* Number of items in "tmprr" */
} UQ;


/**************************************************************************************************
	FREE_UQ
	Frees a 'UQ' structure.
**************************************************************************************************/
static void
free_uq(UQ *uq)
{
	Free(uq->PR);
	Free(uq->UP);
	Free(uq->AD);

	if (uq->num_tmprr)
	{
		int n;

		for (n = 0; n < uq->num_tmprr; n++)
			Free(uq->tmprr[n]);
		Free(uq->tmprr);
	}

	Free(uq);
}
/*--- free_uq() ---------------------------------------------------------------------------------*/


/**************************************************************************************************
	UPDATE_TRANSACTION
	Start/commit/rollback a transaction for the UPDATE queries.
	Returns 0 on success, -1 on failure.
**************************************************************************************************/
static int
update_transaction(TASK *t, const char *query)
{
	if (sql_nrquery(sql, query, strlen(query)) != 0)
	{
		WarnSQL(sql, "%s: %s", desctask(t), _("error deleting all RRsets via DNS UPDATE"));
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_DB_ERROR);
	}
	return 0;
}
/*--- update_transaction() ----------------------------------------------------------------------*/


/**************************************************************************************************
	CHECK_UPDATE
	If the "update" column exists in the soa table, it should contain a list of wildcards separated
	by commas.  In order for the DNS UPDATE to continue, one of the wildcards must match the
	client's IP address.  Returns 0 if okay, -1 if denied.
**************************************************************************************************/
static int
check_update(TASK *t, MYDNS_SOA *soa)
{
	SQL_RES	*res = NULL;
	SQL_ROW	row;
	char		ip[256];
	char		query[512];
	size_t	querylen;
	int		ok = 0;

	/* If the 'soa' table does not have an 'update' column, listing access rules, allow
		DNS UPDATE only from 127.0.0.1 */
	/* TODO: Allow from all listening addresses */
	if (!mydns_soa_use_update_acl)
	{
		strncpy(ip, clientaddr(t), sizeof(ip)-1);

		if (!strcmp(ip, "127.0.0.1"))							/* OK from localhost */
			return 0;

		return dnserror(t, DNS_RCODE_REFUSED, ERR_NO_UPDATE);
	}

	strncpy(ip, clientaddr(t), sizeof(ip)-1);

	querylen = snprintf(query, sizeof(query), "SELECT update_acl FROM %s WHERE id=%u%s",
		mydns_soa_table_name, soa->id, mydns_rr_use_active ? " AND active=1" : "");
#if DEBUG_UPDATE_SQL
	Verbose("%s: DNS UPDATE: %s", desctask(t), query);
#endif

	if (!(res = sql_query(sql, query, querylen)))
		ErrSQL(sql, "%s: %s", desctask(t), _("error loading DNS UPDATE access rules"));

	if ((row = sql_getrow(res)))
	{
		char *wild, *r;

#if DEBUG_ENABLED && DEBUG_UPDATE
		Debug("%s: checking DNS UPDATE access rule '%s'", desctask(t), row[0]);
#endif
		for (r = row[0]; !ok && (wild = strsep(&r, ",")); )
		{
			if (strchr(wild, '/'))
			{
				if (t->family == AF_INET)
					ok = in_cidr(wild, t->addr4.sin_addr);
			}
			else if (wildcard_match(wild, ip))
				ok = 1;
		}
	}
	sql_free(res);

	if (!ok)
		return dnserror(t, DNS_RCODE_REFUSED, ERR_NO_UPDATE);

	return 0;
}
/*--- check_update() ----------------------------------------------------------------------------*/


#if DEBUG_ENABLED && DEBUG_UPDATE
/**************************************************************************************************
	UPDATE_RRDUMP
**************************************************************************************************/
static void
update_rrdump(TASK *t, char *section, int which, UQRR *rr)
{
	char buf[BUFSIZ] = "", *b = buf;
	int n;

	for (n = 0; n < rr->rdlength; n++)
	{
		if (isalnum(rr->rdata[n]))
			b += sprintf(b, "%c", rr->rdata[n]);
		else
			b += sprintf(b, "<%d>", rr->rdata[n]);
	}

	Debug("%s: DNS UPDATE: >>> %s %d: name=[%s] type=%s class=%s ttl=%u rdlength=%u rdata=[%s]",
			desctask(t), section, which, rr->name,
			mydns_qtype_str(rr->type), mydns_class_str(rr->class),
			rr->ttl, rr->rdlength, buf);
}
/*--- update_rrdump() ---------------------------------------------------------------------------*/
#endif


/**************************************************************************************************
	UPDATE_GOBBLE_RR
	Reads the next RR from the query.  Returns the new source or NULL on error.
**************************************************************************************************/
static char *
update_gobble_rr(TASK *t, MYDNS_SOA *soa, char *query, size_t querylen, char *current, UQRR *rr)
{
	char *src = current;

	if (!(src = name_unencode(query, querylen, src, rr->name, sizeof(rr->name))))
	{
		formerr(t, DNS_RCODE_FORMERR, (task_error_t)rr->name[0], NULL);
		return NULL;
	}

	DNS_GET16(rr->type, src);
	DNS_GET16(rr->class, src);
	DNS_GET32(rr->ttl, src);
	DNS_GET16(rr->rdlength, src);
	memcpy(rr->rdata, src, rr->rdlength);
	src += rr->rdlength;

	return src;
}
/*--- update_gobble_rr() ------------------------------------------------------------------------*/


/**************************************************************************************************
	PARSE_UPDATE_QUERY
	Parses the various sections of the update query.
	Returns 0 on success, -1 on error.
**************************************************************************************************/
static int
parse_update_query(TASK *t, MYDNS_SOA *soa, UQ *q)
{
	char	*query = t->query;									/* Start of query section */
	int	querylen = t->len;									/* Length of 'query' */
	char	*src = query + DNS_HEADERSIZE;					/* Current position in 'query' */
	int	n;

	/*
	**  Zone section (RFC 2136 2.3)
	*/
	if (!(src = name_unencode(query, querylen, src, q->name, sizeof(q->name))))
		return formerr(t, DNS_RCODE_FORMERR, (task_error_t)q->name[0], NULL);
	DNS_GET16(q->type, src);
	DNS_GET16(q->class, src);
#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s:   ZONE: name=[%s]  type=%s  class=%s", desctask(t), q->name, mydns_qtype_str(q->type), mydns_class_str(q->class));
#endif

	/* ZONE: Must contain exactly one RR with type SOA (RFC 2136 3.1.1) */
	if (t->qdcount != 1)
		return dnserror(t, DNS_RCODE_FORMERR, ERR_MULTI_QUESTIONS);
	if (q->type != DNS_QTYPE_SOA)
		return dnserror(t, DNS_RCODE_FORMERR, ERR_INVALID_TYPE);


	/*
	**  Prerequisite section (RFC 2136 2.4)
	**  These records are in normal RR format (RFC 1035 4.1.3)
	*/
	q->numPR = t->ancount;
	if (!(q->PR = calloc(q->numPR, sizeof(UQRR))))
		Err(_("out of memory"));
	for (n = 0; n < q->numPR; n++)
		if (!(src = update_gobble_rr(t, soa, query, querylen, src, &q->PR[n])))
			return -1;
#if DEBUG_ENABLED && DEBUG_UPDATE
	for (n = 0; n < q->numPR; n++)
		update_rrdump(t, "PREREQ", n, &q->PR[n]);
#endif


	/*
	**  Update section (RFC 2136 2.5)
	**  These records are in normal RR format (RFC 1035 4.1.3)
	*/
	q->numUP = t->nscount;
	if (!(q->UP = calloc(q->numUP, sizeof(UQRR))))
		Err(_("out of memory"));
	for (n = 0; n < q->numUP; n++)
		if (!(src = update_gobble_rr(t, soa, query, querylen, src, &q->UP[n])))
			return -1;
#if DEBUG_ENABLED && DEBUG_UPDATE
	for (n = 0; n < q->numUP; n++)
		update_rrdump(t, "UPDATE", n, &q->UP[n]);
#endif


	/*
	**  Additional data section (RFC 2136 2.6)
	**  These records are in normal RR format (RFC 1035 4.1.3)
	*/
	q->numAD = t->arcount;
	if (!(q->AD = calloc(q->numAD, sizeof(UQRR))))
		Err(_("out of memory"));
	for (n = 0; n < q->numAD; n++)
		if (!(src = update_gobble_rr(t, soa, query, querylen, src, &q->AD[n])))
			return -1;
#if DEBUG_ENABLED && DEBUG_UPDATE
	for (n = 0; n < q->numAD; n++)
		update_rrdump(t, " ADD'L", n, &q->AD[n]);
#endif

	return 0;
}
/*--- parse_update_query() ----------------------------------------------------------------------*/


/**************************************************************************************************
	TEXT_RETRIEVE
	Retrieve a name from the source without end-dot encoding.
**************************************************************************************************/
static char *
text_retrieve(char *src, char *end, char *data, size_t datalen, int one_word_only)
{
	int n, x;														/* Offset in 'data' */

	for (n = 0; src < end && n < datalen; )
	{
		int len = *src++;

		if (n)
			data[n++] = ' ';
		for (x = 0; x < len && src < end && n < datalen; x++)
			data[n++] = *src++;
		if (one_word_only)
		{
			data[n] = '\0';
			return (src);
		}
	}
	data[n] = '\0';
	return (src);
}
/*--- text_retrieve() ---------------------------------------------------------------------------*/


/**************************************************************************************************
	UPDATE_GET_RR_DATA
	Sets 'data' and 'aux'.
	Returns 0 on success, -1 on error.
**************************************************************************************************/
static int
update_get_rr_data(TASK *t, MYDNS_SOA *soa, UQ *q, UQRR *rr, char *data, size_t datalen, uint32_t *aux)
{
	char	*src = rr->rdata;
	char	*end = rr->rdata + rr->rdlength;

	memset(data, 0, datalen);
	*aux = 0;

	if (!rr->rdlength)
		return -1;

	switch (rr->type)
	{
		case DNS_QTYPE_A:
			if (rr->rdlength != 4)
				return -1;
			snprintf(data, datalen, "%d.%d.%d.%d", rr->rdata[0], rr->rdata[1], rr->rdata[2], rr->rdata[3]);
			return 0;

		case DNS_QTYPE_AAAA:
			if (rr->rdlength != 16)
				return -1;
			if (!(inet_ntop(AF_INET6, &rr->rdata, data, datalen - 1)))
				return dnserror(t, DNS_RCODE_FORMERR, ERR_INVALID_ADDRESS);
			return 0;

		case DNS_QTYPE_CNAME:
			if (!(src = name_unencode(t->query, t->len, src, data, datalen)))
				return formerr(t, DNS_RCODE_FORMERR, (task_error_t)data[0], NULL);
			return 0;

		case DNS_QTYPE_HINFO:
			{
				char data1[DNS_MAXPACKETLEN_UDP], data2[DNS_MAXPACKETLEN_UDP], *c;
				int  data1sp, data2sp;

				if (!(src = text_retrieve(src, end, data1, sizeof(data1), 1)))
					return dnserror(t, DNS_RCODE_FORMERR, ERR_INVALID_DATA);
				if (!(src = text_retrieve(src, end, data2, sizeof(data2), 1)))
					return dnserror(t, DNS_RCODE_FORMERR, ERR_INVALID_DATA);

				/* See if either value contains spaces, so we can enclose it with quotes */
				for (c = data1, data1sp = 0; *c && !data1sp; c++)
					if (isspace(*c)) data1sp = 1;
				for (c = data2, data2sp = 0; *c && !data2sp; c++)
					if (isspace(*c)) data2sp = 1;

				snprintf(data, datalen, "%s%s%s %s%s%s",
					data1sp ? "\"" : "", data1, data1sp ? "\"" : "",
					data2sp ? "\"" : "", data2, data2sp ? "\"" : "");
			}
			return 0;

		case DNS_QTYPE_MX:
			DNS_GET16(*aux, src);
			if (!(src = name_unencode(t->query, t->len, src, data, datalen)))
				return formerr(t, DNS_RCODE_FORMERR, (task_error_t)data[0], NULL);
			return 0;

		case DNS_QTYPE_NS:
			if (!(src = name_unencode(t->query, t->len, src, data, datalen)))
				return formerr(t, DNS_RCODE_FORMERR, (task_error_t)data[0], NULL);
			return 0;

		case DNS_QTYPE_TXT:
			if (!(src = text_retrieve(src, end, data, datalen, 0)))
				return dnserror(t, DNS_RCODE_FORMERR, ERR_INVALID_DATA);
			return 0;

		case DNS_QTYPE_PTR:
			return dnserror(t, DNS_RCODE_SERVFAIL, ERR_UNSUPPORTED_TYPE);
			return 0;

		case DNS_QTYPE_RP:
			{
				char data1[DNS_MAXPACKETLEN_UDP], data2[DNS_MAXPACKETLEN_UDP];

				if (!(src = name_unencode(t->query, t->len, src, data1, sizeof(data1))))
					return formerr(t, DNS_RCODE_FORMERR, (task_error_t)data1[0], NULL);
				if (!(src = name_unencode(t->query, t->len, src, data2, sizeof(data2))))
					return formerr(t, DNS_RCODE_FORMERR, (task_error_t)data2[0], NULL);

				snprintf(data, datalen, "%s %s", data1, data2);
			}
			return 0;

		case DNS_QTYPE_SRV:
			{
				uint16_t weight, port;
				char data1[DNS_MAXPACKETLEN_UDP];

				DNS_GET16(*aux, src);
				DNS_GET16(weight, src);
				DNS_GET16(port, src);

				if (!(src = name_unencode(t->query, t->len, src, data1, sizeof(data1))))
					return formerr(t, DNS_RCODE_FORMERR, (task_error_t)data1[0], NULL);

				snprintf(data, datalen, "%u %u %s", weight, port, data1);
			}
			return 0;

		default:
			snprintf(data, datalen, "Unknown type %s", mydns_qtype_str(rr->type));
			break;
	}
	return (-1);
}
/*--- update_get_rr_data() ----------------------------------------------------------------------*/


/**************************************************************************************************
	UPDATE_IN_ZONE
	Checks to see if 'name' is within 'origin'.
	Returns 1 if it is, 0 if it's not.
**************************************************************************************************/
static int
update_in_zone(TASK *t, char *name, char *origin)
{
	char nbuf[DNS_MAXNAMELEN+1], obuf[DNS_MAXNAMELEN+1];

	strncpy(nbuf, name, sizeof(nbuf)-1);
	strtolower(nbuf);

	strncpy(obuf, origin, sizeof(obuf)-1);
	strtolower(obuf);

	if (strlen(obuf) > strlen(nbuf))
		return 0;

	if (strcmp(obuf, nbuf + strlen(nbuf) - strlen(obuf)))
		return 0;

	return 1;
}
/*--- update_in_zone() --------------------------------------------------------------------------*/


/**************************************************************************************************
	UPDATE_ZONE_HAS_NAME
	Check to see that there is at least one RR in the zone whose name is the same as the
	prerequisite RR.
	Returns 1 if the name exists, 0 if not, -1 on error.
**************************************************************************************************/
static int
update_zone_has_name(TASK *t, MYDNS_SOA *soa, UQ *q, UQRR *rr)
{
	SQL_RES	*res = NULL;
	SQL_ROW	row;
	char		query[512];
	size_t	querylen;
	char		*xname = NULL;
	int		found = 0;

#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s: DNS UPDATE: update_zone_has_name: does [%s] have an RR for [%s]?", desctask(t),
			soa->origin, rr->name);
#endif

   if (!(xname = calloc(strlen(rr->name) * 2 + 1, sizeof(char))))
      Err(_("out of memory"));
	sql_escstr(sql, xname, rr->name, strlen(rr->name));

	querylen = snprintf(query, sizeof(query),
		"SELECT id FROM %s WHERE zone=%u AND name='%s' LIMIT 1",
		mydns_rr_table_name, soa->id, xname);
#if DEBUG_UPDATE_SQL
	Verbose("%s: DNS UPDATE: %s", desctask(t), query);
#endif

	if (!(res = sql_query(sql, query, querylen)))
	{
		WarnSQL(sql, "%s: %s", desctask(t), _("error searching name for DNS UPDATE"));
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_DB_ERROR);
	}
	if (sql_num_rows(res) > 0)
		found = 1;
	Free(xname);
	sql_free(res);

	return (found);
}
/*--- update_zone_has_name() --------------------------------------------------------------------*/


/**************************************************************************************************
	UPDATE_ZONE_HAS_RRSET
	Check to see that there is an RRset in the zone whose name and type are the same as the
	prerequisite RR.
	Returns 1 if the name exists, 0 if not, -1 on error.
**************************************************************************************************/
static int
update_zone_has_rrset(TASK *t, MYDNS_SOA *soa, UQ *q, UQRR *rr)
{
	SQL_RES	*res = NULL;
	SQL_ROW	row;
	char		query[512];
	size_t	querylen;
	char		*xname = NULL;
	int		found = 0;

#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s: DNS UPDATE: update_zone_has_rrset: does [%s] have an RR for [%s] with type %s?", desctask(t),
			soa->origin, rr->name, mydns_qtype_str(rr->type));
#endif

   if (!(xname = calloc(strlen(rr->name) * 2 + 1, sizeof(char))))
      Err(_("out of memory"));
	sql_escstr(sql, xname, rr->name, strlen(rr->name));

	querylen = snprintf(query, sizeof(query),
		"SELECT id FROM %s WHERE zone=%u AND name='%s' AND type='%s' LIMIT 1",
		mydns_rr_table_name, soa->id, xname, mydns_qtype_str(rr->type));
#if DEBUG_UPDATE_SQL
	Verbose("%s: DNS UPDATE: %s", desctask(t), query);
#endif

	if (!(res = sql_query(sql, query, querylen)))
	{
		WarnSQL(sql, "%s: %s", desctask(t), _("error searching name/type for DNS UPDATE"));
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_DB_ERROR);
	}
	if (sql_num_rows(res) > 0)
		found = 1;
	Free(xname);
	sql_free(res);

	return (found);
	return 1;
}
/*--- update_zone_has_rrset() -------------------------------------------------------------------*/


/**************************************************************************************************
	CHECK_PREREQUISITE
	Check the specified prerequisite as described in RFC 2136 3.2.
	Returns 0 on success, -1 on error.
**************************************************************************************************/
static int
check_prerequisite(TASK *t, MYDNS_SOA *soa, UQ *q, UQRR *rr)
{
	static char data[DNS_MAXPACKETLEN_UDP] = "";
	uint32_t	aux = 0;
	int n, rv;

#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s: DNS UPDATE: check_prerequsisite: rr->name=[%s]", desctask(t), rr->name);
	Debug("%s: DNS UPDATE: check_prerequsisite: rr->class=%s", desctask(t), mydns_class_str(rr->class));
	Debug("%s: DNS UPDATE: check_prerequsisite: q->class=%s", desctask(t), mydns_class_str(q->class));
	Debug("%s: DNS UPDATE: check_prerequsisite: rr->type=%s", desctask(t), mydns_qtype_str(rr->type));
	Debug("%s: DNS UPDATE: check_prerequsisite: rr->rdlength=%u", desctask(t), rr->rdlength);
#endif

	/* Get aux/data */
	update_get_rr_data(t, soa, q, rr, data, sizeof(data), &aux);		/* Ignore error */

#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s: DNS UPDATE: check_prerequsisite: aux=%u", desctask(t), aux);
	Debug("%s: DNS UPDATE: check_prerequsisite: data=[%s]", desctask(t), data);
#endif

	/* TTL must be zero */
	if (rr->ttl)
	{
#if DEBUG_ENABLED && DEBUG_UPDATE
		Debug("%s: DNS UPDATE: check_prerequisite failed: TTL nonzero", desctask(t));
#endif
		return dnserror(t, DNS_RCODE_FORMERR, ERR_INVALID_TTL);	
	}

	/* rr->name bust be in-zone */
	if (!update_in_zone(t, rr->name, soa->origin))
	{
#if DEBUG_ENABLED && DEBUG_UPDATE
		Debug("%s: DNS UPDATE: check_prerequisite failed: name (%s) not in zone (%s)", desctask(t), rr->name, soa->origin);
#endif
		return dnserror(t, DNS_RCODE_NOTZONE, ERR_INVALID_DATA);
	}

	/* Following pseudocode from section 3.2.5... */
	if (rr->class == DNS_CLASS_ANY)
	{
		if (rr->rdlength)
		{
#if DEBUG_ENABLED && DEBUG_UPDATE
			Debug("%s: DNS UPDATE: check_prerequisite failed: class is ANY but rdlength is nonzero", desctask(t));
#endif
			return dnserror(t, DNS_RCODE_FORMERR, ERR_INVALID_DATA);	
		}
		if (rr->type == DNS_QTYPE_ANY)
		{
			if ((rv = update_zone_has_name(t, soa, q, rr)) != 1)
			{
				if (!rv)
				{
#if DEBUG_ENABLED && DEBUG_UPDATE
					Debug("%s: DNS UPDATE: check_prerequisite failed: zone contains no names matching [%s]",
							desctask(t), rr->name);
#endif
					return dnserror(t, DNS_RCODE_NXDOMAIN, ERR_PREREQUISITE_FAILED);
				}
				else
					return -1;
			}
		}
		else if ((rv = update_zone_has_rrset(t, soa, q, rr)) != 1)
		{
			if (!rv)
			{
#if DEBUG_ENABLED && DEBUG_UPDATE
				Debug("%s: DNS UPDATE: check_prerequisite failed: zone contains no names matching [%s] with type %s",
						desctask(t), rr->name, mydns_qtype_str(rr->type));
#endif
				return dnserror(t, DNS_RCODE_NXRRSET, ERR_PREREQUISITE_FAILED);
			}
			else
				return -1;
		}
	}
	else if (rr->class == DNS_CLASS_NONE)
	{
		if (rr->rdlength != 0)
		{
#if DEBUG_ENABLED && DEBUG_UPDATE
			Debug("%s: DNS UPDATE: check_prerequisite failed: class is NONE but rdlength is zero", desctask(t));
#endif
			return dnserror(t, DNS_RCODE_FORMERR, ERR_INVALID_DATA);	
		}
		if (rr->type == DNS_QTYPE_ANY)
		{
			if ((rv = update_zone_has_name(t, soa, q, rr)) != 0)
			{
				if (rv == 1)
				{
#if DEBUG_ENABLED && DEBUG_UPDATE
					Debug("%s: DNS UPDATE: check_prerequisite failed: zone contains a name matching [%s]",
							desctask(t), rr->name);
#endif
					return dnserror(t, DNS_RCODE_YXDOMAIN, ERR_PREREQUISITE_FAILED);
				}
				else
					return -1;
			}

		}
		else if ((rv = update_zone_has_rrset(t, soa, q, rr)) != 0)
		{
			if (rv == 1)
			{
#if DEBUG_ENABLED && DEBUG_UPDATE
				Debug("%s: DNS UPDATE: check_prerequisite failed: zone contains a name matching [%s] with type %s",
						desctask(t), rr->name, mydns_qtype_str(rr->type));
#endif
				return dnserror(t, DNS_RCODE_YXRRSET, ERR_PREREQUISITE_FAILED);
			}
			else
				return -1;
		}
	}
	else if (rr->class == q->class)
	{
		int		unique;											/* Is this rrset element unique? */
		char		data[DNS_MAXPACKETLEN_UDP + 1];			/* Parsed rrset data */
		uint32_t	aux = 0;											/* 'aux' value for parsed data */

#if DEBUG_ENABLED && DEBUG_UPDATE
		Debug("%s: DNS UPDATE: want to add %s/%s to tmprr", desctask(t), rr->name, mydns_qtype_str(rr->type));
#endif

		/* Get the RR data */
		if (update_get_rr_data(t, soa, q, rr, data, sizeof(data)-1, &aux) < 0)
			return dnserror(t, DNS_RCODE_FORMERR, ERR_INVALID_DATA);	

#if DEBUG_ENABLED && DEBUG_UPDATE
		Debug("%s: DNS UPDATE: for tmprr, data=[%s], aux=%u", desctask(t), data, aux);
#endif

		/* Add this name/type to the "tmprr" list (in the UQRR struct) */
		/* First, check to make sure it's unique */
		for (n = 0, unique = 1; n < q->num_tmprr && unique; n++)
			if (q->tmprr[n]->type == rr->type && !strcasecmp(q->tmprr[n]->name, rr->name)
				 && !strcasecmp(q->tmprr[n]->data, data) && q->tmprr[n]->aux == aux)
				unique = 0;

		if (unique)
		{
			if (!q->num_tmprr)
				q->tmprr = calloc(1, sizeof(TMPRR *));
			else
				q->tmprr = realloc(q->tmprr, sizeof(TMPRR *) * (q->num_tmprr + 1));

			if (!q->tmprr)
				Err(_("out of memory"));

			/* Add this stuff to the new tmprr */
			if (!(q->tmprr[q->num_tmprr] = malloc(sizeof(TMPRR))))
				Err(_("out of memory"));
			strncpy(q->tmprr[q->num_tmprr]->name, rr->name, sizeof(q->tmprr[q->num_tmprr]->name) - 1);
			q->tmprr[q->num_tmprr]->type = rr->type;
			strncpy(q->tmprr[q->num_tmprr]->data, data, sizeof(q->tmprr[q->num_tmprr]->data) - 1);
			q->tmprr[q->num_tmprr]->aux = aux;
			q->tmprr[q->num_tmprr]->checked = 0;

			q->num_tmprr++;
		}
	}
	else
		return dnserror(t, DNS_RCODE_FORMERR, ERR_INVALID_DATA);	

	return 0;
}
/*--- check_prerequisite() ----------------------------------------------------------------------*/


/**************************************************************************************************
	UPDATE_RRTYPE_OK
	Is this RR type okay with MyDNS?  RFC 2136 3.4.1.2 specifically prohibigs ANY, AXFR, MAILA,
	MAILB, or "any other QUERY metatype" or "any unrecognized type".
	Returns 1 if OK, 0 if not OK.
**************************************************************************************************/
static inline int
update_rrtype_ok(dns_qtype_t type)
{
	switch (type)
	{
		/* We support UPDATEs of these types: */
		case DNS_QTYPE_A:
		case DNS_QTYPE_AAAA:
		case DNS_QTYPE_CNAME:
		case DNS_QTYPE_HINFO:
		case DNS_QTYPE_MX:
		case DNS_QTYPE_NS:
		case DNS_QTYPE_TXT:
		case DNS_QTYPE_PTR:
		case DNS_QTYPE_RP:
		case DNS_QTYPE_SRV:
			return 1;

		default:
			return 0;
	}
	return 0;
}
/*--- update_rrtype_ok() ------------------------------------------------------------------------*/


/**************************************************************************************************
	PRESCAN_UPDATE
	Prescan the specified update section record (RFC 2136 3.4.1).
	Returns 0 on success, -1 on error.
**************************************************************************************************/
static int
prescan_update(TASK *t, MYDNS_SOA *soa, UQ *q, UQRR *rr)
{
	/* Class must be ANY, NONE, or the same as the zone's class */
	if ((rr->class != DNS_CLASS_ANY) && (rr->class != DNS_CLASS_NONE) && (rr->class != q->class))
	{
#if DEBUG_ENABLED && DEBUG_UPDATE
		Debug("%s: DNS UPDATE: prescan_update failed test 1 (check class)", desctask(t));
#endif
		return dnserror(t, DNS_RCODE_FORMERR, ERR_DB_ERROR);
	}

	/* "Using the definitions in Section 1.2, each RR's NAME must be in the zone specified by the
		Zone Section, else signal NOTZONE to the requestor. */
	/* XXX WTF? */

	/* "For RRs whose CLASS is not ANY, check the TYPE and if it is ANY, AXFR, MAILA, MAILB, or
		any other QUERY metatype, or any unrecognized type, then signal FORMERR to the requestor. */
	if ((rr->class != DNS_CLASS_ANY) && !update_rrtype_ok(rr->type))
	{
#if DEBUG_ENABLED && DEBUG_UPDATE
		Debug("%s: DNS UPDATE: prescan_update failed test 2 (check RR types)", desctask(t));
#endif
		return dnserror(t, DNS_RCODE_FORMERR, ERR_INVALID_TYPE);
	}

	/* "For RRs whose CLASS is ANY or NONE, check the TTL to see that it is zero (0), else signal
		a FORMERR to the requestor." */
	if (((rr->class == DNS_CLASS_ANY) || (rr->class == DNS_CLASS_NONE)) && (rr->ttl != 0))
	{
#if DEBUG_ENABLED && DEBUG_UPDATE
		Debug("%s: DNS UPDATE: prescan_update failed test 3 (check TTL)", desctask(t));
#endif
		return dnserror(t, DNS_RCODE_FORMERR, ERR_INVALID_TTL);
	}

	/* "For any RR whose CLASS is ANY, check the RDLENGTH to make sure that it is zero (0) (that
		is, the RDATA field is empty), and that the TYPE is not AXFR, MAILA, MAILB, or any other
		QUERY metatype besides ANY, or any unrecognized type, else signal FORMERR to the
		requestor." */
	if ((rr->class == DNS_CLASS_ANY) && (rr->rdlength != 0))
	{
#if DEBUG_ENABLED && DEBUG_UPDATE
		Debug("%s: DNS UPDATE: prescan_update failed test 4 (check RDLENGTH)", desctask(t));
#endif
		return dnserror(t, DNS_RCODE_FORMERR, ERR_INVALID_DATA);
	}
	if ((rr->class == DNS_CLASS_ANY) && (!update_rrtype_ok(rr->type) && rr->type != DNS_QTYPE_ANY))
	{
#if DEBUG_ENABLED && DEBUG_UPDATE
		Debug("%s: DNS UPDATE: prescan_update failed test 5 (rr->type is %s)", desctask(t), mydns_qtype_str(rr->type));
#endif
		return dnserror(t, DNS_RCODE_FORMERR, ERR_INVALID_TYPE);
	}

	return 0;
}
/*--- prescan_update() --------------------------------------------------------------------------*/


/**************************************************************************************************
	UPDATE_ADD_RR
	Add an RR to the zone.
	Returns 0 on success, -1 on failure.
**************************************************************************************************/
static int
update_add_rr(TASK *t, MYDNS_SOA *soa, UQ *q, UQRR *rr)
{
	static char data[DNS_MAXPACKETLEN_UDP];
	uint32_t	aux;
	char		*xname = NULL, *xdata = NULL;
	SQL_RES	*res = NULL;
	SQL_ROW	row;
	char		query[512];
	size_t	querylen = 0;
	int		duplicate = 0;

	if (update_get_rr_data(t, soa, q, rr, data, sizeof(data), &aux) != 0)
	{
#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s: update_get_rr_data failed", desctask(t));
#endif
		return dnserror(t, DNS_RCODE_FORMERR, ERR_INVALID_DATA);
	}

#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s: UPDATE_ADD_RR: %s %u %s %s %u %s", desctask(t),
			rr->name, rr->ttl, mydns_class_str(rr->class), mydns_qtype_str(rr->type), aux, data);
#endif

	/* Construct query */
   if (!(xname = calloc(strlen(rr->name) * 2 + 1, sizeof(char))))
      Err(_("out of memory"));
	sql_escstr(sql, xname, rr->name, strlen(rr->name));

   if (!(xdata = calloc(strlen(data) * 2 + 1, sizeof(char))))
      Err(_("out of memory"));
	sql_escstr(sql, xdata, data, strlen(data));

	/* First we have to see if this record exists.  If it does, we should "silently ignore" it. */
#if USE_PGSQL
	/* This is only necessary for Postgres, we can use "INSERT IGNORE" with MySQL */
	querylen = snprintf(query, sizeof(query),
		"SELECT id FROM %s WHERE zone=%u AND name='%s' AND type='%s' AND data='%s' LIMIT 1",
		mydns_rr_table_name, soa->id, xname, mydns_qtype_str(rr->type), xdata);
#if DEBUG_UPDATE_SQL
	Verbose("%s: DNS UPDATE: %s", desctask(t), query);
#endif
#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s: UPDATE_ADD_RR: %s", desctask(t), query);
#endif
	if (!(res = sql_query(sql, query, querylen)))
	{
		WarnSQL(sql, "%s: %s", desctask(t), _("error searching duplicate for DNS UPDATE"));
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_DB_ERROR);
	}
	if (sql_num_rows(res) > 0)
		duplicate = 1;
	sql_free(res);
#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s: UPDATE_ADD_RR: duplicate=%d", desctask(t), duplicate);
#endif
#endif

	if (!duplicate)
	{
		querylen = snprintf(query, sizeof(query),
#if USE_PGSQL
			"INSERT INTO %s"
#else
			"INSERT IGNORE INTO %s"
#endif
			" (zone,name,type,data,aux,ttl%s)"
			" VALUES (%u,'%s','%s','%s',%u,%u%s%s%s)",
			mydns_rr_table_name,
			mydns_rr_use_active ? ",active" : "",
			soa->id, xname, mydns_qtype_str(rr->type), xdata, aux, rr->ttl,
			mydns_rr_use_active ? ",'" : "",
			mydns_rr_use_active ? "Y" : "",
			mydns_rr_use_active ? "'" : ""
		);
#if DEBUG_UPDATE_SQL
		Verbose("%s: DNS UPDATE: %s", desctask(t), query);
#endif
	}

	Free(xname);
	Free(xdata);

#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s: DNS UPDATE: ADD RR: %s", desctask(t), query);
#endif

	/* Execute the query */
	if (!duplicate)
	{
		if (sql_nrquery(sql, query, querylen) != 0)
		{
			WarnSQL(sql, "%s: %s", desctask(t), _("error adding RR via DNS UPDATE"));
			return dnserror(t, DNS_RCODE_SERVFAIL, ERR_DB_ERROR);
		}
		sql_free(res);
	}

	/* Output info to verbose log */
	snprintf(query, sizeof(query), "ADD %s %u IN %s %u %s",
				rr->name, rr->ttl, mydns_qtype_str(rr->type), aux, data);
	task_output_info(t, query);
	t->update_done++;

	return 0;
}
/*--- update_add_rr() ---------------------------------------------------------------------------*/


/**************************************************************************************************
	UPDATE_DELETE_RRSET_ALL
	Deletes all RRsets from the zone for a specified name.
	Returns 0 on success, -1 on failure.
**************************************************************************************************/
static int
update_delete_rrset_all(TASK *t, MYDNS_SOA *soa, UQ *q, UQRR *rr)
{
	char		*xname = NULL, *xhost = NULL;
	char		query[512];
	size_t	querylen;
	SQL_RES	*res = NULL;
	SQL_ROW	row;

#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s: UPDATE_DELETE_RRSET_ALL: %s %u %s %s", desctask(t),
			rr->name, rr->ttl, mydns_class_str(rr->class), mydns_qtype_str(rr->type));
#endif

#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s: DNS UPDATE: DELETE ALL RRSETS: %s", desctask(t), rr->name);
#endif

	/* Delete rrset - check both the FQDN and the hostname without trailing dot */
   if (!(xname = calloc(strlen(rr->name) * 2 + 1, sizeof(char))))
      Err(_("out of memory"));
	sql_escstr(sql, xname, rr->name, strlen(rr->name));

   if (!(xhost = calloc(strlen(rr->name) * 2 + 1, sizeof(char))))
      Err(_("out of memory"));
	querylen = snprintf(query, sizeof(query), "%.*s", strlen(rr->name) - strlen(soa->origin) - 1, rr->name);
	sql_escstr(sql, xhost, query, querylen);

	querylen = snprintf(query, sizeof(query), "DELETE FROM %s WHERE zone=%u AND (name='%s' OR name='%s')",
							  mydns_rr_table_name, soa->id, xname, xhost);
#if DEBUG_UPDATE_SQL
	Verbose("%s: DNS UPDATE: %s", desctask(t), query);
#endif
#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s: DNS UPDATE: DELETE RRSET_ALL: %s", desctask(t), query);
#endif
	Free(xname);
	Free(xhost);

	/* Execute the query */
	if (sql_nrquery(sql, query, querylen) != 0)
	{
		WarnSQL(sql, "%s: %s", desctask(t), _("error deleting all RRsets via DNS UPDATE"));
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_DB_ERROR);
	}
	sql_free(res);

	/* Output info to verbose log */
	snprintf(query, sizeof(query), "DELETE_ALL_RRSET %s", rr->name);
	task_output_info(t, query);
	t->update_done++;

	return 0;
}
/*--- update_delete_rrset_all() -----------------------------------------------------------------*/


/**************************************************************************************************
	UPDATE_DELETE_RR
	Deletes an RR from the zone for a specified name.
	Returns 0 on success, -1 on failure.
**************************************************************************************************/
static int
update_delete_rr(TASK *t, MYDNS_SOA *soa, UQ *q, UQRR *rr)
{
	static char data[DNS_MAXPACKETLEN_UDP];
	uint32_t	aux;
	char		*xname = NULL, *xhost = NULL, *xdata = NULL;
	char		query[512];
	size_t	querylen;
	SQL_RES	*res = NULL;
	SQL_ROW	row;

#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s: UPDATE_DELETE_RR: %s %u %s %s", desctask(t),
			rr->name, rr->ttl, mydns_class_str(rr->class), mydns_qtype_str(rr->type));
#endif

	if (update_get_rr_data(t, soa, q, rr, data, sizeof(data), &aux) != 0)
	{
#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s: update_get_rr_data failed", desctask(t));
#endif
		return dnserror(t, DNS_RCODE_FORMERR, ERR_INVALID_DATA);
	}

#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s: DNS UPDATE: DELETE RR: %s IN %s %s", desctask(t), rr->name, mydns_qtype_str(rr->type), data);
#endif

	/* Delete rr - check both the FQDN and the hostname without trailing dot */
   if (!(xname = calloc(strlen(rr->name) * 2 + 1, sizeof(char))))
      Err(_("out of memory"));
	sql_escstr(sql, xname, rr->name, strlen(rr->name));

   if (!(xhost = calloc(strlen(rr->name) * 2 + 1, sizeof(char))))
      Err(_("out of memory"));
	querylen = snprintf(query, sizeof(query), "%.*s", strlen(rr->name) - strlen(soa->origin) - 1, rr->name);
	sql_escstr(sql, xhost, query, querylen);

   if (!(xdata = calloc(strlen(data) * 2 + 1, sizeof(char))))
      Err(_("out of memory"));
	sql_escstr(sql, xdata, data, strlen(data));

	querylen = snprintf(query, sizeof(query),
		"DELETE FROM %s WHERE zone=%u AND (name='%s' OR name='%s') AND type='%s' AND data='%s'",
							  mydns_rr_table_name, soa->id, xname, xhost, mydns_qtype_str(rr->type), xdata);
#if DEBUG_UPDATE_SQL
	Verbose("%s: DNS UPDATE: %s", desctask(t), query);
#endif
#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s: DNS UPDATE: DELETE RR: %s", desctask(t), query);
#endif
	Free(xname);
	Free(xhost);
	Free(xdata);

	/* Execute the query */
	if (sql_nrquery(sql, query, querylen) != 0)
	{
		WarnSQL(sql, "%s: %s", desctask(t), _("error deleting RR via DNS UPDATE"));
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_DB_ERROR);
	}
	sql_free(res);

	/* Output info to verbose log */
	snprintf(query, sizeof(query), "DELETE %s IN %s %s", rr->name, mydns_qtype_str(rr->type), data);
	task_output_info(t, query);
	t->update_done++;

	return 0;
}
/*--- update_delete_rr() ------------------------------------------------------------------------*/


/**************************************************************************************************
	UPDATE_DELETE_RRSET
	Deletes an RRset from the zone for a specified name.
	Returns 0 on success, -1 on failure.
**************************************************************************************************/
static int
update_delete_rrset(TASK *t, MYDNS_SOA *soa, UQ *q, UQRR *rr)
{
	char		*xname = NULL, *xhost = NULL;
	char		query[512];
	size_t	querylen;
	SQL_RES	*res = NULL;
	SQL_ROW	row;

#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s: UPDATE_DELETE_RRSET: %s %u %s %s", desctask(t),
			rr->name, rr->ttl, mydns_class_str(rr->class), mydns_qtype_str(rr->type));
#endif

#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s: DNS UPDATE: DELETE RRSET: %s IN %s", desctask(t), rr->name, mydns_qtype_str(rr->type));
#endif

	/* Delete rr - check both the FQDN and the hostname without trailing dot */
   if (!(xname = calloc(strlen(rr->name) * 2 + 1, sizeof(char))))
      Err(_("out of memory"));
	sql_escstr(sql, xname, rr->name, strlen(rr->name));

   if (!(xhost = calloc(strlen(rr->name) * 2 + 1, sizeof(char))))
      Err(_("out of memory"));
	querylen = snprintf(query, sizeof(query), "%.*s", strlen(rr->name) - strlen(soa->origin) - 1, rr->name);
	sql_escstr(sql, xhost, query, querylen);

	querylen = snprintf(query, sizeof(query),
		"DELETE FROM %s WHERE zone=%u AND (name='%s' OR name='%s') AND type='%s'",
							  mydns_rr_table_name, soa->id, xname, xhost, mydns_qtype_str(rr->type));
#if DEBUG_UPDATE_SQL
	Verbose("%s: DNS UPDATE: %s", desctask(t), query);
#endif
#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s: DNS UPDATE: DELETE RRSET: %s", desctask(t), query);
#endif
	Free(xname);
	Free(xhost);

	/* Execute the query */
	if (sql_nrquery(sql, query, querylen) != 0)
	{
		WarnSQL(sql, "%s: %s", desctask(t), _("error deleting RRset via DNS UPDATE"));
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_DB_ERROR);
	}
	sql_free(res);

	/* Output info to verbose log */
	snprintf(query, sizeof(query), "DELETE %s IN %s", rr->name, mydns_qtype_str(rr->type));
	task_output_info(t, query);
	t->update_done++;

	return 0;
}
/*--- update_delete_rr() ------------------------------------------------------------------------*/


/**************************************************************************************************
	PROCESS_UPDATE
	Perform the requested update.
	Returns 0 on success, -1 on failure.
**************************************************************************************************/
static int
process_update(TASK *t, MYDNS_SOA *soa, UQ *q, UQRR *rr)
{
#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s: DNS UPDATE: process_update: q->name=[%s], q->type=%s, q->class=%s", desctask(t),
			q->name, mydns_qtype_str(q->type), mydns_class_str(q->class));
	Debug("%s: DNS UPDATE: process_update: rr->name=[%s], rr->type=%s, rr->class=%s", desctask(t),
			rr->name, mydns_qtype_str(rr->type), mydns_class_str(rr->class));
#endif

	/* 2.5.1: Add to an RRset */
	if (rr->class == q->class)
	{
#if DEBUG_ENABLED && DEBUG_UPDATE
		Debug("%s: DNS UPDATE: 2.5.1: Add to an RRset", desctask(t));
#endif
		return update_add_rr(t, soa, q, rr);
	}

	/* 2.5.2: Delete an RRset */
	if (rr->type != DNS_CLASS_ANY && !rr->rdlength)
	{
#if DEBUG_ENABLED && DEBUG_UPDATE
		Debug("%s: DNS UPDATE: 2.5.2: Delete an RRset", desctask(t));
#endif
		return update_delete_rrset(t, soa, q, rr);
	}

	/* 2.5.3: Delete all RRsets from a name */
	if (rr->type == DNS_CLASS_ANY && !rr->rdlength)
	{
#if DEBUG_ENABLED && DEBUG_UPDATE
		Debug("%s: DNS UPDATE: 2.5.3: Delete all RRsets from a name", desctask(t));
#endif
		return update_delete_rrset_all(t, soa, q, rr);
	}

	/* 2.5.4: Delete an RR from an RRset */
	if (rr->type != DNS_CLASS_ANY && rr->rdlength)
	{
#if DEBUG_ENABLED && DEBUG_UPDATE
		Debug("%s: DNS UPDATE: 2.5.4: Delete an RR from an RRset", desctask(t));
#endif
		return update_delete_rr(t, soa, q, rr);
	}

#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s: DNS UPDATE: process_update: no action", desctask(t));
#endif

	return 0;
}
/*--- process_update() --------------------------------------------------------------------------*/


/**************************************************************************************************
	CHECK_TMPRR
	Check the set of RRs described in q->tmprr -- each RRset must match exactly what's in the
	database, else we send NXRRSET.  AN "RRset" is described as an unique <NAME,TYPE>.
	Returns 0 on success, -1 on error.

	RFC 2136, 3.2.3 says:
	...build an RRset for each unique <NAME,TYPE> and compare each resulting RRset for set
	equality (same members, no more, no less) with RRsets in the zone.  If any Prerequisite
	RRset is not entirely and exactly matched by a zone RRset, signal NXRRSET to the requestor.
	If any RR in this section has a CLASS other than ZCLASS or NONE or ANY, signal FORMERR
	to the requestor.

	The temporary prerequisite RRsets are stored in q->tmprr (the count in q->num_tmprr).

	The algorithm used here is to loop through q->tmprr.
	The <NAME,TYPE> is inspected, and each RR with that <NAME,TYPE> is marked as 'tmprr->checked=1'.
	We then examine each <NAME,TYPE> of that sort in q->tmprr.
	Then, if any members of that <NAME,TYPE> are not matched, or if the count of records
	of that <NAME,TYPE> in the database does not match the number of records of that <NAME,TYPE>
	in q->tmprr, we return NXRRSET.

	The RFC isn't totally clear on AUX values, so I'm only checking AUX values on RR types where
	they ought to be relevant (currently MX and SRV).
**************************************************************************************************/
static int
check_tmprr(TASK *t, MYDNS_SOA *soa, UQ *q)
{
	int n, i;

#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s: DNS UPDATE: Checking prerequisite RRsets for exact match", desctask(t));
#endif

	/* Examine "tmprr" */
	for (n = 0; n < q->num_tmprr; n++)
	{
		TMPRR *tmprr = q->tmprr[n];
		char	*current_name = tmprr->name;					/* Current NAME being examined */
		dns_qtype_t	current_type = tmprr->type;			/* Current TYPE being examined */
		MYDNS_RR	*rr_first = NULL;								/* RRs for the current name/type */
		MYDNS_RR	*rr;												/* Current RR */
		int	total_prereq_rr = 0, total_db_rr = 0;		/* Total RRs in prereq and database */

		if (tmprr->checked)										/* Ignore if already checked */
		{
#if DEBUG_ENABLED && DEBUG_UPDATE
			Debug("%s: DNS UPDATE: Skipping prerequisite RRsets for %s/%s (already checked)", desctask(t), current_name, mydns_qtype_str(current_type));
#endif
			continue;
		}

#if DEBUG_ENABLED && DEBUG_UPDATE
		Debug("%s: DNS UPDATE: Checking prerequisite RRsets for %s/%s", desctask(t), current_name, mydns_qtype_str(current_type));
#endif

		/* Load all RRs for this name/type */
		if (mydns_rr_load(sql, &rr_first, soa->id, current_type, current_name, NULL) != 0)
		{
			sql_reopen();
			if (mydns_rr_load(sql, &rr_first, soa->id, current_type, current_name, NULL) != 0)
			{
				WarnSQL(sql, _("error finding %s type resource records for name `%s' in zone %u"),
						  mydns_qtype_str(current_type), current_name, soa->id);
				sql_reopen();
				return dnserror(t, DNS_RCODE_FORMERR, ERR_DB_ERROR);
			}
		}

		/* If no RRs were found, return NXRRSET */
		if (!rr_first)
		{
#if DEBUG_ENABLED && DEBUG_UPDATE
			Debug("%s: DNS UPDATE: Found prerequisite RRsets for %s/%s, but none in database (NXRRSET)",
					desctask(t), current_name, mydns_qtype_str(current_type));
#endif
			return dnserror(t, DNS_RCODE_NXRRSET, ERR_PREREQUISITE_FAILED);
		}

		/* Count the total number of RRs found in database */
		for (rr = rr_first; rr; rr = rr->next)
			total_db_rr++;
#if DEBUG_ENABLED && DEBUG_UPDATE
			Debug("%s: DNS UPDATE: Found %d database RRsets for %s/%s", desctask(t), total_db_rr,
					current_name, mydns_qtype_str(current_type));
#endif

		/* Mark all <NAME,TYPE> matches in tmprr with checked=1, and count the number of RRs */
		for (i = 0; i < q->num_tmprr; i++)
			if (q->tmprr[i]->type == current_type && !strcasecmp(q->tmprr[i]->name, current_name))
			{
				q->tmprr[i]->checked = 1;
				total_prereq_rr++;
			}
#if DEBUG_ENABLED && DEBUG_UPDATE
		Debug("%s: DNS UPDATE: Found %d prerequisite RRsets for %s/%s", desctask(t), total_prereq_rr,
				current_name, mydns_qtype_str(current_type));
#endif

		/* If total_db_rr doesn't equal total_prereq_rr, return NXRRSET */
		if (total_db_rr != total_prereq_rr)
		{
#if DEBUG_ENABLED && DEBUG_UPDATE
			Debug("%s: DNS UPDATE: Found %d prerequisite RRsets for %s/%s, but %d in database (NXRRSET)",
					desctask(t), total_prereq_rr, current_name, mydns_qtype_str(current_type), total_db_rr);
#endif
			mydns_rr_free(rr_first);
			return dnserror(t, DNS_RCODE_NXRRSET, ERR_PREREQUISITE_FAILED);
		}

		/* Also, for each matching <NAME,TYPE>, check to see if the record exists in the database.
			If it does, set matched=1.  If it does not, return NXRRSET */
		for (i = 0; i < q->num_tmprr; i++)
			if (q->tmprr[i]->type == current_type && !strcasecmp(q->tmprr[i]->name, current_name))
			{
				int found_match = 0;								/* Did we find a match for this RR? */

#if DEBUG_ENABLED && DEBUG_UPDATE
				Debug("%s: DNS UPDATE: looking for tmprr[%d] = %s/%s/%u/%s in database", desctask(t),
						i, q->tmprr[i]->name, mydns_qtype_str(q->tmprr[i]->type), q->tmprr[i]->aux, q->tmprr[i]->data);
#endif
				for (rr = rr_first; rr && !found_match; rr = rr->next)
				{
					/* See if the DATA (and possibly the AUX) matches */
					if (!strcasecmp(rr->data, q->tmprr[i]->data))
					{
						if (current_type == DNS_QTYPE_MX || current_type == DNS_QTYPE_SRV)
						{
							if (q->tmprr[i]->aux == rr->aux)
								found_match = 1;
						}
						else
							found_match = 1;
					}
				}

				/* No match found - return NXRRSET */
				if (!found_match)
				{
#if DEBUG_ENABLED && DEBUG_UPDATE
					Debug("%s: DNS UPDATE: No match for prerequisite %s/%s/%u/%s (NXRRSET)", desctask(t),
							q->tmprr[i]->name, mydns_qtype_str(q->tmprr[i]->type), q->tmprr[i]->aux, q->tmprr[i]->data);
#endif
					mydns_rr_free(rr_first);
					return dnserror(t, DNS_RCODE_NXRRSET, ERR_PREREQUISITE_FAILED);
				}
			}
		mydns_rr_free(rr_first);

	}

	return 0;
}
/*--- check_tmprr() -----------------------------------------------------------------------------*/


/**************************************************************************************************
	DNS_UPDATE
	Process a DNS UPDATE query.
**************************************************************************************************/
int
dns_update(TASK *t)
{
	MYDNS_SOA	*soa;												/* SOA record for zone */
	UQ				*q;												/* Update query data */
	int			n;

	/* Try to load SOA for zone */
	if (mydns_soa_load(sql, &soa, t->qname) < 0)
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_DB_ERROR);

	/* If there's no such zone, say REFUSED rather than NOTAUTH, to prevent "zone mining" */
	if (!soa)
		return dnserror(t, DNS_RCODE_REFUSED, ERR_ZONE_NOT_FOUND);

#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s: DNS UPDATE: SOA id %u", desctask(t), soa->id);
	Debug("%s: DNS UPDATE: ZOCOUNT=%d (Zone)", desctask(t), t->qdcount);
	Debug("%s: DNS UPDATE: PRCOUNT=%d (Prerequisite)", desctask(t), t->ancount);
	Debug("%s: DNS UPDATE: UPCOUNT=%d (Update)", desctask(t), t->nscount);
	Debug("%s: DNS UPDATE: ADCOUNT=%d (Additional data)", desctask(t), t->arcount);
#endif

	/* Check the optional 'update' column if it exists */
	if (check_update(t, soa) != 0)
		return -1;

	/* Parse the update query */
	if (!(q = calloc(1, sizeof(UQ))))
		Err(_("out of memory"));
	if (parse_update_query(t, soa, q) != 0)
	{
#if DEBUG_ENABLED && DEBUG_UPDATE
		Debug("%s: DNS UPDATE: parse_update_query failed", desctask(t));
#endif
		goto dns_update_error;
	}

	/* Check the prerequsites as described in RFC 2136 3.2 */
	for (n = 0; n < q->numPR; n++)
		if (check_prerequisite(t, soa, q, &q->PR[n]) != 0)
		{
#if DEBUG_ENABLED && DEBUG_UPDATE
			Debug("%s: DNS UPDATE: check_prerequisite failed", desctask(t));
#endif
			goto dns_update_error;
		}

	/* Check the prerequisite RRsets -- RFC 2136 3.2.3 */
	if (check_tmprr(t, soa, q) != 0)
	{
#if DEBUG_ENABLED && DEBUG_UPDATE
			Debug("%s: DNS UPDATE: check_tmprr failed", desctask(t));
#endif
			goto dns_update_error;
	}

	/* Prescan the update section (RFC 2136 3.4.1) */
	for (n = 0; n < q->numUP; n++)
		if (prescan_update(t, soa, q, &q->UP[n]) != 0)
		{
#if DEBUG_ENABLED && DEBUG_UPDATE
			Debug("%s: DNS UPDATE: prescan_update failed", desctask(t));
#endif
			goto dns_update_error;
		}

	/* Process the update section (RFC 2136 3.4.2) */
	if (update_transaction(t, "BEGIN") != 0)				/* Start transaction */
		goto dns_update_error;
	for (n = 0; n < q->numUP; n++)
	{
		if (process_update(t, soa, q, &q->UP[n]) != 0)
		{
#if DEBUG_ENABLED && DEBUG_UPDATE
			Debug("%s: DNS UPDATE: process_update failed", desctask(t));
#endif
			if (update_transaction(t, "ROLLBACK") != 0)	/* Rollback transaction */
				goto dns_update_error;
			goto dns_update_error;
		}
	}
	if (update_transaction(t, "COMMIT") != 0)				/* Commit changes */
		goto dns_update_error;

	if (t->update_done)
		t->info_already_out = 1;

	/* Purge the cache for this zone */
	cache_purge_zone(ZoneCache, soa->id);
#if USE_NEGATIVE_CACHE
	cache_purge_zone(NegativeCache, soa->id);
#endif
	cache_purge_zone(ReplyCache, soa->id);

	/* Construct reply and set task status */
	build_reply(t, 0);
	t->status = NEED_WRITE;

	/* Clean up and return */
	free_uq(q);
	mydns_soa_free(soa);
	return 0;

dns_update_error:
	build_reply(t, 1);
#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s: DNS UPDATE: Went to dns_update_error", desctask(t));
#endif
	free_uq(q);
	mydns_soa_free(soa);
	return -1;
}
/*--- dns_update() ------------------------------------------------------------------------------*/

/* vi:set ts=3: */
