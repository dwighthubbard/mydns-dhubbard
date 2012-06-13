/**************************************************************************************************
	$Id: axfr.c,v 1.39 2005/05/06 16:06:18 bboy Exp $

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

#include "named.h"

/* Make this nonzero to enable debugging for this source file */
#define	DEBUG_AXFR	1


#define	AXFR_TIME_LIMIT		3600		/* AXFR may not take more than this long, overall */

static size_t total_records, total_octets;


/**************************************************************************************************
	AXFR_ERROR
	Quits and outputs a warning message.
**************************************************************************************************/
/* Stupid compiler doesn't know exit from _exit... */
/* static void axfr_error(TASK *, const char *, ...) __attribute__ ((__noreturn__)); */
static void
axfr_error(TASK *t, const char *fmt, ...)
{
	va_list	ap;
	char		msg[BUFSIZ];

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	if (t)
		task_output_info(t, NULL);
	else
		Warnx("%s", msg);

	sockclose(t->fd);

	_exit(EXIT_FAILURE);
	/* NOTREACHED */
}
/*--- axfr_error() ------------------------------------------------------------------------------*/


/**************************************************************************************************
	AXFR_TIMEOUT
	Hard timeout called by SIGALRM after one hour.
**************************************************************************************************/
static void
axfr_timeout(int dummy)
{
	axfr_error(NULL, _("AXFR timed out"));
}
/*--- axfr_timeout() ----------------------------------------------------------------------------*/


/**************************************************************************************************
	AXFR_WRITE_WAIT
	Wait for the client to become ready to read.  Times out after `task_timeout' seconds.
**************************************************************************************************/
static void
axfr_write_wait(TASK *t)
{
	fd_set	wfd;
	struct timeval tv;
	int		rv;

	FD_ZERO(&wfd);
	FD_SET(t->fd, &wfd);
	tv.tv_sec = task_timeout;
	tv.tv_usec = 0;
	if ((rv = select(t->fd + 1, NULL, &wfd, NULL, &tv)) < 0)
		axfr_error(t, "%s: %s", _("select"), strerror(errno));
	if (rv != 1 || !FD_ISSET(t->fd, &wfd))
		axfr_error(t, _("write timeout"));
}
/*--- axfr_write_wait() -------------------------------------------------------------------------*/


/**************************************************************************************************
	AXFR_WRITE
	Writes the specified buffer, obeying task_timeout (via axfr_write_wait).
**************************************************************************************************/
static void
axfr_write(TASK *t, char *buf, size_t size)
{
	int		rv;
	size_t	offset = 0;

	do
	{
		axfr_write_wait(t);
		if ((rv = write(t->fd, buf+offset, size-offset)) < 0)
			axfr_error(t, "write: %s", strerror(errno));
		if (!rv)
			axfr_error(t, _("client closed connection"));
		offset += rv;
	} while (offset < size);
}
/*--- axfr_write() ------------------------------------------------------------------------------*/


/**************************************************************************************************
	AXFR_REPLY
	Sends one reply to the client.
**************************************************************************************************/
static void
axfr_reply(TASK *t)
{
	char len[2], *l = len;

	build_reply(t, 0);
	DNS_PUT16(l, t->replylen);
	axfr_write(t, len, SIZE16);
	axfr_write(t, t->reply, t->replylen);
	total_octets += SIZE16 + t->replylen;
	total_records++;

	/* Reset the pertinent parts of the task reply data */
	rrlist_free(&t->an);
	rrlist_free(&t->ns);
	rrlist_free(&t->ar);

	Free(t->reply);
	t->replylen = 0;

	name_forget(t);

	Free(t->rdata);
	t->rdlen = 0;

	/* Nuke question data */
	t->qdcount = 0;
	t->qdlen = 0;
}
/*--- axfr_reply() ------------------------------------------------------------------------------*/


/**************************************************************************************************
	CHECK_XFER
	If the "xfer" column exists in the soa table, it should contain a list of wildcards separated
	by commas.  In order for this zone transfer to continue, one of the wildcards must match
	the client's IP address.
**************************************************************************************************/
static void
check_xfer(TASK *t, MYDNS_SOA *soa)
{
	SQL_RES	*res = NULL;
	SQL_ROW	row;
	char		ip[256];
	char		query[512];
	size_t	querylen;
	int		ok = 0;

	if (!mydns_soa_use_xfer)
		return;

	strncpy(ip, clientaddr(t), sizeof(ip)-1);

	querylen = snprintf(query, sizeof(query), "SELECT xfer FROM %s WHERE id=%u%s",
		mydns_soa_table_name, soa->id, mydns_rr_use_active ? " AND active=1" : "");

	if (!(res = sql_query(sql, query, querylen)))
		ErrSQL(sql, "%s: %s", desctask(t), _("error loading zone transfer access rules"));

	if ((row = sql_getrow(res)))
	{
		char *wild, *r;

#if DEBUG_ENABLED && DEBUG_AXFR
		Debug("%s: checking AXFR access rule '%s'", desctask(t), row[0]);
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
	{
		dnserror(t, DNS_RCODE_REFUSED, ERR_NO_AXFR);
		axfr_reply(t);
		axfr_error(t, _("access denied"));
	}
}
/*--- check_xfer() ------------------------------------------------------------------------------*/


/**************************************************************************************************
	AXFR_ZONE
	DNS-based zone transfer.
**************************************************************************************************/
static void
axfr_zone(TASK *t, MYDNS_SOA *soa)
{
#if DEBUG_ENABLED && DEBUG_AXFR
	Debug("%s: Beginning zone transfer", desctask(t));
#endif

	/* Check optional "xfer" column and initialize reply */
	check_xfer(t, soa);
	reply_init(t);

	/* Send opening SOA record */
	rrlist_add(t, ANSWER, DNS_RRTYPE_SOA, (void *)soa, soa->origin);
	axfr_reply(t);

#if DEBUG_ENABLED && DEBUG_AXFR
	Debug("%s: Initial SOA record sent", desctask(t));
#endif

	/*
	**  Get all resource records for zone (if zone ID is nonzero, i.e. not manufactured)
	**  and transmit each resource record.
	*/
	if (soa->id)
	{
		MYDNS_RR *ThisRR = NULL, *rr;

		if (mydns_rr_load(sql, &ThisRR, soa->id, DNS_QTYPE_ANY, NULL, soa->origin) == 0)
		{
			for (rr = ThisRR; rr; rr = rr->next)
			{
				int len;

#if DEBUG_ENABLED && DEBUG_AXFR
				Debug("%s: Examining rr->name '%s'", desctask(t), rr->name);
#endif

				/* If 'name' doesn't end with a dot, append the origin */
				len = strlen(rr->name);
				if (rr->name[len-1] != '.')
				{
#if DEBUG_ENABLED && DEBUG_AXFR
					Debug("%s: Appending origin for name '%s'", desctask(t), rr->name);
#endif
					if (*rr->name)
						strcat(rr->name, ".");
					strncat(rr->name, soa->origin, sizeof(rr->name) - len - 1);
#if DEBUG_ENABLED && DEBUG_AXFR
					Debug("%s: rr->name is now '%s'", desctask(t), rr->name);
#endif
				}

#if ALIAS_ENABLED
				/* If we have been compiled with alias support and the current record is an alias pass it to alias_recurse() */
				if (rr->alias != 0)
					alias_recurse(t, ANSWER, rr->name, soa, NULL, rr);
				else
#endif
				rrlist_add(t, ANSWER, DNS_RRTYPE_RR, (void *)rr, rr->name);
				/* Transmit this resource record */
				axfr_reply(t);
			}
			mydns_rr_free(ThisRR);
		}
	}

	/* Send closing SOA record */
	rrlist_add(t, ANSWER, DNS_RRTYPE_SOA, (void *)soa, soa->origin);
	axfr_reply(t);
#if DEBUG_ENABLED && DEBUG_AXFR
	Debug("%s: Closing SOA record sent", desctask(t));
#endif

	mydns_soa_free(soa);
}
/*--- axfr_zone() -------------------------------------------------------------------------------*/


/**************************************************************************************************
	AXFR_GET_SOA
	Attempt to find a SOA record.  If SOA id is 0, we made it up.
**************************************************************************************************/
static MYDNS_SOA *
axfr_get_soa(TASK *t)
{
	MYDNS_SOA *soa = NULL;

	/* Try to load SOA */
	if (mydns_soa_load(sql, &soa, t->qname) < 0)
		ErrSQL(sql, "%s: %s", desctask(t), _("error loading zone"));
	if (soa)
	{
#if DEBUG_ENABLED && DEBUG_AXFR
		Debug("AXFR: %s: SOA record %u", soa->origin, soa->id);
#endif
		return (soa);
	}

	/* STILL no SOA?  We aren't authoritative */
	dnserror(t, DNS_RCODE_REFUSED, ERR_ZONE_NOT_FOUND);
	axfr_reply(t);
	axfr_error(t, _("unknown zone"));
	/* NOTREACHED */
	return (NULL);
}
/*--- axfr_get_soa() ----------------------------------------------------------------------------*/


/**************************************************************************************************
	AXFR
	DNS-based zone transfer.  Send all resource records for in QNAME's zone to the client.
**************************************************************************************************/
void
axfr(TASK *t)
{
	struct timeval start, finish;								/* Time AXFR began and ended */
	MYDNS_SOA *soa;												/* SOA record for zone (may be bogus!) */

	/* Do generic startup stuff; this is a child process */
	signal(SIGALRM, axfr_timeout);
	alarm(AXFR_TIME_LIMIT);
	sql = NULL;
	db_connect();
	gettimeofday(&start, NULL);
	total_records = total_octets = 0;
	t->no_markers = 1;

#if DEBUG_ENABLED && DEBUG_AXFR
	Debug("%s: Starting AXFR for task ID %lu", desctask(t), t->internal_id);
#endif

	/* Get SOA for zone */
	soa = axfr_get_soa(t);

	/* Transfer that zone */
	axfr_zone(t, soa);

	/* Report result */
	gettimeofday(&finish, NULL);
#if DEBUG_ENABLED && DEBUG_AXFR
	Debug("AXFR: %u records, %u octets, %.3fs", 
		total_records, total_octets,
		((finish.tv_sec + finish.tv_usec / 1000000.0) - (start.tv_sec + start.tv_usec / 1000000.0)));
#endif
	t->qdcount = 1;
	t->an.size = total_records;
	task_output_info(t, NULL);

	sockclose(t->fd);

	_exit(EXIT_SUCCESS);
}
/*--- axfr() ------------------------------------------------------------------------------------*/

/* vi:set ts=3: */
/* NEED_PO */
