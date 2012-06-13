/**************************************************************************************************
	$Id: recursive.c,v 1.8 2005/03/22 17:44:57 bboy Exp $

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
#define	DEBUG_RECURSIVE	1


/**************************************************************************************************
	RECURSIVE_FWD
	Forward a request to a recursive server.
**************************************************************************************************/
int
recursive_fwd(TASK *t)
{
	int rv;

#if DEBUG_ENABLED && DEBUG_RECURSIVE
	Debug("%s: recursive_fwd()", desctask(t));
#endif

#if HAVE_IPV6
	if (t->family == AF_INET6)
	{
	}
	else
#endif
	{
		if ((t->recursive_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		{
			Warn("%s: %s", recursive_fwd_server, _("error creating socket for recursive forwarding"));
			return dnserror(t, DNS_RCODE_SERVFAIL, ERR_FWD_RECURSIVE);
		}
		fcntl(t->recursive_fd, F_SETFL, fcntl(t->recursive_fd, F_GETFL, 0) | O_NONBLOCK);
		if ((rv = connect(t->recursive_fd, (const struct sockaddr *)&recursive_sa, sizeof(struct sockaddr_in))) < 0)
		{
			Warn("%s: %s", recursive_fwd_server, _("error connecting to recursive forwarder"));
			return dnserror(t, DNS_RCODE_SERVFAIL, ERR_FWD_RECURSIVE);
		}
#if DEBUG_ENABLED && DEBUG_RECURSIVE
		Debug("%s: connect to %s returned %d", desctask(t), recursive_fwd_server, rv);
#endif
		if (!rv)
			t->status = NEED_RECURSIVE_FWD_WRITE;
		else
			t->status = NEED_RECURSIVE_FWD_CONNECT;
	}
	return 0;
}
/*--- recursive_fwd() ---------------------------------------------------------------------------*/


/**************************************************************************************************
	RECURSIVE_FWD_CONNECT
	Open connection to recursive forwarder.
	XXX: Will this connect() ever block?
**************************************************************************************************/
int
recursive_fwd_connect(TASK *t)
{
#if DEBUG_ENABLED && DEBUG_RECURSIVE
	Debug("%s: recursive_fwd_connect()", desctask(t));
#endif
	return dnserror(t, DNS_RCODE_SERVFAIL, ERR_FWD_RECURSIVE);
	return 0;
}
/*--- recursive_fwd_connect() -------------------------------------------------------------------*/


/**************************************************************************************************
	RECURSIVE_FWD_WRITE
	Write question to recursive forwarder.
**************************************************************************************************/
int
recursive_fwd_write(TASK *t)
{
	char		*query = NULL;										/* Query packet */
	size_t	querylen;											/* Length of 'query' */
	int		rv;

#if DEBUG_ENABLED && DEBUG_RECURSIVE
	Debug("%s: recursive_fwd_write()", desctask(t));
#endif

	/* Construct the query */
	if (!(query = dns_make_question(t->id, t->qtype, t->qname, 1, &querylen)))
		return dnserror(t, DNS_RCODE_FORMERR, querylen);

#if DEBUG_ENABLED && DEBUG_RECURSIVE
	Debug("%s: recursive_fwd_write(): Constructed %d byte query", desctask(t), querylen);
#endif

	/* Send to remote server */
	if ((rv = sendto(t->recursive_fd, query, querylen, 0,
						  (struct sockaddr *)&recursive_sa, sizeof(struct sockaddr_in))) != querylen)
	{
		if (errno == EAGAIN)
		{
#if DEBUG_ENABLED && DEBUG_RECURSIVE
			Debug("%s: not ready to write, will retry", recursive_fwd_server);
#endif
			return 1;
		}
		
		if (rv < 0)
			Warn("%s: %s", recursive_fwd_server, _("error sending question to recursive forwarder"));
		else
			Warnx("%s: %s", recursive_fwd_server, _("short count sending quersion to recursive forwarder"));
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_FWD_RECURSIVE);
	}

#if DEBUG_ENABLED && DEBUG_RECURSIVE
	Debug("%s: recursive_fwd_write(): Sent %d bytes to %s", desctask(t), querylen, recursive_fwd_server);
#endif
	return 0;
}
/*--- recursive_fwd_write() ---------------------------------------------------------------------*/


/**************************************************************************************************
	RECURSIVE_FWD_READ
	Reads question from recursive forwarder.
	Returns -1 on error, 0 on success, 1 on "try again".
**************************************************************************************************/
int
recursive_fwd_read(TASK *t)
{
	char	reply[DNS_MAXPACKETLEN_UDP + 2], *r;
	int	replylen, addrlen = sizeof(struct sockaddr_in);
	uint16_t id, qdcount, ancount, nscount, arcount;
	DNS_HEADER hdr;

#if DEBUG_ENABLED && DEBUG_RECURSIVE
	Debug("%s: recursive_fwd_read()", desctask(t));
#endif

	if ((replylen = recvfrom(t->recursive_fd, &reply, sizeof(reply), 0,
									 (struct sockaddr *)&recursive_sa, &addrlen)) < 0)
	{
		if (errno == EAGAIN)
		{
#if DEBUG_ENABLED && DEBUG_RECURSIVE
			Debug("%s: not ready to read, will retry", recursive_fwd_server);
#endif
			return 1;
		}

		Warn("%s: %s", recursive_fwd_server, _("error reading reply from recursive forwarder"));
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_FWD_RECURSIVE);
	}
   if (!replylen)
	{
		Warnx("%s: %s", recursive_fwd_server, _("no reply from recursive forwarder"));
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_FWD_RECURSIVE);
	}

#if DEBUG_ENABLED && DEBUG_RECURSIVE
	Debug("%s: recursive_fwd_read(): Read %d bytes from %s", desctask(t), replylen, recursive_fwd_server);
#endif

	/* Copy reply into task */
	if (!(t->reply = malloc(replylen)))
		Err(_("out of memory"));
	memcpy(t->reply, reply, replylen);
	t->replylen = replylen;
	r = t->reply;

	/* Parse reply data into id, header, etc */
	DNS_GET16(id, r);
	memcpy(&hdr, r, SIZE16); r += SIZE16;
	DNS_GET16(qdcount, r);
	DNS_GET16(ancount, r);
	DNS_GET16(nscount, r);
	DNS_GET16(arcount, r);

	/* Set record counts and rcode */
	t->hdr.rcode = hdr.rcode;
	t->an.size = ancount;
	t->ns.size = nscount;
	t->ar.size = arcount;

	/* Cache these replies? */
	t->reply_cache_ok = 1;

	/* Record the fact that this question was forwarded to another server */
	t->forwarded = 1;

	return 0;
}
/*--- recursive_fwd_read() ----------------------------------------------------------------------*/

/* vi:set ts=3: */
/* NEED_PO */
