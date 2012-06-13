/**************************************************************************************************
	$Id: task.c,v 1.86 2006/01/18 20:50:39 bboy Exp $

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
#define	DEBUG_TASK	1


extern void server_status(void);
extern void named_cleanup(int);


/**************************************************************************************************
	NEW_TASK
	Given a request (TCP or UDP), populates task structure.
	'socktype' should be either SOCK_STREAM or SOCK_DGRAM.
	Returns 0 on success, -1 on error, -2 if the task is now invalid.
**************************************************************************************************/
int
new_task(TASK *t, unsigned char *data, size_t len)
{
	unsigned char qname[DNS_MAXNAMELEN+1], *src, *qdtop;

#if DEBUG_ENABLED && DEBUG_TASK
	Debug("new_task(%p, %p, %u)", t, data, len);
#endif

	/* Query needs to at least contain a proper header */
	if (len < DNS_HEADERSIZE)
		return formerr(t, DNS_RCODE_FORMERR, ERR_MALFORMED_REQUEST, _("query so small it has no header"));

	/* Refuse queries that are too long */
	if (len > (t->protocol == SOCK_STREAM ? DNS_MAXPACKETLEN_TCP : DNS_MAXPACKETLEN_UDP))
		return formerr(t, DNS_RCODE_FORMERR, ERR_MALFORMED_REQUEST, _("query too large"));

	/* Parse query header data */
	src = data;
	DNS_GET16(t->id, src);
	memcpy(&t->hdr, src, SIZE16); src += SIZE16;
	DNS_GET16(t->qdcount, src);
	DNS_GET16(t->ancount, src);
	DNS_GET16(t->nscount, src);
	DNS_GET16(t->arcount, src);

	/* Discard queries where the response bit is set; it might be a spoofed packet
		asking us to talk to ourselves */
	if (t->hdr.qr)
	{
		formerr(t, DNS_RCODE_FORMERR, ERR_RESPONSE_BIT_SET, _("response bit set on query"));
		if (t->protocol == SOCK_STREAM)
			sockclose(t->fd);
		dequeue(Tasks, t);
		return -2;
	}

#if DEBUG_ENABLED && DEBUG_TASK
	Debug("%s: id=%u qr=%u opcode=%s aa=%u tc=%u rd=%u ra=%u z=%u rcode=%u", desctask(t),
			t->id, t->hdr.qr, mydns_opcode_str(t->hdr.opcode),
			t->hdr.aa, t->hdr.tc, t->hdr.rd, t->hdr.ra, t->hdr.z, t->hdr.rcode);
	Debug("%s: qd=%u an=%u ns=%u ar=%u", desctask(t),
			t->qdcount, t->ancount, t->nscount, t->arcount);
#endif

	/* If 'query' isn't set and this is an UPDATE query, save a copy of the whole query for parsing */
	if (!t->query && t->hdr.opcode == DNS_OPCODE_UPDATE)
	{
		t->len = len;
		if (!(t->query = malloc(t->len)))
			Err(_("out of memory"));
		memcpy(t->query, data, t->len);
	}

	task_init_header(t);											/* Initialize header fields for reply */

	t->qdlen = len - DNS_HEADERSIZE;							/* Fill in question data */
	if (t->qdlen <= 0)
		return formerr(t, DNS_RCODE_FORMERR, ERR_MALFORMED_REQUEST, _("question has zero length"));
	if (!(t->qd = malloc(t->qdlen)))
		Err(_("out of memory"));
	memcpy(t->qd, src, t->qdlen);
	qdtop = src;

	/* Get query name */
	if (!(src = name_unencode(t->qd, t->qdlen, src, qname, sizeof(qname))))
	{
		Warnx("%s: FORMERR in query", desctask(t));
		return formerr(t, DNS_RCODE_FORMERR, (task_error_t)qname[0], NULL);
	}
	strncpy(t->qname, qname, sizeof(t->qname)-1);

	/* Now we have question data, so initialize encoding */
	if (reply_init(t) < 0)
		return Warnx("%s: %s", desctask(t), _("failed to initialize reply"));

	/* Get query type */
	if (src + SIZE16 > data + len)
		return formerr(t, DNS_RCODE_FORMERR, ERR_MALFORMED_REQUEST, _("query too short; no qtype"));
	DNS_GET16(t->qtype, src);

	/* If this request is TCP and TCP is disabled, refuse the request */
	if (t->protocol == SOCK_STREAM && !tcp_enabled && (t->qtype != DNS_QTYPE_AXFR || !axfr_enabled))
		return formerr(t, DNS_RCODE_REFUSED, ERR_TCP_NOT_ENABLED, NULL);

	/* Get query class */
	if (src + SIZE16 > data + len)
		return formerr(t, DNS_RCODE_FORMERR, ERR_MALFORMED_REQUEST, _("query too short; no qclass"));
	DNS_GET16(t->qclass, src);

	t->qdlen = src - qdtop;

	/* Request must have at least one question */
	if (!t->qdcount)
		return formerr(t, DNS_RCODE_FORMERR, ERR_NO_QUESTION, _("query contains no questions"));

	/* Server can't handle more than 1 question per packet */
	if (t->qdcount > 1)
		return formerr(t, DNS_RCODE_FORMERR, ERR_MULTI_QUESTIONS, _("query contains more than one question"));

	/* Server won't accept truncated query */
	if (t->hdr.tc)
		return formerr(t, DNS_RCODE_FORMERR, ERR_QUESTION_TRUNCATED, _("query is truncated"));

	/* If DNS updates are enabled and the opcode is UPDATE, do the update */
	if (dns_update_enabled && t->hdr.opcode == DNS_OPCODE_UPDATE)
		return dns_update(t);

	/* Server only handles QUERY opcode */
	if (t->hdr.opcode != DNS_OPCODE_QUERY)
		return formerr(t, DNS_RCODE_NOTIMP, ERR_UNSUPPORTED_OPCODE, NULL);

	/* Check class (only IN or ANY are allowed unless status is enabled) */
	if ((t->qclass != DNS_CLASS_IN) && (t->qclass != DNS_CLASS_ANY)
#if STATUS_ENABLED
		 && (t->qclass != DNS_CLASS_CHAOS)
#endif
		)
		return formerr(t, DNS_RCODE_NOTIMP, ERR_NO_CLASS, NULL);

	/* If AXFR is requested, it must be TCP, and AXFR must be enabled */
	if (t->qtype == DNS_QTYPE_AXFR && (!axfr_enabled || t->protocol != SOCK_STREAM))
		return formerr(t, DNS_RCODE_REFUSED, ERR_NO_AXFR, NULL);

	/* If this is AXFR, fork to handle it so that other requests don't block */
	if (t->protocol == SOCK_STREAM && t->qtype == DNS_QTYPE_AXFR)
	{
		int pfd[2];													/* Parent/child pipe descriptors */
		pid_t pid, parent;

		if (pipe(pfd))
			Err("pipe");
		parent = getpid();
		if ((pid = fork()) < 0)
		{
			close(pfd[0]);
			close(pfd[1]);
			return Warn("%s: fork", clientaddr(t));
		}

		if (!pid)	/* Child: Let parent know I have started */
		{
			close(pfd[0]);
			if (write(pfd[1], "OK", 2) != 2)
				Warn(_("error writing startup notification"));
			close(pfd[1]);
			axfr(t);
		}
		else	/* Parent */
		{
			char	buf[5] = "\0\0\0\0\0";
			int	errct = 0;

			close(pfd[1]);

			for (errct = 0; errct < 5; errct++)
			{
				if (read(pfd[0], &buf, 4) != 2)
					Warn("%s (%d of 5)", _("error reading startup notification"), errct+1);
				else
					break;
			}
			close(pfd[0]);

#if DEBUG_ENABLED && DEBUG_TASK
			Debug("AXFR: process started on pid %d for TCP fd %d, task ID %lu", pid, t->fd, t->internal_id);
#endif
		}
		return (0);
	}

	t->status = NEED_ANSWER;

	return (0);
}
/*--- new_task() --------------------------------------------------------------------------------*/


/**************************************************************************************************
	CLIENTADDR
	Given a task, returns the client's IP address in printable format.
**************************************************************************************************/
char *
clientaddr(TASK *t)
{
	static char buf[256];

	buf[0] = '\0';

#if HAVE_IPV6
	if (t->family == AF_INET6)
		inet_ntop(AF_INET6, &t->addr6.sin6_addr, buf, sizeof(buf) - 1);
	else
#endif
		inet_ntop(AF_INET, &t->addr4.sin_addr, buf, sizeof(buf) - 1);
	return (buf);
}
/*--- clientaddr() ------------------------------------------------------------------------------*/


/**************************************************************************************************
	DESCTASK
	Describe a task; used by error/warning/debug output.
**************************************************************************************************/
char *
desctask(TASK *t)
{
	static char desc[1024];

	snprintf(desc, sizeof(desc), "%s: %s %s",
		clientaddr(t), mydns_qtype_str(t->qtype), t->qname ? (char *)t->qname : "<NONE>");
	return (desc);
}
/*--- desctask() --------------------------------------------------------------------------------*/


/**************************************************************************************************
	_TASK_INIT
	Allocates and initializes a new task, and returns a pointer to it.
	t = task_init(NEED_ZONE, SOCK_DGRAM, fd, &addr);
**************************************************************************************************/
TASK *
_task_init(
	taskstat_t status,			/* Initial status */
	int fd,							/* Associated file descriptor for socket */
	int protocol,					/* Protocol (SOCK_DGRAM or SOCK_STREAM) */
	int family,						/* Protocol (SOCK_DGRAM or SOCK_STREAM) */
	void *addr,						/* Remote address */
	const char *file, int line
)
{
	TASK *new;

	if (!(new = calloc(1, sizeof(TASK))))
		Err(_("out of memory"));

	new->status = status;
	new->fd = fd;
	new->recursive_fd = -1;
	new->protocol = protocol;
	new->family = family;
#if HAVE_IPV6
	if (new->family == AF_INET6)
		memcpy(&new->addr6, addr, sizeof(struct sockaddr_in6));
	else
#endif
		memcpy(&new->addr4, addr, sizeof(struct sockaddr_in));
	new->internal_id = Status.udp_requests + Status.tcp_requests;
	new->timeout = current_time + task_timeout;
	new->minimum_ttl = DNS_MINIMUM_TTL;
	new->reply_cache_ok = 1;

#if DEBUG_ENABLED && DEBUG_TASK
	Debug("%s: task_init(%p) from %s:%d", desctask(new), new, file, line);
#endif

	if (enqueue(Tasks, new) < 0)
	{
		task_free(new);
		return (NULL);
	}

	return (new);
}
/*--- _task_init() -------------------------------------------------------------------------------*/


/**************************************************************************************************
	_TASK_FREE
	Free the memory used by a task.
**************************************************************************************************/
void
_task_free(TASK *t, const char *file, int line)
{
	if (!t)
		return;

	sockclose(t->recursive_fd);

#if DEBUG_ENABLED && DEBUG_TASK
	Debug("%s: task_free(%p) from %s:%d", desctask(t), t, file, line);
#endif

#if DYNAMIC_NAMES
	{
		register int n;

		for (n = 0; n < t->numNames; n++)
			Free(t->Names[n]);
		if (t->numNames)
			Free(t->Names);
		Free(t->Offsets);
	}
#endif

	Free(t->query);
	Free(t->qd);
	rrlist_free(&t->an);
	rrlist_free(&t->ns);
	rrlist_free(&t->ar);
	Free(t->rdata);
	Free(t->reply);

	Free(t);

	if (answer_then_quit && (Status.udp_requests + Status.tcp_requests) >= answer_then_quit)
		named_cleanup(SIGQUIT);
}
/*--- _task_free() ------------------------------------------------------------------------------*/


/**************************************************************************************************
	TASK_INIT_HEADER
	Sets and/or clears header fields and values as necessary.
**************************************************************************************************/
void
task_init_header(TASK *t)
{
	t->hdr.qr = 1;								/* This is the response, not the query */
	t->hdr.ra = forward_recursive;		/* Are recursive queries available? */
	t->hdr.rcode = DNS_RCODE_NOERROR;	/* Assume success unless told otherwise */
}
/*--- task_init_header() ------------------------------------------------------------------------*/


/**************************************************************************************************
	TASK_OUTPUT_INFO
**************************************************************************************************/
void
task_output_info(TASK *t, char *update_desc)
{
#if !DISABLE_DATE_LOGGING
	struct timeval tv;
	time_t tt;
	struct tm *tm;
	char datebuf[80];
#endif

	/* If we've already outputted the info for this (i.e. multiple DNS UPDATE requests), ignore */
	if (t->info_already_out)
		return;

	/* Don't output anything for TCP sockets in the process of closing */
	if (t->protocol == SOCK_STREAM && t->fd < 0)
		return;

#if !DISABLE_DATE_LOGGING
	gettimeofday(&tv, NULL);
	tt = tv.tv_sec;
	tm = localtime(&tt);

	strftime(datebuf, sizeof(datebuf)-1, "%d-%b-%Y %H:%M:%S", tm);
#endif

	Verbose(
#if !DISABLE_DATE_LOGGING
		"%s+%06lu "
#endif
		"#%lu "
		"%d "		/* Client-provided ID */
		"%s "		/* TCP or UDP? */
		"%s "		/* Client IP */
		"%s "		/* Class */
		"%s "		/* Query type (A, MX, etc) */
		"%s " 	/* Name */
		"%s "		/* Return code (NOERROR, NXDOMAIN, etc) */
		"%s "		/* Reason */
		"%d "		/* Question section */
		"%d "		/* Answer section */
		"%d "		/* Authority section */
		"%d "		/* Additional section */
		"LOG "
		"%s "		/* Reply from cache? */
		"%s "		/* Opcode */
		"\"%s\""	/* UPDATE description (if any) */
		,
#if !DISABLE_DATE_LOGGING
		datebuf, tv.tv_usec,
#endif
		t->internal_id,
		t->id,
		t->protocol == SOCK_STREAM ? "TCP" : "UDP",
		clientaddr(t),
		mydns_class_str(t->qclass),
		mydns_qtype_str(t->qtype),
		t->qname,
		mydns_rcode_str(t->hdr.rcode),
		err_reason_str(t, t->reason),
		t->qdcount,
		t->an.size,
		t->ns.size,
		t->ar.size,
		(t->reply_from_cache ? "Y" : "N"),
		mydns_opcode_str(t->hdr.opcode),
		update_desc ? update_desc : ""
	);
}
/*--- task_output_info() ------------------------------------------------------------------------*/


/**************************************************************************************************
	TASK_PROCESS
	Process the specified task, if possible.  Returns a pointer to the next task.
**************************************************************************************************/
void
task_process(register TASK *t)
{
	int rv;


	/*
	**  NEED_READ: Need to read query
	*/
	if (t->status == NEED_READ)
	{
#if DEBUG_ENABLED && DEBUG_TASK
		Debug("%s: starting task_process() with NEED_READ status", desctask(t));
#endif

		switch (t->protocol)
		{
			case SOCK_DGRAM:
				Warnx("%s: %s", desctask(t), _("invalid state for UDP query"));
				return dequeue(Tasks, t);

			case SOCK_STREAM:
				if ((rv = read_tcp_query(t)) < 0)
				{
#if 0
					/* WHY??  20 May 2004 WDM */
					if (t->status == NEED_WRITE)
						break;
#endif
					sockclose(t->fd);

					/* If read_tcp_query() returns -2, the task has already been freed */
					if (rv == -1)
						dequeue(Tasks, t);

					return;
				}
				if (t->status != NEED_ANSWER)
					return;
				/* read_tcp_query did OK, status is now NEED_ANSWER, so move down and resolve */
				break;

			default:
				Warnx("%s: %d: %s", desctask(t), t->protocol, _("unknown/unsupported protocol"));
				return dequeue(Tasks, t);
		}
	}

	/*
	**  NEED_ANSWER: Need to resolve query
	*/
	if (t->status == NEED_ANSWER)
	{
#if DEBUG_ENABLED && DEBUG_TASK
		Debug("%s: starting task_process() with NEED_ANSWER status", desctask(t));
#endif

		if (reply_cache_find(t))
		{
			char *dest = t->reply;

			DNS_PUT16(dest, t->id);								/* Query ID */
			DNS_PUT(dest, &t->hdr, SIZE16);					/* Header */
			t->status = NEED_WRITE;
		}
		else
		{
			resolve(t, ANSWER, t->qtype, t->qname, 0);

			if (t->status < NEED_RECURSIVE_FWD_CONNECT)
			{
				build_reply(t, 1);
				if (t->reply_cache_ok)
					add_reply_to_cache(t);
				t->status = NEED_WRITE;
				if (t->protocol == SOCK_STREAM)
					return;
			}
		}
	}

	/*
	**  NEED_WRITE: Need to write reply
	*/
	if (t->status == NEED_WRITE)
	{
#if DEBUG_ENABLED && DEBUG_TASK
		Debug("%s: starting task_process() with NEED_WRITE status", desctask(t));
#endif

		switch (t->protocol)
		{
			case SOCK_DGRAM:
				return write_udp_reply(t);

			case SOCK_STREAM:
				/* No need to check return value, since we always return anyway. */
				write_tcp_reply(t);
				return;

			default:
				Warnx("%s: %d: %s", desctask(t), t->protocol, _("unknown/unsupported protocol"));
				return dequeue(Tasks, t);
		}
	}

	/*
	**  NEED_RECURSIVE_FWD_CONNECT: Need to connnect to recursive forwarder
	*/
	if (t->status == NEED_RECURSIVE_FWD_CONNECT)
	{
#if DEBUG_ENABLED && DEBUG_TASK
		Debug("%s: starting task_process() with NEED_RECURSIVE_FWD_CONNECT status", desctask(t));
#endif

		if (recursive_fwd_connect(t) < 0)
			return dequeue(Tasks, t);

		/* Successfully connected to the recursive forwarder */
		t->status = NEED_RECURSIVE_FWD_WRITE;
	}

	/*
	**  NEED_RECURSIVE_FWD_WRITE: Need to write request to recursive forwarder
	*/
	if (t->status == NEED_RECURSIVE_FWD_WRITE)
	{
		int rv2;

#if DEBUG_ENABLED && DEBUG_TASK
		Debug("%s: starting task_process() with NEED_RECURSIVE_FWD_WRITE status", desctask(t));
#endif

		rv2 = recursive_fwd_write(t);

		if (rv2 < 0)
			return dequeue(Tasks, t);
		else if (rv2 == 1)				/* 1 means "try again" */
			return;

		/* Forwarded recursive query written successfully */
		t->status = NEED_RECURSIVE_FWD_READ;
	}

	/*
	**  NEED_RECURSIVE_FWD_READ: Need to read reply from recursive forwarder
	*/
	if (t->status == NEED_RECURSIVE_FWD_READ)
	{
		int rv2;

#if DEBUG_ENABLED && DEBUG_TASK
		Debug("%s: starting task_process() with NEED_RECURSIVE_FWD_READ status", desctask(t));
#endif

		rv2 = recursive_fwd_read(t);

		if (rv2 < 0)
			return dequeue(Tasks, t);
		else if (rv2 == 1)				/* 1 means "try again" */
			return;

		/* Got recursive forwarder's reply; write it to the client */
		if (t->reply_cache_ok)
			add_reply_to_cache(t);
		t->status = NEED_WRITE;
	}

	return;
}
/*--- task_process() ----------------------------------------------------------------------------*/

/* vi:set ts=3: */
/* NEED_PO */
