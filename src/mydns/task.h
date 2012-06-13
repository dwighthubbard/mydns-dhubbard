/**************************************************************************************************
	$Id: task.h,v 1.18 2005/04/20 16:49:12 bboy Exp $

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

#ifndef _MYDNS_TASK_H
#define _MYDNS_TASK_H

/* If defined, DYNAMIC_NAMES causes dynamic allocation of the encoded names list.  It's slow. */
#define	DYNAMIC_NAMES	0

#define	MAX_CNAME_LEVEL	6


/* Task status flags */
typedef enum _taskstat_t
{
	NEED_READ = 0,								/* We need to read the question */
	NEED_ANSWER = 1,							/* We need to find the answer */
	NEED_WRITE = 2,							/* We need to write the answer */
	NEED_RECURSIVE_FWD_CONNECT = 3,		/* Need to open connection to recursive server */
	NEED_RECURSIVE_FWD_WRITE = 4,			/* Need to write the question to recursive forwarder */
	NEED_RECURSIVE_FWD_READ = 5,			/* Need to read the answer from recursive forwarder */
} taskstat_t;


/* RR: A single resource record (of any supported type) */
typedef struct _named_rr
{
	dns_rrtype_t	rrtype;					/* Record type (what table this data came from) */
	uint32_t			id;						/* ID associated with RR */
	unsigned char	name[DNS_MAXNAMELEN];/* Name to send with reply */
	off_t				offset;					/* The offset within the reply data (t->rdata) */
	size_t			length;					/* The length of data within the reply */
	uint8_t			sort_level;				/* Primary sort order */
	uint32_t			sort1, sort2;			/* Sort order within level */
	unsigned int	lb_low, lb_high;		/* High/low values for load balancing (ugh) */
	void				*rr;						/* The RR data */

	struct _named_rr *next;					/* Pointer to the next item */
} RR;

/* RRLIST: A list of resource records */
typedef struct _named_rrlist
{
	size_t	size;								/* Count of records */

	int		a_records;						/* Number of A or AAAA records (for sorting) */
	int		mx_records;						/* Number of MX records (for sorting) */
	int		srv_records;					/* Number of SRV records (for sorting) */

	RR			*head;							/* Head of list */
	RR			*tail;							/* Tail of list */
} RRLIST;


/* TASK: DNS query task */
typedef struct _named_task
{
	unsigned long	internal_id;								/* Internal task ID */
	taskstat_t		status;										/* Current status of query */
	int				fd;											/* Socket FD */
	time_t			timeout;										/* Time task expires (timeout) */

	int				recursive_fd;								/* Connection with recursive forwarder */

	int				protocol;									/* Type of socket (SOCK_DGRAM/SOCK_STREAM) */
	int				family;										/* Socket family (AF_INET/AF_INET6) */

	struct sockaddr_in	addr4;								/* IPv4 address of client */
#if HAVE_IPV6
	struct sockaddr_in6	addr6;								/* IPv6 address of client */
#endif

	/* I/O information for TCP queries */
	size_t			len;											/* Query length */
	char				*query;										/* Query data */
	size_t			offset;										/* Current offset */
	int				len_written;								/* Have we written length octets? */

	/* Query information */
	uint32_t			minimum_ttl;								/* Minimum TTL for current zone */
	uint16_t			id;											/* Query ID */
	DNS_HEADER		hdr;											/* Header */
	dns_class_t		qclass;										/* Query class */
	dns_qtype_t		qtype;										/* Query type */
	char				qname[DNS_MAXNAMELEN];					/* Query name object */
	task_error_t	reason;										/* Further explanation of the error */

	uint32_t			Cnames[MAX_CNAME_LEVEL];				/* Array of CNAMEs found */

	unsigned char	*qd;											/* Question section data */
	size_t			qdlen;										/* Size of question section */
	uint16_t			qdcount;										/* "qdcount", from header */
	uint16_t			ancount;										/* "ancount", from header */
	uint16_t			nscount;										/* "nscount", from header */
	uint16_t			arcount;										/* "arcount", from header */

	int				no_markers;									/* Do not use markers? */

#if DYNAMIC_NAMES
	char				**Names;										/* Names stored in reply */
	unsigned int	*Offsets;									/* Offsets for names */
#else
#define	MAX_STORED_NAMES	128
	char				Names[MAX_STORED_NAMES][DNS_MAXNAMELEN + 1];	/* Names stored in reply */
	unsigned int	Offsets[MAX_STORED_NAMES];				/* Offsets for names */
#endif

	unsigned int	numNames;									/* Number of names in the list */

	uint32_t			zone;											/* Zone ID */

	uint8_t			sort_level;									/* Current sort level */

	RRLIST			an, ns, ar;									/* RR's for ANSWER, AUTHORITY, ADDITIONAL */

	char				*rdata;										/* Header portion of reply */
	size_t			rdlen;										/* Length of `rdata' */

	char				*reply;										/* Total constructed reply data */
	size_t			replylen;									/* Length of `reply' */

	int				reply_from_cache;							/* Did reply come from reply cache? */

	int				reply_cache_ok;							/* Can we cache this reply? */
	int				name_ok;										/* Does _some_ record match the name? */

	int				forwarded;									/* Forwarded to a recursive server? */

	int				update_done;								/* Did we do any dynamic updates? */
	int				info_already_out;							/* Has the info already been output? */

	struct _named_task *prev, *next;							/* Pointers to previous/next rec in queue */
} TASK;

#endif /* !_MYDNS_TASK_H */
/* vi:set ts=3: */
