/**************************************************************************************************
	$Id: named.h,v 1.65 2005/04/20 16:49:12 bboy Exp $

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

#ifndef _MYDNS_NAMED_H
#define _MYDNS_NAMED_H

#include "mydnsutil.h"
#include "header.h"
#include "mydns.h"
#include "task.h"
#include "cache.h"

#if HAVE_SYS_RESOURCE_H
#	include <sys/resource.h>
#endif

#if HAVE_SYS_WAIT_H
#	include <sys/wait.h>
#endif

#if HAVE_NETDB_H
#	include <netdb.h>
#endif


/* The alarm function runs every ALARM_INTERVAL seconds */
#define		ALARM_INTERVAL		15
#define		DNS_MAXPACKETLEN	DNS_MAXPACKETLEN_UDP
#if ALIAS_ENABLED
#	define	MAX_ALIAS_LEVEL	6
#endif

/* Maximum CNAME recursion depth */
#define	DNS_MAX_CNAME_RECURSION	25

/* Size of reply header data; that's id + DNS_HEADER + qdcount + ancount + nscount + arcount */
#define	DNS_HEADERSIZE		(SIZE16 * 6)


#define SQLESC(s,d) { \
		char *rv = alloca(strlen((s))*2+1); \
		if (!rv) Err("alloca"); \
		sql_escstr(sql, rv, s, strlen((s))); \
		d = rv; \
	}

/* This is the header offset at the start of most reply functions.
	The extra SIZE16 at the end is the RDLENGTH field in the RR's header. */
#define CUROFFSET(t) (DNS_HEADERSIZE + (t)->qdlen + (t)->rdlen + SIZE16)


#if DEBUG_ENABLED
extern char *datasection_str[];			/* Strings describing data section types */
#endif


/* Queue structure for TASK records (really not a queue, but a list) */
typedef struct _named_queue
{
	size_t	size;													/* Number of elements in queue */
	TASK		*head;												/* Pointer to first element in list */
	TASK		*tail;												/* Pointer to last element in list */
} QUEUE;


#define MAX_RESULTS	20
typedef struct _serverstatus									/* Server status information */
{
	time_t	start_time;	 										/* Time server started */
	uint32_t	udp_requests, tcp_requests;					/* Total # of requests handled */
	uint32_t	timedout;	 										/* Number of requests that timed out */
	uint32_t	results[MAX_RESULTS];							/* Result codes */
} SERVERSTATUS;

extern SERVERSTATUS Status;



/* Global variables */
extern CONF		*Conf;											/* Config file data */
extern QUEUE	*Tasks;											/* Task queue */
extern CACHE	*Cache;											/* Zone cache */
extern time_t	current_time;									/* Current time */
extern time_t	task_timeout;									/* Task timeout */
extern int		axfr_enabled;									/* Allow AXFR? */
extern int		tcp_enabled;									/* Enable TCP? */
extern int		dns_update_enabled;							/* Enable DNS UPDATE? */
extern int		ignore_minimum;								/* Ignore minimum TTL? */
extern char		hostname[256];									/* This machine's hostname */

extern uint32_t answer_then_quit;							/* Answer this many queries then quit */
extern int		show_data_errors;								/* Output data errors? */

extern int		forward_recursive;							/* Forward recursive queries? */
extern char		*recursive_fwd_server;						/* Name of server for recursive forwarding */
extern int		recursive_family;								/* Protocol family for recursion */

#if HAVE_IPV6
extern struct sockaddr_in6	recursive_sa6;					/* Recursive server (IPv6) */
#endif
extern struct sockaddr_in	recursive_sa;					/* Recursive server (IPv4) */


#if ALIAS_ENABLED
/* alias.c */
extern MYDNS_RR	*find_alias(TASK *, char *);
extern int			alias_recurse(TASK *t, datasection_t section, char *fqdn, MYDNS_SOA *soa, char *label, MYDNS_RR *alias);
#endif


/* axfr.c */
extern void		axfr(TASK *);


/* conf.c */
extern void		load_config(void);
extern void		dump_config(void);
extern void		conf_set_logging(void);
extern void		check_config_file_perms(void);


/* data.c */
extern MYDNS_SOA	*find_soa(TASK *, char *, char *);
extern MYDNS_RR	*find_rr(TASK *, MYDNS_SOA *, dns_qtype_t, char *);


/* db.c */
extern void		db_connect(void);
extern void		db_output_create_tables(void);
extern void		db_verify_tables(void);


/* encode.c */
extern int		name_remember(TASK *, char *, unsigned int);
extern void		name_forget(TASK *);
extern unsigned int	name_find(TASK *, char *);
extern char		*name_unencode(char *, size_t, char *, char *, size_t);
extern int		name_encode(TASK *, char *, char *, unsigned int, int);


/* error.c */
extern int		_formerr_internal(TASK *, dns_rcode_t, task_error_t, char *, const char *, unsigned int);
extern int		_dnserror_internal(TASK *, dns_rcode_t, task_error_t, const char *, unsigned int);
extern char		*err_reason_str(TASK *, task_error_t);
extern int		rr_error_repeat(uint32_t);
extern int		rr_error(uint32_t, const char *, ...) __printflike(2,3);

#define formerr(task,rcode,reason,xtra)	_formerr_internal((task),(rcode),(reason),(xtra),__FILE__,__LINE__)
#define dnserror(task,rcode,reason)			_dnserror_internal((task),(rcode),(reason),__FILE__,__LINE__)


/* queue.c */
extern QUEUE	*queue_init(void);
extern int		_enqueue(QUEUE *, TASK *, const char *, unsigned int);
extern void		_dequeue(QUEUE *, TASK *, const char *, unsigned int);

#define			enqueue(Q,T)	_enqueue((Q), (T), __FILE__, __LINE__)
#define			dequeue(Q,T)	_dequeue((Q), (T), __FILE__, __LINE__)


/* recursive.c */
extern int		recursive_fwd(TASK *);
extern int		recursive_fwd_connect(TASK *);
extern int		recursive_fwd_write(TASK *);
extern int		recursive_fwd_read(TASK *);


/* reply.c */
extern int		reply_init(TASK *);
extern void		build_cache_reply(TASK *);
extern void		build_reply(TASK *, int);


/* resolve.c */
extern int		resolve(TASK *, datasection_t, dns_qtype_t, char *, int);


/* rr.c */
extern void		rrlist_add(TASK *, datasection_t, dns_rrtype_t, void *, char *);
extern void		rrlist_free(RRLIST *);


/* sort.c */
extern void		sort_a_recs(TASK *, RRLIST *, datasection_t);
extern void		sort_mx_recs(TASK *, RRLIST *, datasection_t);
extern void		sort_srv_recs(TASK *, RRLIST *, datasection_t);


/* task.c */
extern int		new_task(TASK *, unsigned char *, size_t);
extern void		task_init_header(TASK *);
extern char		*clientaddr(TASK *);
extern char		*desctask(TASK *);
extern TASK		*_task_init(taskstat_t, int, int, int, void *, const char *, int);
#define			task_init(S,fd,p,f,a)	_task_init((S), (fd), (p), (f), (a), __FILE__, __LINE__)
extern void		_task_free(TASK *, const char *, int);
#define			task_free(T)	if ((T)) _task_free((T), __FILE__, __LINE__), (T) = NULL


extern void		task_build_reply(TASK *);
extern void		task_output_info(TASK *, char *);
extern void		task_process(register TASK *);


/* tcp.c */
extern int		accept_tcp_query(int, int);
extern int		read_tcp_query(TASK *);
extern int		write_tcp_reply(TASK *);


/* udp.c */
extern int		read_udp_query(int, int);
extern void		write_udp_reply(TASK *);


/* update.c */
extern int		dns_update(TASK *);

#endif /* _MYDNS_NAMED_H */

/* vi:set ts=3: */
