/**************************************************************************************************
	$Id: mydns.h,v 1.98 2005/12/18 19:16:41 bboy Exp $

	libmydns.h: Header file for the MyDNS library.

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

#ifndef _MYDNS_H
#define _MYDNS_H

#include "mydnsutil.h"
#include "bits.h"
#include "header.h"

/* Table names */
#define	MYDNS_SOA_TABLE	"soa"
#define	MYDNS_RR_TABLE		"rr"

/* Configurable table names */
extern char mydns_soa_table_name[PATH_MAX];
extern char mydns_rr_table_name[PATH_MAX];

/* Configurable WHERE clauses */
extern char *mydns_soa_where_clause;
extern char *mydns_rr_where_clause;

/* If this is nonzero, an 'active' field is assumed to exist in the table, and
	only active rows will be loaded by mydns_*_load() */
extern int mydns_soa_use_active;
#define mydns_set_soa_use_active(S)	\
				(mydns_soa_use_active = sql_iscolumn((S), mydns_soa_table_name, "active"))
extern int mydns_rr_use_active;
#define mydns_set_rr_use_active(S)	\
				(mydns_rr_use_active = sql_iscolumn((S), mydns_rr_table_name, "active"))

/* This is set by mydns_set_soa_use_xfer */
extern int mydns_soa_use_xfer;
#define mydns_set_soa_use_xfer(S)	\
				(mydns_soa_use_xfer = sql_iscolumn((S), mydns_soa_table_name, "xfer"))

/* This is set by mydns_set_soa_use_update_acl */
extern int mydns_soa_use_update_acl;
#define mydns_set_soa_use_update_acl(S)	\
				(mydns_soa_use_update_acl = sql_iscolumn((S), mydns_soa_table_name, "update_acl"))


/* This is set by mydns_set_rr_use_stamp (currently unimplemented - for future IXFR support */
extern int mydns_rr_use_stamp;
#define mydns_set_rr_use_stamp(S)	\
				(mydns_rr_use_stamp = sql_iscolumn((S), mydns_rr_table_name, "stamp"))

/* NOTE: `type' is listed at the end so that we can possibly set the value of `aux' for
	convenience based on the RR type; for example, an `A' record might store the IP in `aux'. */
#define	MYDNS_SOA_NUMFIELDS	10
#ifdef DN_COLUMN_NAMES
#	define	MYDNS_SOA_FIELDS	"zone_id,CONCAT(origin,\".\"),\"ns\",CONCAT(owner,\".\"),serial,refresh,retry,expire,min_ttl,min_ttl"
#else
#	define	MYDNS_SOA_FIELDS	"id,origin,ns,mbox,serial,refresh,retry,expire,minimum,ttl"
#endif

#define	MYDNS_RR_NUMFIELDS	7
#ifdef DN_COLUMN_NAMES
#	define	MYDNS_RR_FIELDS	"rr_id,zone_id,name,data,pref,7200,type"
#else
#	define	MYDNS_RR_FIELDS	"id,zone,name,data,aux,ttl,type"
#endif

/* Does the specified string end with a dot? */
#define	ENDS_WITH_DOT(s)	(s && (s[strlen(s)-1] == '.'))

/* Convert str to unsigned int */
#define atou(s) (uint32_t)strtoul(s, (char **)NULL, 10)

/* Size ranges for various bits of DNS data */
#define	DNS_MAXPACKETLEN_TCP		65536		/* Use 64k for TCP */
#define	DNS_MAXPACKETLEN_UDP		512		/* RFC1035: "512 octets or less" */
#define	DNS_MAXNAMELEN				255		/* RFC1035: "255 octets or less" */
#define	DNS_MAXESC					DNS_MAXNAMELEN + DNS_MAXNAMELEN + 1
#define	DNS_MAXLABELLEN			63			/* RFC1035: "63 octets or less" */
#define	DNS_POINTER_MASK			0xC0
#define	DNS_QUERYBUFSIZ			512		/* Used as buffer size for SQL queries */

/* Default values in SOA records */
#define	DNS_DEFAULT_REFRESH		28800
#define	DNS_DEFAULT_RETRY			7200
#define	DNS_DEFAULT_EXPIRE		604800
#define	DNS_DEFAULT_MINIMUM		86400
#define	DNS_DEFAULT_TTL			86400
#define	DNS_MINIMUM_TTL			300

/* Information about the PTR suffix */
/* #define	PTR_SUFFIX					".in-addr.arpa." */
/* #define	PTR_SUFFIX_LEN				14 */

/* Macro to convert quads into address -- result like MySQL's INET_ATON() */
#define INET_ATON(a,b,c,d) (((a) << 24) | ((b) << 16) | ((c) << 8) | (d))


typedef enum _task_error_t					/* Common errors */
{
	ERR_NONE = 0,								/* No error */
	ERR_INTERNAL,								/* "Internal error" */
	ERR_ZONE_NOT_FOUND,						/* "Zone not found" */
	ERR_NO_MATCHING_RECORDS,				/* "No matching resource records" */
	ERR_NO_AXFR,								/* "AXFR disabled" */
	ERR_RR_NAME_TOO_LONG,					/* "Name too long in RR" */
	ERR_RR_LABEL_TOO_LONG,					/* "Label too long in RR" */
	ERR_Q_BUFFER_OVERFLOW,					/* "Input name buffer overflow" */
	ERR_Q_INVALID_COMPRESSION,				/* "Invalid compression method" */
	ERR_Q_NAME_TOO_LONG,						/* "Question name too long" */
	ERR_Q_LABEL_TOO_LONG,					/* "Question label too long" */
	ERR_NO_CLASS,								/* "Unknown class" */
	ERR_NAME_FORMAT,							/* "Invalid name format" */
	ERR_TIMEOUT,								/* "Communications timeout" */
	ERR_BROKEN_GLUE,							/* "Malformed glue" */
	ERR_INVALID_ADDRESS,						/* "Invalid address" */
	ERR_INVALID_TYPE,							/* "Invalid type" */
	ERR_INVALID_CLASS,						/* "Invalid class" */
	ERR_INVALID_TTL,							/* "Invalid TTL" (for update) */
	ERR_INVALID_DATA,							/* "Invalid data" (for update) */
	ERR_DB_ERROR,								/* "Database error" */
	ERR_NO_QUESTION,							/* "No question in query" */
	ERR_MULTI_QUESTIONS,						/* "Multiple questions in query" */
	ERR_QUESTION_TRUNCATED,					/* "Question truncated" */
	ERR_UNSUPPORTED_OPCODE,					/* "Unsupported opcode" */
	ERR_UNSUPPORTED_TYPE,					/* "Unsupported type" */
	ERR_MALFORMED_REQUEST,					/* "Malformed request" */
	ERR_AXFR_NOT_ENABLED,					/* "AXFR not enabled" */
	ERR_TCP_NOT_ENABLED,						/* "TCP not enabled" */
	ERR_RESPONSE_BIT_SET,					/* "Response bit set on query" */
	ERR_FWD_RECURSIVE,						/* "Recursive query forwarding error" */
	ERR_NO_UPDATE,								/* "UPDATE denied" */
	ERR_PREREQUISITE_FAILED,				/* "UPDATE prerequisite failed" */

} task_error_t;


typedef enum									/* Query classes */
{                                      
	DNS_CLASS_UNKNOWN = -1,					/* Unknown */

	DNS_CLASS_IN		= 1,					/* Internet */
	DNS_CLASS_CHAOS	= 3,					/* CHAOS (obsolete) */
	DNS_CLASS_HESIOD	= 4,					/* HESIOD (obsolete) */

	DNS_CLASS_NONE		= 254,				/* NONE (RFC 2136) */
	DNS_CLASS_ANY		= 255					/* ANY */

} dns_class_t;


typedef enum									/* Query types */
{
	DNS_QTYPE_UNKNOWN		= -1,				/* Unknown */

	DNS_QTYPE_NONE			= 0,				/* None/invalid */
	DNS_QTYPE_A				= 1,				/* Address */
	DNS_QTYPE_NS			= 2,				/* Nameserver */
	DNS_QTYPE_MD			= 3,				/* Mail dest */
	DNS_QTYPE_MF			= 4,				/* Mail forwarder */
	DNS_QTYPE_CNAME		= 5,				/* Canonical name */
	DNS_QTYPE_SOA			= 6,				/* Start of authority */
	DNS_QTYPE_MB			= 7,				/* Mailbox name */
	DNS_QTYPE_MG			= 8,				/* Mail group */
	DNS_QTYPE_MR			= 9,				/* Mail rename */
	DNS_QTYPE_NULL			= 10,				/* Null */
	DNS_QTYPE_WKS			= 11,				/* Well known service */
	DNS_QTYPE_PTR			= 12,				/* IP -> fqdn mapping */
	DNS_QTYPE_HINFO		= 13,				/* Host info */
	DNS_QTYPE_MINFO		= 14,				/* Mailbox info */
	DNS_QTYPE_MX			= 15,				/* Mail routing info */
	DNS_QTYPE_TXT			= 16,				/* Text */
	DNS_QTYPE_RP			= 17,				/* Responsible person */
	DNS_QTYPE_AFSDB		= 18,				/* AFS cell database */
	DNS_QTYPE_X25			= 19,				/* X_25 calling address */
	DNS_QTYPE_ISDN			= 20,				/* ISDN calling address */
	DNS_QTYPE_RT			= 21,				/* Router */
	DNS_QTYPE_NSAP			= 22,				/* NSAP address */
	DNS_QTYPE_NSAP_PTR	= 23,				/* Reverse NSAP lookup (depreciated) */
	DNS_QTYPE_SIG			= 24,				/* Security signature */
	DNS_QTYPE_KEY			= 25,				/* Security key */
	DNS_QTYPE_PX			= 26,				/* X.400 mail mapping */
	DNS_QTYPE_GPOS			= 27,				/* Geographical position (withdrawn) */
	DNS_QTYPE_AAAA			= 28,				/* IPv6 Address */
	DNS_QTYPE_LOC			= 29,				/* Location info */
	DNS_QTYPE_NXT			= 30,				/* Next domain (security) */
	DNS_QTYPE_EID			= 31,				/* Endpoint identifier */
	DNS_QTYPE_NIMLOC		= 32,				/* Nimrod Locator */
	DNS_QTYPE_SRV			= 33,				/* Server */
	DNS_QTYPE_ATMA			= 34,				/* ATM Address */
	DNS_QTYPE_NAPTR		= 35,				/* Naming Authority Pointer */
	DNS_QTYPE_KX			= 36,				/* Key Exchange */
	DNS_QTYPE_CERT			= 37,				/* Certification record */
	DNS_QTYPE_A6			= 38,				/* IPv6 address (deprecates AAAA) */
	DNS_QTYPE_DNAME		= 39,				/* Non-terminal DNAME (for IPv6) */
	DNS_QTYPE_SINK			= 40,				/* Kitchen sink (experimentatl) */
	DNS_QTYPE_OPT			= 41,				/* EDNS0 option (meta-RR) */
	DNS_QTYPE_TSIG			= 250,			/* Transaction signature */
	DNS_QTYPE_IXFR			= 251,			/* Incremental zone transfer */
	DNS_QTYPE_AXFR			= 252,			/* Zone transfer */
	DNS_QTYPE_MAILB		= 253,			/* Transfer mailbox records */
	DNS_QTYPE_MAILA		= 254,			/* Transfer mail agent records */
	DNS_QTYPE_ANY			= 255,			/* Any */

#if ALIAS_ENABLED
	DNS_QTYPE_ALIAS		= 500,			/* Extension - David Phillips, alias patch */
#endif
} dns_qtype_t;


typedef enum									/* DNS opcode types */
{
	DNS_OPCODE_UNKNOWN	= -1,				/* Unknown */

	DNS_OPCODE_QUERY		= 0,				/* Query (RFC 1035) */
	DNS_OPCODE_IQUERY		= 1,				/* Inverse query (RFC 1035) */
	DNS_OPCODE_STATUS		= 2,				/* Status request (RFC 1035) */
	DNS_OPCODE_NOTIFY		= 4,				/* Notify request (RFC 1996) */
	DNS_OPCODE_UPDATE		= 5,				/* Update request (RFC 2136) */
} dns_opcode_t;




/* Return codes */
typedef enum
{
	DNS_RCODE_UNKNOWN		= -1,				/* Unknown */

	DNS_RCODE_NOERROR		= 0,				/* No error (RFC 1035) */
	DNS_RCODE_FORMERR		= 1,				/* Format error (RFC 1035) */
	DNS_RCODE_SERVFAIL	= 2,				/* Server failure (RFC 1035) */
	DNS_RCODE_NXDOMAIN	= 3,				/* Nonexistent domain (RFC 1035) */
	DNS_RCODE_NOTIMP		= 4,				/* Not implemented (RFC 1035) */
	DNS_RCODE_REFUSED		= 5,				/* Query refused (RFC 1035) */

	DNS_RCODE_YXDOMAIN	= 6,				/* Name exists when it should not (RFC 2136) */
	DNS_RCODE_YXRRSET		= 7,				/* RR set exists when it should not (RFC 2136) */
	DNS_RCODE_NXRRSET		= 8,				/* RR set that should exist does not (RFC 2136) */
	DNS_RCODE_NOTAUTH		= 9,				/* Server not authoritative for zone (RFC 2136) */
	DNS_RCODE_NOTZONE		= 10,				/* Name not contained in zone (RFC 2136) */

	/* Codes that can't fit in 4 bits are found in OPT (RFC 2671), TSIG (RFC 2845), and
		TKEY (RFC 2930) RRs */ 
	/* RFC 2671 says that rcode 16 is BADVERS ("Bad OPT version").  This conlicts with
		RFC 2845.  RFC 2845 seems like best current practice. */
	DNS_RCODE_BADSIG		= 16,				/* TSIG signature failure (RFC 2845) */
	DNS_RCODE_BADKEY		= 17,				/* Key not recognized (RFC 2845) */
	DNS_RCODE_BADTIME		= 18,				/* Signature out of time window (RFC 2845) */
	DNS_RCODE_BADMODE		= 19,				/* Bad TKEY mode (RFC 2930) */
	DNS_RCODE_BADNAME		= 20,				/* Duplicate key name (RFC 2930) */
	DNS_RCODE_BADALG		= 21,				/* Algorithm not supported (RFC 2930) */

} dns_rcode_t;


/* The record types */
typedef enum _dns_rrtype_t					/* DNS record types (for MyDNS) */
{
	DNS_RRTYPE_SOA,
	DNS_RRTYPE_RR
} dns_rrtype_t;


typedef enum _datasection_t				/* Sections in reply */
{
	QUESTION = 0,
	ANSWER,
	AUTHORITY,
	ADDITIONAL
} datasection_t;


/*
**  Structures describing each record type
*/
typedef struct _mydns_soa							/* `soa' table data (zones of authority) */
{
	uint32_t		id;
	char			origin[DNS_MAXNAMELEN + 1];
	char			ns[DNS_MAXNAMELEN + 1];
	char			mbox[DNS_MAXNAMELEN + 1];
	uint32_t		serial;
	uint32_t		refresh;
	uint32_t		retry;
	uint32_t		expire;
	uint32_t		minimum;
	uint32_t		ttl;

	struct _mydns_soa *next;
} MYDNS_SOA;

typedef struct _mydns_rr							/* `rr' table data (resource records) */
{
	uint32_t		id;
	uint32_t		zone;
	char			name[DNS_MAXNAMELEN + 1];
	dns_qtype_t	type;
	dns_class_t	class;
	char			data[DNS_MAXNAMELEN * 2 + 2];
	uint32_t		aux;
	uint32_t		ttl;
#if ALIAS_ENABLED
	int			alias;
#endif

	/* This data used by SRV records only - parsed (and removed) from "data" */
	uint16_t		srv_weight, srv_port;

	/* For RP records, this points to the "txt" part of the data, which is preceded by a NUL */
	char			rp_txt[DNS_MAXNAMELEN + 1];

	/* Data for NAPTR records: */
	/* This is potentially a lot of data.  I'm a little unclear from the RFC on what the
		maximum length of some of these fields are, so I'm just making them big for now.
		Hopefully these extra fields won't take up too much extra memory in the cache, slowing
		down the mere mortals who don't use NAPTR -- these fields add over 700 bytes to this
		structure */
	uint16_t		naptr_order;
	uint16_t		naptr_pref;
	char			naptr_flags[8];
	char			naptr_service[DNS_MAXNAMELEN + 1];
	char			naptr_regex[DNS_MAXNAMELEN + 1];
	char			naptr_replacement[DNS_MAXNAMELEN + 1];

	struct _mydns_rr *next;
} MYDNS_RR;


/* sql.c */
#if USE_PGSQL
typedef PGconn SQL;
typedef unsigned char ** SQL_ROW;
typedef struct _sql_res {
	PGresult *result;
	int		tuples;
	int		fields;
	int		current_tuple;
	SQL_ROW	current_row;
} SQL_RES;
#else
typedef MYSQL SQL;
typedef MYSQL_RES SQL_RES;
typedef MYSQL_ROW SQL_ROW;
#endif



/* ip.c */
extern uint32_t	mydns_revstr_ip4(char *);
extern int			mydns_extract_arpa(char *, uint8_t ip[]);


/* question.c */
extern char			*dns_make_question(uint16_t id, dns_qtype_t qtype, char *name, int rd, size_t *length);


/* rr.c */
extern long			mydns_rr_count(SQL *);
extern void			mydns_set_rr_table_name(char *);
extern void			mydns_set_rr_where_clause(char *);
extern dns_qtype_t mydns_rr_get_type(char *);
extern MYDNS_RR	*mydns_rr_parse(SQL_ROW, const char *);
extern int			mydns_rr_load(SQL *, MYDNS_RR **, uint32_t, dns_qtype_t, char *, char *);
extern MYDNS_RR	*mydns_rr_dup(MYDNS_RR *, int);
extern size_t		mydns_rr_size(MYDNS_RR *);
extern void			_mydns_rr_free(MYDNS_RR *);
#define				mydns_rr_free(p)	if ((p)) _mydns_rr_free((p)), (p) = NULL


/* soa.c */
extern long			mydns_soa_count(SQL *);
extern void			mydns_set_soa_table_name(char *);
extern void			mydns_set_soa_where_clause(char *);
extern MYDNS_SOA	*mydns_soa_parse(SQL_ROW);
extern int			mydns_soa_load(SQL *, MYDNS_SOA **, char *);
extern int			mydns_soa_make(SQL *, MYDNS_SOA **, unsigned char *, unsigned char *);
extern MYDNS_SOA	*mydns_soa_dup(MYDNS_SOA *, int);
extern size_t		mydns_soa_size(MYDNS_SOA *);
extern void			_mydns_soa_free(MYDNS_SOA *);
#define				mydns_soa_free(p)	if ((p)) _mydns_soa_free((p)), (p) = NULL


/* sql.c */
extern SQL		*sql;
extern void		sql_open(char *user, char *password, char *host, char *database);
extern void		sql_reopen(void);
extern void		_sql_close(SQL *);
#define			sql_close(p) if ((p)) _sql_close((p)), (p) = NULL
extern int		sql_nrquery(SQL *, const char *query, size_t querylen);
extern SQL_RES	*sql_query(SQL *, const char *query, size_t querylen);
extern SQL_RES	*sql_queryf(SQL *, const char *, ...) __printflike(2,3);
extern long		sql_count(SQL *, const char *, ...) __printflike(2,3);
extern SQL_ROW	sql_getrow(SQL_RES *res);
extern void		sql_escstr(SQL *, char *, char *, size_t);
extern void		_sql_free(SQL_RES *res);
extern long		sql_num_rows(SQL_RES *res);
extern int		sql_istable(SQL *, const char *);
extern int		sql_iscolumn(SQL *, const char *, const char *);
#define			sql_free(p) if ((p)) _sql_free((p)), (p) = NULL


/* str.c */
extern char		*mydns_qtype_str(dns_qtype_t);
extern char		*mydns_class_str(dns_class_t);
extern char		*mydns_opcode_str(dns_opcode_t);
extern char		*mydns_rcode_str(dns_rcode_t);
extern char		*mydns_section_str(datasection_t);
extern int		hinfo_parse(char *, char *, char *, size_t);


/* unencode.c */
extern char		*name_unencode(char *, size_t, char *, char *, size_t);


#endif /* !_MYDNS_H */

/* vi:set ts=3: */
