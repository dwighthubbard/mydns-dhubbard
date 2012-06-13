/**************************************************************************************************
	$Id: check.c,v 1.36 2005/05/04 16:49:59 bboy Exp $

	check.c: Check for problems with the data in the database.

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

#include "util.h"

MYDNS_SOA	*soa;													/* Current SOA record being scanned */
MYDNS_RR		*rr;													/* Current RR record */
char	name[DNS_MAXNAMELEN*2];									/* Current expanded name */
char	data[DNS_MAXNAMELEN*2];									/* Current expanded data */
int	opt_consistency = 0;										/* Consistency check? */
int	opt_consistency_only = 0;								/* Consistency check only? */
int	ignore_minimum = 0;										/* Ignore minimum TTL? */

#ifdef EXTENDED_CHECK_WRITTEN
int	opt_extended_check = 0;									/* Extended check? */
#endif

int	syntax_errors, consistency_errors;					/* Number of errors found */

#define EXPAND_DATA(str) \
			if (!(str)[0] || LASTCHAR((str)) != '.') \
			{ \
				if ((str)[0]) strncat((str), ".", sizeof((str))-strlen((str))-1); \
				strncat((str), soa->origin, sizeof((str))-strlen((str))-1); \
			}


/**************************************************************************************************
	USAGE
	Display program usage information.
**************************************************************************************************/
static void
usage(int status)
{
	if (status != EXIT_SUCCESS)
	{
		fprintf(stderr, _("Try `%s --help' for more information."), progname);
		fputs("\n", stderr);
	}
	else
	{
		printf(_("Usage: %s [ZONE..]"), progname);
		puts("");
		puts(_("Check zone(s) or entire database for errors and consistency."));
		puts("");
/*		puts("----------------------------------------------------------------------------78");  */
		puts(_("  -c, --consistency       do key consistency checks"));
		puts(_("  -C, --consistency-only  do only the key consistency checks"));
#ifdef EXTENDED_CHECK_WRITTEN
		puts(_("  -x, --extended          extended check for data/name references"));
#endif
		puts("");
		puts(_("  -D, --database=DB       database name to use"));
		puts(_("  -h, --host=HOST         connect to SQL server at HOST"));
		puts(_("  -p, --password=PASS     password for SQL server (or prompt from tty)"));
		puts(_("  -u, --user=USER         username for SQL server if not current user"));
		puts("");
#if DEBUG_ENABLED
		puts(_("  -d, --debug             enable debug output"));
#endif
		puts(_("  -v, --verbose           be more verbose while running"));
		puts(_("      --help              display this help and exit"));
		puts(_("      --version           output version information and exit"));
		puts("");
		printf(_("Report bugs to <%s>.\n"), PACKAGE_BUGREPORT);
	}
	exit(status);
}
/*--- usage() -----------------------------------------------------------------------------------*/


/**************************************************************************************************
	CMDLINE
	Process command line options.
**************************************************************************************************/
static void
cmdline(int argc, char **argv)
{
	char	*optstr;
	int	optc, optindex;
	struct option const longopts[] =
	{
		{"consistency-only",	no_argument,			NULL,	'C'},
		{"consistency",		no_argument,			NULL,	'c'},
#ifdef EXTENDED_CHECK_WRITTEN
		{"extended",			no_argument,			NULL,	'x'},
#endif

		{"database",			required_argument,	NULL,	'D'},
		{"host",					required_argument,	NULL,	'h'},
		{"password",			optional_argument,	NULL,	'p'},
		{"user",					required_argument,	NULL,	'u'},

		{"debug",				no_argument,			NULL,	'd'},
		{"verbose",				no_argument,			NULL,	'v'},
		{"help",					no_argument,			NULL,	0},
		{"version",				no_argument,			NULL,	0},

		{NULL, 0, NULL, 0}
	};

	err_file = stdout;
	error_init(argv[0], LOG_USER);							/* Init output routines */
	optstr = getoptstr(longopts);
	while ((optc = getopt_long(argc, argv, optstr, longopts, &optindex)) != -1)
	{
		switch (optc)
		{
			case 0:
				{
					const char *opt = longopts[optindex].name;

					if (!strcmp(opt, "version"))									/* --version */
					{
						printf("%s ("PACKAGE_NAME") "PACKAGE_VERSION" ("SQL_VERSION_STR")\n", progname);
						puts("\n" PACKAGE_COPYRIGHT);
						puts(_("This is free software; see the source for copying conditions.  There is NO"));
						puts(_("warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."));
						exit(EXIT_SUCCESS);
					}
					else if (!strcmp(opt, "help"))								/* --help */
						usage(EXIT_SUCCESS);
				}
				break;
			case 'C':																	/* -C, --consistency-only */
				opt_consistency = opt_consistency_only = 1;
				break;
			case 'c':																	/* -c, --consistency */
				opt_consistency = 1;
				break;
			case 'd':																	/* -d, --debug */
#if DEBUG_ENABLED
				err_verbose = err_debug = 1;
#endif
				break;
			case 'D':																	/* -D, --database=DB */
				conf_set(&Conf, "database", optarg, 0);
				break;
			case 'h':																	/* -h, --host=HOST */
				conf_set(&Conf, "db-host", optarg, 0);
				break;
			case 'p':																	/* -p, --password=PASS */
				if (optarg)
				{
					conf_set(&Conf, "db-password", optarg, 0);
					memset(optarg, 'X', strlen(optarg));
				}
				else
					conf_set(&Conf, "db-password", passinput(_("Enter password")), 0);
				break;
			case 'u':																	/* -u, --user=USER */
				conf_set(&Conf, "db-user", optarg, 0);
				break;

			case 'v':																	/* -v, --verbose */
				err_verbose = 1;
				break;
#ifdef EXTENDED_CHECK_WRITTEN
			case 'x':																	/* -x, --extended */
				opt_extended_check = 1;
				break;
#endif
			default:
				usage(EXIT_FAILURE);
		}
	}
}
/*--- cmdline() ---------------------------------------------------------------------------------*/


/**************************************************************************************************
	RRPROBLEM
	Output a string describing a problem found.
**************************************************************************************************/
static void rrproblem(const char *fmt, ...) __printflike(1,2);
static void
rrproblem(const char *fmt, ...)
{
	va_list ap;

	meter(0,0);

	va_start(ap, fmt);
	vprintf(fmt, ap);																					/* 1. message */
	va_end(ap);
	printf("\t");

	if (soa)																								/* 2. soa id */
		printf("%u\t", soa->id);
	else
		printf("-\t");

	if (rr)																								/* 3. rr id */
		printf("%u\t", rr->id);
	else
		printf("-\t");

	printf("%s\t", *name ? name : "-");															/* 4. name */

	if (soa || rr)																						/* 5. ttl */
		printf("%u\t", rr ? rr->ttl : soa->ttl);
	else
		printf("-\t");

	printf("%s\t", rr ? mydns_qtype_str(rr->type) : "-");									/* 6. rr type */
	printf("%s\n", *data ? data : "-");															/* 7. data */

	fflush(stdout);

	syntax_errors++;
}
/*--- rrproblem() -------------------------------------------------------------------------------*/


#ifdef EXTENDED_CHECK_WRITTEN
/**************************************************************************************************
	CHECK_NAME_EXTENDED
**************************************************************************************************/
static void
check_name_extended(const char *name_in, const char *fqdn, const char *col)
{
	/* XXX: Add check to detect names that we should be authoritative for but
		that do not have records */
}
/*--- check_name_extended() ---------------------------------------------------------------------*/
#endif


/**************************************************************************************************
	SHORTNAME
	Removes the origin from a name if it is present.
**************************************************************************************************/
static char *
shortname(char *name_to_shorten, int empty_name_is_ok)
{
	size_t nlen = strlen(name_to_shorten), olen = strlen(soa->origin);

	if (nlen < olen)
		return (name_to_shorten);
	if (!strcasecmp(soa->origin, name_to_shorten))
	{
		if (empty_name_is_ok)
			return ("");
		else
			return (name_to_shorten);
	}
	if (!strcasecmp(name_to_shorten + nlen - olen, soa->origin))
		name[nlen - olen - 1] = '\0';
	return (name_to_shorten);
}
/*--- shortname() -------------------------------------------------------------------------------*/


/**************************************************************************************************
	CHECK_NAME
	Verifies that "name" is a valid name.
**************************************************************************************************/
static void
check_name(const char *name_in, const char *col, int is_rr)
{
	char buf[DNS_MAXNAMELEN * 2], *b, *label;
	char fqdn[DNS_MAXNAMELEN * 2];

	strncpy(fqdn, name_in, sizeof(fqdn)-1);

	/* If last character isn't '.', append the origin */
	if (is_rr && LASTCHAR(fqdn) != '.')
		strncat(fqdn, soa->origin, sizeof(fqdn) - strlen(fqdn) - 1);

	if (!strlen(fqdn))
		return rrproblem(_("FQDN in `%s' is empty"), col);

	if (strlen(fqdn) > DNS_MAXNAMELEN)
		return rrproblem(_("FQDN in `%s' is too long"), col);

	/* Break into labels, verifying each */
	if (strcmp(fqdn, "."))
	{
		strncpy(buf, fqdn, sizeof(buf)-1);
		for (b = buf; (label = strsep(&b, ".")); )
		{
			register int len = strlen(label);
			register char *cp;

			if (!b)		/* Last label - should be the empty string */
			{
				if (strlen(label))
					rrproblem(_("Last label in `%s' not the root zone"), col);
				break;
			}
			if (strcmp(label, "*"))
			{
				if (len > DNS_MAXLABELLEN)
					rrproblem(_("Label in `%s' is too long"), col);
				if (len < 1)
					rrproblem(_("Blank label in `%s'"), col);
				for (cp = label; *cp; cp++)
				{
					if (*cp == '-' && cp == label)
						rrproblem(_("Label in `%s' begins with a hyphen"), col);
					if (*cp == '-' && ((cp - label) == len-1))
						rrproblem(_("Label in `%s' ends with a hyphen"), col);
					if (!isalnum((int)(*cp)) && *cp != '-')
					{
						if (is_rr && *cp == '*')
							rrproblem(_("Wildcard character `%c' in `%s' not alone"), *cp, col);
						else
							rrproblem(_("Label in `%s' contains illegal character `%c'"), col, *cp);
					}
				}
			}
			else if (!is_rr)
				rrproblem(_("Wildcard not allowed in `%s'"), col);
		}
	}

#ifdef EXTENDED_CHECK_WRITTEN
	/* If extended check, do extended check */
	if (is_rr && opt_extended_check)
		check_name_extended(name_in, fqdn, col);
#endif
}
/*--- check_name() ------------------------------------------------------------------------------*/


/**************************************************************************************************
	CHECK_SOA
	Perform SOA check for this zone and return the SOA record.
	Checks currently performed:
		- Make sure "ns" and "mbox" are present and valid.
		- Make sure none of the numeric values are unreasonable (like 0)
**************************************************************************************************/
static MYDNS_SOA *
check_soa(const char *zone)
{
	if (mydns_soa_load(sql, &soa, (char *)zone) != 0)
		Errx("%s: %s", zone, _("error loading SOA record for zone"));
	if (!soa)
		Errx("%s: %s", zone, _("zone not found"));
	rr = NULL;
	*name = *data = '\0';

	/* SOA validation */
	strncpy(name, soa->origin, sizeof(name)-1);
	check_name(soa->ns, "soa.ns", 0);
	check_name(soa->mbox, "soa.mbox", 0);

	if (LASTCHAR(name) != '.')
		rrproblem(_("soa.origin is not a FQDN (no trailing dot)"));

	if (soa->refresh < 300) rrproblem(_("soa.refresh is less than 300 seconds"));
	if (soa->retry < 300) rrproblem(_("soa.retry is less than 300 seconds"));
	if (soa->expire < 300) rrproblem(_("soa.expire is less than 300 seconds"));
	if (soa->minimum < 300) rrproblem(_("soa.minimum is less than 300 seconds"));
	if (soa->ttl < 300) rrproblem(_("soa.ttl is less than 300 seconds"));
	if (soa->minimum < 300) rrproblem(_("soa.minimum is less than 300 seconds"));

	return (soa);
}
/*--- check_soa() -------------------------------------------------------------------------------*/


/**************************************************************************************************
	CHECK_RR_CNAME
	Expanded check for CNAME resource record.
**************************************************************************************************/
static void
check_rr_cname(void)
{
	unsigned char *xname;
	int found = 0;

	EXPAND_DATA(data);
	check_name(data, "rr.data", 1);

	/* A CNAME record can't have any other type of RR data for the same name */
	if (!(xname = calloc(strlen(name) * 2 + 1, sizeof(unsigned char))))
		Err(_("out of memory"));
	sql_escstr(sql, xname, (unsigned char *)name, strlen(name));
	found = sql_count(sql, "SELECT COUNT(*) FROM %s WHERE zone=%u AND name='%s' AND type != 'CNAME'",
								  mydns_rr_table_name, rr->zone, xname);

	/* If not found that way, check short name */
	if (!found)
	{
		Free(xname);
		shortname(name, 1);
		if (!(xname = calloc(strlen(name) * 2 + 1, sizeof(unsigned char))))
			Err(_("out of memory"));
		sql_escstr(sql, xname, (unsigned char *)name, strlen(name));
		found = sql_count(sql, "SELECT COUNT(*) FROM %s WHERE zone=%u AND name='%s' AND type != 'CNAME'",
									  mydns_rr_table_name, rr->zone, xname);
		EXPAND_DATA(name);
	}

	if (found)
		rrproblem(_("non-CNAME record(s) present alongside CNAME"));
	Free(xname);
}
/*--- check_rr_cname() --------------------------------------------------------------------------*/


/**************************************************************************************************
	CHECK_RR_HINFO
	Expanded check for HINFO resource record.
**************************************************************************************************/
static void
check_rr_hinfo(void)
{
	char	os[DNS_MAXNAMELEN + 1] = "", cpu[DNS_MAXNAMELEN + 1] = "";

	if (hinfo_parse(rr->data, cpu, os, DNS_MAXNAMELEN) < 0)
		rrproblem(_("data too long in HINFO record"));
}
/*--- check_rr_hinfo() --------------------------------------------------------------------------*/


/**************************************************************************************************
	CHECK_RR_NAPTR
	Expanded check for NAPTR resource record.
**************************************************************************************************/
static void
check_rr_naptr(void)
{
	char tmp[DNS_MAXNAMELEN * 2 + 2], data_copy[DNS_MAXNAMELEN * 2 + 2], *p;

	strncpy(data_copy, rr->data, sizeof(data_copy) - 1);
	p = data_copy;

	if (!strsep_quotes(&p, tmp, sizeof(tmp)))
		return rrproblem(_("'order' field missing from NAPTR record"));

	if (!strsep_quotes(&p, tmp, sizeof(tmp)))
		return rrproblem(_("'preference' field missing from NAPTR record"));

	if (!strsep_quotes(&p, tmp, sizeof(tmp)))
		return rrproblem(_("'flags' field missing from NAPTR record"));

	if (!strsep_quotes(&p, tmp, sizeof(tmp)))
		return rrproblem(_("'service' field missing from NAPTR record"));

	if (!strsep_quotes(&p, tmp, sizeof(tmp)))
		return rrproblem(_("'regexp' field missing from NAPTR record"));

	if (!strsep_quotes(&p, tmp, sizeof(tmp)))
		return rrproblem(_("'replacement' field missing from NAPTR record"));

	/* For now, don't check 'replacement'.. the example in the RFC even contains illegal chars */
	/* EXPAND_DATA(tmp); */
	/* check_name(tmp, "replacement", 1); */
}
/*--- check_rr_naptr() --------------------------------------------------------------------------*/


/**************************************************************************************************
	CHECK_RR
	Check an individual resource record.
**************************************************************************************************/
static void
check_rr(void)
{
	/* Expand RR's name into `name' */
	strncpy(name, rr->name, sizeof(name)-1);
	strncpy(data, rr->data, sizeof(data)-1);
	EXPAND_DATA(name);
	check_name(name, "rr.name", 1);

	if (!ignore_minimum && (rr->ttl < soa->minimum))
		rrproblem(_("TTL below zone minimum"));

	switch (rr->type)
	{
		case DNS_QTYPE_A:											/* Data: IPv4 address */
			{
				struct in_addr addr;
#if ALIAS_ENABLED
				if (rr->alias == 1)
					check_rr_cname();
				else
				{
#endif /* ALIAS_ENABLED */
					if (inet_pton(AF_INET, data, (void *)&addr) <= 0)
						rrproblem(_("IPv4 address in `data' is invalid"));
#if ALIAS_ENABLED
				}
#endif /* ALIAS_ENABLED */
			}
			break;

		case DNS_QTYPE_AAAA:										/* Data: IPv6 address */
			{
				uint8_t addr[16];
				if (inet_pton(AF_INET6, data, (void *)&addr) <= 0)
					rrproblem(_("IPv6 address in `data' is invalid"));
			}
			break;

		case DNS_QTYPE_CNAME:									/* Data: Name */
			check_rr_cname();
			break;

		case DNS_QTYPE_HINFO:									/* Data: Host info */
			check_rr_hinfo();
			break;

		case DNS_QTYPE_MX:										/* Data: Name */
			EXPAND_DATA(data);
			check_name(data, "rr.data", 1);
			break;

		case DNS_QTYPE_NAPTR:									/* Data: Multiple fields */
			check_rr_naptr();
			break;

		case DNS_QTYPE_NS:										/* Data: Name */
			EXPAND_DATA(data);
			check_name(data, "rr.data", 1);
			break;

		case DNS_QTYPE_PTR:										/* Data: PTR */
			/* TODO */
			break;

		case DNS_QTYPE_RP:										/* Data: Responsible person */
			{
				char	txt[DNS_MAXNAMELEN*2];

				strncpy(txt, rr->rp_txt, sizeof(txt)-1);
				EXPAND_DATA(txt);
				check_name(data, "rr.data (mbox)", 1);
				check_name(txt, "rr.data (txt)", 1);
			}
			break;

		case DNS_QTYPE_SRV:										/* Data: Server location */
			/* TODO */
			break;

		case DNS_QTYPE_TXT:										/* Data: Undefined text string */
			/* Can be anything, so consider it always OK */
			break;

		default:
			rrproblem(_("Unknown/unsupported resource record type"));
			break;
	}
}
/*--- check_rr() --------------------------------------------------------------------------------*/

                                                                                                                               

/**************************************************************************************************
	CHECK_ZONE
	Checks each RR in the current zone through check_rr.
**************************************************************************************************/
static void
check_zone(void)
{
	char query[BUFSIZ];
	size_t querylen;
	unsigned int rrct = 0;
	SQL_RES *res;
	SQL_ROW row;

	querylen = snprintf(query, sizeof(query), "SELECT "MYDNS_RR_FIELDS" FROM %s WHERE zone=%u",
		mydns_rr_table_name, soa->id);
	if (!(res = sql_query(sql, query, querylen)))
		return;
	while ((row = sql_getrow(res)))
	{
		if (!(rr = mydns_rr_parse(row, soa->origin)))
			continue;
		check_rr();
		mydns_rr_free(rr);
		rrct++;
   }
	sql_free(res);

	if (err_verbose)
	{
		meter(0, 0);
		Verbose("%s: %u %s", soa->origin, rrct, rrct == 1 ? _("resource record") : _("resource records"));
	}
}
/*--- check_zone() ------------------------------------------------------------------------------*/


/**************************************************************************************************
	CONSISTENCY_RR_ZONE
	Makes sure rr.zone matches a soa.id.
**************************************************************************************************/
static void
consistency_rr_zone(void)
{
	char query[BUFSIZ];
	size_t querylen;
	SQL_RES *res;
	SQL_ROW row;

	querylen = snprintf(query, sizeof(query),
      "SELECT %s.id,%s.zone FROM %s LEFT JOIN %s ON %s.zone=%s.id WHERE %s.id IS NULL",
		mydns_rr_table_name, mydns_rr_table_name, mydns_rr_table_name, mydns_soa_table_name,
		mydns_rr_table_name, mydns_soa_table_name, mydns_soa_table_name);
	if (!(res = sql_query(sql, query, querylen)))
		return;
	while ((row = sql_getrow(res)))
	{
		char msg[80];

		meter(0,0);
		snprintf(msg, sizeof(msg),
					_("%s id %s references invalid %s id %s"),
					mydns_rr_table_name, row[0], mydns_soa_table_name, row[1]);
		printf("%s\t-\t%s\t-\t-\t-\t-\t-\n", msg, row[0]);
		fflush(stdout);

		consistency_errors++;
	}
	sql_free(res);
}
/*--- consistency_rr_zone() ---------------------------------------------------------------------*/


/**************************************************************************************************
	CONSISTENCY_CHECK
	Does a general database consistency check - makes sure all keys are kosher.
**************************************************************************************************/
static void
consistency_check(void)
{
	consistency_rr_zone();
}
/*--- consistency_check() -----------------------------------------------------------------------*/


/**************************************************************************************************
	MAIN
**************************************************************************************************/
int
main(int argc, char **argv)
{
	setlocale(LC_ALL, "");										/* Internationalization */
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	cmdline(argc, argv);
	load_config();
	ignore_minimum = GETBOOL(conf_get(&Conf, "ignore-minimum", NULL));
	db_connect();

	if (!opt_consistency_only)
	{
		if (optind >= argc)											/* Check all zones */
		{
			char query[BUFSIZ];
			size_t querylen;
			SQL_RES *res;
			SQL_ROW row;
			unsigned long current = 0, total;

			querylen = snprintf(query, sizeof(query), "SELECT origin FROM %s", mydns_soa_table_name);
			if ((res = sql_query(sql, query, querylen)))
			{
				total = sql_num_rows(res);
				while ((row = sql_getrow(res)))
				{
					meter(current++, total);
					if ((soa = check_soa(row[0])))
					{
						check_zone();
						mydns_soa_free(soa);
					}
				}
				sql_free(res);
			}
		}
		else while (optind < argc)									/* Check zones provided as args */
		{
			char zone[DNS_MAXNAMELEN+2];
			strncpy(zone, argv[optind++], sizeof(zone)-2);
			if (LASTCHAR(zone) != '.')
				strcat(zone, ".");
			if ((soa = check_soa(zone)))
			{
				check_zone();
				mydns_soa_free(soa);
			}
		}
	}

	if (opt_consistency)
		consistency_check();											/* Do consistency check if requested */

	meter(0, 0);
	if (!syntax_errors && !consistency_errors)
		Verbose(_("No errors"));
	else
	{
		if (opt_consistency_only)
			Verbose("%s: %d", _("Consistency errors"), consistency_errors);
		else if (opt_consistency)
			Verbose("%s: %d  %s: %d",
					 _("Syntax errors"), syntax_errors, _("Consistency errors"), consistency_errors);
		else
			Verbose("%s: %d", _("Syntax errors"), syntax_errors);
	}

	return (0);
}
/*--- main() ------------------------------------------------------------------------------------*/

/* vi:set ts=3: */
/* NEED_PO */
