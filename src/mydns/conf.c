/**************************************************************************************************
	$Id: conf.c,v 1.59 2006/01/18 20:46:46 bboy Exp $

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
#define	DEBUG_CONF	1


#include <pwd.h>
#include <grp.h>

CONF		*Conf = (CONF *)NULL;								/* Config options */
int		opt_daemon = 0;										/* Run in background? (-d, --daemon) */
char		*opt_conf = MYDNS_CONF;								/* Location of config file (-c, --conf) */
uid_t		perms_uid = 0;											/* User permissions */
gid_t		perms_gid = 0;											/* Group permissions */
time_t	task_timeout;											/* Task timeout */
int		axfr_enabled = 0;										/* Enable AXFR? */
int		tcp_enabled = 0;										/* Enable TCP? */
int		dns_update_enabled = 0;								/* Enable DNS UPDATE? */
int		ignore_minimum = 0;									/* Ignore minimum TTL? */

int		forward_recursive = 0;								/* Forward recursive queries? */
char		*recursive_fwd_server = NULL;						/* Name of server for recursive forwarding */
int		recursive_family = AF_INET;						/* Protocol family for recursion */

#if HAVE_IPV6
struct sockaddr_in6	recursive_sa6;							/* Recursive server (IPv6) */
#endif
struct sockaddr_in	recursive_sa;							/* Recursive server (IPv4) */

#ifdef DN_COLUMN_NAMES
char		*dn_default_ns = NULL;								/* Default NS for directNIC */
#endif


/*
**  Default config values
**
**  If the 'name' is "-", the --dump-config option treats 'desc' as a header field.
*/
static CONF defConfig[] = {
/* name						value							desc	*/
{	"-",						NULL,							N_("DATABASE INFORMATION")},
{	"db-host",				"localhost",				N_("SQL server hostname")},
{	"db-user",				"username",					N_("SQL server username")},
{	"db-password",			"password",					N_("SQL server password")},
{	"database",				PACKAGE_NAME,				N_("MyDNS database name")},

{	"-",						NULL,							N_("GENERAL OPTIONS")},

{	"user",					"nobody",					N_("Run with the permissions of this user")},
{	"group",					"nobody",					N_("Run with the permissions of this group")},
{	"listen",				"*",							N_("Listen on these addresses ('*' for all)"),	"bind"},
{	"no-listen",			"",							N_("Do not listen on these addresses")},

{	"-",						NULL,							N_("CACHE OPTIONS")},

{	"cache-size",			"1024",						N_("Maximum number of elements stored in the data/reply cache")},
{	"cache-expire",		"60",							N_("Number of seconds after which cached data/replies expire")},

{	"zone-cache-size",	"1024",						N_("Maximum number of elements stored in the zone cache")},
{	"zone-cache-expire",	"60",							N_("Number of seconds after which cached zones expires")},

{	"reply-cache-size",	"1024",						N_("Maximum number of elements stored in the reply cache")},
{	"reply-cache-expire","30",							N_("Number of seconds after which cached replies expire")},

{	"-",						NULL,							N_("ESOTERICA")},
{	"log",					"LOG_DAEMON",				N_("Facility to use for program output (LOG_*/stdout/stderr)")},
{	"pidfile",				"/var/run/"PACKAGE_NAME".pid",	N_("Path to PID file")},
{	"timeout",				"120",						N_("Number of seconds after which queries time out")},
{	"multicpu",				"1",							N_("Number of CPUs installed on your system")},
{	"recursive",			"",							N_("Location of recursive resolver")},
{	"allow-axfr",			"no",							N_("Should AXFR be enabled?")},
{	"allow-tcp",			"no",							N_("Should TCP be enabled?")},
{	"allow-update",		"no",							N_("Should DNS UPDATE be enabled?")},
{	"ignore-minimum",		"no",							N_("Ignore minimum TTL for zone?")},
{	"soa-table",			MYDNS_SOA_TABLE,			N_("Name of table containing SOA records")},
{	"rr-table",				MYDNS_RR_TABLE,			N_("Name of table containing RR data")},

#ifdef DN_COLUMN_NAMES
{	"default-ns",			"ns0.example.com.",		N_("Default nameserver for all zones")},
#endif

{	"soa-where",			"",							N_("Extra WHERE clause for SOA queries")},
{	"rr-where",				"",							N_("Extra WHERE clause for RR queries")},

{	NULL,						NULL,							NULL}
};


/**************************************************************************************************
	DUMP_CONFIG
	Output configuration info (in a sort of config-file format).
**************************************************************************************************/
void
dump_config(void)
{
	time_t	time_now = time(NULL);
	int		len = 0, w = 0, n, defaulted;
	char		pair[512], buf[80];
	CONF		*c;

	/*
	**	Pretty header
	*/
	puts("##");
	puts("##  "MYDNS_CONF);
	printf("##  %.24s\n", ctime(&time_now));
	printf("##  %s\n", _("For more information, see mydns.conf(5)."));
	puts("##");

	/*
	** Get longest words
	*/
	for (n = 0; defConfig[n].name; n++)
	{
		char *value = conf_get(&Conf, defConfig[n].name, &defaulted);

		c = &defConfig[n];
		if (!c->value || !c->value[0])
			continue;
		if (!value)
		{
			if ((len = strlen(c->name) + (c->value ? strlen(c->value) : 0)) > w)
				w = len;
		}
		else
		{
			char *cp, *vbuf, *v;
			if (!strcasecmp(c->name, "listen") || !strcasecmp(c->name, "no-listen"))
			{
				while ((cp = strchr(value, ',')))
					*cp = CONF_FS_CHAR;
			}
			if (!(vbuf = strdup(value)))
				Err("strdup");
			for (cp = vbuf; (v = strsep(&cp, CONF_FS_STR));)
				if ((len = strlen(c->name) + strlen(v)) > w)
					w = len;
			Free(vbuf);
		}
	}
	w += strlen(" = ");


	/*
	**	Output name/value pairs
	*/
	for (n = 0; defConfig[n].name; n++)
	{
		char	*value = conf_get(&Conf, defConfig[n].name, &defaulted);

		c = &defConfig[n];

		if (c->name[0] == '-')
		{
			printf("\n\n%-*.*s\t# %s\n\n", w, w, " ", _(c->desc));
			continue;
		}

		if (!value)
		{
			if (!c->value || !c->value[0])
				continue;
			value = c->value;
			defaulted = 1;
		}

		/* Pick between "nobody" and "nogroup" for default group */
		if (!strcasecmp(c->name, "group") && getgrnam("nogroup"))
			c->value = "nogroup";

		/* If cache-size/cache-expire are set, copy values into data/reply-cache-size */
		if (!strcasecmp(c->name, "cache-size"))
		{
			if (defaulted)
				continue;
			else
			{
				snprintf(buf, sizeof(buf), "%d", atou(value) - (atou(value)/3));
				conf_clobber(&Conf, "zone-cache-size", buf);
				snprintf(buf, sizeof(buf), "%d", atou(value)/3);
				conf_clobber(&Conf, "reply-cache-size", buf);
			}
		}
		else if (!strcasecmp(c->name, "cache-expire"))
		{
			if (defaulted)
				continue;
			else
			{
				snprintf(buf, sizeof(buf), "%d", atou(value));
				conf_clobber(&Conf, "zone-cache-expire", buf);
				snprintf(buf, sizeof(buf), "%d", atou(value)/2);
				conf_clobber(&Conf, "reply-cache-expire", buf);
			}
		}
		else if (!strcasecmp(c->name, "listen") || !strcasecmp(c->name, "no-listen"))
		{
			char *cp, *vbuf, *v;
			while ((cp = strchr(value, ',')))
				*cp = CONF_FS_CHAR;
			if (!(vbuf = strdup(value)))
				Err("strdup");
			for (cp = vbuf; (v = strsep(&cp, CONF_FS_STR));)
			{
				if (v == vbuf)
				{
					snprintf(pair, sizeof(pair), "%s = %s", c->name, v);
					printf("%-*.*s\t# %s\n", w, w, pair, _(c->desc));
				}
				else
					printf("%s = %s\n", c->name, v);
			}
			Free(vbuf);
		}
		else
		{
			snprintf(pair, sizeof(pair), "%s = %s", c->name, value);
			printf("%-*.*s\t# %s\n", w, w, pair, _(c->desc));
		}
	}
	printf("\n");
}
/*--- dump_config() -----------------------------------------------------------------------------*/


/**************************************************************************************************
	CONF_SET_LOGGING
	Sets the logging type and opens the syslog connection if necessary.
**************************************************************************************************/
void
conf_set_logging(void)
{
	char logtype[80];

	strncpy(logtype, conf_get(&Conf, "log", NULL), sizeof(logtype)-1);
	strtolower(logtype);

	if (!err_file)
		closelog();

	if (!strcmp(logtype, "stderr")) { err_file = stderr; closelog(); }
	else if (!strcmp(logtype, "stdout")) { err_file = stdout; closelog(); }
	else if (!strcmp(logtype, "log_daemon")) error_init(NULL, LOG_DAEMON);
	else if (!strcmp(logtype, "log_local0")) error_init(NULL, LOG_LOCAL0);
	else if (!strcmp(logtype, "log_local1")) error_init(NULL, LOG_LOCAL1);
	else if (!strcmp(logtype, "log_local2")) error_init(NULL, LOG_LOCAL2);
	else if (!strcmp(logtype, "log_local3")) error_init(NULL, LOG_LOCAL3);
	else if (!strcmp(logtype, "log_local4")) error_init(NULL, LOG_LOCAL4);
	else if (!strcmp(logtype, "log_local5")) error_init(NULL, LOG_LOCAL5);
	else if (!strcmp(logtype, "log_local6")) error_init(NULL, LOG_LOCAL6);
	else if (!strcmp(logtype, "log_local7")) error_init(NULL, LOG_LOCAL7);
	else
	{
		FILE *fp;

		if (!(fp = fopen(logtype, "a")))
			Warn("%s: %s: %s", opt_conf, logtype, _("Error opening log file"));
		err_file = fp;
		closelog();
	}
}
/*--- conf_set_logging() ------------------------------------------------------------------------*/


/**************************************************************************************************
	CHECK_CONFIG_FILE_PERMS
**************************************************************************************************/
void
check_config_file_perms(void)
{
	FILE *fp;

	if ((fp = fopen(opt_conf, "r")))
	{
		Warnx("%s: %s", opt_conf, _("WARNING: config file is readable by unprivileged user"));
		fclose(fp);
	}
}
/*--- check_config_file_perms() -----------------------------------------------------------------*/


/**************************************************************************************************
	CONF_SET_RECURSIVE
	If the 'recursive' configuration option was specified, set the recursive server.
**************************************************************************************************/
void
conf_set_recursive(void)
{
	char	*c, *address = conf_get(&Conf, "recursive", NULL), addr[512];
	int	port = 53;

	if (!address || !address[0])
		return;
	strncpy(addr, address, sizeof(addr)-1);

#if HAVE_IPV6
	if (is_ipv6(addr))		/* IPv6 - treat '+' as port separator */
	{
		recursive_family = AF_INET6;
		if ((c = strchr(addr, '+')))
		{
			*c++ = '\0';
			if (!(port = atoi(c)))
				port = 53;
		}
		if (inet_pton(AF_INET6, addr, &recursive_sa6.sin6_addr) <= 0)
		{
			Warnx("%s: %s", address, _("invalid network address for recursive server"));
			return;
		}
		recursive_sa6.sin6_family = AF_INET6;
		recursive_sa6.sin6_port = htons(port);
		forward_recursive = 1;
#if DEBUG_ENABLED
		Debug(_("recursive forwarding service through %s:%u"), ipaddr(AF_INET6, &recursive_sa6.sin6_addr), port);
#endif
		if (!(recursive_fwd_server = strdup(address)))
			recursive_fwd_server = _("forwarder");
	}
	else							/* IPv4 - treat '+' or ':' as port separator  */
#endif
	{
		recursive_family = AF_INET;
		if ((c = strchr(addr, '+')) || (c = strchr(addr, ':')))
		{
			*c++ = '\0';
			if (!(port = atoi(c)))
				port = 53;
		}
		if (inet_pton(AF_INET, addr, &recursive_sa.sin_addr) <= 0)
		{
			Warnx("%s: %s", address, _("invalid network address for recursive server"));
			return;
		}
		recursive_sa.sin_family = AF_INET;
		recursive_sa.sin_port = htons(port);
#if DEBUG_ENABLED
		Debug(_("recursive forwarding service through %s:%u"), ipaddr(AF_INET, &recursive_sa.sin_addr), port);
#endif
		forward_recursive = 1;
		if (!(recursive_fwd_server = strdup(address)))
			recursive_fwd_server = _("forwarder");
	}
}
/*--- conf_set_recursive() ----------------------------------------------------------------------*/


/**************************************************************************************************
	LOAD_CONFIG
	Load the configuration file.
**************************************************************************************************/
void
load_config(void)
{
	int n;
	struct passwd *pwd = NULL;
	struct group *grp = NULL;

	/* Load config */
	conf_load(&Conf, opt_conf);

	/* Set defaults */
	for (n = 0; defConfig[n].name; n++)
	{
		if (defConfig[n].name[0] == '-' || !defConfig[n].value)
			continue;
		if (!conf_get(&Conf, defConfig[n].name, NULL))
			conf_set(&Conf, defConfig[n].name, defConfig[n].value, 1);
	}

	/* Support "mysql-user" etc. for backwards compatibility */
	if (conf_get(&Conf, "mysql-host", NULL))
		conf_set(&Conf, "db-host", conf_get(&Conf, "mysql-host", NULL), 0);
	if (conf_get(&Conf, "mysql-user", NULL))
		conf_set(&Conf, "db-user", conf_get(&Conf, "mysql-user", NULL), 0);
	if (conf_get(&Conf, "mysql-pass", NULL))
		conf_set(&Conf, "db-password", conf_get(&Conf, "mysql-pass", NULL), 0);
	if (conf_get(&Conf, "mysql-password", NULL))
		conf_set(&Conf, "db-password", conf_get(&Conf, "mysql-password", NULL), 0);

#if HAVE_GETPWUID
	/* Set default for database username to real username if none was provided */
	if (!conf_get(&Conf, "db-user", NULL))
	{
		struct passwd *pwd2;

		if ((pwd2 = getpwuid(getuid())) && pwd2->pw_name)
		{
			conf_set(&Conf, "db-user", pwd2->pw_name, 0);
			memset(pwd2, 0, sizeof(struct passwd));
		}
	}
#endif

	/* Load user/group perms */
	if (!(pwd = getpwnam(conf_get(&Conf, "user", NULL))))
		Err(_("error loading uid for user `%s'"), conf_get(&Conf, "user", NULL));
	perms_uid = pwd->pw_uid;
	perms_gid = pwd->pw_gid;
	memset(pwd, 0, sizeof(struct passwd));

	if (!(grp = getgrnam(conf_get(&Conf, "group", NULL))) && !(grp = getgrnam("nobody")))
	{
		Warnx(_("error loading gid for group `%s'"), conf_get(&Conf, "group", NULL));
		Warnx(_("using gid %lu from user `%s'"), (unsigned long)perms_gid, conf_get(&Conf, "user", NULL));
	}
	else
	{
		perms_gid = grp->gr_gid;
		memset(grp, 0, sizeof(struct group));
	}

	/* We call conf_set_logging() again after moving into background, but it's called here
		to report on errors. */
	conf_set_logging();

	/* Set global options */
	task_timeout = atou(conf_get(&Conf, "timeout", NULL));
	axfr_enabled = GETBOOL(conf_get(&Conf, "allow-axfr", NULL));
	tcp_enabled = GETBOOL(conf_get(&Conf, "allow-tcp", NULL));
	dns_update_enabled = GETBOOL(conf_get(&Conf, "allow-update", NULL));

	ignore_minimum = GETBOOL(conf_get(&Conf, "ignore-minimum", NULL));

	/* Set table names if provided */
	mydns_set_soa_table_name(conf_get(&Conf, "soa-table", NULL));
	mydns_set_rr_table_name(conf_get(&Conf, "rr-table", NULL));

	/* Set additional where clauses if provided */
	mydns_set_soa_where_clause(conf_get(&Conf, "soa-where", NULL));
	mydns_set_rr_where_clause(conf_get(&Conf, "rr-where", NULL));

	/* Set recursive server if specified */
	conf_set_recursive();

#ifdef DN_COLUMN_NAMES
	dn_default_ns = conf_get(&Conf, "default-ns", NULL);
#endif
}
/*--- load_config() -----------------------------------------------------------------------------*/

/* vi:set ts=3: */
/* NEED_PO */
