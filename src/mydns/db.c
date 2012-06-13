/**************************************************************************************************
	$Id: db.c,v 1.43 2006/01/18 20:46:47 bboy Exp $

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
#define	DEBUG_DB	1


/**************************************************************************************************
	DB_CONNECT
	Connect to the database.
**************************************************************************************************/
void
db_connect(void)
{
	char *host = conf_get(&Conf, "db-host", NULL);
	char *password = conf_get(&Conf, "db-password", NULL);
	char *user = conf_get(&Conf, "db-user", NULL);
	char *database = conf_get(&Conf, "database", NULL);

	sql_open(user, password, host, database);
}
/*--- db_connect() ------------------------------------------------------------------------------*/


/**************************************************************************************************
	DB_OUTPUT_CREATE_TABLES
	Output SQL statements to create tables and exit.
**************************************************************************************************/
void
db_output_create_tables(void)
{
	load_config();

	/* Header */
	printf("--\n");
	printf("--  Table layouts for "PACKAGE_STRING" ("PACKAGE_DATE")\n");
	printf("--  "PACKAGE_COPYRIGHT"\n");
	printf("--\n");
	printf("--  You might create these tables with a command like:\n");
	printf("--\n");

#if USE_PGSQL
	printf("--    $ %s --create-tables | psql -h HOST -U USER DATABASE\n", progname);
#else
	printf("--    $ %s --create-tables | mysql -hHOST -p -uUSER DATABASE\n", progname);
#endif
	printf("--\n");
	printf("--\n\n");

	/* Zone/SOA table */
	printf("--\n--  Table structure for table '%s' (zones of authority)\n--\n", mydns_soa_table_name);

#if USE_PGSQL
	printf("CREATE TABLE %s (\n", mydns_soa_table_name);
	puts  ("  id      SERIAL NOT NULL PRIMARY KEY,");
	puts  ("  origin  VARCHAR(255) NOT NULL,");
	puts  ("  ns      VARCHAR(255) NOT NULL,");
	puts  ("  mbox    VARCHAR(255) NOT NULL,");
	puts  ("  serial  INTEGER NOT NULL default 1,");
	printf("  refresh INTEGER NOT NULL default %u,\n", DNS_DEFAULT_REFRESH);
	printf("  retry   INTEGER NOT NULL default %u,\n", DNS_DEFAULT_RETRY);
	printf("  expire  INTEGER NOT NULL default %u,\n", DNS_DEFAULT_EXPIRE);
	printf("  minimum INTEGER NOT NULL default %u,\n", DNS_DEFAULT_MINIMUM);
	printf("  ttl     INTEGER NOT NULL default %u,\n", DNS_DEFAULT_TTL);
	puts  ("  UNIQUE  (origin)");
	puts  (");\n");
#else
	printf("CREATE TABLE IF NOT EXISTS %s (\n", mydns_soa_table_name);
	printf("  id         INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,\n");
	printf("  origin     CHAR(255) NOT NULL,\n");
	printf("  ns         CHAR(255) NOT NULL,\n");
	printf("  mbox       CHAR(255) NOT NULL,\n");
	printf("  serial     INT UNSIGNED NOT NULL default '1',\n");
	printf("  refresh    INT UNSIGNED NOT NULL default '%u',\n", DNS_DEFAULT_REFRESH);
	printf("  retry      INT UNSIGNED NOT NULL default '%u',\n", DNS_DEFAULT_RETRY);
	printf("  expire     INT UNSIGNED NOT NULL default '%u',\n", DNS_DEFAULT_EXPIRE);
	printf("  minimum    INT UNSIGNED NOT NULL default '%u',\n", DNS_DEFAULT_MINIMUM);
	printf("  ttl        INT UNSIGNED NOT NULL default '%u',\n", DNS_DEFAULT_TTL);
	printf("  UNIQUE KEY (origin)\n");
	printf(") TYPE=MyISAM;\n");
	printf("\n");
#endif

	/* Resource record table */
	printf("--\n--  Table structure for table '%s' (resource records)\n--\n", mydns_rr_table_name);

#if USE_PGSQL
	printf("CREATE TABLE %s (\n", mydns_rr_table_name);
	printf("  id     SERIAL NOT NULL PRIMARY KEY,\n");
	printf("  zone   INTEGER NOT NULL,\n");
	printf("  name   VARCHAR(64) NOT NULL,\n");
	printf("  type   VARCHAR(5) NOT NULL CHECK ");
		printf("(type='A' OR type='AAAA' ");
#if ALIAS_ENABLED
		printf("OR type='ALIAS' ");
#endif
		printf("OR type='CNAME' OR type='HINFO' OR type='MX' OR type='NAPTR' OR type='NS' ");
		printf("OR type='PTR' OR type='RP' OR type='SRV' OR type='TXT'),\n");
	printf("  data   VARCHAR(128) NOT NULL,\n");
	printf("  aux    INTEGER NOT NULL default 0,\n");
	printf("  ttl    INTEGER NOT NULL default %u,\n", DNS_DEFAULT_TTL);
	printf("  UNIQUE (zone,name,type,data),\n");
	printf("  FOREIGN KEY (zone) REFERENCES soa (id) ON DELETE CASCADE\n");
	printf(");\n\n");
#else
	printf("CREATE TABLE IF NOT EXISTS %s (\n", mydns_rr_table_name);
	printf("  id         INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,\n");
	printf("  zone       INT UNSIGNED NOT NULL,\n");
	printf("  name       CHAR(64) NOT NULL,\n");
	printf("  type       ENUM('A','AAAA',");
#if ALIAS_ENABLED
		printf("'ALIAS',");
#endif
		printf("'CNAME','HINFO','MX','NAPTR','NS','PTR','RP','SRV','TXT'),\n");
	printf("  data       CHAR(128) NOT NULL,\n");
	printf("  aux        INT UNSIGNED NOT NULL,\n");
	printf("  ttl        INT UNSIGNED NOT NULL default '%u',\n", DNS_DEFAULT_TTL);
	printf("  UNIQUE KEY rr (zone,name,type,data)\n");
	printf(") TYPE=MyISAM;\n\n");
#endif

	exit(EXIT_SUCCESS);
}
/*--- db_output_create_tables() -----------------------------------------------------------------*/


#ifdef notdef
/**************************************************************************************************
	DB_SQL_NUMROWS
	Returns the number of rows from a specified result.
**************************************************************************************************/
static int
db_sql_numrows(const char *fmt, ...)
{
	va_list ap;
	char query[256];
	size_t querylen;
	SQL_RES *res = NULL;
	int rv;

	va_start(ap, fmt);
	querylen = vsnprintf(query, sizeof(query), fmt, ap);
	va_end(ap);

	if (!(res = sql_query(sql, query, querylen)))
		ErrSQL(sql, "%s", _("database error"));
	rv = sql_num_rows(res);
	sql_free(res);
	return (rv);
}
/*--- db_sql_numrows() --------------------------------------------------------------------------*/
#endif


/**************************************************************************************************
	DB_CHECK_COLUMN
	Makes sure the specified column name exists in the specified table for the database.
	Fatal if the column does not exist.
**************************************************************************************************/
static void
db_check_column(char *database, char *table, char *name)
{
	if (!sql_iscolumn(sql, table, name))
	{
		Warnx(_("Required column `%s' in table `%s' (database `%s') not found or inaccessible"),
				name, table, database);
		Warnx(_("Do you need to create the tables in the `%s' database?"), database);
		Warnx(_("You can run `%s --create-tables' to output appropriate SQL commands"), progname);
		exit(EXIT_FAILURE);
	}
}
/*--- db_check_column() -------------------------------------------------------------------------*/


/**************************************************************************************************
	DB_VERIFY_TABLE
	Verifies each column in a comma-separated list.
**************************************************************************************************/
static void
db_verify_table(char *database, char *table, char *columns)
{
	char fields[80], *f = fields, *name;

	/* Check that the table itself exists */
	if (!sql_istable(sql, table))
	{
		Warnx(_("Required table `%s' in database `%s' not found or inaccessible"), table, database);
		Warnx(_("Do you need to create the tables in the `%s' database?"), database);
		Warnx(_("You can run `%s --create-tables' to output appropriate SQL commands"), progname);
		exit(EXIT_FAILURE);
	}

	/* Check each field in field list */
	strncpy(fields, columns, sizeof(fields)-1);
	while ((name = strsep(&f, ",")))
		db_check_column(database, table, name);
}
/*--- db_verify_table() -------------------------------------------------------------------------*/


/**************************************************************************************************
	DB_CHECK_OPTIONAL
	Check optional columns.
**************************************************************************************************/
void
db_check_optional(void)
{
	int old_soa_use_active = mydns_soa_use_active;
	int old_soa_use_xfer = mydns_soa_use_xfer;
	int old_soa_use_update_acl = mydns_soa_use_update_acl;
	int old_rr_use_active = mydns_rr_use_active;

	/* Check for soa.active */
	mydns_set_soa_use_active(sql);
	if (mydns_soa_use_active != old_soa_use_active)
		Verbose(_("optional 'active' column found in '%s' table"), mydns_soa_table_name);

	/* Check for soa.xfer */
	mydns_set_soa_use_xfer(sql);
	if (mydns_soa_use_xfer != old_soa_use_xfer)
		Verbose(_("optional 'xfer' column found in '%s' table"), mydns_soa_table_name);

	/* Check for soa.update_acl */
	mydns_set_soa_use_update_acl(sql);
	if (mydns_soa_use_update_acl != old_soa_use_update_acl)
		Verbose(_("optional 'update_acl' column found in '%s' table"), mydns_soa_table_name);

	/* Check for rr.active */
	mydns_set_rr_use_active(sql);
	if (mydns_rr_use_active != old_rr_use_active)
		Verbose(_("optional 'active' column found in '%s' table"), mydns_rr_table_name);
}
/*--- db_check_optional() -----------------------------------------------------------------------*/


/**************************************************************************************************
	DB_CHECK_PTR_TABLE
	See if the obsolete "ptr" table exists.  If so, warn the user.
**************************************************************************************************/
static void
db_check_ptr_table(const char *database)
{
	char *table = conf_get(&Conf, "ptr-table", NULL);

	if (!table)
		table = "ptr";

	if (sql_istable(sql, table))
	{
		Warnx(_("Obsolete table `%s' found in database `%s'"), table, database);
		Warnx(_("Please drop this table; it is no longer supported"));
		Warnx(_("Use the \"mydnsptrconvert\" program to convert your current PTR data"));
		Warnx(_("See %s/ptr.html for more information"), PACKAGE_HOMEPAGE);
		exit(EXIT_FAILURE);
	}
}
/*--- db_check_ptr_table() ----------------------------------------------------------------------*/


/**************************************************************************************************
	DB_VERIFY_TABLES
	Makes sure the required tables exist and that we can read from them.
**************************************************************************************************/
void
db_verify_tables(void)
{
	char *host = conf_get(&Conf, "db-host", NULL);
	char *database = conf_get(&Conf, "database", NULL);
	char *password = conf_get(&Conf, "db-password", NULL);
	char *user = conf_get(&Conf, "db-user", NULL);

	sql_open(user, password, host, database);

	/* XXX: Fix this - check existence of database etc */
#ifndef DN_COLUMN_NAMES
	db_verify_table(database, mydns_soa_table_name, MYDNS_SOA_FIELDS);
	db_verify_table(database, mydns_rr_table_name, MYDNS_RR_FIELDS);

	db_check_ptr_table(database);

	db_check_optional();
#endif

	sql_close(sql);
}
/*--- db_verify_tables() ------------------------------------------------------------------------*/

/* vi:set ts=3: */
/* NEED_PO */
