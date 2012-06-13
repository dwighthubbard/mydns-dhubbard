/**************************************************************************************************
	$Id: main.c,v 1.122 2005/12/08 17:45:56 bboy Exp $

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



QUEUE *Tasks;														/* Task queue */
time_t current_time;												/* Current time */

static int multicpu;												/* If multi-CPU, number of CPUs */
static pid_t *pidlist;											/* List of related PIDs */
static int is_master;											/* Is the current process the master? */
static int got_sigusr1 = 0,
			  got_sigusr2 = 0,
			  got_sighup = 0,
			  got_sigalrm = 0,									/* Signal flags */
			  got_sigchld = 0;									/* Signal flags */
static int shutting_down = 0;									/* Shutdown in progress? */

int	run_as_root = 0;											/* Run as root user? */
uint32_t answer_then_quit = 0;								/* Answer this many queries then quit */
char	hostname[256];												/* Hostname of local machine */

extern int *tcp4_fd, *udp4_fd;								/* Listening FD's (IPv4) */
extern int num_tcp4_fd, num_udp4_fd;						/* Number of listening FD's (IPv4) */
#if HAVE_IPV6
extern int *tcp6_fd, *udp6_fd;								/* Listening FD's (IPv6) */
extern int num_tcp6_fd, num_udp6_fd;						/* Number of listening FD's (IPv6) */
#endif

int	show_data_errors = 1;									/* Output data errors? */

SERVERSTATUS Status;												/* Server status information */

extern void create_listeners(void);
extern void db_check_optional(void);

extern int	opt_daemon;
extern char	*opt_conf;
extern uid_t perms_uid;
extern gid_t perms_gid;


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
		printf(_("Usage: %s [OPTION]..."), progname);
		puts("");
		puts(_("Listen for and respond to Internet domain name queries."));
		puts("");
/*		puts("----------------------------------------------------------------------------78");  */
		puts(_("  -b, --background        run as a daemon (move process into background)"));
		puts(_("  -c, --conf=FILE         read config from FILE instead of the default"));
		puts(_("      --create-tables     output table creation SQL and exit"));
		puts(_("      --dump-config       output configuration and exit"));
		printf("                          (%s: \"%s\")\n", _("default"), MYDNS_CONF);
		puts("");
		puts(_("  -D, --database=DB       database name to use"));
		puts(_("  -h, --host=HOST         connect to database at HOST"));
		puts(_("  -p, --password=PASS     password for database (or prompt from tty)"));
		puts(_("  -u, --user=USER         username for database if not current user"));
		puts("");
#if DEBUG_ENABLED
		puts(_("  -d, --debug             enable debug output"));
#endif
		puts(_("  -v, --verbose           be more verbose while running"));
		puts(_("      --no-data-errors    don't output errors about bad data"));
		puts(_("      --help              display this help and exit"));
		puts(_("      --version           output version information and exit"));
		puts("");
		printf(_("The %s homepage is at %s\n"), PACKAGE_NAME, PACKAGE_HOMEPAGE);
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
	int	want_dump_config = 0, optc, optindex;
	struct option const longopts[] =
	{
		{"background",		no_argument,			NULL,	'b'},
		{"conf",				required_argument,	NULL,	'c'},
		{"create-tables",	no_argument,			NULL,	0},
		{"dump-config",	no_argument,			NULL,	0},

		{"database",		required_argument,	NULL,	'D'},
		{"host",				required_argument,	NULL,	'h'},
		{"password",		optional_argument,	NULL,	'p'},
		{"user",				required_argument,	NULL,	'u'},

		{"debug",			no_argument,			NULL,	'd'},
		{"verbose",			no_argument,			NULL,	'v'},
		{"help",				no_argument,			NULL,	0},
		{"version",			no_argument,			NULL,	0},

		{"quit-after",		required_argument,	NULL,	0}, /* Undocumented.. Useful when debugging */
		{"run-as-root",	no_argument,			NULL,	0}, /* Undocumented.. */

		{"no-data-errors",no_argument,			NULL,	0},

		{NULL, 0, NULL, 0}
	};

	error_init(argv[0], LOG_DAEMON);							/* Init output/logging routines */

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
					else if (!strcmp(opt, "dump-config"))						/* --dump-config */
						want_dump_config++;
					else if (!strcmp(opt, "create-tables"))					/* --create-tables */
						db_output_create_tables();
					else if (!strcmp(opt, "quit-after"))						/* --quit-after */
						answer_then_quit = strtoul(optarg, (char **)NULL, 10);
					else if (!strcmp(opt, "run-as-root"))						/* --run-as-root */
						run_as_root = 1;
					else if (!strcmp(opt, "no-data-errors"))					/* --no-data-errors */
						show_data_errors = 0;
				}
				break;

			case 'b':																	/* -b, --background */
				opt_daemon = 1;
				break;

			case 'c':																	/* -c, --conf=FILE */
				opt_conf = optarg;
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

			default:
				usage(EXIT_FAILURE);
		}
	}

	if (optind < argc)
		fprintf(stderr, "%s: %s\n", progname, _("Extraneous command-line arguments ignored"));

	load_config();

	if (want_dump_config)
	{
		dump_config();
		exit(EXIT_SUCCESS);
	}

	db_verify_tables();											/* Make sure tables are OK */

	/* Random numbers are just for round robin and load balancing */
	srand(time(NULL));
}
/*--- cmdline() ---------------------------------------------------------------------------------*/


/**************************************************************************************************
	SET_SIGHANDLER
**************************************************************************************************/
typedef void (*sig_handler)(int);
static void
set_sighandler(int sig, sig_handler h)
{
	struct sigaction act;

	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	if (sig == SIGALRM)
	{
#ifdef SA_INTERRUPT
		act.sa_flags |= SA_INTERRUPT;
#endif
	}
	else
	{
#ifdef SA_RESTART
		act.sa_flags |= SA_RESTART;
#endif
	}

	act.sa_handler = h;
	sigaction(sig, &act, 0);
}
/*--- set_sighandler() --------------------------------------------------------------------------*/


/**************************************************************************************************
	BECOME_DAEMON
**************************************************************************************************/
static void
become_daemon(void)
{
	int pid;
	struct rlimit rl;

	sql_close(sql);

	if ((pid = fork()) < 0)
		Err("fork");
	if (pid)
		_exit(EXIT_SUCCESS);

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	setsid();

	if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
		Err("getrlimit");
	rl.rlim_cur = rl.rlim_max;
	setrlimit(RLIMIT_NOFILE, &rl);

	if (getrlimit(RLIMIT_CORE, &rl) < 0)
		Err("getrlimit");
	rl.rlim_cur = rl.rlim_max;
	setrlimit(RLIMIT_CORE, &rl);

	db_connect();
}
/*--- become_daemon() ---------------------------------------------------------------------------*/


/**************************************************************************************************
	CREATE_PIDFILE
	Creates the PID file.
**************************************************************************************************/
static void
create_pidfile(void)
{
	char *name = conf_get(&Conf, "pidfile", NULL);
	FILE *fp;

	if (!(fp = fopen(name, "w")))
		Err("%s", name);
	fprintf(fp, "%lu\n", (unsigned long)getpid());
	fclose(fp);

	/* Change ownership so we can delete it later */
	chown(name, perms_uid, perms_gid);
}
/*--- create_pidfile() --------------------------------------------------------------------------*/


/**************************************************************************************************
	SERVER_STATUS
**************************************************************************************************/
void
server_status(void)
{
	char buf[1024], *b = buf;
	time_t uptime = time(NULL) - Status.start_time;
	unsigned long requests = Status.udp_requests + Status.tcp_requests;

	b += snprintf(b, sizeof(buf)-(b-buf), "%s ", hostname);
	b += snprintf(b, sizeof(buf)-(b-buf), "%s %s (%lus) ", _("up"), strsecs(uptime), (unsigned long)uptime);
	b += snprintf(b, sizeof(buf)-(b-buf), "%lu %s ", requests, _("questions"));
	b += snprintf(b, sizeof(buf)-(b-buf), "(%.0f/s) ", requests ? AVG(requests, uptime) : 0.0);
	b += snprintf(b, sizeof(buf)-(b-buf), "NOERROR=%u ", Status.results[DNS_RCODE_NOERROR]);
	b += snprintf(b, sizeof(buf)-(b-buf), "SERVFAIL=%u ", Status.results[DNS_RCODE_SERVFAIL]);
	b += snprintf(b, sizeof(buf)-(b-buf), "NXDOMAIN=%u ", Status.results[DNS_RCODE_NXDOMAIN]);
	b += snprintf(b, sizeof(buf)-(b-buf), "NOTIMP=%u ", Status.results[DNS_RCODE_NOTIMP]);
	b += snprintf(b, sizeof(buf)-(b-buf), "REFUSED=%u ", Status.results[DNS_RCODE_REFUSED]);

	/* If the server is getting TCP queries, report on the percentage of TCP queries */
	if (Status.tcp_requests)
		b += snprintf(b, sizeof(buf)-(b-buf), "(%d%% TCP, %lu queries)",
						  (int)PCT(requests, Status.tcp_requests), (unsigned long)Status.tcp_requests);

	Notice("%s", buf);
}
/*--- server_status() ---------------------------------------------------------------------------*/


/**************************************************************************************************
	SIGUSR1
	Outputs server stats.
**************************************************************************************************/
void
sigusr1(int dummy)
{
	if (is_master)
	{
		int n;
		for (n = 0; n < multicpu - 1; n++)
			kill(pidlist[n], SIGUSR1);
	}
	server_status();
	got_sigusr1 = 0;
}
/*--- sigusr1() ---------------------------------------------------------------------------------*/


/**************************************************************************************************
	SIGUSR2
	Outputs cache stats.
**************************************************************************************************/
void
sigusr2(int dummy)
{
	if (is_master)
	{
		int n;
		for (n = 0; n < multicpu - 1; n++)
			kill(pidlist[n], SIGUSR2);
	}
	cache_status(ZoneCache);
#if USE_NEGATIVE_CACHE
	cache_status(NegativeCache);
#endif
	cache_status(ReplyCache);
	got_sigusr2 = 0;
}
/*--- sigusr2() ---------------------------------------------------------------------------------*/


/**************************************************************************************************
	PERIODIC_TASK
**************************************************************************************************/
void
periodic_task(int dummy)
{
	alarm(ALARM_INTERVAL);
	got_sigalrm = 0;
}
/*--- periodic_task() ---------------------------------------------------------------------------*/


/**************************************************************************************************
	SIGHUP
**************************************************************************************************/
void
sighup(int dummy)
{
	if (is_master)
	{
		int n;
		for (n = 0; n < multicpu - 1; n++)
			kill(pidlist[n], SIGHUP);
	}
	cache_empty(ZoneCache);
#if USE_NEGATIVE_CACHE
	cache_empty(NegativeCache);
#endif
	cache_empty(ReplyCache);
	db_check_optional();
	Notice(_("SIGHUP received: cache emptied, tables reloaded"));
	got_sighup = 0;
}
/*--- sighup() ----------------------------------------------------------------------------------*/


/**************************************************************************************************
	SIGNAL_HANDLER
**************************************************************************************************/
void
signal_handler(int signo)
{
	switch (signo)
	{
		case SIGHUP: got_sighup = 1; break;
		case SIGUSR1: got_sigusr1 = 1; break;
		case SIGUSR2: got_sigusr2 = 1; break;
		case SIGALRM: got_sigalrm = 1; break;
		case SIGCHLD: got_sigchld = 1; break;
		default: break;
	}
}
/*--- signal_handler() --------------------------------------------------------------------------*/


/**************************************************************************************************
	NAMED_CLEANUP
**************************************************************************************************/
void
named_cleanup(int signo)
{
	register TASK *t;

	shutting_down = 1;

	server_status();

	switch (signo)
	{
		case SIGINT:  Notice(_("interrupted")); break;
		case SIGQUIT: Notice(_("quit")); break;
		case SIGTERM: Notice(_("terminated")); break;
		default: Notice(_("exiting due to signal %d"), signo); break;
	}

	if (is_master)
	{
		int n, status;
		for (n = 0; n < multicpu - 1; n++)
		{
			kill(pidlist[n], signo);
			waitpid(pidlist[n], &status, 0);
		}
	}

	/* Close any TCP connections */
	for (t = Tasks->head; t; t = Tasks->head)
	{
		if (t->protocol == SOCK_STREAM && t->fd != -1)
			sockclose(t->fd);
		dequeue(Tasks, t);
	}

	/* Close listening FDs */
	if (is_master)
	{
		register int n;

		for (n = 0; n < num_tcp4_fd; n++)
			sockclose(tcp4_fd[n]);

		for (n = 0; n < num_udp4_fd; n++)
			sockclose(udp4_fd[n]);

#if HAVE_IPV6
		for (n = 0; n < num_tcp6_fd; n++)
			sockclose(tcp6_fd[n]);

		for (n = 0; n < num_udp6_fd; n++)
			sockclose(udp6_fd[n]);
#endif	/* HAVE_IPV6 */

	}

	cache_empty(ZoneCache);
#if USE_NEGATIVE_CACHE
	cache_empty(NegativeCache);
#endif
	cache_empty(ReplyCache);

	unlink(conf_get(&Conf, "pidfile", NULL));
	exit(EXIT_SUCCESS);
}
/*--- named_cleanup() ---------------------------------------------------------------------------*/


/**************************************************************************************************
	CHILD_CLEANUP
**************************************************************************************************/
static void
child_cleanup(int signo)
{
	int n, status, pid;

	got_sigchld = 0;

	if (shutting_down)
		return;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
	{
		if (!WIFEXITED(status))
		{
#ifdef WCOREDUMP
			if (WIFSIGNALED(status))
				Warnx("pid %d exited due to signal %d%s", pid, WTERMSIG(status),
						WCOREDUMP(status) ? " (core dumped)" : "");
			else
				Warnx("pid %d exited with status %d%s", pid, WEXITSTATUS(status),
						WCOREDUMP(status) ? " (core dumped)" : "");
#else
			if (WIFSIGNALED(status))
				Warnx("pid %d exited due to signal %d", pid, WTERMSIG(status));
			else
				Warnx("pid %d exited with status %d", pid, WEXITSTATUS(status));
#endif
		}
		else
		{
#if DEBUG_ENABLED
			Debug("child pid %d exited successfully", pid);
#endif
		}

		/* If the dead child is part of pidlist (for multicpu), restart */
		for (n = 0; n < multicpu - 1; n++)
			if (pid == pidlist[n])
				Errx("pid %d died", pid);
	}
}
/*--- child_cleanup() ---------------------------------------------------------------------------*/


/**************************************************************************************************
	SPAWN_MULTICPU
**************************************************************************************************/
static void
spawn_multicpu(void)
{
	int n;

	is_master = 1;
	if (!(pidlist = malloc(multicpu * sizeof(pid_t))))
		Err(_("out of memory"));
	for (n = 1; n < multicpu; n++)
	{
		pid_t pid;

		if ((pid = fork()) < 0)
			Err("fork");
		if (pid > 0)
		{
			pidlist[n-1] = pid;
		}
		else
		{
			is_master = 0;
			db_connect();
			return;
		}
	}
}
/*--- spawn_multicpu() --------------------------------------------------------------------------*/


/**************************************************************************************************
	_INIT_RLIMIT
	Sets a single resource limit and optionally prints out a notification message; called by
	init_rlimits().
**************************************************************************************************/
static void
_init_rlimit(int resource, const char *desc, long long set)
{
	struct rlimit rl;

	if (getrlimit(resource, &rl) < 0)
		Err("getrlimit");
	if (set == -1)
		rl.rlim_cur = rl.rlim_max;
	else if (set > 0 && rl.rlim_cur < set)
		rl.rlim_cur = set;
	setrlimit(resource, &rl);
	if (getrlimit(resource, &rl) < 0)
		Err("getrlimit");
}
/*--- _init_rlimit() ----------------------------------------------------------------------------*/


/**************************************************************************************************
	INIT_RLIMITS
	Max out allowed resource limits.
**************************************************************************************************/
static void
init_rlimits(void)
{
#ifdef RLIMIT_CPU
	_init_rlimit(RLIMIT_CPU, "RLIMIT_CPU", 0);
#endif
#ifdef RLIMIT_FSIZE
	_init_rlimit(RLIMIT_FSIZE, "RLIMIT_FSIZE", 0);
#endif
#ifdef RLIMIT_DATA
	_init_rlimit(RLIMIT_DATA, "RLIMIT_DATA", 0);
#endif
#ifdef RLIMIT_STACK
	_init_rlimit(RLIMIT_STACK, "RLIMIT_STACK", -1);
#endif
#ifdef RLIMIT_CORE
	_init_rlimit(RLIMIT_CORE, "RLIMIT_CORE", -1);
#endif
#ifdef RLIMIT_RSS
	_init_rlimit(RLIMIT_RSS, "RLIMIT_RSS", 0);
#endif
#ifdef RLIMIT_NPROC
	_init_rlimit(RLIMIT_NPROC, "RLIMIT_NPROC", -1);
#endif
#ifdef RLIMIT_NOFILE
	_init_rlimit(RLIMIT_NOFILE, "RLIMIT_NOFILE", -1);
#endif
#ifdef RLIMIT_MEMLOCK
	_init_rlimit(RLIMIT_MEMLOCK, "RLIMIT_MEMLOCK", 0);
#endif
#ifdef RLIMIT_AS
	_init_rlimit(RLIMIT_AS, "RLIMIT_AS", 0);
#endif
}
/*--- init_rlimits() ----------------------------------------------------------------------------*/


/**************************************************************************************************
	CLOSE_TIMED_OUT_TASK
	Check for and dequeue timed out tasks.
**************************************************************************************************/
static inline void
close_timed_out_task(register TASK *t)
{
	Status.timedout++;

	t->reason = ERR_TIMEOUT;
	t->hdr.rcode = DNS_RCODE_SERVFAIL;

	/* Close TCP connection */
	if (t->protocol == SOCK_STREAM)
		sockclose(t->fd);

	dequeue(Tasks, t);
}
/*--- close_timed_out_task() --------------------------------------------------------------------*/


/**************************************************************************************************
	MAIN
**************************************************************************************************/
int
main(int argc, char **argv)
{
	register int n;
	int plain_maxfd = 0, maxfd, rv, want_timeout = 0;
	fd_set rfd, start_rfd, wfd;
	struct timeval tv;
	register TASK	*t, *next_task;

	setlocale(LC_ALL, "");										/* Internationalization */
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	cmdline(argc, argv);											/* Process command line */

	/* Set hostname */
	gethostname(hostname, sizeof(hostname)-1);

	set_sighandler(SIGHUP,	signal_handler);
	set_sighandler(SIGUSR1, signal_handler);
	set_sighandler(SIGUSR2, signal_handler);
	set_sighandler(SIGALRM, signal_handler);
	set_sighandler(SIGCHLD, child_cleanup);

	set_sighandler(SIGINT,  named_cleanup);
	set_sighandler(SIGQUIT, named_cleanup);
	set_sighandler(SIGABRT, named_cleanup);
	set_sighandler(SIGTERM, named_cleanup);

	if (opt_daemon)												/* Move into background if requested */
		become_daemon();
	conf_set_logging();
	db_connect();
	create_pidfile();												/* Create PID file */
	Tasks = queue_init();										/* Initialize task queue */
	cache_init();													/* Initialize cache */

	/* Start listening fd's */
	create_listeners();
	time(&Status.start_time);

	/* Spawn a process for each CPU, if multicpu > 1 */
	if ((multicpu = atoi(conf_get(&Conf, "multicpu", NULL))) > 1)
		spawn_multicpu();

	if (run_as_root)
	{
		init_rlimits();
		chdir("/tmp");
		Notice("%s", _("WARNING: running with superuser permissions (cwd=/tmp)"));
	}
	if (!run_as_root)
	{
#if PROFILING
		/* If profiling, change to a dir that a user without perms can likely write profiling data to */
		chdir("/tmp");
#endif

		/* Drop permissions */
		if (getgid() == 0 && setgid(perms_gid))
			Err(_("error setting group ID to %u"), (unsigned int)perms_gid);
		if (getuid() == 0 && setuid(perms_uid))
			Err(_("error setting user ID to %u"), (unsigned int)perms_uid);
		if (!getgid() || !getuid())
			Errx(_("refusing to run as superuser"));
		check_config_file_perms();
	}

	FD_ZERO(&start_rfd);
	for (n = 0; n < num_udp4_fd; n++)
	{
		FD_SET(udp4_fd[n], &start_rfd);
		if (udp4_fd[n] > plain_maxfd)
			plain_maxfd = udp4_fd[n];
	}
	for (n = 0; n < num_tcp4_fd; n++)
	{
		FD_SET(tcp4_fd[n], &start_rfd);
		if (tcp4_fd[n] > plain_maxfd)
			plain_maxfd = tcp4_fd[n];
	}
#if HAVE_IPV6
	for (n = 0; n < num_udp6_fd; n++)
	{
		FD_SET(udp6_fd[n], &start_rfd);
		if (udp6_fd[n] > plain_maxfd)
			plain_maxfd = udp6_fd[n];
	}
	for (n = 0; n < num_tcp6_fd; n++)
	{
		FD_SET(tcp6_fd[n], &start_rfd);
		if (tcp6_fd[n] > plain_maxfd)
			plain_maxfd = tcp6_fd[n];
	}
#endif

	periodic_task(SIGALRM);										/* Initialize alarm state */

	/* Main loop: Read connections and process queue */
	for (;;)
	{
		/* Handle signals */
		if (got_sighup) sighup(SIGHUP);
		if (got_sigusr1) sigusr1(SIGUSR1);
		if (got_sigusr2) sigusr2(SIGUSR2);
		if (got_sigalrm) periodic_task(SIGUSR1);
		if (got_sigchld) child_cleanup(SIGCHLD);

		memcpy(&rfd, &start_rfd, sizeof(rfd));
		maxfd = plain_maxfd;
		FD_ZERO(&wfd);

		/* Add TCP requests to fd set */
		if (num_tcp4_fd
#if HAVE_IPV6
			 || num_tcp6_fd
#endif
			 )
			for (want_timeout = 0, t = Tasks->head; t; t = t->next)
			{
				if ((t->protocol == SOCK_STREAM) && (t->fd >= 0))
				{
					want_timeout = 10000;
					switch (t->status)
					{
						case NEED_READ:
							FD_SET(t->fd, &rfd);
							if (t->fd > maxfd)
								maxfd = t->fd;
							break;

						case NEED_WRITE:
							FD_SET(t->fd, &wfd);
							if (t->fd > maxfd)
								maxfd = t->fd;
							break;

						default:
							break;
					}
				}
			}

		tv.tv_sec = 0;
		tv.tv_usec = want_timeout ? want_timeout : 10000;
		rv = select(maxfd+1, &rfd, &wfd, NULL, &tv);

		time(&current_time);

		if (rv < 0)
		{
			if (errno == EINTR)
				continue;
			Err("select");
		}
		if (rv > 0)
		{
			/* Check incoming connections */
			for (n = 0; n < num_tcp4_fd; n++)
				if (FD_ISSET(tcp4_fd[n], &rfd))
					if (accept_tcp_query(tcp4_fd[n], AF_INET) < 0)
						continue;
			for (n = 0; n < num_udp4_fd; n++)
				if (FD_ISSET(udp4_fd[n], &rfd))
					if (read_udp_query(udp4_fd[n], AF_INET) < 0)
						continue;
#if HAVE_IPV6
			for (n = 0; n < num_tcp6_fd; n++)
				if (FD_ISSET(tcp6_fd[n], &rfd))
					if (accept_tcp_query(tcp6_fd[n], AF_INET6) < 0)
						continue;
			for (n = 0; n < num_udp6_fd; n++)
				if (FD_ISSET(udp6_fd[n], &rfd))
					if (read_udp_query(udp6_fd[n], AF_INET6) < 0)
						continue;
#endif
		}

		/* Process tasks */
		for (t = Tasks->head; t; t = next_task)
		{
			next_task = t->next;
			if (current_time > t->timeout)
				close_timed_out_task(t);
			else if (t->protocol == SOCK_DGRAM)
				task_process(t);
			else if (t->protocol == SOCK_STREAM && t->status == NEED_READ && FD_ISSET(t->fd, &rfd))
				task_process(t);
			else if (t->protocol == SOCK_STREAM && t->status == NEED_WRITE && FD_ISSET(t->fd, &wfd))
				task_process(t);
		}
	}
	return (0);
}
/*--- main() ------------------------------------------------------------------------------------*/

/* vi:set ts=3: */
/* NEED_PO */
