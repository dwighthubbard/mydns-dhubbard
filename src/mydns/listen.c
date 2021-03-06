/**************************************************************************************************
	$Id: listen.c,v 1.42 2006/01/18 20:46:47 bboy Exp $

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
#define	DEBUG_LISTEN	1


#if HAVE_NET_IF_H
#  include <net/if.h>
#endif
#  include <sys/ioctl.h>


int *udp4_fd = (int *)NULL;									/* Listening socket: UDP, IPv4 */
int *tcp4_fd = (int *)NULL;									/* Listening socket: TCP, IPv4 */
int num_udp4_fd = 0;												/* Number of items in 'udp4_fd' */
int num_tcp4_fd = 0;												/* Number of items in 'tcp4_fd' */

#if HAVE_IPV6
int *udp6_fd = (int *)NULL;									/* Listening socket: UDP, IPv6 */
int *tcp6_fd = (int *)NULL;									/* Listening socket: TCP, IPv6 */
int num_udp6_fd = 0;												/* Number of items in 'udp6_fd' */
int num_tcp6_fd = 0;												/* Number of items in 'tcp6_fd' */
#endif

extern char	*opt_conf;
extern uint32_t answer_then_quit;

static void server_greeting(void);


typedef struct _addrlist
{
	int					family;									/* AF_INET or AF_INET6 */
	struct in_addr		addr4;									/* Address if IPv4 */
#if HAVE_IPV6
	struct in6_addr	addr6;									/* Address if IPv6 */
#endif
	int					port;										/* Port number */
	int					ok;										/* OK to use this address? */

	struct _addrlist *next;										/* Next address */
} ADDRLIST;

static ADDRLIST *FirstAddr, *LastAddr;						/* Current address list */


/**************************************************************************************************
	ADDRLIST_ADD
	Adds the specified address to the current list, checking for duplicates, etc.
**************************************************************************************************/
static void
addrlist_add(int family, void *address, int port)
{
	ADDRLIST *A;
	struct in_addr addr4;
#if HAVE_IPV6
	struct in6_addr addr6;
#endif

	/* Copy address into struct and make sure it's not the "catch-all" address */
	if (family == AF_INET)
	{
		memcpy(&addr4, address, sizeof(struct in_addr));
		if (addr4.s_addr == INADDR_ANY)
			return;
	}
#if HAVE_IPV6
	else if (family == AF_INET6)
	{
		memcpy(&addr6, address, sizeof(struct in6_addr));
		if (!memcmp(&addr6, &in6addr_any, sizeof(struct in6_addr)))
			return;
	}
#endif
	else return;	/* Invalid family */

	/* Check for duplicate */
	for (A = FirstAddr; A; A = A->next)
		switch (family)
		{
			case AF_INET:
				if ((A->port == port) && !memcmp(&addr4, &A->addr4, sizeof(struct in_addr)))
					return;
				break;
#if HAVE_IPV6
			case AF_INET6:
				if ((A->port == port) && !memcmp(&addr6, &A->addr6, sizeof(struct in6_addr)))
					return;
				break;
#endif
		}

	/* Not a duplicate; add new interface */
	if (!(A = calloc(1, sizeof(ADDRLIST))))
		Err(_("out of memory"));
	switch ((A->family = family))
	{
		case AF_INET: memcpy(&A->addr4, &addr4, sizeof(struct in_addr)); break;
#if HAVE_IPV6
		case AF_INET6: memcpy(&A->addr6, &addr6, sizeof(struct in6_addr)); break;
#endif
	}
	A->port = port;
	A->ok = 1;

	/* Add new interface to list */
	if (!LastAddr)
		FirstAddr = LastAddr = A;
	else
	{
		LastAddr->next = A;
		LastAddr = A;
	}
}
/*--- addrlist_add() ----------------------------------------------------------------------------*/


#if DEBUG_ENABLED && DEBUG_LISTEN && HAVE_IPV6
/**************************************************************************************************
	IP6_EXTRA
**************************************************************************************************/
char *
ip6_extra(const struct in6_addr *a)
{
	static char buf[2048];
	char *b = buf;

	*b = '\0';

	if (IN6_IS_ADDR_UNSPECIFIED(a)) b += snprintf(b, sizeof(buf)-(b-buf), "UNSPECIFIED ");
	if (IN6_IS_ADDR_LOOPBACK(a)) b += snprintf(b, sizeof(buf)-(b-buf), "LOOPBACK ");
	if (IN6_IS_ADDR_MULTICAST(a)) b += snprintf(b, sizeof(buf)-(b-buf), "MULTICAST ");
	if (IN6_IS_ADDR_LINKLOCAL(a)) b += snprintf(b, sizeof(buf)-(b-buf), "LINKLOCAL ");
	if (IN6_IS_ADDR_SITELOCAL(a)) b += snprintf(b, sizeof(buf)-(b-buf), "SITELOCAL ");
	if (IN6_IS_ADDR_V4MAPPED(a)) b += snprintf(b, sizeof(buf)-(b-buf), "V4MAPPED ");
	if (IN6_IS_ADDR_V4COMPAT(a)) b += snprintf(b, sizeof(buf)-(b-buf), "V4COMPAT ");

	if (IN6_IS_ADDR_MULTICAST(a))
	{
		if (IN6_IS_ADDR_MC_NODELOCAL(a)) b += snprintf(b, sizeof(buf)-(b-buf), "MC_NODELOCAL ");
		if (IN6_IS_ADDR_MC_LINKLOCAL(a)) b += snprintf(b, sizeof(buf)-(b-buf), "MC_LINKLOCAL ");
		if (IN6_IS_ADDR_MC_SITELOCAL(a)) b += snprintf(b, sizeof(buf)-(b-buf), "MC_SITELOCAL ");
		if (IN6_IS_ADDR_MC_ORGLOCAL(a)) b += snprintf(b, sizeof(buf)-(b-buf), "MC_ORGLOCAL ");
		if (IN6_IS_ADDR_MC_GLOBAL(a)) b += snprintf(b, sizeof(buf)-(b-buf), "MC_GLOBAL ");
	}

	return buf;
}
/*--- ip6_extra() -------------------------------------------------------------------------------*/
#endif


/**************************************************************************************************
	LINUX_LOAD_IP6
	Linux does not return IPv6 interfaces via SIOCGIFCONF, so we load them from
	/proc/net/if_inet6.
	See http://tldp.org/HOWTO/Linux+IPv6-HOWTO/proc-net.html for file format.
**************************************************************************************************/
#ifdef __linux__
#if HAVE_IPV6
static void
linux_load_ip6(int port)
{
	FILE *fp;
	char line[512];

	if ((fp = fopen("/proc/net/if_inet6", "r")))
	{
		while (fgets(line, sizeof(line), fp))
		{
			int n;
			char *l, *hex, *device_number, *prefix_length, *scope_value, *if_flags;
			char buf[sizeof("XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX\0")];
			struct in6_addr addr;

			l = line;
			if (!(hex = strsep(&l, " "))) continue;
			if (!(device_number = strsep(&l, " "))) continue;
			if (!(prefix_length = strsep(&l, " "))) continue;
			if (!(scope_value = strsep(&l, " "))) continue;
			if (!(if_flags = strsep(&l, " "))) continue;
			strtrim(l);

			/* Convert hex address into 'addr' */
			for (n = 0; n < 8; n++)
			{
				memcpy(buf + (4 * n) + (n * 1), hex + (4 * n), 4);
				buf[(4 * n) + (n * 1) + 4] = ':';
			}
			buf[39] = '\0';
#if DEBUG_ENABLED && DEBUG_LISTEN
			{
				uint16_t dn, pl, sv, f;
				dn = (uint16_t)strtoul(device_number, NULL, 16);
				pl = (uint16_t)strtoul(prefix_length, NULL, 16);
				sv = (uint16_t)strtoul(scope_value, NULL, 16);
				f = (uint16_t)strtoul(if_flags, NULL, 16);
				Debug("IPv6 %s: device_number=%u prefix_length=%u scope_value=%u if_flags=%u", buf, dn, pl, sv, f);
			}
#endif
			if (inet_pton(AF_INET6, buf, &addr) > 0)
			{
				/* I am not at all sure which of these scopes from RFC 2553 we should NOT try to
					bind to..  LINKLOCAL for sure doesn't work if you try it */
				if (IN6_IS_ADDR_LINKLOCAL(&addr))
					continue;
#if DEBUG_ENABLED && DEBUG_LISTEN
				Debug("  extra: %s", ip6_extra(&addr));
#endif
				addrlist_add(AF_INET6, &addr, port);
			}
		}
		fclose(fp);
	}
}
#endif
#endif
/*--- linux_load_ip6() --------------------------------------------------------------------------*/


/**************************************************************************************************
	ADDRLIST_LOAD
	Gets the IP addresses for all interfaces on the system.
	Returns the interface list, or NULL on error.
**************************************************************************************************/
static ADDRLIST *
addrlist_load(int port)
{
	struct ifconf ifc;
	struct ifreq *ifr;
	int sockfd, buflen = 8192, n;
	unsigned char *buf;

	FirstAddr = LastAddr = NULL;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		Warn("error creating socket for interface scan");
		return NULL;
	}

	for (;;)															/* Allocate buffer space */
	{
		if (!(buf = malloc(buflen)))
			Err(_("out of memory"));
		ifc.ifc_len = buflen;
		ifc.ifc_buf = buf;

		if ((n = ioctl(sockfd, SIOCGIFCONF, (char *)&ifc)) != -1)
		{
			if (ifc.ifc_len + 2 * sizeof(struct ifreq) < buflen)
				break;
		}
		if ((n == -1) && errno != EINVAL)
		{
			Err("error setting SIOCGIFCONF for interface scan");
			return NULL;
		}
		free(buf);
		buflen += 4096;
	}

	for (n = 0; n < ifc.ifc_len;)								/* Scan interfaces */
	{
		struct in_addr addr4;
#if HAVE_IPV6
		struct in6_addr addr6;
#endif

		ifr = (struct ifreq *)((char *)ifc.ifc_req + n);

#ifdef HAVE_SOCKADDR_SA_LEN
		n += sizeof(ifr->ifr_name) + (ifr->ifr_addr.sa_len > sizeof(struct sockaddr)
												? ifr->ifr_addr.sa_len : sizeof(struct sockaddr));
#else
		n += sizeof(struct ifreq);
#endif /* HAVE_SOCKADDR_SA_LEN */

		if (ifr->ifr_flags & IFF_UP)							/* Must be up */
			continue;
		if (ioctl(sockfd, SIOCGIFADDR, ifr) < 0)			/* Get address */
			continue;

		switch (ifr->ifr_addr.sa_family)
		{
			case AF_INET:
				memcpy(&addr4, &((struct sockaddr_in *)&ifr->ifr_addr)->sin_addr, sizeof(struct in_addr));
				addrlist_add(AF_INET, &addr4, port);
				break;
#if HAVE_IPV6
			case AF_INET6:
				memcpy(&addr6, &((struct sockaddr_in6 *)&ifr->ifr_addr)->sin6_addr, sizeof(struct in6_addr));
				addrlist_add(AF_INET, &addr4, port);
				break;
#endif
			default:
				continue;
		}
	}
	close(sockfd);
	free(buf);

#ifdef __linux__
#if HAVE_IPV6
	linux_load_ip6(port);
#endif
#endif

	return (FirstAddr);
}
/*--- addrlist_load() ---------------------------------------------------------------------------*/


/**************************************************************************************************
	ADDRLIST_FREE
**************************************************************************************************/
void
addrlist_free(ADDRLIST *Addresses)
{
	ADDRLIST *A, *tmp;

	for (A = Addresses; A; A = tmp)
	{
		tmp = A->next;
		free(A);
	}
}
/*--- addrlist_free() ---------------------------------------------------------------------------*/


/**************************************************************************************************
	GET_OPT_ADDRLIST
	Examines the provided configuration option string and returns an ADDRLIST structure containing
	the addresses.
**************************************************************************************************/
static ADDRLIST *
get_opt_addrlist(ADDRLIST *Addresses, const char *opt, int default_port, char *desc)
{
	int family;														/* Protocol family (AF_INET/AF_INET6) */
	struct in_addr addr4;										/* IPv4 address buffer */
#if HAVE_IPV6
	struct in6_addr addr6;										/* IPv6 address buffer */
#endif
	register ADDRLIST *A;
	char *cc, *oc, *a, *c;

	FirstAddr = LastAddr = NULL;
	if (!opt || !opt[0])
		return (NULL);
	if (!(oc = strdup((char *)opt)))							/* Make copy of 'opt' for mangling */
		Err("strdup");
	for (c = oc; *c; c++)										/* Replace commas with CONF_FS */
		if (*c == ',')
			*c = CONF_FS_CHAR;

	for (cc = oc; (a = strsep(&cc, CONF_FS_STR)); )		/* Add each address */
	{
		char	addr[256];											/* Address/port part of address */
		int	port = default_port;								/* Port number */

		strncpy(addr, a, sizeof(addr)-1);

#if HAVE_IPV6
		if (is_ipv6(addr))		/* IPv6 - treat '+' as port separator */
		{
			family = AF_INET6;
			if ((c = strchr(addr, '+')))
			{
				*c++ = '\0';
				if (!(port = atoi(c)))
					port = default_port;
			}
		}
		else							/* IPv4 - treat '+' or ':' as port separator  */
#endif
		{
			family = AF_INET;
			if ((c = strchr(addr, '+')) || (c = strchr(addr, ':')))
			{
				*c++ = '\0';
				if (!(port = atoi(c)))
					port = default_port;
			}
		}

		/* If the address specifies the wildcard '*', add a record for each address */
		if (addr[0] == '*')
		{
			for (A = Addresses; A; A = A->next)
				if (A->family == AF_INET)
					addrlist_add(A->family, &A->addr4, port);
#if HAVE_IPV6
				else if (A->family == AF_INET6)
					addrlist_add(A->family, &A->addr6, port);
#endif
			continue;
		}

		/* Handle "localhost" */
		if (!strcasecmp(addr, "localhost"))
		{
			/* Only add the IPv4 localhost if there are SOME IPv4 addresses */
			for (A = Addresses; A; A = A->next)
				if (A->family == AF_INET)
				{
					if (inet_pton(AF_INET, "127.0.0.1", &addr4) > 0)
						addrlist_add(AF_INET, &addr4, port);
					break;
				}

#if HAVE_IPV6
			/* Only add the IPv6 localhost if there are SOME IPv6 addresses */
			for (A = Addresses; A; A = A->next)
				if (A->family == AF_INET6)
				{
					memcpy(&addr6, &in6addr_loopback, sizeof(struct in6_addr));
					addrlist_add(AF_INET6, &addr6, port);
					break;
				}
#endif
			continue;
		}

		if (family == AF_INET)									/* Add regular IPv4 address */
		{
			if (inet_pton(AF_INET, addr, &addr4) <= 0)
				Warnx("%s: `%s' %s: %s", addr, desc, _("address"), _("invalid IPv4 address format"));
			else
				addrlist_add(AF_INET, &addr4, port);
		}
#if HAVE_IPV6
		else if (family == AF_INET6)							/* Add regular IPv6 address */
		{
			if (inet_pton(AF_INET6, addr, &addr6) <= 0)
				Warnx("%s: `%s' %s: %s", addr, desc, _("address"), _("invalid IPv6 address format"));
			else
				addrlist_add(AF_INET6, &addr4, port);
		}
#endif
	}
	Free(oc);
	return (FirstAddr);
}
/*--- get_opt_addrlist() ------------------------------------------------------------------------*/


/**************************************************************************************************
	IPV4_LISTENER
	Create IPv4 listening socket.  Returns the new file descriptor.  Errors are fatal.
**************************************************************************************************/
static int
ipv4_listener(struct sockaddr_in *sa, int protocol)
{
	int fd, opt = 1;

	if ((fd = socket(AF_INET, protocol, (protocol == SOCK_STREAM) ? IPPROTO_TCP : IPPROTO_UDP)) < 0)
		Err("socket");
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
		Warn("setsockopt");
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
	if (bind(fd, (struct sockaddr *)sa, sizeof(struct sockaddr_in)) < 0)
		Err("bind (%s): %s:%d",
			 (protocol == SOCK_STREAM) ? "TCP" : "UDP", inet_ntoa(sa->sin_addr), ntohs(sa->sin_port));
	if (protocol == SOCK_STREAM)
	{
		if (listen(fd, SOMAXCONN) < 0)
			Err("listen");
	}
	else
	{
		int n, size;

		for (n = 1; n < 1024; n++)
		{
			size = n * 1024;
			if ((setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size))) < 0)
				break;
		}
	}

#if DEBUG_ENABLED && DEBUG_LISTEN
	Debug("listening on %s, %s port %d", ipaddr(AF_INET, &sa->sin_addr),
			protocol == SOCK_STREAM ? "TCP" : "UDP", ntohs(sa->sin_port));
#endif

	return (fd);
}
/*--- ipv4_listener() ---------------------------------------------------------------------------*/


#if HAVE_IPV6
/**************************************************************************************************
	IPV6_LISTENER
	Create IPv6 listening socket.  Returns the new file descriptor.  Errors are fatal.
**************************************************************************************************/
static int
ipv6_listener(struct sockaddr_in6 *sa, int protocol)
{
	int fd, opt = 1;

	if ((fd = socket(AF_INET6, protocol, (protocol == SOCK_STREAM) ? IPPROTO_TCP : IPPROTO_UDP)) < 0)
		Err("socket");

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
		Warn("setsockopt");
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
	if (bind(fd, (struct sockaddr *)sa, sizeof(struct sockaddr_in6)) < 0)
		Err("bind (%s): %s+%d", (protocol == SOCK_STREAM) ? "TCP" : "UDP",
			 ipaddr(AF_INET6, &sa->sin6_addr), ntohs(sa->sin6_port));
	if (protocol == SOCK_STREAM)
	{
		if (listen(fd, 5) < 0)
			Err("listen");
	}
	else
	{
		int n, size;

		for (n = 1; n < 1024; n++)
		{
			size = n * 1024;
			if ((setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size))) < 0)
				break;
		}
	}

#if DEBUG_ENABLED && DEBUG_LISTEN
	Debug("listening on %s, %s port %d", ipaddr(AF_INET6, &sa->sin6_addr), 
			protocol == SOCK_STREAM ? "TCP" : "UDP", ntohs(sa->sin6_port));
#endif

	return (fd);
}
/*--- ipv6_listener() ---------------------------------------------------------------------------*/
#endif


/**************************************************************************************************
	CREATE_LISTENERS
**************************************************************************************************/
void
create_listeners(void)
{
	ADDRLIST	*Addresses;											/* List of available addresses */
	ADDRLIST	*Listen;												/* Listen on these addresses */
	ADDRLIST	*NoListen;											/* Don't listen on these addresses */
	ADDRLIST	*L, *N;												/* Current address */
	char		*port_opt = conf_get(&Conf, "port", 0);	/* "port" config option */
	int		port = 53;											/* Listen on this port number */

	/* Set default port number */
	if (port_opt && atoi(port_opt))
		port = atoi(port_opt);

	Addresses = addrlist_load(port);							/* Get available addresses */

#if DEBUG_ENABLED && DEBUG_LISTEN
	Debug(" ");
	for (L = Addresses; L; L = L->next)
		if (L->family == AF_INET)
			Debug("Address: %s (port %d)", ipaddr(AF_INET, &L->addr4), L->port);
#if HAVE_IPV6
		else if (L->family == AF_INET6)
			Debug("Address: %s (port %d)", ipaddr(AF_INET6, &L->addr6), L->port);
#endif
	Debug(" ");
#endif

	/* Get addresses specified in 'listen' and 'no-listen' configuration variables */
	Listen = get_opt_addrlist(Addresses, conf_get(&Conf, "listen", NULL), port, "listen");
	NoListen = get_opt_addrlist(Addresses, conf_get(&Conf, "no-listen", NULL), port, "no-listen");

#if DEBUG_ENABLED && DEBUG_LISTEN
	for (L = NoListen; L; L = L->next)
		if (L->family == AF_INET)
			Debug("NoListen: %s (port %d)", ipaddr(AF_INET, &L->addr4), L->port);
#if HAVE_IPV6
		else if (L->family == AF_INET6)
			Debug("NoListen: %s (port %d)", ipaddr(AF_INET6, &L->addr6), L->port);
#endif
	Debug(" ");
#endif

#if DEBUG_ENABLED && DEBUG_LISTEN
	for (L = Listen; L; L = L->next)
		if (L->family == AF_INET)
			Debug("Listen: %s (port %d)", ipaddr(AF_INET, &L->addr4), L->port);
#if HAVE_IPV6
		else if (L->family == AF_INET6)
			Debug("Listen: %s (port %d)", ipaddr(AF_INET6, &L->addr6), L->port);
#endif
	Debug(" ");
#endif

	/* Deactivate any 'NoListen' addresses found in 'Listen' */
	for (N = NoListen; N; N = N->next)
		for (L = Listen; L; L = L->next)
			if (L->ok && (N->family == L->family) && (N->port == L->port)
#if HAVE_IPV6
				 && !memcmp(&N->addr6, &L->addr6, sizeof(struct in6_addr))
#endif
				 && !memcmp(&N->addr4, &L->addr4, sizeof(struct in_addr)))
				L->ok = 0;

	/* Free 'Addresses' and 'NoListen'; we're done with them */
	addrlist_free(Addresses);
	addrlist_free(NoListen);

	/* Create listening socket for each address in 'Listen' */
	for (L = Listen; L; L = L->next)
	{
		if (!L->ok)
			continue;

		if (L->family == AF_INET)
		{
			struct sockaddr_in sa;

			memset(&sa, 0, sizeof(struct sockaddr_in));
			sa.sin_family = AF_INET;
			sa.sin_port = htons(L->port);
			memcpy(&sa.sin_addr, &L->addr4, sizeof(struct in_addr));

			/* Expand FD lists as appropriate and create listening sockets */
			if (!(udp4_fd = realloc(udp4_fd, (1 + num_udp4_fd) * sizeof(int))))
				Err(_("out of memory"));
			udp4_fd[num_udp4_fd++] = ipv4_listener(&sa, SOCK_DGRAM);

			if (axfr_enabled || tcp_enabled)
			{
				if (!(tcp4_fd = realloc(tcp4_fd, (1 + num_tcp4_fd) * sizeof(int))))
					Err(_("out of memory"));
				tcp4_fd[num_tcp4_fd++] = ipv4_listener(&sa, SOCK_STREAM);
			}
		}
#if HAVE_IPV6
		else if (L->family == AF_INET6)
		{
			struct sockaddr_in6 sa;

			memset(&sa, 0, sizeof(struct sockaddr_in6));
			sa.sin6_family = AF_INET6;
			sa.sin6_port = htons(L->port);
			memcpy(&sa.sin6_addr, &L->addr6, sizeof(struct in6_addr));
#if 0
			/* These two vars are part of struct sockaddr_in6, but I don't know what they are: */
			uint32_t sin6_flowinfo;   /* IPv6 flow information */
			uint32_t sin6_scope_id;   /* IPv6 scope-id */
#endif

			/* Expand FD lists as appropriate and create listening sockets */
			if (!(udp6_fd = realloc(udp6_fd, (1 + num_udp6_fd) * sizeof(int))))
				Err(_("out of memory"));
			udp6_fd[num_udp6_fd++] = ipv6_listener(&sa, SOCK_DGRAM);

			if (axfr_enabled || tcp_enabled)
			{
				if (!(tcp6_fd = realloc(tcp6_fd, (1 + num_tcp6_fd) * sizeof(int))))
					Err(_("out of memory"));
				tcp6_fd[num_tcp6_fd++] = ipv6_listener(&sa, SOCK_STREAM);
			}
		}
#endif
	}

	server_greeting();
	addrlist_free(Listen);
}
/*--- create_listeners() ------------------------------------------------------------------------*/


/**************************************************************************************************
	SERVER_GREETING
**************************************************************************************************/
static void
server_greeting(void)
{
	char	greeting[512], *g = greeting;						/* Server startup message */
	int	total;													/* Total listening sockets */
	time_t now = time(NULL);

	g += sprintf(g, "%s %s %s %.24s", progname, PACKAGE_VERSION, _("started"), ctime(&now));

	total = num_udp4_fd;
#if HAVE_IPV6
	total += num_udp6_fd;
#endif
	g += sprintf(g, " (%s %d %s)", _("listening on"),
					 total, total == 1 ? _("address") : _("addresses"));

#if DEBUG_ENABLED
	g += sprintf(g, "%s", _(" (compiled with debug)"));
#endif

	if (answer_then_quit)
		g += sprintf(g, _(" (quit after %u requests)"), answer_then_quit);

	Notice("%s", greeting);
}
/*--- server_greeting() -------------------------------------------------------------------------*/

/* vi:set ts=3: */
/* NEED_PO */
