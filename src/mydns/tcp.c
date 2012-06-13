/**************************************************************************************************
	$Id: tcp.c,v 1.47 2005/04/20 17:30:38 bboy Exp $

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
#define	DEBUG_TCP	1


/**************************************************************************************************
	ACCEPT_TCP_QUERY
**************************************************************************************************/
int
accept_tcp_query(int fd, int family)
{
	struct sockaddr_in addr4;
#if HAVE_IPV6
	struct sockaddr_in6 addr6;
#endif
	socklen_t	addrlen;
	int			rmt_fd;
	TASK			*t;

#if HAVE_IPV6
	if (family == AF_INET6)
	{
	 	addrlen = sizeof(struct sockaddr_in6);
		if ((rmt_fd = accept(fd, (struct sockaddr *)&addr6, &addrlen)) < 0)
		{
			return Warn("%s", _("accept (TCPv6)"));
		}
		fcntl(rmt_fd, F_SETFL, fcntl(rmt_fd, F_GETFL, 0) | O_NONBLOCK);
		if (!(t = task_init(NEED_READ, rmt_fd, SOCK_STREAM, AF_INET6, &addr6)))
			return (-1);
	}
	else
#endif
	{
	 	addrlen = sizeof(struct sockaddr_in);
		if ((rmt_fd = accept(fd, (struct sockaddr *)&addr4, &addrlen)) < 0)
		{
			return Warn("%s", _("accept (TCP)"));
		}
		fcntl(rmt_fd, F_SETFL, fcntl(rmt_fd, F_GETFL, 0) | O_NONBLOCK);
		if (!(t = task_init(NEED_READ, rmt_fd, SOCK_STREAM, AF_INET, &addr4)))
			return (-1);
	}

#if DEBUG_ENABLED && DEBUG_TCP
	Debug("%s: TCP connection accepted", clientaddr(t));
#endif

	return 0;
}
/*--- accept_tcp_query() ------------------------------------------------------------------------*/


/**************************************************************************************************
	READ_TCP_LENGTH
	The first two octets of a TCP question are the length.  Read them.
	Returns 0 on success, -1 on failure.
**************************************************************************************************/
static int
read_tcp_length(TASK *t)
{
	int	rv;
	char	len[2];

	if ((rv = recv(t->fd, len, 2, 0)) != 2)
	{
		if (rv < 0)
		{
			if (errno == EAGAIN)
				return (0);
			if (errno != ECONNRESET)
				Warn("%s: %s", clientaddr(t), _("recv (length) (TCP)"));
			return (-1);
		}
		if (rv == 0)
			return (-1);
		return Warnx("%s: %s", clientaddr(t), _("TCP message length invalid"));
	}

	if ((t->len = ((len[0] << 8) | (len[1]))) < DNS_HEADERSIZE)
		return Warnx("%s: %s (%d octet%s)", clientaddr(t), _("TCP message too short"), t->len, S(t->len));
	if (t->len > DNS_MAXPACKETLEN_TCP)
		return Warnx("%s: %s (%d octet%s)", clientaddr(t), _("TCP message too long"), t->len, S(t->len));

	if (!(t->query = calloc(1, t->len + 1)))
		Err(_("out of memory"));
	t->offset = 0;
	return (0);
}
/*--- read_tcp_length() -------------------------------------------------------------------------*/


/**************************************************************************************************
	READ_TCP_QUERY
	Returns 0 on success, -1 on failure.
**************************************************************************************************/
int
read_tcp_query(TASK *t)
{
	unsigned char *end;
	int rv;

	/* Read packet length if we haven't already */
	if (!t->len)
		return read_tcp_length(t);

	end = t->query + t->len;

	/* Read whatever data is ready */
	if ((rv = recv(t->fd, t->query + t->offset, t->len - t->offset, 0)) < 0)
		return Warn("%s: %s", clientaddr(t), _("recv (TCP)"));
	if (!rv)
		return (-1);	/* Client closed connection */

#if DEBUG_ENABLED && DEBUG_TCP
	Debug("%s: 2+%d TCP octets in", clientaddr(t), rv);
#endif

	t->offset += rv;
	if (t->offset > t->len)
		return Warnx("%s: %s", clientaddr(t), _("TCP message data too long"));
	if (t->offset < t->len)
		return 0;													/* Not finished reading */
	t->offset = 0;													/* Reset offset for writing reply */

	return new_task(t, t->query, t->len);
}
/*--- read_tcp_query() --------------------------------------------------------------------------*/


/**************************************************************************************************
	WRITE_TCP_LENGTH
	Writes the length octets for TCP reply.  Returns 0 on success, -1 on failure.
**************************************************************************************************/
static int
write_tcp_length(TASK *t)
{
	char	len[2], *l;
	int	rv;

	l = len;
	DNS_PUT16(l, t->replylen);

	if ((rv = write(t->fd, len + t->offset, SIZE16 - t->offset)) < 0)
	{
		if (errno == EINTR)
			return 0;
		return Warn("%s: %s", clientaddr(t), _("write (length) (TCP)"));
	}
	if (!rv)
		return (-1);		/* Client closed connection */
	t->offset += rv;
	if (t->offset >= SIZE16)
	{
		t->len_written = 1;
		t->offset = 0;
	}
	return 0;
}
/*--- write_tcp_length() ------------------------------------------------------------------------*/


/**************************************************************************************************
	WRITE_TCP_REPLY
	Returns 0 on success, -1 on error.  If -1 is returned, the task is no longer valid.
**************************************************************************************************/
int
write_tcp_reply(TASK *t)
{
	int rv, rmt_fd;
	struct sockaddr_in addr4;
#if HAVE_IPV6
	struct sockaddr_in6 addr6;
#endif

	/* Write TCP length if we haven't already */
	if (!t->len_written)
	{
		if (write_tcp_length(t) < 0)
		{
			dequeue(Tasks, t);
			return (-1);
		}
		return (0);
	}

	/* Write the reply */
	if ((rv = write(t->fd, t->reply + t->offset, t->replylen - t->offset)) < 0)
	{
		if (errno == EINTR)
			return (0);
		dequeue(Tasks, t);
		return Warn("%s: %s", clientaddr(t), _("write (TCP)"));
	}
	if (!rv)
	{
		dequeue(Tasks, t);
		return (-1);												/* Client closed connection */
	}
	t->offset += rv;
	if (t->offset < t->replylen)
		return (0);													/* Not finished yet... */

	/* Task complete; reset.  The TCP client must be able to perform multiple queries on
		the same connection (BIND8 AXFR does this for sure) */
#if HAVE_IPV6
	if (t->family == AF_INET6)
	{
		memcpy(&addr6, &t->addr6, sizeof(struct sockaddr_in6));
		rmt_fd = t->fd;
		dequeue(Tasks, t);

		/* Reinitialize to allow multiple queries on TCP */
		if (!(t = task_init(NEED_READ, rmt_fd, SOCK_STREAM, AF_INET6, &addr6)))
			return (-2);
	}
	else
#endif
	{
		memcpy(&addr4, &t->addr4, sizeof(struct sockaddr_in));
		rmt_fd = t->fd;
		dequeue(Tasks, t);

		/* Reinitialize to allow multiple queries on TCP */
		if (!(t = task_init(NEED_READ, rmt_fd, SOCK_STREAM, AF_INET, &addr4)))
			return (-2);
	}
	return (0);
}
/*--- write_tcp_reply() -------------------------------------------------------------------------*/

/* vi:set ts=3: */
/* NEED_PO */
