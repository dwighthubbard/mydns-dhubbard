/**************************************************************************************************
	$Id: udp.c,v 1.41 2005/04/20 16:49:12 bboy Exp $

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
#define	DEBUG_UDP	1


/**************************************************************************************************
	READ_UDP_QUERY
	Returns 0 on success (a task was added), -1 on failure.
**************************************************************************************************/
int
read_udp_query(int fd, int family)
{
	struct sockaddr_in addr4;
#if HAVE_IPV6
	struct sockaddr_in6 addr6;
#endif
	char			in[DNS_MAXPACKETLEN_UDP];
	socklen_t 	addrlen;
	int			len;
	TASK			*t;

	/* Read message */
#if HAVE_IPV6
	if (family == AF_INET6)
	{
		addrlen = sizeof(addr6);
		memset(&in, 0, sizeof(in));
		if ((len = recvfrom(fd, &in, sizeof(in), 0, (struct sockaddr *)&addr6, &addrlen)) <= 0)
		{
			if (len == 0)
				return (-1);
			if (errno == EAGAIN)
				return (0);
			return Warn("%s", _("recvfrom (UDPv6)"));
		}
		if (!(t = task_init(NEED_ANSWER, fd, SOCK_DGRAM, AF_INET6, &addr6)))
			return (-1);
	}
	else
#endif
	{
		addrlen = sizeof(addr4);
		memset(&in, 0, sizeof(in));
		if ((len = recvfrom(fd, &in, sizeof(in), 0, (struct sockaddr *)&addr4, &addrlen)) <= 0)
		{
			if (len == 0)
				return (-1);
			if (errno == EAGAIN)
				return (0);
			return Warn("%s", _("recvfrom (UDP)"));
		}
		if (!(t = task_init(NEED_ANSWER, fd, SOCK_DGRAM, AF_INET, &addr4)))
			return (-1);
	}
#if DEBUG_ENABLED && DEBUG_UDP
	Debug("%s: %d %s", clientaddr(t), len, _("UDP octets in"));
#endif
	return new_task(t, in, len);
}
/*--- read_udp_query() --------------------------------------------------------------------------*/


/**************************************************************************************************
	WRITE_UDP_REPLY
**************************************************************************************************/
void
write_udp_reply(TASK *t)
{
	int rv;

#if HAVE_IPV6
	if (t->family == AF_INET6)
		rv = sendto(t->fd, t->reply, t->replylen, 0, (struct sockaddr *)&t->addr6, sizeof(t->addr6));
	else
#endif
		rv = sendto(t->fd, t->reply, t->replylen, 0, (struct sockaddr *)&t->addr4, sizeof(t->addr4));

	if (rv < 0)
	{
		if (errno != EPERM && errno != EINVAL)
			Warn("%s: %s", desctask(t), _("sendto (UDP)"));
		return dequeue(Tasks, t);
	}

	/* Task complete; dequeue */
#if DEBUG_ENABLED && DEBUG_UDP
	Debug("%s: WRITE %u UDP octets (id %u)", desctask(t), t->replylen, t->id);
#endif
	return dequeue(Tasks, t);
}
/*--- write_udp_reply() -------------------------------------------------------------------------*/

/* vi:set ts=3: */
/* NEED_PO */
