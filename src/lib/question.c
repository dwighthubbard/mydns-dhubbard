/**************************************************************************************************
	$Id: question.c,v 1.6 2005/03/22 17:44:56 bboy Exp $

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

#include "mydns.h"

/* Set this to nonzero to enable debugging for this source file */
#define	QUESTION_DEBUG	1


/**************************************************************************************************
	DNS_MAKE_QUESTION
	Make a DNS query packet with the specified attributes.
	Returns a pointer to static data containing the question or NULL on error.
	Sets 'length' to the length of the question packet.
**************************************************************************************************/
char *
dns_make_question(uint16_t id, dns_qtype_t qtype, char *name, int rd, size_t *length)
{
	static char	req[1024];										/* Request buffer */
	char	*dest;													/* Current destination in 'req' */
	DNS_HEADER	header;											/* DNS header */
	char *mark;														/* Location of last label separator */
	register int labels = 0;									/* Number of labels found */
	register char *c;

	dest = req;
	if (length)
		*length = 0;
	if (!name)
	{
		if (length) *length = (int)ERR_MALFORMED_REQUEST;
		return (NULL);
	}

	memset(&header, 0, sizeof(DNS_HEADER));
	DNS_PUT16(dest, id);											/* ID */
	header.rd = rd;												/* Recursion desired? */
	memcpy(dest, &header, sizeof(DNS_HEADER)); dest += SIZE16;
	DNS_PUT16(dest, 1);											/* QDCOUNT */
	DNS_PUT16(dest, 0);											/* ANCOUNT */
	DNS_PUT16(dest, 0);											/* NSCOUNT */
	DNS_PUT16(dest, 0);											/* ARCOUNT */

	for (mark = dest++, c = name; *c; c++)					/* QNAME */
	{
		if ((c - name) > DNS_MAXNAMELEN)
		{
			if (length) *length = (int)ERR_Q_NAME_TOO_LONG;
			return NULL;											/* Name too long */
		}
		if (*c != '.')												/* Append current character */
			*dest++ = *c;
		if (mark && (*c == '.' || !c[1]))					/* Store current label length at 'mark' */
		{
			if ((*mark = dest - mark - 1) > DNS_MAXLABELLEN)
			{
				if (length) *length = (int)ERR_Q_LABEL_TOO_LONG;
				return NULL;	/* Label too long */
			}
			mark = dest++;
			labels++;
		}
		if (*c == '.' && !c[1])									/* Is this the end? */
		{
			*mark = 0;
			break;
		}
	}
	DNS_PUT16(dest, (uint16_t)qtype);						/* QTYPE */
	DNS_PUT16(dest, DNS_CLASS_IN);							/* QCLASS */

	if (length)
		*length = dest - req;

	return (req);
}
/*--- dns_make_question() -----------------------------------------------------------------------*/

/* vi:set ts=3: */
