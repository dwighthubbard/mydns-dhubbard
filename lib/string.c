/**************************************************************************************************
	$Id: string.c,v 1.22 2005/04/20 16:49:11 bboy Exp $

	string.c: Typical generic string manipulation routines.

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

#include "mydnsutil.h"


/**************************************************************************************************
	STRTRIMLEAD
	Remove trailing spaces, etc.
**************************************************************************************************/
char *
strtrimlead(char *str)
{
	char *obuf;

	if (str)
	{
		for (obuf = str; *obuf && isspace((int)(*obuf)); ++obuf)
			;
		if (str != obuf)
			memmove(str, obuf, strlen(obuf) + 1);
	}
	return (str);
}
/*--- strtrimlead() -----------------------------------------------------------------------------*/


/**************************************************************************************************
	STRTRIMTRAIL
**************************************************************************************************/
char *
strtrimtrail(char *str)
{
	int i;

	if (str && 0 != (i = strlen(str)))
	{
		while (--i >= 0)
		{
			if (!isspace((int)(str[i])))
				break;
		}
		str[++i] = '\0';
	}
	return (str);
}
/*--- strtrimtrail() ----------------------------------------------------------------------------*/


/**************************************************************************************************
	STRTRIM
	Removes leading and trailing whitespace from a string.  Converts tabs and newlines to spaces.
**************************************************************************************************/
char *
strtrim(char *str)
{
	strtrimlead(str);
	strtrimtrail(str);
	return (str);
}
/*--- strtrim() ---------------------------------------------------------------------------------*/


/**************************************************************************************************
	STRTOUPPER
	Converts a string to uppercase.
**************************************************************************************************/
char *
strtoupper(char *str)
{
	register char *c;

	if (!str || !*str)
		return (NULL);
	for (c = str; *c; c++)
		*c = toupper(*c);
	return (str);
}  
/*--- strtoupper() ------------------------------------------------------------------------------*/


/**************************************************************************************************
	STRTOLOWER
	Converts a string to lowercase.
**************************************************************************************************/
char *
strtolower(char *str)
{
	register char *c;

	if (!str || !*str)
		return (NULL);
	for (c = str; *c; c++)
		*c = tolower(*c);
	return (str);
}  
/*--- strtolower() ------------------------------------------------------------------------------*/


/**************************************************************************************************
	STRSECS
	Outputs a number of seconds in a more human-friendly format.
**************************************************************************************************/
char *
strsecs(time_t seconds)
{
	int weeks, days, hours, minutes;
	static char str[40];
	char *s;

	weeks = seconds / 604800; seconds -= (weeks * 604800);
	days = seconds / 86400; seconds -= (days * 86400);
	hours = seconds / 3600; seconds -= (hours * 3600);
	minutes = seconds / 60; seconds -= (minutes * 60);

	s = str;
	if (weeks) s += snprintf(s, sizeof(str) - strlen(str), "%dw", weeks);
	if (days) s += snprintf(s, sizeof(str) - strlen(str), "%dd", days);
	if (hours) s += snprintf(s, sizeof(str) - strlen(str), "%dh", hours);
	if (minutes) s += snprintf(s, sizeof(str) - strlen(str), "%dm", minutes);
	if (seconds || s == str) s += snprintf(s, sizeof(str) - strlen(str), "%ds", (int)seconds);
	return (str);
}
/*--- strsecs() ---------------------------------------------------------------------------------*/


/**************************************************************************************************
	STRDCAT
	Dynamically-allocated strcat(3).
**************************************************************************************************/
char *
strdcat(char **dest, const char *src)
{
	register int	srclen,									/* Length of src */
						destlen;									/* Length of dest */
	char				*d = *dest;								/* Ptr to dest */

	/* If we pass a length of 0 to realloc, it frees memory: just return */
	if ((srclen = strlen(src)) == 0)
		return (d);
	destlen = (d) ? strlen(d) : 0;

	/* Allocate/reallocate the storage in dest */
	if (!d)
	{
		if (!(d = malloc(destlen + srclen + 1)))
			Err("malloc");
	}
	else
	{
		if (!(d = realloc(d, destlen + srclen + 1)))
			Err("realloc");
	}

	memcpy(d + destlen, src, srclen);
	d[destlen + srclen] = '\0';

	*dest = d;
	return (d);
}
/*--- strdcat() ---------------------------------------------------------------------------------*/


/**************************************************************************************************
	SDPRINTF
	Dynamically-allocated sprintf(3).
**************************************************************************************************/
int
sdprintf(char **dest, const char *fmt, ...)
{
#if HAVE_VASPRINTF
	char	*buf = NULL;
#else
	char	buf[BUFSIZ];
#endif
	va_list ap;
	int len;

	va_start(ap, fmt);
#if HAVE_VASPRINTF
	vasprintf(&buf, fmt, ap);
	len = strlen(buf);
#else
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
#endif
	va_end(ap);

	strdcat(dest, buf);

#if HAVE_VASPRINTF
	Free(buf);
#endif
	return (len);	
}
/*--- sdprintf() --------------------------------------------------------------------------------*/


/**************************************************************************************************
	Given a string such as "10MB" returns the size represented, in bytes.
**************************************************************************************************/
size_t
human_file_size(const char *str)
{  
	size_t numeric = 0;											/* Numeric part of `str' */
	register char *c;												/* Ptr to first nonalpha char */

	numeric = (size_t)strtoul(str, (char **)NULL, 10);

	for (c = (char *)str; *c && isdigit((int)(*c)); c++)
		/* DONOTHING */;

	if (!*c)
		return (numeric);

	switch (tolower(*c))
	{
		case 'k': return (numeric * 1024);
		case 'm': return (numeric * 1048576);
		case 'g': return (numeric * 1073741824);
		default:
			break;
	}
	return (numeric);
}
/*--- human_file_size() -------------------------------------------------------------------------*/


/**************************************************************************************************
	ESCDATA
	(for debugging) Outputs a received packet.
**************************************************************************************************/
void
escdata(char *data, int len)
{
	register int n, ct;

	for (ct = 0; ct < len; ct += 8)
	{
		for (n = ct; n < ct + 8; n++)
		{
			printf("%c", n < len ? (isprint(data[n]) ? data[n] : '.') : ' ');
			if (n == ct+3)
				printf(" ");
		}
		printf("   ");
		for (n = ct; n < ct + 8 && n < len; n++)
			printf("%02x%s", data[n], (n == ct+3) ? "  " : " ");
		printf(" %d-%d %d-%d\n", ct, ct+3, ct+4, ct+7);
	}
}
/*--- escdata() ---------------------------------------------------------------------------------*/


/**************************************************************************************************
	BYTESTR
	(for debugging) Return a static string containing `byte' shown as binary.
**************************************************************************************************/
char *
bytestr(unsigned char byte)
{
	register int i, j;
	int bits = 8;
	int strwid = 9;
	static char str[80], *s;

	s = str;
	j = strwid - (bits + (bits >> 2)- (bits % 4 ? 0 : 1));
	for (i = 0; i < j; i++)
		*s++ = ' ';
	while (--bits >= 0)
	{
		*s++ = ((byte >> bits) & 1) + '0';
		if (!(bits % 4) && bits)
			*s++ = ' ';
	}
	*s = '\0';
	return (str);
}
/*--- bytestr() ---------------------------------------------------------------------------------*/


/**************************************************************************************************
	ESCSTR
	(for debugging)
**************************************************************************************************/
char *
escstr(char *str, size_t len)
{
	static char buf[BUFSIZ];
	register char *s, *d;

	for (s = str, d = buf; s < str + len; s++)
		*(d++) = (isprint(*s)) ? *s : '?';
	return ((char *)buf);
}
/*--- escstr() ----------------------------------------------------------------------------------*/


/**************************************************************************************************
	COMMAFMT
	Copies the numeric value of N into buffer 'buf' of size 'bufsiz', inserting commas where
	appropriate.
**************************************************************************************************/
static size_t
commafmt(char *buf, size_t bufsiz, unsigned long N)
{
	unsigned int len = 1, posn = 1;
	char *ptr = buf + bufsiz - 1;

	if (bufsiz < 2)
	{
		*buf = '\0';
		return 0;
	}
	*ptr-- = '\0';
	--bufsiz;
	for ( ; len <= bufsiz; ++len, ++posn)
	{
		*ptr-- = (char)((N % 10L) + '0');
		if (0L == (N /= 10L))
			break;
		if (0 == (posn % 3))
		{
			*ptr-- = ',';
			++len;
		}
		if (len >= bufsiz)
		{
			*buf = '\0';
			return 0;
		}
	}
	strcpy(buf, ++ptr);
	return (size_t)len;
}
/*--- commafmt() --------------------------------------------------------------------------------*/


/**************************************************************************************************
	COMMA1-3
	Making printf life easy for Don at the expense of repetition and a few hundred bytes of RAM.
**************************************************************************************************/
char *comma(unsigned long num)
{ static char cbuf[81];  commafmt(cbuf, 80, num); return (cbuf); }
char *comma1(unsigned long num)
{ static char cbuf[81];  commafmt(cbuf, 80, num); return (cbuf); }
char *comma2(unsigned long num)
{ static char cbuf[81];  commafmt(cbuf, 80, num); return (cbuf); }
char *comma3(unsigned long num)
{ static char cbuf[81];  commafmt(cbuf, 80, num); return (cbuf); }
/*--- comma1-3() --------------------------------------------------------------------------------*/



/* vi:set ts=3: */
