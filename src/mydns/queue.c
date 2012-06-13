/**************************************************************************************************
	$Id: queue.c,v 1.33 2005/04/20 16:49:12 bboy Exp $

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
#define	DEBUG_QUEUE	1


/**************************************************************************************************
	QUEUE_INIT
	Creates a new queue and returns a pointer to it.
**************************************************************************************************/
QUEUE *
queue_init(void)
{
	QUEUE *q;

	if (!(q = malloc(sizeof(QUEUE))))
		Err(_("out of memory"));
	q->size = 0;
	q->head = q->tail = (TASK *)NULL;
	return (q);
}
/*--- queue_init() ------------------------------------------------------------------------------*/


/**************************************************************************************************
	_ENQUEUE
	Enqueues a TASK item, appending it to the end of the list.
**************************************************************************************************/
int
_enqueue(QUEUE *q, TASK *t, const char *file, unsigned int line)
{
	t->next = t->prev = NULL;

	/* If there's no head of the list, make this the head.  Otherwise, do nothing */
	if (!q->head)
		q->head = t;
	else
	{
		q->tail->next = t;
		t->prev = q->tail;
	}
	q->tail = t;

	q->size++;

	t->len = 0;														/* Reset TCP packet len */

	if (t->protocol == SOCK_STREAM)
		Status.tcp_requests++;
	else
		Status.udp_requests++;

#if DEBUG_ENABLED && DEBUG_QUEUE
	Debug("%s: enqueued (by %s:%u)", desctask(t), file, line);
#endif

	return (0);
}
/*--- _enqueue() --------------------------------------------------------------------------------*/


/**************************************************************************************************
	_DEQUEUE
	Removes the item specified from the queue.  Pass this a pointer to the actual element in the
	queue.
	For `error' pass 0 if the task was dequeued due to sucess, 1 if dequeued due to error.
**************************************************************************************************/
void
_dequeue(QUEUE *q, TASK *t, const char *file, unsigned int line)
{
#if DEBUG_ENABLED && DEBUG_QUEUE
	Debug("%s: dequeued (by %s:%u)", desctask(t), file, line);
#endif
	if (err_verbose)											/* Output task info if being verbose */
		task_output_info(t, NULL);

	if (t->hdr.rcode < MAX_RESULTS)						/* Store results in stats */
		Status.results[t->hdr.rcode]++;

	if (t == q->head)											/* Item is head of list */
	{
		q->head = t->next;
		if (q->head == NULL)
			q->tail = NULL;
		else if (t->next)
			t->next->prev = NULL;
	}
	else															/* Item is not head of list */
	{
		if (t->prev)
			t->prev->next = t->next;
		if (t->next == NULL)
			q->tail = t->prev;
		else
			t->next->prev = t->prev;
	}
	q->size--;

	task_free(t);
}
/*--- _dequeue() --------------------------------------------------------------------------------*/

/* vi:set ts=3: */
