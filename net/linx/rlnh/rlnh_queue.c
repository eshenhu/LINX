/*
 * Copyright (c) 2006-2007, Enea Software AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * Neither the name of Enea Software AB nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/***************************************************************************
 * SIGNAL QUEUE MANAGEMENT
 ***************************************************************************/

#include <rlnh/rlnh_queue.h>
#include <linx_mem.h>
#include <linux/string.h>
#include <linx_assert.h>
#include <linx_trace.h>

int rlnh_queue_init(struct RlnhObj *rlnh_obj, struct RlnhQueue *q)
{
	size_t sz = (sizeof(struct RlnhQueueNode *) *
		     (linx_max_sockets_per_link + 1));

	memset(q, 0, sizeof(struct RlnhQueue));

	q->head = linx_kmalloc(sz);
	if (unlikely(q->head == NULL)) {
		goto nomem;
	}

	q->tail = linx_kmalloc(sz);
	if (unlikely(q->tail == NULL)) {
		linx_kfree(q->head);
		goto nomem;
	}

	q->preallocated = linx_kmalloc(sizeof(*(q->preallocated)));
	if (unlikely(q->preallocated == NULL)) {
		linx_kfree(q->tail);
		linx_kfree(q->head);
		goto nomem;
	}

	memset(q->head, 0, sz);
	memset(q->tail, 0, sz);

	return 0;

      nomem:
	linx_err("LINX: out of memory.");
	return -ENOMEM;
}

void rlnh_queue_exit(struct RlnhObj *rlnh_obj, struct RlnhQueue *q)
{
	linx_kfree(q->head);
	linx_kfree(q->tail);
	linx_kfree(q->preallocated);
}

void rlnh_queue_enqueue(struct RlnhObj *rlnh_obj,
			struct RlnhQueue *q,
			uint32_t src_la,
			uint32_t dst_la,
			void *sig, size_t size, uint32_t buffer_type)
{
	LINX_ASSERT(src_la != 0);
	LINX_ASSERT(src_la <= linx_max_sockets_per_link);
	LINX_ASSERT(q != NULL);
	LINX_ASSERT(rlnh_obj != NULL);
	LINX_ASSERT(q->preallocated != NULL);
	LINX_ASSERT(sig != NULL);
	LINX_ASSERT(size >= 4);

	/* NOTE: It is not OK to LINX_ASSERT on dst_la != LINX_ILLEGAL_SPID
	 *       because of the shutdown signal. */

	q->preallocated->next = NULL;
	q->preallocated->sig = sig;
	q->preallocated->size = size;
	q->preallocated->dst_la = dst_la;
	q->preallocated->buffer_type = buffer_type;

	if (q->head[src_la] == NULL) {
		q->head[src_la] = q->preallocated;
		q->tail[src_la] = q->preallocated;
	} else {
		q->tail[src_la]->next = q->preallocated;
		q->tail[src_la] = q->preallocated;
	}

#ifdef LINX_ASSERT
	q->preallocated = NULL;
#endif
	q->preallocated = linx_kmalloc(sizeof(*(q->preallocated)));
}

struct RlnhQueueNode *rlnh_queue_get(struct RlnhQueue *q, uint32_t la)
{
	struct RlnhQueueNode *n;

	LINX_ASSERT(la <= linx_max_sockets_per_link);
	LINX_ASSERT(la != 0);

	n = q->head[la];
	q->head[la] = NULL;
	q->tail[la] = NULL;

	return n;
}

int rlnh_queue_is_empty(struct RlnhQueue *q, uint32_t la)
{
	LINX_ASSERT(la <= linx_max_sockets_per_link);
	return q->head[la] == NULL;
}
