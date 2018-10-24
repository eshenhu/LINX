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

#ifndef __RLNH_QUEUE_H__
#define __RLNH_QUEUE_H__

#include <stddef.h>
#include <af_linx.h>

struct RlnhQueueNode {
	struct RlnhQueueNode *next;
	void *sig;
	size_t size;
	uint32_t dst_la;
	uint32_t buffer_type;
};

struct RlnhQueue {
	struct RlnhQueueNode **head;
	struct RlnhQueueNode **tail;
	struct RlnhQueueNode *preallocated;
	void *lock_handle;
};

struct RlnhObj;

int rlnh_queue_init(struct RlnhObj *rlnh_obj, struct RlnhQueue *q);

void rlnh_queue_exit(struct RlnhObj *rlnh_obj, struct RlnhQueue *q);

void
rlnh_queue_enqueue(struct RlnhObj *rlnh_obj,
		   struct RlnhQueue *q,
		   uint32_t src_la,
		   uint32_t dst_la,
		   void *sig, size_t size, uint32_t buffer_type);

struct RlnhQueueNode *rlnh_queue_get(struct RlnhQueue *q, uint32_t la);

int rlnh_queue_is_empty(struct RlnhQueue *q, uint32_t la);

#endif
