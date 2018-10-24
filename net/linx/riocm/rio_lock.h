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

#ifndef __RIO_LOCK_H__
#define __RIO_LOCK_H__

#include <asm/atomic.h>
#include <linux/wait.h>
#include <linux/sched.h>

#include <rio_kutils.h>

/*
 * First, some functions inspired by atomic_add_unless()...
 */

/*
 * atomic_positive_inc() - if v is positive, increment v and return true.
 */
static inline int atomic_positive_inc(atomic_t *v)
{
	int c, old;

	c = atomic_read(v);
	for (;;) {
		if (unlikely(c <= 0))
			break;
		old = atomic_cmpxchg(v, c, c + 1);
		if (likely(old == c))
			break;
		c = old;
	}
	return c > 0;
}

/*
 * A synchronization mechanism base on an atomic variable and a waitqueue.
 */
struct rio_lock {
        atomic_t count;
        wait_queue_head_t waitq;
};

static inline void init_rio_lock(struct rio_lock *lock, int v)
{
        atomic_set(&lock->count, v);
        init_waitqueue_head(&lock->waitq);
}

static inline void reset_rio_lock(struct rio_lock *lock, int v)
{
        if (waitqueue_active(&lock->waitq))
                BUG();

        atomic_set(&lock->count, v);
}

static inline int rio_trylock(struct rio_lock *lock)
{
        return atomic_positive_inc(&lock->count);
}

static inline void rio_unlock(struct rio_lock *lock)
{
        if (atomic_add_negative(-1, &lock->count))
                wake_up_interruptible_sync(&lock->waitq);
}

static inline void synchronize_rio_lock(struct rio_lock *lock)
{
        int k;

        k = atomic_xchg(&lock->count, 0) - 1;        
        if (k <= 0)
                return;
        /*
         * Hmm, we should check return value, but the problem is what to do
         * if -ERESTARTSYS is returned! Use wait_event() instead?
         */
        wait_event_interruptible(lock->waitq, atomic_read(&lock->count) == -k);
}

#endif
