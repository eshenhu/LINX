/*
 * Copyright (c) 2008-2009, Enea Software AB
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

#ifndef __ECM_KUTILS_H
#define __ECM_KUTILS_H

#include <linux/types.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/timer.h>

#ifndef DEFINE_SPINLOCK
#define DEFINE_SPINLOCK(x) spinlock_t x = SPIN_LOCK_UNLOCKED
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,13))
#if defined(GFP_IS_INT)
extern char *kstrdup(const char *s, int gfp);
#else
extern char *kstrdup(const char *s, unsigned int gfp);
#endif
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14))
#if defined(GFP_IS_INT)
#define gfp_t int
#else
#define gfp_t unsigned int
#endif

#ifdef ECM_KZALLOC
extern void *kzalloc(size_t size, gfp_t flags);
#endif
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15))
/* NOTE: This function is arch specfic!!!! */
#define atomic_cmpxchg(v, old, new) (cmpxchg(&((v)->counter), (old), (new)))

static inline void setup_timer(struct timer_list * timer,
                               void (*function)(unsigned long),
                               unsigned long data)
{
        timer->function = function;
        timer->data = data;
        init_timer(timer);
}
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16))
/* NOTE: This function is arch specfic!!!! */
#define atomic_xchg(v, new) (xchg(&((v)->counter), (new)))
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22))
#define list_first_entry(ptr, type, member) \
        list_entry((ptr)->next, type, member)
#endif

#endif
