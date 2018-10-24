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

/*
 * Linux kernel version dependencies
 */

#ifndef __LINX_COMPAT_H__
#define __LINX_COMPAT_H__

#include <linux/version.h>
#include <net/sock.h>

#if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,9))
/* This is needed because of a type-o in spinlock.h where
   rw_lock_t should be rwlock_t */
#ifdef DEFINE_RWLOCK
#undef DEFINE_RWLOCK
#endif
#define DEFINE_RWLOCK(x)	rwlock_t x = RW_LOCK_UNLOCKED
#endif

static inline struct sock *sk_alloc_compat(void *net, int pf, int prio,
					   void *sk_cachep)
{
#ifdef SK_ALLOC_COMPAT
	static struct proto prot = {.name = "PF_LINX",
		.owner = THIS_MODULE,
		.obj_size = sizeof(struct sock),
	};
	prot.slab = sk_cachep;
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
	return sk_alloc(pf, prio, &prot, 1);
#else
	return sk_alloc(net, pf, prio, &prot);
#endif
#else
	return sk_alloc(pf, prio, 1, sk_cachep);
#endif
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11))
#define sk_set_owner_compat(sk, owner) sk_set_owner(sk, owner);
#else
#define sk_set_owner_compat(sk, owner)
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14))
#define __skb_unlink_compat(skb, sk) \
  do { __skb_unlink(skb, skb->list); } while(0)
#else
#define __skb_unlink_compat(skb, sk) \
  do { __skb_unlink(skb, &sk->sk_receive_queue); } while(0)
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23))
#define kmem_cache_create_compat(_name, _size, _align, _flags, _ctor, _dtor) \
  kmem_cache_create((_name), (_size), (_align), (_flags), (_ctor), (_dtor))
#else
#define kmem_cache_create_compat(_name, _size, _align, _flags, _ctor, _dtor) \
  kmem_cache_create((_name), (_size), (_align), (_flags), (_ctor))
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15))
/* NOTE: This function is arch specfic!!!! */
#define atomic_cmpxchg(v, old, new) (cmpxchg(&((v)->counter), (old), (new)))
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16))
/* NOTE: This function is arch specfic!!!! */
#define atomic_xchg(v, new) (xchg(&((v)->counter), (new)))
#endif

#endif
