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
 * Handle tmo.
 */

#include <af_linx.h>
#include <ipc/tmo.h>
#include <ipc/rlnh.h>
#include <linx_assert.h>
#include <linx_mem.h>
#include <linux/linx_types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linx_compat.h>
#include <linx_trace.h>
#include <net/sock.h>
#include <rlnh.h>
#include <buf_types.h>

#ifndef DEFINE_SPINLOCK
#define DEFINE_SPINLOCK(x)	spinlock_t x = SPIN_LOCK_UNLOCKED
#endif

#define LINX_OSTMOREF_INDEX_MASK       (linx_max_tmorefs - 1)
#define LINX_OSTMOREF_INSTANCE_MASK    (~(LINX_OSTMOREF_INDEX_MASK))
#define LINX_OSTMOREF_INDEX(tmoref)    ((tmoref) & (LINX_OSTMOREF_INDEX_MASK))
#define LINX_OSTMOREF_INSTANCE(tmoref) \
        ((tmoref) & (LINX_OSTMOREF_INSTANCE_MASK))
#define LINX_OSTMOREF_INSTANCE_INC(tmoref) ((tmoref) + (linx_max_tmorefs))

/* A lock that allow exclusive access to the pending tmo lists. */
DEFINE_SPINLOCK(pend_tmo_lock);

extern atomic_t linx_no_of_pend_tmo;
extern atomic_t linx_no_of_queued_signals;

#define MAGIC_PEND_TMO 0xAC3FFAC3

/* A data structure that hold information about a pending tmo. */
struct pend_tmo {
	uint32_t magic;		/* MAGIC_PEND_TMO */
	struct list_head timeouts;	/* List of timouts for one socket. */
	LINX_SPID spid;		/* The process requesting tmo. */
	LINX_OSBUFSIZE sigsize;	/* The size of the tmo signal. */
	struct sk_buff *skb;	/* A sent tmo signal pointer. */
	struct timer_list timer;	/* The timeout */
	uint16_t index;		/*  */
};

struct pend_tmo_entry {
	void *pt;
	LINX_OSTMOREF tmoref;
};

struct pend_tmo_entry *pt_free_list;
struct pend_tmo_entry *pt_free_list_end;
struct pend_tmo_entry *pt_array;

static inline LINX_OSTMOREF __pt_to_tmoref(struct pend_tmo *pt)
{
	struct pend_tmo_entry *pte;

	pte = &pt_array[pt->index];
	return pte->tmoref;
}

static inline struct pend_tmo *__tmoref_to_pt(LINX_OSTMOREF tmoref)
{
	struct pend_tmo_entry *pte;

	pte = &pt_array[LINX_OSTMOREF_INDEX(tmoref)];
	if (pte->tmoref != tmoref)
		return NULL;
	else if (pte->pt == NULL)
		return NULL;
	else if (((struct pend_tmo *)pte->pt)->magic != MAGIC_PEND_TMO)
		return NULL;
	else
		return pte->pt;
}

int linx_init_tmoref_array(void)
{
	int i;

	pt_array = linx_vmalloc(sizeof(*pt_array) * linx_max_tmorefs);
	if (unlikely(!pt_array)) {
		return -ENOMEM;
	}

	spin_lock_bh(&pend_tmo_lock);

	pt_free_list = pt_array;
	pt_free_list_end = &pt_array[linx_max_tmorefs - 1];
	for (i = 0; i < linx_max_tmorefs - 1; i++) {
		pt_array[i].pt = &pt_array[i + 1];
		pt_array[i].tmoref = LINX_OSTMOREF_INSTANCE_INC(i);
	}
	pt_free_list_end->pt = NULL;
	pt_free_list_end->tmoref =
	    LINX_OSTMOREF_INSTANCE_INC(LINX_OSTMOREF_INDEX_MASK);
	spin_unlock_bh(&pend_tmo_lock);

	return 0;
}

void linx_exit_tmoref_array(void)
{
	linx_vfree(pt_array);
}

/*
 *
 * Pending tmo utilities
 *
 */

/* Check a pend_tmo structure for errors. */
static inline void __check_pend_tmo(struct pend_tmo *pt)
{
	if (pt != NULL) {
		LINX_ASSERT(pt->magic == MAGIC_PEND_TMO);
		LINX_ASSERT(pt->spid != LINX_ILLEGAL_SPID);
	}
}

static struct sk_buff *__release_tmoref(struct pend_tmo *pt)
{
	struct pend_tmo_entry *pte;
	struct sk_buff *skb = NULL;

	LINX_ASSERT(pt);

	pte = &pt_array[pt->index];

	LINX_ASSERT(pte);

	if (LINX_OSTMOREF_INSTANCE(pte->tmoref) == LINX_OSTMOREF_INSTANCE_MASK)
		/* Tmoref has reached max instance number, wrap to 0. */
		pte->tmoref = LINX_OSTMOREF_INDEX(pte->tmoref);

	/* Add one to the instance number. */
	pte->tmoref = LINX_OSTMOREF_INSTANCE_INC(pte->tmoref);
	if (pt_free_list != NULL) {
		pt_free_list_end->pt = pte;
		pt_free_list_end = pte;
		pte->pt = NULL;
	} else {
		pt_free_list = pte;
		pt_free_list_end = pte;
		pte->pt = NULL;
	}

	pt->magic = 0;

	skb = pt->skb;
	pt->skb = NULL;
	
	LINX_ASSERT(skb->sk != NULL);
	spin_lock_bh(&skb->sk->sk_receive_queue.lock);
	/* Check if the tmo signal was sent to the timeouter, if so
	 * unlink it from the timeouters queue. */
	if ((skb->next != NULL) && (skb->prev != NULL)) {
		atomic_dec(&linx_no_of_queued_signals);
		__skb_unlink_compat(skb, skb->sk);
	}
	spin_unlock_bh(&skb->sk->sk_receive_queue.lock);
	LINX_ASSERT(skb->next == NULL);
	LINX_ASSERT(skb->prev == NULL);
	
	linx_kfree(pt);

	return skb;
}

static inline struct sk_buff *__linx_free_pend_tmo(LINX_OSTMOREF tmoref)
{
	struct pend_tmo *pt;
	struct sk_buff *skb;

	pt = __tmoref_to_pt(tmoref);

	if (pt == NULL)
		return NULL;

	list_del(&pt->timeouts);
	skb = __release_tmoref(pt);
	atomic_dec(&linx_no_of_pend_tmo);

	return skb;
}

void linx_free_pend_tmo(LINX_OSTMOREF tmoref)
{
	struct sk_buff *skb;
	struct pend_tmo *pt;
	spin_lock_bh(&pend_tmo_lock);
	pt = __tmoref_to_pt(tmoref);
        spin_unlock_bh(&pend_tmo_lock);
	if (pt == NULL)
                return;

	del_timer_sync(&pt->timer);        

	spin_lock_bh(&pend_tmo_lock);
	list_del(&pt->timeouts);
	skb = __release_tmoref(pt);
	atomic_dec(&linx_no_of_pend_tmo);
	spin_unlock_bh(&pend_tmo_lock);

	kfree_skb(skb);
}

void linx_remove_timeouts(struct sock *sk)
{
	struct list_head *p, *q;

	linx_check_sock(sk);

	list_for_each(p, &linx_sk(sk)->timeouts) {
		struct pend_tmo *pt;
		pt = list_entry(p, struct pend_tmo, timeouts);
                del_timer_sync(&pt->timer);
        }

	spin_lock_bh(&pend_tmo_lock);
	list_for_each_safe(p, q, &linx_sk(sk)->timeouts) {
		struct pend_tmo *pt;
		LINX_OSTMOREF tmoref;
		struct sk_buff *skb;

		pt = list_entry(p, struct pend_tmo, timeouts);
		tmoref = __pt_to_tmoref(pt);
		skb = __linx_free_pend_tmo(tmoref);
		kfree_skb(skb);
	}
	spin_unlock_bh(&pend_tmo_lock);
}

/* Callback when a timeout fires. */
static void linx_trigger_tmo(unsigned long data)
{
	struct pend_tmo *pt = (struct pend_tmo *)data;
	struct sock *sk = linx_spid_to_sock(pt->spid);
	LINX_OSTMOREF tmoref;
	int rv;
	
	if(sk == NULL)
		ERROR(); /* sock_hold should have prevented this */

	linx_check_sock(sk);
	
	spin_lock_bh(&pend_tmo_lock);

	tmoref = __pt_to_tmoref(pt);

	rv = __linx_do_sendmsg_skb_to_local_sk(sk, pt->skb, pt->sigsize, sk,
					  pt->spid, linx_free_pend_tmo, tmoref);
	
	spin_unlock_bh(&pend_tmo_lock);

	if (rv < 0) {
		linx_skb_queue_purge(sk, &sk->sk_receive_queue);
	}
	
	sock_put(sk);
}

/* Allocate and initialize a pending tmo structure. */
static inline struct pend_tmo *create_pend_tmo(struct sock *sk,
					       LINX_OSBUFSIZE sigsize,
					       LINX_OSTIME tmo)
{
	struct pend_tmo *pt;

	/* Alloc memory for pending timeout structure and timeout signal. */
	pt = linx_kmalloc(sizeof(*pt));
	if (unlikely(pt == NULL)) {
		return NULL;
	}

	/* Initialize pending timeout structure. */
	pt->sigsize = sigsize;
	pt->skb = NULL;
	pt->magic = MAGIC_PEND_TMO;
	INIT_LIST_HEAD(&pt->timeouts);
	init_timer(&pt->timer);
	/* We must sleep at least tmo ms, since ther's been a while
	 * since jiffies was incremented the last time we must add 1
	 * extra tick to make sure we don't return too eraly. */
	pt->timer.expires = jiffies + msecs_to_jiffies(tmo + 1);
	pt->timer.data = (unsigned long)pt;
	pt->timer.function = linx_trigger_tmo;

	return pt;
}

/* Store a pending timeout in the pending timeout list. */
static inline int __allocate_tmoref(struct pend_tmo *pt)
{
	struct pend_tmo_entry *pte;

	__check_pend_tmo(pt);

	if (pt_free_list == NULL) {
		return LINX_ILLEGAL_TMOREF;
	}

	pte = pt_free_list;
	pt_free_list = pt_free_list->pt;
	if (pt_free_list == NULL)
		pt_free_list_end = NULL;

	pte->pt = pt;
	pt->index = LINX_OSTMOREF_INDEX(pte->tmoref);
	atomic_inc(&linx_no_of_pend_tmo);

	return pte->tmoref;
}

int
linx_request_tmo(struct sock *sk,
		 LINX_OSTIME tmo,
		 void *sig, LINX_OSBUFSIZE sigsize, LINX_OSTMOREF * tmoref)
{
	int err = 0;
	struct pend_tmo *pt = NULL;
	struct linx_skb_cb *cb;
	LINX_SPID spid = linx_sock_to_spid(sk);
	LINX_SIGSELECT default_signo = LINX_OS_TMO_SIG;

	linx_check_sock(sk);

	LINX_ASSERT(sk != LINX_ILLEGAL_SPID);
	LINX_ASSERT(!(sigsize == 0 && sig != NULL));
	LINX_ASSERT(!(sigsize != 0 && sig == NULL));
	LINX_ASSERT(tmoref != NULL);

	/* If user didn't provide a signal, use default. */
	if (sigsize == 0) {
		sigsize = sizeof(LINX_SIGSELECT);
	}

	/* Allocate pending tmo. */
	pt = create_pend_tmo(sk, sigsize, tmo);
	if (pt == NULL) {
		err = -ENOMEM;
		goto linx_tmo_failed;
	}

	pt->spid = linx_sock_to_spid(sk);
	LINX_ASSERT(pt->spid != LINX_ILLEGAL_SPID);

	/* Prepare the tmo signal. */
	if (sig != NULL) {
		err = linx_skb_create(sig, pt->sigsize, sk,
				      BUFFER_TYPE_USER, &pt->skb,
				      linx_mem_frag);
		if (err != 0)
			goto linx_tmo_failed;
		cb = (struct linx_skb_cb *)(pt->skb->cb);
		get_user(cb->signo, (LINX_SIGSELECT *)sig);
	} else {
		err = linx_skb_create(&default_signo, pt->sigsize, sk,
				      BUFFER_TYPE_KERNEL, &pt->skb, 0);
		if(err != 0)
			goto linx_tmo_failed;
		cb = (struct linx_skb_cb *)(pt->skb->cb);
		cb->signo = default_signo;
	}

	/* Prevent cancelation / modify of pending tmos during the
	 * adding of the pending tmo. */
	spin_lock_bh(&pend_tmo_lock);

	if ((*tmoref = __allocate_tmoref(pt)) == LINX_ILLEGAL_TMOREF) {
		err = -ENOMEM;
		goto linx_tmo_failed_unlock;
	}

	if (tmo == 0) {
		int rv;
		LINX_ASSERT(linx_sk(sk)->type != LINX_TYPE_REMOTE);
		list_add_tail(&pt->timeouts, &linx_sk(sk)->timeouts);

		rv = __linx_do_sendmsg_skb_to_local_sk(sk, pt->skb, sigsize, sk,
						  spid, linx_free_pend_tmo,
						  *tmoref);

		spin_unlock_bh(&pend_tmo_lock);

		if (rv < 0) {
			linx_skb_queue_purge(sk, &sk->sk_receive_queue);
		}		
	} else {
		add_timer(&pt->timer);
		list_add_tail(&pt->timeouts, &linx_sk(sk)->timeouts);
		spin_unlock_bh(&pend_tmo_lock);
	}

	return err;

      linx_tmo_failed_unlock:
	spin_unlock_bh(&pend_tmo_lock);

      linx_tmo_failed:
	if (*tmoref != LINX_ILLEGAL_TMOREF) {
		/* Cancel the allocation of the tmo reference */
		linx_free_pend_tmo(*tmoref);
	} else if (pt != NULL) {
		if (pt->sigsize > 0 && pt->skb != NULL) {
			kfree_skb(pt->skb);
		}
		linx_kfree(pt);
	}
	LINX_ASSERT(err < 0);
	return err;
}

int linx_cancel_tmo(struct sock *sk, LINX_OSTMOREF tmoref)
{
	int err = 0;
	struct pend_tmo *pt;
	LINX_SPID spid;

	linx_check_sock(sk);

	linx_trace_enter(LINX_TRACEGROUP_IPC, "%p, %x", sk, tmoref);

	/* Check arguments */
	spid = linx_sock_to_spid(sk);
	LINX_ASSERT(spid != LINX_ILLEGAL_SPID);

	spin_lock_bh(&pend_tmo_lock);
	pt = __tmoref_to_pt(tmoref);
	if (pt == NULL) {
		err = -EINVAL;
	} else if (pt->spid != spid) {
		err = -EINVAL;
	}
	spin_unlock_bh(&pend_tmo_lock);

	/* Remove timeout */
	if (err == 0) {
		linx_free_pend_tmo(tmoref);
	}

	return err;
}

int linx_modify_tmo(struct sock *sk, LINX_OSTIME tmo, LINX_OSTMOREF tmoref)
{
	int err = 0;
	struct pend_tmo *pt = NULL;
	LINX_SPID spid;
	struct sk_buff *skb;
	struct linx_skb_cb *cb;
	
	linx_check_sock(sk);

	LINX_ASSERT(linx_sock_to_spid(sk) != LINX_ILLEGAL_SPID);
	LINX_ASSERT(tmoref != LINX_ILLEGAL_TMOREF);

	/* Check arguments */
	spid = linx_sock_to_spid(sk);
	LINX_ASSERT(spid != LINX_ILLEGAL_SPID);

	spin_lock_bh(&pend_tmo_lock);
	pt = __tmoref_to_pt(tmoref);
	if (pt == NULL) {
		err = -EINVAL;
	} else if (pt->spid != spid) {
		err = -EINVAL;
	}
	spin_unlock_bh(&pend_tmo_lock);

	if (err != 0) {
		goto linx_modify_tmo_out;
	}
	
        /*
         * Modify time-out:
         * 1. Stop timer.
         * 2. Check if the time-out already has occurred, if so remove
         *    the skb from the receive queue.
         * 3. Restart timer.
         *
         * If mod_timer is used instead of del_timer_sync followed by
         * a add_timer, there is a risk that the skb is put twice in
         * the receive queue (first time-out ouccurs between check and
         * mod_timer call and then later when mod_timer expires).
         */
        del_timer_sync(&pt->timer);
	
	skb = pt->skb;
	LINX_ASSERT(skb->sk != NULL);
	spin_lock_bh(&skb->sk->sk_receive_queue.lock);
	/* If the tmo has already fired, don't destroy a fired timeout,
	 * just remove it from the receive queue and reset the clock. */
	if ((skb->next != NULL) && (skb->prev != NULL)) {
		atomic_dec(&linx_no_of_queued_signals);
		__skb_unlink_compat(skb, skb->sk);
                /*
		 * __linx_do_sendmsg_skb_to_local_sk()...
                 */
                cb = (struct linx_skb_cb *)skb->cb;
                cb->ref = LINX_ILLEGAL_TMOREF;
	}
	spin_unlock_bh(&skb->sk->sk_receive_queue.lock);
	LINX_ASSERT(skb->next == NULL);
	LINX_ASSERT(skb->prev == NULL);

        pt->timer.expires = jiffies + msecs_to_jiffies(tmo + 1);
        add_timer(&pt->timer);

      linx_modify_tmo_out:
	return err;
}

/* Initialize the socket specific tmo data structures.
 * NOTE: This function may only be called before a socket is fully created. */
void linx_init_tmo(struct sock *sk)
{
	LINX_ASSERT(sk != NULL);

	INIT_LIST_HEAD(&linx_sk(sk)->timeouts);
}

int
linx_info_pend_tmo(struct linx_info_pend_tmo *ipend_tmo,
		   struct linx_info_tmo __user * timeouts)
{
	struct sock *sk;
	struct linx_info_tmo itmo;
	int size = 0;
	char *buffer = NULL;
	int no_of_tmo = 0;
	struct list_head *p;

	LINX_ASSERT(ipend_tmo != NULL);

	sk = linx_spid_to_sock(ipend_tmo->spid);
	if (sk == NULL) {
		if (!linx_is_zombie_spid(ipend_tmo->spid)) {
			return -EINVAL;
		}
		return -ECONNRESET;
	}

	linx_check_sock(sk);

	spin_lock_bh(&pend_tmo_lock);
	list_for_each(p, &linx_sk(sk)->timeouts) {
		struct pend_tmo *pt;

		pt = list_entry(p, struct pend_tmo, timeouts);
		__check_pend_tmo(pt);
		no_of_tmo++;
	}

	if (no_of_tmo * sizeof(struct linx_info_tmo) <=
	    ipend_tmo->buffer_size) {
		buffer = linx_kmalloc(no_of_tmo * sizeof(struct linx_info_tmo));
		if (buffer == NULL) {
			spin_unlock_bh(&pend_tmo_lock);
			sock_put(sk);
			return -ENOMEM;
		}

		list_for_each(p, &linx_sk(sk)->timeouts) {
			struct pend_tmo *pt;
			struct linx_skb_cb *cb;
			
			pt = list_entry(p, struct pend_tmo, timeouts);
			cb = (struct linx_skb_cb *)(pt->skb->cb);
			
			/* __check_pend_tmo(pt); */
			itmo.tmoref = pt_array[pt->index].tmoref;

			itmo.tmo_signal.signo = cb->signo;
			itmo.tmo_signal.size = pt->sigsize;
			itmo.tmo_signal.from = pt->spid;
			memcpy(buffer + size, &itmo,
			       sizeof(struct linx_info_tmo));
			size += sizeof(struct linx_info_tmo);
		}
	}
	spin_unlock_bh(&pend_tmo_lock);

	if (buffer != NULL && 0 != copy_to_user(timeouts, buffer, size)) {

		sock_put(sk);
		linx_kfree(buffer);
		return -EFAULT;
	}
	if (buffer != NULL)
		linx_kfree(buffer);

	sock_put(sk);

	return no_of_tmo;
}

int
linx_info_pend_tmo_payload(struct sock *sk,
			   struct linx_info_signal_payload *isig_payload)
{
	struct linx_info_signal *isig;
	int err;
	struct list_head *p;
	struct iovec to;
	int size;

	LINX_ASSERT(isig_payload != NULL);
	linx_check_sock(sk);

	isig = &isig_payload->signal;

	spin_lock_bh(&pend_tmo_lock);

	list_for_each(p, &linx_sk(sk)->timeouts) {
		struct pend_tmo *pt;
		struct linx_skb_cb *cb;
		pt = list_entry(p, struct pend_tmo, timeouts);
		cb = (struct linx_skb_cb *)(pt->skb->cb);
		__check_pend_tmo(pt);
		if (isig->signo == cb->signo &&
		    isig_payload->buffer_size == pt->sigsize &&
		    isig_payload->spid == pt->spid) {
			size = isig->size > isig_payload->buffer_size ?
			    isig_payload->buffer_size : isig->size;
			/* bump users count to prevent freeing after
			 * releasing spinlock */
			atomic_inc(&pt->skb->users);
			to.iov_base = isig_payload->buffer;
			to.iov_len = size;
			spin_unlock_bh(&pend_tmo_lock);
			err = skb_copy_datagram_iovec(pt->skb, 0, &to, size);
			/* decrease users count/free skb */
			kfree_skb(pt->skb);
			if (unlikely(err < 0)) {
				return err;
			}
			return size;
		}
	}
		spin_unlock_bh(&pend_tmo_lock);
		return 0;
}
