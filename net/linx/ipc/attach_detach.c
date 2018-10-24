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
 * Handle attach and detach.
 */

#include <af_linx.h>
#include <ipc/attach_detach.h>
#include <ipc/rlnh.h>
#include <linx_assert.h>
#include <linx_mem.h>
#include <rlnh.h>
#include <linux/linx_types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/version.h>
#include <net/sock.h>
#include <linx_compat.h>
#include <linx_trace.h>
#include <buf_types.h>

#define LINX_OSATTREF_INDEX_MASK       (linx_max_attrefs-1)
#define LINX_OSATTREF_INSTANCE_MASK    (~(LINX_OSATTREF_INDEX_MASK))
#define LINX_OSATTREF_INDEX(attref)    ((attref) & (LINX_OSATTREF_INDEX_MASK))
#define LINX_OSATTREF_INSTANCE(attref) \
        ((attref) & (LINX_OSATTREF_INSTANCE_MASK))
#define LINX_OSATTREF_INSTANCE_INC(attref) ((attref) + (linx_max_attrefs))

extern atomic_t linx_no_of_pend_attach;
extern atomic_t linx_no_of_queued_signals;

spinlock_t pend_attach_lock;

#define MAGIC_PEND_ATTACH 0xEDA11AC8

/* A data structure that hold information about a pending attach. */
struct pend_attach {
	uint32_t magic;		/* MAGIC_PEND_ATTACH */
	struct hlist_node node_caller;	/* Linked list information (caller). */
	struct hlist_node node_victim;	/* Linked list information (victim). */
	LINX_SPID caller;	/* The spid of the attaching (caller) entity */
	LINX_SPID victim;	/* The spid of the victim entity. */
	LINX_OSBUFSIZE sigsize;	/* The size of the attach signal. */

	struct sk_buff *skb;    /* skb containing the attach sig. */
	int attach_sent;        /* attach has been sent to caller? */
	uint16_t index;

	/* NOTE:
	 *  if sigsize = 0 and sig = NULL, rlnh is the caller
	 *  if sigsize = 4 and sig = NULL, a default signal shall be used.
	 *  This is needed to avoid allocating default signals at attach rather
	 *  than at resolve.
	 */
};

struct pend_attach_entry {
	void *pa;
	LINX_OSATTREF attref;
};

struct pend_attach_entry *pa_free_list;
struct pend_attach_entry *pa_free_list_end;
struct pend_attach_entry *pa_array;

static inline LINX_OSATTREF __pa_to_attref(struct pend_attach *pa)
{
	struct pend_attach_entry *pae;
	pae = &pa_array[pa->index];
	return pae->attref;
}

static inline struct pend_attach *__attref_to_pa(LINX_OSATTREF attref)
{
	struct pend_attach_entry *pae;
	pae = &pa_array[LINX_OSATTREF_INDEX(attref)];
	if (pae->attref != attref)
		return NULL;
	else if (pae->pa == NULL)
		return NULL;
	else if (((struct pend_attach *)pae->pa)->magic != MAGIC_PEND_ATTACH)
		return NULL;
	else
		return pae->pa;
}

int linx_init_attref_array(void)
{
	int i;

	LINX_ASSERT(sizeof(LINX_OSATTREF) == 4);

	spin_lock_init(&pend_attach_lock);

	pa_array = linx_vmalloc(sizeof(*pa_array) * linx_max_attrefs);
	if (unlikely(!pa_array)) {
		return -ENOMEM;
	}

	pa_free_list = pa_array;
	pa_free_list_end = &pa_array[linx_max_attrefs - 1];
	for (i = 0; i < linx_max_attrefs - 1; i++) {
		pa_array[i].pa = &pa_array[i + 1];
		pa_array[i].attref = LINX_OSATTREF_INSTANCE_INC(i);
	}
	pa_free_list_end->pa = NULL;
	pa_free_list_end->attref =
	    LINX_OSATTREF_INSTANCE_INC(LINX_OSATTREF_INDEX_MASK);

	return 0;
}

void linx_exit_attref_array(void)
{
	linx_vfree(pa_array);
}

/*
 *
 * Pending attach utilities
 *
 */

/* Check a pend_attach structure for errors. */
static inline void __check_pend_attach(struct pend_attach *pa)
{
	if (pa != NULL) {
		LINX_ASSERT(pa->caller != LINX_ILLEGAL_SPID);
		LINX_ASSERT(pa->victim != LINX_ILLEGAL_SPID);
	}
}

static inline void __unlink_pend_attach_victim(struct pend_attach *pa)
{
	__check_pend_attach(pa);

	if (pa->node_victim.pprev != NULL) {
		/* Remove the list information. */
		__hlist_del(&pa->node_victim);
		/* Unhash the node. */
		pa->node_victim.pprev = NULL;
	}
}

static inline void __unlink_pend_attach_caller(struct pend_attach *pa)
{
	__check_pend_attach(pa);

	if (pa->node_caller.pprev != NULL) {
		/* Remove the list information. */
		__hlist_del(&pa->node_caller);
		/* Unhash the node. */
		pa->node_caller.pprev = NULL;
	}
}

static inline void __unlink_pend_attach(struct pend_attach *pa)
{
	/* NOTE: A pend_attach structure belong to two lists,
	 *       the caller(caller) and the victim (victim) lists. */

	__check_pend_attach(pa);
	__unlink_pend_attach_caller(pa);
	__unlink_pend_attach_victim(pa);
}

static struct sk_buff *__free_pend_attach(struct pend_attach *pa)
{
	struct pend_attach_entry *pae;
	struct sk_buff *skb = NULL;

	LINX_ASSERT(sizeof(LINX_OSATTREF) == 4);
	LINX_ASSERT(pa->node_victim.pprev == NULL);
	LINX_ASSERT(pa->node_caller.pprev == NULL);

	pae = &pa_array[pa->index];

	if (LINX_OSATTREF_INSTANCE(pae->attref) == LINX_OSATTREF_INSTANCE_MASK)
		/* The attref has reached the max instance number, wrap to 0. */
		pae->attref = LINX_OSATTREF_INDEX(pae->attref);

	/* Add one to the instance number. */
	pae->attref = LINX_OSATTREF_INSTANCE_INC(pae->attref);
	if (pa_free_list != NULL) {
		pa_free_list_end->pa = pae;
		pa_free_list_end = pae;
		pae->pa = NULL;
	} else {
		pa_free_list = pae;
		pa_free_list_end = pae;
		pae->pa = NULL;
	}

	pa->magic = 0;

	if (pa->attach_sent) {
		skb = pa->skb;
		pa->skb = NULL;

		atomic_dec(&linx_no_of_queued_signals);

		/* The attach signal was sent to the attacher. */
		LINX_ASSERT(skb->sk != NULL);
		spin_lock_bh(&skb->sk->sk_receive_queue.lock);
		if (skb->next != NULL && skb->prev != NULL) {
			__skb_unlink_compat(skb, skb->sk);
		}
		spin_unlock_bh(&skb->sk->sk_receive_queue.lock);
		LINX_ASSERT(skb->next == NULL);
		LINX_ASSERT(skb->prev == NULL);
	}

	if (pa->skb != NULL && pa->sigsize > 0) {
		skb = pa->skb;
		pa->skb = NULL;
	}

	linx_kfree(pa);

	return skb;
}

static inline struct sk_buff *__linx_free_pend_attach(LINX_OSATTREF attref)
{
	struct pend_attach *pa;
	struct sk_buff *skb;

	pa = __attref_to_pa(attref);
	if (pa == NULL)
		return NULL;
	__unlink_pend_attach(pa);
	skb = __free_pend_attach(pa);
	atomic_dec(&linx_no_of_pend_attach);

	return skb;
}

void linx_free_pend_attach(uint32_t ref)
{
	struct sk_buff *skb;
	spin_lock_bh(&pend_attach_lock);
	skb = __linx_free_pend_attach(ref);
	spin_unlock_bh(&pend_attach_lock);
	if (skb != NULL)
		kfree_skb(skb);
}

/* Return the first element in the list of victims for a specific socket.
 * NOTE: This function require exclusive access on the pending attach
 *	 structures.
 */
static inline struct pend_attach *__pend_victims_head(struct sock *sk)
{
	struct pend_attach *pa;

	linx_check_sock(sk);
	pa = hlist_empty(&linx_sk(sk)->attach_victims) ? NULL :
	    hlist_entry(linx_sk(sk)->attach_victims.first,
			struct pend_attach, node_victim);
	__check_pend_attach(pa);

	return pa;
}

/* Move to the next node in the pending victims list.
 * NOTE: This function require exclusive access on the pending attach
 *	 structures.
 */
static inline struct pend_attach *__pend_victims_next(struct pend_attach *pa)
{
	struct pend_attach *pa_next;

	__check_pend_attach(pa);
	pa_next = pa->node_victim.next ?
	    hlist_entry(pa->node_victim.next,
			struct pend_attach, node_victim) : NULL;
	__check_pend_attach(pa_next);

	return pa_next;
}

/* This function is called as part of release,
 * it resolve pending attachs that match the released socket. */
static void __resolve_pend_attach(struct sock *victim_sk)
{
	struct pend_attach *pa;

	linx_check_sock(victim_sk);

	/* NOTE: victim_sk is being closed and need no sock_hold/sock_put */
	/* NOTE: This is part of release so the
	 *       socket need no additional locking. */

	/* Get the first element in the pend attach list. */
	pa = __pend_victims_head(victim_sk);

	/* Traverse all elements of the list and resolve
	 * matching pending attaches. */
	while (pa != NULL) {
		struct sock *caller_sk;
		LINX_OSATTREF attref;

		__check_pend_attach(pa);

		attref = __pa_to_attref(pa);
		LINX_ASSERT(attref != LINX_ILLEGAL_ATTREF);

		/* Remove the pending attach from the list. */
		__unlink_pend_attach_victim(pa);

		caller_sk = linx_spid_to_sock(pa->caller);
		if (caller_sk == NULL) {
			spin_unlock_bh(&pend_attach_lock);
		} else if (pa->sigsize == 0) {
			LINX_SPID victim = pa->victim;
			spin_unlock_bh(&pend_attach_lock);
			(void)
			    linx_rlnh_attach_notification(linx_sk
							  (caller_sk)->
							  rlnh, victim);
			sock_put(caller_sk);

			linx_free_pend_attach(attref);
			spin_lock_bh(&pend_attach_lock);
		} else {
			int rv;

			LINX_ASSERT(caller_sk != NULL);
			/* Send the signal to the socket that
			 * issued the pending attach. */
			rv = __linx_do_sendmsg_skb_to_local_sk(
				caller_sk, pa->skb, pa->sigsize, victim_sk,
				linx_sock_to_spid(victim_sk),
				linx_free_pend_attach, attref);

			pa->attach_sent = 1;
			sock_put(caller_sk);

			if (rv < 0) {
				spin_unlock_bh(&pend_attach_lock);
				linx_skb_queue_purge(
					caller_sk,
					&caller_sk->sk_receive_queue);
				spin_lock_bh(&pend_attach_lock);
			}
		}
		pa = __pend_victims_head(victim_sk);
	}
}

/* Return the first element in the list of callers for a specific socket.
 * NOTE: This function require exclusive access on the pending attach
 *	 structures.
 */
static inline struct pend_attach *__pend_callers_head(struct sock *sk)
{
	struct pend_attach *pa;

	linx_check_sock(sk);
	pa = hlist_empty(&linx_sk(sk)->attach_callers) ?
	    NULL :
	    hlist_entry(linx_sk(sk)->attach_callers.first,
			struct pend_attach, node_caller);
	__check_pend_attach(pa);

	return pa;
}

/* Move to the next node in the pending callers list.
 * NOTE: This function require exclusive access on the pending attach
 *	 structures.
 */
static inline struct pend_attach *__pend_callers_next(struct pend_attach *pa)
{
	struct pend_attach *pa_next;

	__check_pend_attach(pa);
	pa_next = pa->node_caller.next ?
	    hlist_entry(pa->node_caller.next,
			struct pend_attach, node_caller) : NULL;
	__check_pend_attach(pa_next);

	return pa_next;
}

/* This function is called as part of release,
 * Cancel all pending attachs from a specific socket.
 * If sk == NULL, all pending attachs are removed.
 */
static void __cancel_pend_attach(struct sock *sk)
{
	struct pend_attach *pa;

	linx_check_sock(sk);

	/* Get the first element in the pend attach list. */
	pa = __pend_callers_head(sk);

	/* Traverse all elements of the list and resolve
	 * matching pending huts. */
	while (pa != NULL) {
		LINX_OSATTREF attref = __pa_to_attref(pa);

		__check_pend_attach(pa);

		spin_unlock_bh(&pend_attach_lock);

		/* remove the pending attach */
		linx_free_pend_attach(attref);

		spin_lock_bh(&pend_attach_lock);

		pa = __pend_callers_head(sk);
	}
}

void linx_trigger_attach(struct sock *sk)
{
	linx_check_sock(sk);

	/* Exclude all other access to the attach lists. */
	spin_lock_bh(&pend_attach_lock);

	__cancel_pend_attach(sk);
	__resolve_pend_attach(sk);

	/* Mark the socket as attaches resolved. */
	linx_sk(sk)->resolved = LINX_TRUE;

	/* Allow others to access the pending attach lists. */
	spin_unlock_bh(&pend_attach_lock);
}

/* Add a new pend_attach structure to the caller and victim lists.
 * NOTE: This function require exclusive access on the pending attach
 *	 structures.
 */
static inline
    void __init_pend_attach(struct pend_attach *pa,
			    struct sock *caller_sk, struct sock *victim_sk)
{
	__check_pend_attach(pa);
	linx_check_sock(caller_sk);
	hlist_add_head(&pa->node_caller, &linx_sk(caller_sk)->attach_callers);

	if (victim_sk != NULL) {
		linx_check_sock(victim_sk);
		hlist_add_head(&pa->node_victim,
			       &linx_sk(victim_sk)->attach_victims);
	}
	atomic_inc(&linx_no_of_pend_attach);
}

/* Allocate an initialize a pending attach structure. */
static inline struct pend_attach *alloc_pend_attach(LINX_SPID victim,
						    LINX_SPID caller)
{
	struct pend_attach *pa;

	LINX_ASSERT(victim != LINX_ILLEGAL_SPID);
	LINX_ASSERT(caller != LINX_ILLEGAL_SPID);

	pa = linx_kmalloc(sizeof(*pa));
	if (unlikely(pa == NULL)) {
		linx_err("alloc_pend_attach() failed, out of memory.");
		return NULL;
	}

	/* Calculate the location of the signal of the pending
	 * attach (directly after the ph data structure). */
	pa->caller = caller;
	pa->victim = victim;
	pa->skb = NULL;
	pa->attach_sent = 0;
	pa->magic = MAGIC_PEND_ATTACH;
	INIT_HLIST_NODE(&pa->node_caller);
	INIT_HLIST_NODE(&pa->node_victim);
	return pa;
}

/* Allocate an initialize a pending attach structure. */
static inline int __insert_pend_attach(struct pend_attach *pa)
{
	struct pend_attach_entry *pae;

	__check_pend_attach(pa);

	LINX_ASSERT(sizeof(LINX_OSATTREF) == 4);

	if (pa_free_list == NULL) {
		linx_err("allocation of an attach reference failed, "
			 "max reached.");
		return 0;
	}

	pae = pa_free_list;
	pa_free_list = pa_free_list->pa;
	if (pa_free_list == NULL)
		pa_free_list_end = NULL;

	pae->pa = pa;
	pa->index = LINX_OSATTREF_INDEX(pae->attref);

	return 1;
}

static int add_attach(struct sock *caller_sk, struct pend_attach *pa,
		      LINX_SPID victim_spid, LINX_OSATTREF *attref,
		      LINX_OSBOOLEAN rlnh)
{
	struct sock *victim_sk = NULL;
	LINX_OSATTREF this_attref = LINX_ILLEGAL_ATTREF;

	/*
	 * Prevent cancelation / resolve of pending attaches
	 * during the adding of the pending attach.
	 * The mutex shall handle the race between release and attach.
	 */

	spin_lock_bh(&pend_attach_lock);
	if (!__insert_pend_attach(pa)) {
		spin_unlock_bh(&pend_attach_lock);
		return -ENOMEM;
	}

	/* Check if the victim is dead/destructed. */
	victim_sk = linx_spid_to_sock(victim_spid);
	if (victim_sk == NULL && !linx_is_zombie_spid(victim_spid)) {
		spin_unlock_bh(&pend_attach_lock);
		return -EINVAL;
	}

	if (victim_sk != NULL && linx_sk(victim_sk)->resolved == LINX_TRUE) {
		sock_put(victim_sk);
		victim_sk = NULL;
	}

	this_attref = __pa_to_attref(pa);

	if (victim_sk == NULL && rlnh == LINX_TRUE) {
		(void)__free_pend_attach(pa);
		spin_unlock_bh(&pend_attach_lock);
		(void)linx_rlnh_attach_notification(linx_sk(caller_sk)->rlnh,
						    victim_spid);
	} else if (victim_sk == NULL) {
		int rv;
		LINX_ASSERT(linx_sk(caller_sk)->type != LINX_TYPE_REMOTE);

		/*
		 * NOTE: If one process would attach and another would
		 *       receive the attach signal, this code would break.
		 */

		__init_pend_attach(pa, caller_sk, NULL);
		*attref = this_attref;

		/*
		 * The caller is sending a signal to itself,
		 * pa cannot be freed since pa can only be freed
		 * by the caller itself (free of received signal)
		 */

		rv = __linx_do_sendmsg_skb_to_local_sk(caller_sk, pa->skb,
						       pa->sigsize, NULL,
						       victim_spid,
						       linx_free_pend_attach,
						       *attref);

		pa->attach_sent = 1;

		spin_unlock_bh(&pend_attach_lock);

		if (rv < 0)
			linx_skb_queue_purge(caller_sk,
					     &caller_sk->sk_receive_queue);
	} else {
		__init_pend_attach(pa, caller_sk, victim_sk);
		*attref = this_attref;
		spin_unlock_bh(&pend_attach_lock);
		sock_put(victim_sk);
	}
	return 0;
}

/* The attach function.
 * The attach function run in the context of the caller socket.
 * The victim spid may be an open or closed socket.
 * The signal sig can be zero of no signal is provided or the
 * RLNH makes the call.
 * The signal size sigsize can be 0 if rlnh makes the call or no
 * signal is provided.
 * Attref is an output parameter that shall contain the attach reference.
 * rlnh specify if the caller is RLNH or not.
 *
 * The attach function is called to supervise a socket. When the socket is
 * closed the provided attach signal, the default attach signal or the rlnh
 * callback shall be sent/called to the caller.
 *
 * If the victim socket is already closed, the attach signal / callback
 * shall be sent imediatelly.
 *
 * The attach signal is always sent from (from address) the closed socket,
 * even if the socket is already closed.
 */
int linx_attach(struct sock *caller_sk,	LINX_SPID victim_spid,void *sig,
		LINX_OSBUFSIZE sigsize,	LINX_OSATTREF * attref,
		LINX_OSBOOLEAN rlnh)
{
	int err = 0;
	struct pend_attach *pa = NULL;

	linx_check_sock(caller_sk);

	LINX_ASSERT(linx_sock_to_spid(caller_sk) != LINX_ILLEGAL_SPID);
	LINX_ASSERT(!(rlnh == LINX_FALSE && sigsize == 0 && sig != NULL));
	LINX_ASSERT(!(rlnh == LINX_FALSE && sigsize != 0 && sig == NULL));
	LINX_ASSERT(!(rlnh != LINX_TRUE && rlnh != LINX_FALSE));
	LINX_ASSERT(!(rlnh == LINX_TRUE && sigsize != 0));
	LINX_ASSERT(attref != 0);

	if (victim_spid == LINX_ILLEGAL_SPID)
		return -EINVAL;

	/* Allocate and initialize the pending attach data structure. */
	pa = alloc_pend_attach(victim_spid, linx_sock_to_spid(caller_sk));
	if (pa == NULL)
		return -ENOMEM;

	/* Prepare the attach signal for transmit or pending. */
	if (rlnh == LINX_TRUE) {
		pa->skb = NULL;
		pa->sigsize = 0;
	} else if (sig != NULL) {
		struct linx_skb_cb *cb;
		err = linx_skb_create(sig, sigsize, caller_sk,
				      BUFFER_TYPE_USER, &pa->skb,
				      linx_mem_frag);
		if(err != 0)
			goto linx_attach_failed;
		cb = (struct linx_skb_cb *)(pa->skb->cb);
		get_user(cb->signo, (LINX_SIGSELECT *)sig);
		pa->sigsize = sigsize;
	} else {
		struct linx_skb_cb *cb;
		LINX_SIGSELECT default_attach_signo = LINX_OS_ATTACH_SIG;
		err = linx_skb_create(&default_attach_signo,
				      sizeof(LINX_SIGSELECT), caller_sk,
				      BUFFER_TYPE_KERNEL, &pa->skb, 0);
		if(err != 0)
			goto linx_attach_failed;
		cb = (struct linx_skb_cb *)(pa->skb->cb);
		cb->signo = default_attach_signo;
		pa->sigsize = sizeof(LINX_SIGSELECT);
	}

	err = add_attach(caller_sk, pa, victim_spid, attref, rlnh);
	if(err == 0)
		return err;

 linx_attach_failed:
	if(pa->skb != NULL)
		kfree_skb(pa->skb);
	linx_kfree(pa);

	return err;
}

int linx_detach(struct sock *sk, LINX_OSATTREF attref)
{
	int err = 0;
	struct pend_attach *pa;
	LINX_SPID spid;

	linx_check_sock(sk);

	linx_trace_enter(LINX_TRACEGROUP_IPC, "%p, %x", sk, attref);

	spid = linx_sock_to_spid(sk);
	LINX_ASSERT(spid != LINX_ILLEGAL_SPID);

	LINX_ASSERT(sizeof(LINX_OSATTREF) == 4);
	spin_lock_bh(&pend_attach_lock);
	pa = __attref_to_pa(attref);
	if (pa == NULL || pa->caller != spid)
		err = -EINVAL;
	spin_unlock_bh(&pend_attach_lock);

	if (err == 0)
		linx_free_pend_attach(attref);

	return err;
}

/* Initialize the socket specific attach data structures.
 * NOTE: This function may only be called before a socket is fully created. */
void linx_init_attach(struct sock *sk)
{
	LINX_ASSERT(sk != NULL);

	/* Initialize the attach to (victim) list. */
	INIT_HLIST_HEAD(&linx_sk(sk)->attach_callers);

	/* Initialize the attach from (caller) list. */
	INIT_HLIST_HEAD(&linx_sk(sk)->attach_victims);

	/* Set the socket to attaches unresolved. */
	linx_sk(sk)->resolved = LINX_FALSE;
}

int linx_info_pend_attach(struct linx_info_pend_attach *ipend_attach,
			  struct linx_info_attach __user * attaches)
{
	struct sock *sk;
	struct linx_info_attach iattach;
	struct pend_attach *pa;
	int size = 0;
	char *buffer = NULL;
	int no_of_attach = 0;

	LINX_ASSERT(ipend_attach != NULL);

	sk = linx_spid_to_sock(ipend_attach->spid);
	if (sk == NULL) {
		if (!linx_is_zombie_spid(ipend_attach->spid)) {
			return -EINVAL;
		}
		return -ECONNRESET;
	}

	spin_lock_bh(&pend_attach_lock);

	if (ipend_attach->from_or_to == LINX_ATTACH_FROM) {
		pa = __pend_callers_head(sk);
		while (pa != NULL) {
			__check_pend_attach(pa);
			no_of_attach++;
			pa = __pend_callers_next(pa);
		}

		if (0 != no_of_attach &&
                    (no_of_attach * sizeof(struct linx_info_attach) <=
                     ipend_attach->buffer_size)) {
			buffer = linx_kmalloc(no_of_attach *
					      sizeof(struct linx_info_attach));
			if (buffer == NULL) {
				spin_unlock_bh(&pend_attach_lock);
				sock_put(sk);
				return -ENOMEM;
			}

			pa = __pend_callers_head(sk);
			while (pa != NULL) {
				__check_pend_attach(pa);
				iattach.attref = pa_array[pa->index].attref;
				iattach.spid = pa->victim;
				if (pa->sigsize == 0) {
					/* An attach from RLNH */
					iattach.attach_signal.signo = 0;
				} else {
					/* A user attach signal */
					struct linx_skb_cb *cb;
					cb = (struct linx_skb_cb *)
						(pa->skb->cb);
					iattach.attach_signal.signo = cb->signo;
				}
				iattach.attach_signal.size = pa->sigsize;
				iattach.attach_signal.from = pa->caller;
				memcpy(buffer + size,
				       &iattach,
				       sizeof(struct linx_info_attach));
				size += sizeof(struct linx_info_attach);
				pa = __pend_callers_next(pa);
			}
		}
	} else if (ipend_attach->from_or_to == LINX_ATTACH_TO) {
		pa = __pend_victims_head(sk);
		while (pa != NULL) {
			__check_pend_attach(pa);
			no_of_attach++;
			pa = __pend_victims_next(pa);
		}
		if (0 != no_of_attach &&
                    (no_of_attach * sizeof(struct linx_info_attach) <=
                     ipend_attach->buffer_size)) {
			buffer = linx_kmalloc(no_of_attach *
					      sizeof(struct linx_info_attach));
			if (buffer == NULL) {
				spin_unlock_bh(&pend_attach_lock);
				sock_put(sk);
				return -ENOMEM;
			}

			pa = __pend_victims_head(sk);
			while (pa != NULL) {
				__check_pend_attach(pa);

				iattach.attref = pa_array[pa->index].attref;
				iattach.spid = pa->victim;
				if (pa->sigsize == 0) {
					/* An attach from RLNH */
					iattach.attach_signal.signo = 0;
				} else {
					/* A user attach signal */
					struct linx_skb_cb *cb;
					cb = (struct linx_skb_cb *)
						(pa->skb->cb);
					iattach.attach_signal.signo = cb->signo;
				}
				iattach.attach_signal.size = pa->sigsize;
				iattach.attach_signal.from = pa->caller;
				memcpy(buffer + size,
				       &iattach,
				       sizeof(struct linx_info_attach));

				size += sizeof(struct linx_info_attach);
				pa = __pend_victims_next(pa);
			}
		}
	} else {
		spin_unlock_bh(&pend_attach_lock);
		sock_put(sk);
		return -EINVAL;
	}

	spin_unlock_bh(&pend_attach_lock);

	if (buffer != NULL && 0 != copy_to_user(attaches, buffer, size)) {

		sock_put(sk);
		linx_kfree(buffer);
		return -EFAULT;
	}
	if (buffer != NULL)
		linx_kfree(buffer);

	sock_put(sk);

	return no_of_attach;
}

int linx_info_pend_attach_payload(struct sock *sk,
				  struct linx_info_signal_payload *isig_payload)
{
	struct linx_info_signal *isig;
	struct pend_attach *pa;
	int err;
	struct iovec to;
	int size;

	LINX_ASSERT(isig_payload != NULL);

	isig = &isig_payload->signal;

	if (isig == NULL)
		return -EFAULT;

	spin_lock_bh(&pend_attach_lock);

	pa = __pend_callers_head(sk);
	while (pa != NULL) {
		struct linx_skb_cb *cb;
		__check_pend_attach(pa);
		cb = (struct linx_skb_cb *)(pa->skb->cb);

		if (isig->signo == cb->signo &&
		    isig_payload->buffer_size == pa->sigsize &&
		    isig_payload->spid == pa->caller) {
			size = isig->size > isig_payload->buffer_size ?
				isig_payload->buffer_size : isig->size;
			/* bump users count to prevent freeing after
			 * releasing spinlock */
			atomic_inc(&pa->skb->users);
			to.iov_base = isig_payload->buffer;
			to.iov_len = size;
			spin_unlock_bh(&pend_attach_lock);
			err = skb_copy_datagram_iovec(pa->skb, 0, &to, size);
			/* decrease users count/free skb */
			kfree_skb(pa->skb);
			if (unlikely(err < 0)) {
				return err;
			}
			return size;
		}
		pa = __pend_callers_next(pa);
	}
	spin_unlock_bh(&pend_attach_lock);
	return 0;
}
