/*
 *  Copyright (c) 2006-2007, Enea Software AB .
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

/*
 *  AF_LINX socket layer
 */

#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/dcache.h>
#include <linux/linx_ioctl.h>
#include <linux/linx_socket.h>
#include <linux/linx_types.h>
#include <linux/tcp.h>
#include <ipc/stat.h>
#include <ipc/rlnh.h>
#include <ipc/attach_detach.h>
#include <ipc/hunt.h>
#include <ipc/tmo.h>
#include <ipc/new_link.h>
#include <linx_mem.h>
#include <linx_assert.h>
#include <linx_ioctl_info.h>
#include <linx_trace.h>
#ifdef LINX_MESSAGE_TRACE
#include <linx_message_trace.h>
#endif
#include <linx_compat.h>
#include <net/compat.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22))
#else
#include <linux/ioctl32.h>
#endif
#include <linx_compat32.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33))
#include <linux/autoconf.h>
#else
#include <generated/autoconf.h>
#endif
#include <cfg/db.h>
#ifdef LINX_RBLOG
#include <rblog.h>
#endif
#include <buf_types.h>
#include <linux/types.h>
#include <linux/highmem.h>

/*
 *  SMP locking strategy:
 *
 *  bound socket table is protected with rwlock
 *  linx_socket_table_lock pending hunt list is protected with rwlock
 *  linx_pend_hunt_lock hunt path list is protected with rwlock
 *  linx_hunt_path_lock each socket state is protected by separate
 *  rwlock.
 */

/*
 *
 * Global variables, constansts, structures and macros.
 *
 */

extern unsigned int linx_version(void);

struct workqueue_struct *linx_workqueue;

/* list for routed skb's. initialized by af_linx*/
struct sk_buff_head routed_skb_list;

/* The linx sk cache pointer. */

#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20))
static kmem_cache_t *linx_sk_cachep;
#else
static struct kmem_cache *linx_sk_cachep;
#endif

/* The no of created sockets counter. */
static atomic_t linx_nr_socks = ATOMIC_INIT(0);

/* A signal filter that match all signals. */
static const LINX_SIGSELECT linx_sel_all[] = { 0 };

/* Variables used for statistics in the info interface. */
atomic_t linx_no_of_local_sockets = ATOMIC_INIT(0);
atomic_t linx_no_of_remote_sockets = ATOMIC_INIT(0);
atomic_t linx_no_of_link_sockets = ATOMIC_INIT(0);
atomic_t linx_no_of_pend_attach = ATOMIC_INIT(0);
atomic_t linx_no_of_pend_hunt = ATOMIC_INIT(0);
atomic_t linx_no_of_queued_signals = ATOMIC_INIT(0);
atomic_t linx_no_of_pend_tmo = ATOMIC_INIT(0);

#define LINX_SPID_INDEX_MASK	       (linx_max_spids-1)
#define LINX_SPID_SHIFT_INSTANCE(i)    \
        ((i) << (ffs(LINX_SPID_INSTANCE_MAX_DEFAULT)-1))
#define LINX_SPID_INSTANCE_MASK	       \
	LINX_SPID_SHIFT_INSTANCE(LINX_SPID_INSTANCE_MAX_DEFAULT - 1)
#define LINX_SPID_INDEX(spid)	       ((spid) & (LINX_SPID_INDEX_MASK))
#define LINX_SPID_INSTANCE(spid)       ((spid) & (LINX_SPID_INSTANCE_MASK))
#define LINX_SPID_INSTANCE_INC(spid)   \
	(LINX_SPID_INDEX(spid) +       \
	 LINX_SPID_INSTANCE(spid) +    \
	 LINX_SPID_SHIFT_INSTANCE(1))
#define CMSG_COMPAT_ALIGN(len) ( ((len)+sizeof(int)-1) & ~(sizeof(int)-1) )
#define CMSG_COMPAT_DATA(cmsg)	       \
	((void *)((char *)(cmsg) +     \
	 CMSG_COMPAT_ALIGN(sizeof(struct compat_cmsghdr))))

/* A lock that allow exclusive access to the pending attach lists. */
#ifndef DEFINE_RWLOCK
#define DEFINE_RWLOCK(x)	rwlock_t x = RW_LOCK_UNLOCKED
#endif

#ifdef CONFIG_64BIT
#define get_uptr(ptr,uptr) get_user(ptr,uptr)
#define put_uptr(ptr,uptr) put_user(ptr,uptr)
#else
#include <asm/byteorder.h>
#ifdef __LITTLE_ENDIAN
#define get_uptr(ptr,uptr) get_user(ptr,(unsigned long *)(uptr))
#define put_uptr(ptr,uptr) put_user(ptr,(unsigned long *)(uptr))
#else
#define get_uptr(ptr,uptr) get_user(ptr,(unsigned long *)(uptr)+1)
#define put_uptr(ptr,uptr) put_user(ptr,(unsigned long *)(uptr)+1)
#endif
#endif

DEFINE_RWLOCK(spid_lock);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22))
#define LINX_SKB_RESET_TRANSPORT_HEADER(skb) (skb_reset_transport_header(skb))
#else
#define LINX_SKB_RESET_TRANSPORT_HEADER(skb) ((skb)->h.raw = (skb)->data)
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
#define sk_sleep(sk) (sk)->sk_sleep
#endif

struct spid_entry {
	void *sk;
	LINX_SPID spid;
};

static int linx_sk_trylock(struct sock *sk)
{
	if (unlikely(atomic_cmpxchg(&linx_sk(sk)->in_use, 0, 1)))
		return -EACCES;
	return 0;
	
}

static void linx_sk_unlock(struct sock *sk)
{
	/* atomic_xchg is "safer" then atomic_dec or atomic_set
	 * since it implies memory barriers */
	(void)atomic_xchg(&linx_sk(sk)->in_use, 0);
}

struct spid_entry *spid_free_list;
struct spid_entry *spid_free_list_end;
struct spid_entry *spid_array;


static inline LINX_SPID __spid_index_inc(LINX_SPID spid)
{
	uint32_t index = LINX_SPID_INDEX(spid);
	uint32_t instance = LINX_SPID_INSTANCE(spid);
	index++;
	if (index == linx_max_spids)
		return instance;
	else
		return instance + index;
}

static inline LINX_SPID __spid_index_dec(LINX_SPID spid)
{
	uint32_t index = LINX_SPID_INDEX(spid);
	uint32_t instance = LINX_SPID_INSTANCE(spid);
	if (index == 0)
		return instance + linx_max_spids - 1;
	else
		return instance + index - 1;
}

int linx_init_spid_array(void)
{
	int i;

	LINX_ASSERT(sizeof(LINX_SPID) == 4);

	spid_array = linx_vmalloc(sizeof(*spid_array) * linx_max_spids);
	if (!spid_array) {
		return -ENOMEM;
	}

	write_lock_bh(&spid_lock);

	spid_free_list = spid_array;
	spid_free_list_end = &spid_array[linx_max_spids - 1];
	for (i = 0; i < linx_max_spids - 1; i++) {
		spid_array[i].sk = &spid_array[i + 1];
		spid_array[i].spid = LINX_SPID_INSTANCE_INC(i);
		spid_array[i].spid = __spid_index_dec(spid_array[i].spid);
	}
	spid_free_list_end->sk = NULL;
	spid_free_list_end->spid = LINX_SPID_INSTANCE_INC(LINX_SPID_INDEX_MASK);
	spid_free_list_end->spid = __spid_index_dec(spid_free_list_end->spid);
	write_unlock_bh(&spid_lock);

	return 0;
}

void linx_exit_spid_array(void)
{
	linx_vfree(spid_array);
}

static void create_spid(struct sock *sk)
{
	struct spid_entry *se;

	write_lock_bh(&spid_lock);

	LINX_ASSERT(sizeof(LINX_SPID) == 4);

	if (spid_free_list == NULL) {
		linx_sk(sk)->spid = LINX_ILLEGAL_SPID;
		write_unlock_bh(&spid_lock);
		return;
	}

	se = spid_free_list;

	spid_free_list = spid_free_list->sk;
	if (spid_free_list == NULL)
		spid_free_list_end = NULL;

	se->sk = sk;
	se->spid = __spid_index_inc(se->spid);
	linx_sk(sk)->spid = se->spid;
	write_unlock_bh(&spid_lock);
}

static inline int __validate_spid(LINX_SPID spid)
{
	struct spid_entry *se = &spid_array[LINX_SPID_INDEX(spid)];
	return se->spid == spid;
}

static void destroy_spid(LINX_SPID spid)
{
	struct spid_entry *se;
	uint32_t index;

	LINX_ASSERT(sizeof(LINX_SPID) == 4);

	write_lock_bh(&spid_lock);
	LINX_ASSERT(__validate_spid(spid));

	index = LINX_SPID_INDEX(spid);
	se = &spid_array[index];
	LINX_ASSERT(se->spid == spid);

	if (LINX_SPID_INSTANCE(spid) == LINX_SPID_INSTANCE_MASK)
		/* The spid has reached the max instance number, wrap to 0. */
		se->spid = index;

	/* Add one to the instance number. */
	se->spid = LINX_SPID_INSTANCE_INC(se->spid);
	/* We increment the spid index to indicate that it is free */
	se->spid = __spid_index_dec(se->spid);

	if (spid_free_list != NULL) {
		spid_free_list_end->sk = se;
		spid_free_list_end = se;
		se->sk = NULL;
	} else {
		spid_free_list = se;
		spid_free_list_end = se;
		se->sk = NULL;
	}
	write_unlock_bh(&spid_lock);
}

/* If a spid has a value that can not be masked away completely by both the
 * index and instance mask canot be a spid.  a spid with instance number 0 can
 * not be a spid. */
int linx_is_zombie_spid(LINX_SPID spid)
{
	uint32_t instance;
	uint32_t rest;
	uint32_t mask;

	mask = LINX_SPID_INDEX_MASK | LINX_SPID_INSTANCE_MASK;
	instance = LINX_SPID_INSTANCE(spid);
	rest = spid & (~mask);

	return rest == 0 && instance != 0;
}

/* Translate a spid to a sock struct. */
struct sock *linx_spid_to_sock(LINX_SPID spid)
{
	struct sock *sk = NULL;
	struct spid_entry *se;
	uint32_t index;

	LINX_ASSERT(sizeof(LINX_SPID) == 4);

	index = LINX_SPID_INDEX(spid);

	read_lock_bh(&spid_lock);
	se = &spid_array[index];
	if (likely(se->sk != NULL && se->spid == spid)) {
		linx_check_sock(se->sk);
		if (likely(!sock_flag(se->sk, SOCK_DEAD))) {
			sk = se->sk;
			/* Make sure the specific socket is not destructed. */
			sock_hold(sk);
		}
	}

	read_unlock_bh(&spid_lock);

	return sk;
}

/*
 *
 * struct sockaddr_linx utilities
 *
 */

/* Validate a sockaddr_linx data structure. */
static inline LINX_OSBOOLEAN
linx_validate_sockaddr_linx(struct sockaddr_linx *sao, int len)
{
	if (unlikely(len < sizeof(struct sockaddr_linx))) {
		return LINX_FALSE;
	} else if (unlikely(sao->family != AF_LINX)) {
		return LINX_FALSE;
	}

	return LINX_TRUE;
}

/* Copy the sockets sockaddr_linx address to a message structure but avoid the
 * ascii name. */
static inline void linx_copy_addr(struct msghdr *msg,
				  struct sock *sk, LINX_SPID real_spid)
{
	struct sockaddr_linx *sa;

	linx_check_sock(sk);
	LINX_ASSERT(msg != NULL);

	/* If the socket is not bound, there is no address and thus the namelen
	 * is set to 0.
	 */
	LINX_ASSERT(linx_sk(sk)->addr != NULL);

	sa = msg->msg_name;

	LINX_ASSERT(msg->msg_name != NULL);
	LINX_ASSERT(msg->msg_namelen >= sizeof(struct sockaddr_linx));

	linx_check_spid(sk);
	msg->msg_namelen = sizeof(struct sockaddr_linx);

	sa->family = AF_LINX;

	LINX_ASSERT(real_spid != LINX_ILLEGAL_SPID);
	sa->spid = real_spid;
	linx_check_sockaddr_linx(sa);
}

struct linx_huntname *linx_alloc_huntname(LINX_SPID spid, const char *name)
{
	struct linx_huntname *huntname;
	int namelen, namebytes;

	if (name == NULL) {
		namelen = 0;
		namebytes = 0;
	} else {
		namelen = strlen(name);
		namebytes = namelen + 1;
		if (namelen == 0) {
			return NULL;
		}
	}
	huntname = linx_kmalloc(sizeof(*huntname) + namebytes);
	if (huntname == NULL) {
		return NULL;
	}
	memset(huntname, 0, sizeof(struct linx_huntname) + namebytes);

	huntname->namelen = namelen;
	if (name != NULL) {
		huntname->name = (char *)(huntname + 1);
		memcpy((char *)huntname->name, name, huntname->namelen + 1);
	} else {
		huntname->name = NULL;
	}

	return huntname;
}

/* Free linx_name. */
void linx_free_linx_name(struct linx_huntname *name)
{
	linx_check_linx_huntname(name);
	linx_kfree(name);
}

/*
 *
 * Signal filtering.
 *
 */

static inline LINX_OSBOOLEAN
match_filter(LINX_SIGSELECT signo, LINX_SIGSELECT * filter)
{
	int count = *filter;
	int i;

	linx_trace_enter(LINX_TRACEGROUP_AF_LINX, "%d, %p", signo, filter);

	if (likely(count == 0)) {
		return LINX_TRUE;
	}

	if (unlikely(count < 0)) {
		count = -count;
		for (i = 1; i <= count; i++) {
			if (filter[i] == signo) {
				return LINX_FALSE;
			}
		}
		return LINX_TRUE;
	}

	for (i = 1; i <= count; i++) {
		if (filter[i] == signo) {
			return LINX_TRUE;
		}
	}

	return LINX_FALSE;
}

/* Find a match in the receive queue using the provided filters. */
static struct sk_buff *__linx_match_filters(struct sock *sk)
{
	struct sk_buff *skb;
	linx_trace_enter(LINX_TRACEGROUP_AF_LINX, "%p", sk);

	linx_check_sock(sk);

	skb_queue_walk(&sk->sk_receive_queue, skb) {
		struct linx_skb_cb *cb = (struct linx_skb_cb *)skb->cb;
		if (unlikely(linx_sk(sk)->from_filter != LINX_ILLEGAL_SPID)) {
			/* First sort out signals that are from the wrong
			 * sender. */
			if (cb->from_spid != linx_sk(sk)->from_filter) {
				continue;
			}
		}
		if (likely(linx_sk(sk)->filter == NULL)) {
			return skb;
		}
		if (match_filter(cb->signo, linx_sk(sk)->filter)) {
			return skb;
		}
	}
	return NULL;
}

static struct sk_buff *linx_match_filters(struct sock *sk)
{
	struct sk_buff *skb;

	linx_check_sock(sk);

	/* Spin until the match is made and avoid local interrupts during the
	 * matching.  The locking is needed to avoid changes to the receive
	 * queue while reading from it.
	 */
	spin_lock_bh(&sk->sk_receive_queue.lock);

	skb = __linx_match_filters(sk);

	/* Stop spinning and restore the interrupts. */
	spin_unlock_bh(&sk->sk_receive_queue.lock);

	return skb;
}

/*
 *
 * Modified code from net/core/datagram.c
 *
 */

/*
 * Wait for a packet..
 */

static int linx_wait_for_packet(struct sock *sk, int *err, long *timeo_p)
{
	int error;

	/* Create and initialize a wait queue entry. */
	DEFINE_WAIT(wait);

	linx_check_sock(sk);

	/* Add the wait entry to the sk_sleep wait queue and and set the
	 * process state to interruptable. */	
	prepare_to_wait_exclusive(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);

	set_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);

	/* Make sure the task still needs to sleep. */

	/* Socket errors? */
	error = sock_error(sk);
	if (unlikely(error)) {
		linx_err("sock_error %d.", error);
		goto out_err;
	}

	if (unlikely(linx_match_filters(sk) != NULL)) {
		goto out;
	}

	/* handle signals */
	if (unlikely(signal_pending(current))) {
		/* This should not result in a warning, this is a normal
		 * case. */
		goto interrupted;
	}
	error = 0;
	*timeo_p = schedule_timeout(*timeo_p);
      out:
	clear_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);
	finish_wait(sk_sleep(sk), &wait);
	return error;
      interrupted:
	error = sock_intr_errno(*timeo_p);
      out_err:
	*err = error;
	goto out;
}

/* Taken from net/core/skbuff.c */
void linx_skb_queue_purge(struct sock *sk, struct sk_buff_head *list)
{
	struct sk_buff *skb;
	while ((skb = skb_dequeue(list)) != NULL) {
		struct linx_skb_cb *cb;
		cb = (struct linx_skb_cb *)skb->cb;
		if (unlikely(cb->destructor != NULL)) {
			cb->destructor(cb->ref);
		} else {
			atomic_dec(&linx_no_of_queued_signals);
			kfree_skb(skb);
		}
	}
}

/**
 *	skb_recv_datagram - Receive a datagram skbuff
 *	@sk - socket
 *	@flags - MSG_ flags
 *	@noblock - blocking operation?
 *	@err - error code returned
 *
 *	Get a datagram skbuff, understands the peeking, nonblocking wakeups
 *	and possible races. This replaces identical code in packet, raw and
 *	udp, as well as the IPX AX.25 and Appletalk. It also finally fixes
 *	the long standing peek and read race for datagram sockets. If you
 *	alter this routine remember it must be re-entrant.
 *
 *	This function will lock the socket if a skb is returned, so the caller
 *	needs to unlock the socket in that case (usually by calling
 *	skb_free_datagram)
 *
 *	* It does not lock socket since today. This function is
 *	* free of race conditions. This measure should/can improve
 *	* significantly datagram socket latencies at high loads,
 *	* when data copying to user space takes lots of time.
 *	* (BTW I've just killed the last cli() in IP/IPv6/core/netlink/packet
 *	*  8) Great win.)
 *	*					    --ANK (980729)
 *
 *	The order of the tests when we find no data waiting are specified
 *	quite explicitly by POSIX 1003.1g, don't change them without having
 *	the standard around please.
 */
static struct sk_buff *linx_recv_datagram(struct sock *sk, unsigned flags,
					  int *err, int max_size, long timeo)
{
	struct sk_buff *skb;

	/*
	 * Caller is allowed not to check sk->sk_err before
	 * skb_recv_datagram()
	 */
	int error;
	
	linx_trace_enter(LINX_TRACEGROUP_AF_LINX,
			 "%p, 0x%x, %p, %d",
			 sk, flags, err, max_size);

	linx_check_sock(sk);

	error = sock_error(sk);
	if (unlikely(error))
		goto no_packet;
	
	linx_sk(sk)->state = LINX_STATE_RECV;
	
	do {
		/* Again only user level code calls this function, so nothing
		 * interrupt level will suddenly eat the receive_queue.
		 *
		 * Look at current nfs client by the way...  However, this
		 * function was corrent in any case. 8)
		 */

		skb = linx_match_filters(sk);
		if (likely(skb)) {
			linx_sk(sk)->state = LINX_STATE_RUNNING;
			return skb;
		}
		
		if (unlikely(timeo == 0)) {
			break;
		}
	} while (!linx_wait_for_packet(sk, err, &timeo));

	linx_sk(sk)->state = LINX_STATE_RUNNING;
	return NULL;

      no_packet:
	*err = error;
	linx_sk(sk)->state = LINX_STATE_RUNNING;
	return NULL;
}

static void reset_receive_filter(struct sock *sk)
{
	LINX_SIGSELECT *filter;

	linx_trace_enter(LINX_TRACEGROUP_AF_LINX, "%p", sk);

	filter = linx_sk(sk)->filter;
	if (unlikely(filter != NULL)) {
		spin_lock_bh(&sk->sk_receive_queue.lock);
		linx_sk(sk)->from_filter = LINX_ILLEGAL_SPID;
		linx_sk(sk)->filter = NULL;
		spin_unlock_bh(&sk->sk_receive_queue.lock);
		linx_kfree(filter);
	}
}

static int
setup_receive_filter(struct sock *sk, struct linx_receive_filter_param *rfp)
{
	LINX_SIGSELECT *filter = NULL, *old_filter;
	int err = 0;

	linx_trace_enter(LINX_TRACEGROUP_AF_LINX, "%p, %p", sk, rfp);

	if (rfp->sigselect_size) {
		filter = linx_kmalloc(rfp->sigselect_size);
		if (unlikely(filter == NULL)) {
			err = -ENOMEM;
			goto out;
		}
		if (unlikely(0 != copy_from_user(filter, (void *)rfp->sigselect,
						 rfp->sigselect_size))) {
			err = -EFAULT;
			goto out;
		}
	}

	old_filter = linx_sk(sk)->filter;

	spin_lock_bh(&sk->sk_receive_queue.lock);
	linx_sk(sk)->filter = filter;
	linx_sk(sk)->from_filter = rfp->from;
	spin_unlock_bh(&sk->sk_receive_queue.lock);

	if (old_filter) {
		linx_kfree(old_filter);
	}
	return 0;

      out:
	if (filter != NULL)
		linx_kfree(filter);
	reset_receive_filter(sk);
	return err;
}

/*
 *
 * Poll and wakeup.
 *
 */

/* This function is called to wake up a receiving socket when it is sleeping
 * waiting for a new message in poll or select.
 */
static void linx_data_ready(struct sock *sk, int len)
{
	linx_check_sock(sk);

	read_lock_bh(&sk->sk_callback_lock);

	/* Check if the socket is writable. */
	if (likely(linx_match_filters(sk))) {
		/* Only wake up from sleep if the receiver is sleeping. */
		if (likely(sk_sleep(sk) && waitqueue_active(sk_sleep(sk)))) {
			/* Wake up the sleeping receiver. */
			wake_up_interruptible(sk_sleep(sk));
		}
		/* Send sigio to the receiving process. */
		sk_wake_async(sk, 1, POLL_IN);
	}

	read_unlock_bh(&sk->sk_callback_lock);
}

/* The linx_poll function is called as part of poll() and select() calls.  The
 * linx_poll function return a bitmask that indicate the state of the receive
 * queue. The linx_poll function is called initially when select of poll is
 * called, if the linx_poll return 0, the process will sleep until a timeout is
 * reached or wake_up_interruptable is called for the specific socket. When the
 * thread is woken up, the linx_poll function is called again to get the
 * correct mask.
 */
static unsigned int
linx_poll(struct file *file, struct socket *sock, poll_table * wait)
{
	struct sock *sk = sock->sk;
	unsigned int mask;
	int err;
	
	linx_trace_enter(LINX_TRACEGROUP_AF_LINX, "%p, %p, %p", file, sk, wait);

	linx_debug(LINX_TRACEGROUP_AF_LINX,
		   "sock name: %s", linx_sk(sk)->addr->name);

	if ((err = linx_sk_trylock(sk)) < 0) {
		return err;
	}
	
	/* The poll_wait function is called to add the sk_sleep(sk) wait queue
	 * to the poll. After the poll function has returned (with 0 mask) the
	 * task will sleep until the wake_up_interruptable call is made on
	 * sk_sleep(sk). If the linx_poll function return a mask indicating an
	 * event has occured already, the thread will not sleep. */
	poll_wait(file, sk_sleep(sk), wait);

	/* Clear the mask to indicate no event has occured yet. */
	mask = 0;

	/* Handle current events. */
	if (sk->sk_err) {
		/* The socket is in an error state. */
		mask |= POLLERR;
	}

	if (sk->sk_shutdown == SHUTDOWN_MASK) {
		/* The socket is shutdown (released). */
		mask |= POLLHUP;
	}

	if (linx_match_filters(sk) || (sk->sk_shutdown & RCV_SHUTDOWN)) {
		/* The socket is readable. */
		mask |= POLLIN | POLLRDNORM;
	}

	if (mask) {
		reset_receive_filter(sk);
		linx_sk(sk)->state = LINX_STATE_RUNNING;
	}

	linx_sk_unlock(sk);
	
	return mask;
}

/*
 *
 * Socket destruction and closure.
 *
 */

/* This function is called when a socket is finally destructed. */
static void linx_sock_destructor(struct sock *sk)
{
	linx_check_sock(sk);

	linx_trace_enter(LINX_TRACEGROUP_AF_LINX, "%p", sk);
	linx_debug(LINX_TRACEGROUP_AF_LINX, "Removing sock %p", sk);

	/* Remove all remaining buffers in the receive queue. */
	linx_skb_queue_purge(sk, &sk->sk_receive_queue);

	/* Error checks. */
	LINX_ASSERT(!atomic_read(&sk->sk_wmem_alloc));
	LINX_ASSERT(sk_unhashed(sk));
	LINX_ASSERT(!sk->sk_socket);

	if (!sock_flag(sk, SOCK_DEAD)) {
		linx_warn("Attempt to release alive linx socket: 0x%p", sk);
		return;
	}

	reset_receive_filter(sk);

	if (linx_sk(sk)->addr) {
		int err = linx_sock_stats_del(linx_sk(sk));
		if (err != 0) {
			linx_err("Could not remove socket '%s' from DB (%d).\n", 
                                 linx_sk(sk)->addr->name, err);
		}
	}

	/* Remove the address buffer is allocated. */
	spin_lock_bh(&sk->sk_receive_queue.lock);
	if (linx_sk(sk)->addr) {
		linx_free_linx_name(linx_sk(sk)->addr);
		linx_sk(sk)->addr = NULL;
	}
	spin_unlock_bh(&sk->sk_receive_queue.lock);

	linx_sk_unlock(sk);
	
	/* Decrease the global linx socket counter. */
	atomic_dec(&linx_nr_socks);

}

/* This function is called as part of close. */
static int linx_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	int err;
	
	linx_trace_enter(LINX_TRACEGROUP_AF_LINX, "%p", sock);

	LINX_ASSERT(sk != NULL);

	linx_check_socket(sock);

	if ((err = linx_sk_trylock(sk)) < 0) {
		return err;
	}
	
	/* NOTE: This is how the sock->sk structure is used all over the linux
	 *       socket implementation. Since there is no locking protecting
	 *       the sock->sk pointer, the linux socket implementation do not
	 *       support multiple threads using the same socket descriptor,
	 *       since if one of the threads close the socket, the other
	 *       threads may end up accessing a pointer to NULL. See for
	 *       instance sock_setsockopt in net/socket.c, it uses sock->sk
	 *       without checking if its value is NULL. */
	sock->sk = NULL;

	/* Unlink the socket from the hunt name table. */
	linx_unpublish(sk);

	/* Trigger the pending attachs from and to the socket.  This needs to
	 * be done before the socket starts to be released. */
	linx_trigger_attach(sk);

	/* Remove pending timeouts to the socket. Timeouts differs from
	 * attaches in that they aren't going anywhere when the socket is
	 * removed. */
	linx_remove_timeouts(sk);

	/* Remove pending new link requests. */
	linx_remove_new_link_requests(sk);
	
	if (linx_sk(sk)->type == LINX_TYPE_LOCAL)
		atomic_dec(&linx_no_of_local_sockets);
	else if (linx_sk(sk)->type == LINX_TYPE_LINK)
		atomic_dec(&linx_no_of_link_sockets);
	else			/* if(linx_sk(sk)->type == LINX_TYPE_REMOTE) */
		atomic_dec(&linx_no_of_remote_sockets);

	write_lock_bh(&spid_lock);

	/* Detach the socket from its process context by making it orphan. */
	sock_orphan(sk);

	/* Setting SHUTDOWN_MASK means that both send and receive are shutdown
	 * for the socket. */
	sk->sk_shutdown = SHUTDOWN_MASK;

	/* Set the socket state to closed, the TCP_CLOSE macro is used when
	 * closing any socket. */
	sk->sk_state = TCP_CLOSE;

	write_unlock_bh(&spid_lock);

	/* Flush out this sockets receive queue. */
	linx_skb_queue_purge(sk, &sk->sk_receive_queue);

	destroy_spid(linx_sk(sk)->spid);

	/* Finally release the socket. */
	sock_put(sk);

	return 0;

	/* The rest of the cleanup will be handled from the
	 * linx_sock_destructor */
}

/*
 *	Generic send/receive buffer handlers
 */

/* This function is copied form the linux kernel code (2.6.13). */
static struct sk_buff *linx_alloc_send_pskb(struct sock *sk,
					    unsigned long data_len,
					    int *errcode)
{
	struct sk_buff *skb;
	int err;
	unsigned int sk_allocation;
	
	if (unlikely(in_atomic()))
		sk_allocation = sk->sk_allocation &
		    (~(__GFP_WAIT | __GFP_IO | __GFP_HIGH));
	else
		sk_allocation = sk->sk_allocation | GFP_KERNEL;

	for (;;) {
		err = sock_error(sk);
		if (unlikely(err != 0))
			goto failure;

		err = -EPIPE;
		if (unlikely(sk->sk_shutdown & SEND_SHUTDOWN))
			goto failure;

		if (likely(atomic_read(&sk->sk_wmem_alloc) < sk->sk_sndbuf)) {
			skb = alloc_skb(0, sk_allocation);
			if (skb) {
				int npages;
				int i;

				/* No pages, we're done... */
				if (!data_len)
					break;

				npages = (data_len +
					  (PAGE_SIZE - 1)) >> PAGE_SHIFT;
				skb->truesize += data_len;
				skb_shinfo(skb)->nr_frags = npages;
				for (i = 0; i < npages; i++) {
					struct page *page;
					skb_frag_t *frag;
					page = alloc_pages(sk_allocation, 0);
					if (unlikely(!page)) {
						err = -ENOBUFS;
						skb_shinfo(skb)->nr_frags = i;
						kfree_skb(skb);
						goto failure;
					}

					frag = &skb_shinfo(skb)->frags[i];
					frag->page = page;
					frag->page_offset = 0;
					frag->size = (data_len >= PAGE_SIZE ?
						      PAGE_SIZE : data_len);
					data_len -= PAGE_SIZE;
				}

				/* Full success... */
				break;
			}
			err = -ENOBUFS;
			goto failure;
		}
		set_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		err = -EAGAIN;
		goto failure;
	}

	skb_set_owner_w(skb, sk);
	return skb;

      failure:
	*errcode = err;
	return NULL;
}
	
/**
 *	linx_skb_store_bits - store bits from kernel/user buffer to skb
 *	@skb: destination buffer
 *	@offset: offset in destination
 *	@from: source buffer
 *	@len: number of bytes to copy
 *
 *	Copy the specified number of bytes from the source buffer to the
 *	destination skb.  This function handles all the messy bits of
 *	traversing fragment lists and such.
 */
/* This function is copied form the linux kernel code (2.6.13). */
static int linx_skb_store_bits(struct sk_buff *skb,
			void *from, int len, uint32_t buffer_type)
{
	int i, copy, offset = 0;
	int start = skb_headlen(skb);
	int err;
	
	if ((copy = start - offset) > 0) {
                if (copy > len)
                        copy = len;
		if (BUF_TYPE_USER(buffer_type)) {
			err = copy_from_user(skb->data + offset, from, copy);
			if (unlikely(err != 0)) {
				return err;
			}
		} else {
			memcpy(skb->data + offset, from, copy);
		}
		if ((len -= copy) == 0)
                        return 0;
                offset += copy;
                from += copy;
	}
	
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		int end;
                
		LINX_ASSERT(start > offset + len);

		end = start + frag->size;
		if ((copy = end - offset) > 0) {
			u8 *vaddr;

			if (copy > len)
				copy = len;

			vaddr = kmap(frag->page);
			if (BUF_TYPE_USER(buffer_type)) {
				err = copy_from_user(vaddr + frag->page_offset +
						     offset - start, from,
						     copy);
					if (unlikely(err != 0)) {
						return err;
					}
			} else {
				memcpy(vaddr + frag->page_offset +
				       offset - start, from, copy);
			}
			kunmap(frag->page);

			if ((len -= copy) == 0)
				return 0;
			
			offset += copy;
			from += copy;
		}
		start = end;
	}
	if (likely(!len))
		return 0;
	return -EFAULT;
}

static struct sk_buff *linx_alloc_send_skb(struct sock *sk,
				    unsigned long data_len,
				    int *err)
{
	struct sk_buff *skb;
	unsigned int sk_allocation = sk->sk_allocation;
	
	if (unlikely(in_atomic()))
		sk->sk_allocation &= (~(__GFP_WAIT | __GFP_IO | __GFP_HIGH));
	else
		sk->sk_allocation |= GFP_KERNEL;
	
	/* Allocate a buffer structure to hold the signal. */
	skb = sock_alloc_send_skb(sk, data_len, 1, err);
	
	sk->sk_allocation = sk_allocation;
	
	return skb;
}

int linx_skb_create(void *payload,
		    LINX_OSBUFSIZE payload_size,
		    struct sock *to,
		    uint32_t buffer_type,
		    struct sk_buff **skb,
		    int frag)
{
	int err = 0;

	linx_check_sock(to);
	
	spin_lock_bh(&linx_sk(to)->skb_alloc_lock);

	if (unlikely(frag))
		*skb = linx_alloc_send_pskb(to, payload_size, &err);
	else
		*skb = linx_alloc_send_skb(to, payload_size, &err);
	
	spin_unlock_bh(&linx_sk(to)->skb_alloc_lock);

	if (unlikely(*skb == NULL || err != 0)) {
		if (err == -EAGAIN) {
			linx_err("Failed to allocate skb with "
				 "sock_alloc_send_skb\n EAGAIN is returned\n");
			return -ENOMEM;
		} else if (err == -EPIPE) {
			/* The socket is shutting down, handle this silently. */
			if (unlikely(*skb != NULL))
				kfree_skb(*skb);
			*skb = NULL;
			return 0;
		} else {
			return err;
		}
	}

	/* h is a union of transport header pointers, the LINX uses the raw
	 * pointer to point directly at the data since there is not transport
	 * layer header defined.
	 */
	LINX_SKB_RESET_TRANSPORT_HEADER(*skb);

	/* Depending on if linx_sendmsg or the user space sendto/sendmsg are
	 * used, the signal is stored in a kernel space buffer or a user space
	 * buffer. When the data is copied into the sk send buffer different
	 * methods for copying of the data are used depending on the data
	 * location.*/

	/* Find the base pointer to the signal and make room for the signal. */
	if (unlikely(!frag))
		skb_put(*skb, payload_size);

	/* Copy the signal, that can be in user- or kernelspace, to the skb. */
	err = linx_skb_store_bits(*skb, payload, payload_size, buffer_type);
	if (unlikely(err != 0)) {
		kfree_skb(*skb);
		*skb = NULL;
		linx_err("Failed to copy payload, err=%d", err);
		return err;
	}
	return 0;
}

static int linx_skb_create_no_copy(struct sock *to, struct sk_buff **skb)
{
	int err = 0;

	linx_check_sock(to);
	
	spin_lock_bh(&linx_sk(to)->skb_alloc_lock);
	*skb = linx_alloc_send_skb(to, sizeof(void *), &err);	
	spin_unlock_bh(&linx_sk(to)->skb_alloc_lock);

	if (unlikely(*skb == NULL || err != 0)) {
		if (err == -EAGAIN) {
			linx_err("Failed to allocate skb with "
				 "sock_alloc_send_skb\n EAGAIN is returned\n");
			return -ENOMEM;
		} else if (err == -EPIPE) {
			/* The socket is shutting down, handle this silently. */
			if (unlikely(*skb != NULL))
				kfree_skb(*skb);
			*skb = NULL;
			return 0;
		} else {
			return err;
		}
	}

	/* h is a union of transport header pointers, the LINX uses the raw
	 * pointer to point directly at the data since there is not transport
	 * layer header defined.
	 */
	LINX_SKB_RESET_TRANSPORT_HEADER(*skb);

	/* Depending on if linx_sendmsg or the user space sendto/sendmsg are
	 * used, the signal is stored in a kernel space buffer or a user space
	 * buffer. When the data is copied into the sk send buffer different
	 * methods for copying of the data are used depending on the data
	 * location.*/

	/* Find the base pointer to the signal and make room for the signal. */
	skb_put(*skb, sizeof(void *));

	return 0;
}

void skb_insert_oob(struct sk_buff *oob_skb, struct sk_buff_head *list)
{
	struct sk_buff *trav = NULL;

	spin_lock_bh(&list->lock);
	if(unlikely(list->qlen == 0)) {
		__skb_queue_head(list, oob_skb);
		goto out;
	}
	skb_queue_walk(list, trav) {
		if(!(MSG_OOB & ((struct linx_skb_cb *)trav->cb)->flags))
			break;
	}

	if(unlikely(trav == (struct sk_buff *)list)) /* only oob's in list */
		__skb_queue_tail(list, oob_skb);
	else
		__skb_insert(oob_skb, trav->prev, trav, list);
 out:
	spin_unlock_bh(&list->lock);
}

/*
 *
 * Socket send and receive.
 *
 */

int
linx_do_legacy_sendmsg(struct sock *sk,
		       void *payload,
		       LINX_OSBUFSIZE payload_size,
		       struct sock *to,
		       LINX_SPID to_spid,
		       struct sock *from,
		       LINX_SPID from_spid,
		       uint32_t buffer_type)
{
        int err = 0;
        struct sk_buff *skb;
        struct linx_skb_cb *cb;

        linx_check_sock(sk);
        LINX_ASSERT(payload_size >= sizeof(LINX_SIGSELECT));
        LINX_ASSERT(from != NULL);
        LINX_ASSERT(to != NULL);

#ifdef LINX_MESSAGE_TRACE
        linx_message_trace(payload, payload_size, to,
                           to_spid, from_spid, buffer_type);
#endif

        if (linx_sk(to)->type == LINX_TYPE_REMOTE) {
                err = linx_rlnh_send(payload,
                                     payload_size,
                                     from, from_spid, to, to_spid, buffer_type);

                /* Statistics - increase the remote sent bytes/signals for the
                 * sending socket. */
                LINX_SOCK_STAT_SEND_REMOTE_SIGNAL(from, payload_size);

                /* Statistics - increase the sent bytes/signals for the remote
                 * (phantom) socket. */
                LINX_SOCK_STAT_RECV_LOCAL_SIGNAL(to, payload_size);

                /* Statistics - increase the sent bytes/signals for the link
                 * socket. */
                LINX_LINK_STAT_SEND_SIGNAL(to, payload_size);

                return err;
        }

        /* Add to the receivers receive queue. */
        if (unlikely(!BUF_TYPE_SKB(buffer_type))) {
                err = linx_skb_create(payload, payload_size, to, buffer_type,
                                      &skb, linx_mem_frag);
                if (unlikely(err != 0))
                        goto out;
                if (unlikely(skb == NULL)) {
                        /* socket is shutting down. handle silently */
                        return 0;
                }

                LINX_ASSERT(skb != NULL);
                /* Recvmsg needs to know the signal number.  cb->signo is
                 * always host byte order. */
                cb = (struct linx_skb_cb *)skb->cb;
                if (BUF_TYPE_USER(buffer_type)) {
                        get_user(cb->signo, (LINX_SIGSELECT *) payload);
                } else {
                        cb->signo = *((LINX_SIGSELECT *) payload);
                }
        } else {
                skb = payload;
                /* Attach, hunt, tmo and newlink signals are already owned
                 * by the caller, a new skb_sent_owner_w will increase the
                 * use count. */
                if (likely(skb->sk != to)) {
                        skb_set_owner_w(skb, to);
                }
        }

        cb = (struct linx_skb_cb *)skb->cb;

        /* Send w sender. */
        cb->from_spid = from_spid;
        cb->ref = 0;
        cb->destructor = NULL;          
        cb->flags = 0;
        cb->payload_size = payload_size;
	cb->pass_ptr = 0;

        /* This implementation of sendmsg do not support send timeouts. Set
         * using setsockopt(SO_SNDTIMEO). */

        atomic_inc(&linx_no_of_queued_signals);
        
        if(unlikely(BUF_TYPE_OOB(buffer_type))) {
                /* Mark as OOB. Put before in-band sigs, but after OOB sigs */
                cb->flags |= MSG_OOB;
                skb_insert_oob(skb, &to->sk_receive_queue);
        } else {
                /* Put the signal at the end of the receivers queue. */
                skb_queue_tail(&to->sk_receive_queue, skb);
        }
                
        /* The socket is closing down, this check is to avoid a race with the
         * purgining of the receive queue in linx_release. This check must
         * be done AFTER skb_queue_tail! */
        if (unlikely(to->sk_shutdown == SHUTDOWN_MASK)) {
                linx_skb_queue_purge(to, &to->sk_receive_queue);
                return 0;
        }

#ifdef SOCK_STAT
        /* Statistics - increase the sent bytes/signals for the sender (could
         * be both a local and a remote socket). */
        LINX_SOCK_STAT_SEND_LOCAL_SIGNAL(from, (uint64_t) payload_size);
        
        /* This is so linx_recvmsg() knows if the sender was a local or
         * remote socket when counting local/remote received bytes. */
        cb->type = linx_sk(from)->type;
        
        if (linx_sk(from)->type == LINX_TYPE_REMOTE) {
                /* Statistics - increase the sent bytes/signals for the
                 * remote link socket if the sending socket is of type
                 * REMOTE. */
                LINX_LINK_STAT_RECV_SIGNAL(from, payload_size);
        }
        
        LINX_SOCK_STAT_QUEUE_SIGNAL(to, payload_size);
#endif
        /* Wake up the receiver, if it sleeps and wait for the signal. */
        to->sk_data_ready(to, payload_size);

        return 0;
      out:
        linx_err("linx_do_legacy_sendmsg() failed, err=%d", err);
        return err;
}

int
linx_do_sendmsg(struct sock *sk,
		void *payload,
		LINX_OSBUFSIZE payload_size,
		struct sock *to,
		LINX_SPID to_spid,
		struct sock *from,
		LINX_SPID from_spid,
		uint32_t buffer_type,
		uint32_t *consumed)
{
	int err = 0;
	struct sk_buff *skb;
	struct linx_skb_cb *cb;

	linx_check_sock(sk);
	LINX_ASSERT(payload_size >= sizeof(LINX_SIGSELECT));
	LINX_ASSERT(from != NULL);
	LINX_ASSERT(to != NULL);

#ifdef LINX_MESSAGE_TRACE
	linx_message_trace(payload, payload_size, to,
			   to_spid, from_spid, buffer_type);
#endif

	*consumed = 0;

	if (linx_sk(to)->type == LINX_TYPE_REMOTE) {
		err = linx_rlnh_send(payload,
				     payload_size,
				     from, from_spid, to, to_spid, buffer_type);

		/* Statistics - increase the remote sent bytes/signals for the
		 * sending socket. */
		LINX_SOCK_STAT_SEND_REMOTE_SIGNAL(from, payload_size);

		/* Statistics - increase the sent bytes/signals for the remote
		 * (phantom) socket. */
		LINX_SOCK_STAT_RECV_LOCAL_SIGNAL(to, payload_size);

		/* Statistics - increase the sent bytes/signals for the link
		 * socket. */
		LINX_LINK_STAT_SEND_SIGNAL(to, payload_size);

		return err;
	}

	/* Add to the receivers receive queue. */
	if (unlikely(!BUF_TYPE_SKB(buffer_type))) {
		if (linx_sk(to)->owner_tgid == linx_sk(sk)->owner_tgid) {
			err = linx_skb_create_no_copy(to, &skb);
		} else {
			err = linx_skb_create(payload,
					      payload_size,
					      to,
					      buffer_type,
					      &skb,
					      linx_mem_frag);
		}

		if (unlikely(err != 0))
			goto out;
		if (unlikely(skb == NULL)) {
			/* socket is shutting down. handle silently */
			return 0;
		}

		LINX_ASSERT(skb != NULL);
		/* Recvmsg needs to know the signal number.  cb->signo is
		 * always host byte order. */
		cb = (struct linx_skb_cb *)skb->cb;
		if (BUF_TYPE_USER(buffer_type)) {
			get_user(cb->signo, (LINX_SIGSELECT *) payload);
		} else {
			cb->signo = *((LINX_SIGSELECT *) payload);
		}

		if (linx_sk(to)->owner_tgid == linx_sk(sk)->owner_tgid) {
			*consumed = 1;
			cb->pass_ptr = 1;
			((unsigned long *)(skb->data))[0] =
				(unsigned long)payload;
		} else {
			cb->pass_ptr = 0;
		}
	} else {
		skb = payload;
		/* Attach, hunt, tmo and newlink signals are already owned
		 * by the caller, a new skb_sent_owner_w will increase the
		 * use count. */
		if (likely(skb->sk != to)) {
			skb_set_owner_w(skb, to);
		}
		cb = (struct linx_skb_cb *)skb->cb;
		cb->pass_ptr = 0;
	}


	/* Send w sender. */
	cb->from_spid = from_spid;
	cb->ref = 0;
	cb->destructor = NULL;		
	cb->flags = 0;
	cb->payload_size = payload_size;

	/* This implementation of sendmsg do not support send timeouts. Set
	 * using setsockopt(SO_SNDTIMEO). */

	atomic_inc(&linx_no_of_queued_signals);
	
	if(unlikely(BUF_TYPE_OOB(buffer_type))) {
		/* Mark as OOB. Put before in-band sigs, but after OOB sigs */
		cb->flags |= MSG_OOB;
		skb_insert_oob(skb, &to->sk_receive_queue);
	} else {
		/* Put the signal at the end of the receivers queue. */
		skb_queue_tail(&to->sk_receive_queue, skb);
	}
		
	/* The socket is closing down, this check is to avoid a race with the
	 * purgining of the receive queue in linx_release. This check must
	 * be done AFTER skb_queue_tail! */
	if (unlikely(to->sk_shutdown == SHUTDOWN_MASK)) {
		linx_skb_queue_purge(to, &to->sk_receive_queue);
		return 0;
	}

#ifdef SOCK_STAT
	/* Statistics - increase the sent bytes/signals for the sender (could
	 * be both a local and a remote socket). */
	LINX_SOCK_STAT_SEND_LOCAL_SIGNAL(from, (uint64_t) payload_size);
	
	/* This is so linx_recvmsg() knows if the sender was a local or
	 * remote socket when counting local/remote received bytes. */
	cb->type = linx_sk(from)->type;
	
	if (linx_sk(from)->type == LINX_TYPE_REMOTE) {
		/* Statistics - increase the sent bytes/signals for the
		 * remote link socket if the sending socket is of type
		 * REMOTE. */
		LINX_LINK_STAT_RECV_SIGNAL(from, payload_size);
	}
	
	LINX_SOCK_STAT_QUEUE_SIGNAL(to, payload_size);
#endif
	/* Wake up the receiver, if it sleeps and wait for the signal. */
	to->sk_data_ready(to, payload_size);

	return 0;
      out:
	linx_err("linx_do_sendmsg() failed, err=%d", err);
	return err;
}

/*
 * __linx_do_sendmsg_skb_to_local_sk
 * Simplified version of linx_do_sendmsg used to deliver attach/hunt/newlink/tmo
 * signals, this function can be called with a spinlock taken.
 */

int __linx_do_sendmsg_skb_to_local_sk(struct sock *to, struct sk_buff *skb,
				      LINX_OSBUFSIZE payload_size,
				      struct sock *from, LINX_SPID from_spid,
				      void (*destructor)(uint32_t),
				      uint32_t ref)
{
	struct linx_skb_cb *cb;
	linx_check_sock(to);
	LINX_ASSERT(payload_size >= sizeof(LINX_SIGSELECT));
	LINX_ASSERT(skb->sk == to);

#ifdef LINX_MESSAGE_TRACE
	linx_message_trace(skb, payload_size, to, linx_sock_to_spid(to),
			   from_spid, BUFFER_TYPE_SKB);
#endif
	cb = (struct linx_skb_cb *)skb->cb;
	
	cb->from_spid = from_spid;
	cb->ref = ref;
	cb->destructor = destructor;
	cb->flags = 0;
	cb->payload_size = payload_size;
	cb->pass_ptr = 0;
	
	atomic_inc(&linx_no_of_queued_signals);
	
	/* Put the signal at the end of the receivers queue. */
	skb_queue_tail(&to->sk_receive_queue, skb);

	if (unlikely(to->sk_shutdown == SHUTDOWN_MASK)) {
		/* Handle this in caller since the caller has locked */
		return -1;
	}

#ifdef SOCK_STAT
	if (likely(NULL != from)) {
		LINX_SOCK_STAT_SEND_LOCAL_SIGNAL(from, (uint64_t) payload_size);
		cb->type = linx_sk(from)->type;
	}
	LINX_SOCK_STAT_QUEUE_SIGNAL(to, payload_size);
#endif
	/* Wake up the receiver, if it sleeps and waits for the signal. */
	to->sk_data_ready(to, payload_size);

	return 0;
}

/* Send a signal as a consequence of sendmsg, sendto or linx_sendmsg. */
static int linx_sendmsg(struct kiocb *kiocb, struct socket *sock,
			struct msghdr *msg, size_t len)
{
	struct sock *sk = sock->sk;
	struct sockaddr_linx *linx_addr = msg->msg_name;
	struct sock *to = NULL, *from = NULL;
	int err = 0;
	LINX_SPID from_spid;
	LINX_OSBUFSIZE payload_size = msg->msg_iov->iov_len;
	uint32_t buffer_type = BUFFER_TYPE_USER;

	linx_trace_enter(LINX_TRACEGROUP_AF_LINX,
			 "%p, %p, %p, %Zd", kiocb, sock, msg, len);

	/* Check the spid of the currently running socket. */
	linx_check_socket(sock);
	linx_check_spid(sk);

	if ((err = linx_sk_trylock(sk)) < 0) {
		return err;
	}
	
	LINX_ASSERT(msg->msg_iovlen == 1);

	/* If no address is given, the send has no receiver since the socket is
	 * not connected. */
	if (unlikely(msg->msg_namelen == 0)) {
		linx_sk_unlock(sk);
		return -ENOTCONN;
	}
#ifdef ERRORCHECKS
	if (unlikely(msg->msg_iov->iov_len < sizeof(LINX_SIGSELECT))) {
		linx_err("Buffer length is too short (%u).\n",
			 (unsigned int)msg->msg_iov->iov_len);
		linx_sk_unlock(sk);
		return -EINVAL;
	}

	if (unlikely(msg->msg_iov->iov_base == NULL)) {
		linx_err("Buffer is NULL.\n");
		linx_sk_unlock(sk);
		return -EINVAL;
	}

	if (unlikely(linx_validate_sockaddr_linx(linx_addr,
						 msg->msg_namelen) ==
		     LINX_FALSE)) {
		linx_err("Bad sender.");
		linx_sk_unlock(sk);
		return -EINVAL;
	}
#endif

	/* Translate the destination address to a sock structure. */
	to = linx_spid_to_sock(linx_addr->spid);
	if (unlikely(to == NULL)) {
		/* NOTE: Sending to an already killed process is accepted and
		 *       shall be silent. The user detect this by checking the
		 *       return value -1 and errno -ECONNRESET. */
		if (!linx_is_zombie_spid(linx_addr->spid)) {
			linx_trace(LINX_TRACE_WARNING,
				   LINX_TRACEGROUP_AF_LINX,
				   "Illegal destination spid.");
			linx_sk_unlock(sk);
			return -EINVAL;
		}
		linx_sk_unlock(sk);
		return -ECONNRESET;
	}

	/* If the sender is not bound, the signal can not be sent. */
	if (unlikely(!linx_sk(sk)->addr)) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (likely(msg->msg_controllen == 0)) {
		from_spid = linx_sock_to_spid(sk);
	} else {
		struct linx_sender_param *sp;
		sp = CMSG_DATA(msg->msg_control);
		from_spid = sp->from;
		from = linx_spid_to_sock(from_spid);
		if (unlikely(from == NULL)) {
			if (!linx_is_zombie_spid(from_spid)) {
				err = -EINVAL;
				goto out;
			}
			err = -ECONNRESET;
			goto out;
		}
	}
	if(msg->msg_flags & MSG_OOB)
		buffer_type |= BUFFER_TYPE_OOB;

	err = linx_do_legacy_sendmsg(sk,
				     msg->msg_iov->iov_base,
				     msg->msg_iov->iov_len,
				     to,
				     linx_addr->spid,
				     from == NULL ? sk : from,
				     from_spid,
				     buffer_type);
	
	/* Release the socket (locked by linx_spid_to_sock). */
	sock_put(to);
	if (unlikely(from))
		sock_put(from);
	linx_sk_unlock(sk);
	return err < 0 ? err : payload_size;

      out:
	if (to) {
		/* Release the socket so it can be closed. */
		sock_put(to);
	}
	linx_sk_unlock(sk);
	return err;
}

static int linx_ioctl_legacy_send(struct sock *sk, unsigned long arg)
{
        uint32_t from_spid, to_spid, size, sig_attr;
        uint32_t buffer_type = BUFFER_TYPE_USER;
        unsigned long buffer;
        struct sock *to = NULL;
        int err = 0;
        
        const struct linx_sndrcv_legacy_param __user *sndrcv =
                (struct linx_sndrcv_legacy_param *)arg;

        LINX_ASSERT(access_ok(VERFIFY_READ, sndrcv,
                              sizeof(struct linx_sndrcv_legacy_param)));
        
        linx_check_spid(sk);
        
        /* Get needed params from user-land */
        get_user(to_spid, &sndrcv->to);
        get_user(from_spid, &sndrcv->from);
        get_user(size, &sndrcv->size);
        get_uptr(buffer, &sndrcv->buffer);
        get_user(sig_attr, &sndrcv->sig_attr);

        LINX_ASSERT(size >= sizeof(LINX_SIGSELECT));
        LINX_ASSERT(buffer != 0x0);
        
        to = linx_spid_to_sock(to_spid);
        if (unlikely(to == NULL)) {
                /* NOTE: Sending to an already killed process is accepted and
                 *       shall be silent. The user detect this by checking the
                 *       return value -1 and errno -ECONNRESET. */
                if (!linx_is_zombie_spid(to_spid)) {
                        linx_trace(LINX_TRACE_WARNING,
                                   LINX_TRACEGROUP_AF_LINX,
                                   "Illegal destination spid.");
                        return -EINVAL;
                }
                return -ECONNRESET;
        }
        
        /* If the sender is not bound, the signal can not be sent. */
        if (unlikely(!linx_sk(sk)->addr)) {
                err = -EOPNOTSUPP;
                goto out;
        }

        /* Append attributes */
        if (unlikely(sig_attr & MSG_OOB))
                buffer_type |= BUFFER_TYPE_OOB;
        
        if (unlikely(from_spid != linx_sock_to_spid(sk))) {
                /* linx_send_w_s(...) */
                struct sock *from = linx_spid_to_sock(from_spid);
                if (unlikely(from == NULL)) {
                        if (!linx_is_zombie_spid(from_spid)) {
                                err = -EINVAL;
                                goto out;
                        }
                        err = -ECONNRESET;
                        goto out;
                }
                err = linx_do_legacy_sendmsg(sk, (void *)buffer, size, to,
                                      to_spid, from, from_spid, buffer_type);
                sock_put(from);
        } else {
                /* linx_send(...) */
                err = linx_do_legacy_sendmsg(sk, (void *)buffer, size, to,
                                      to_spid, sk, from_spid, buffer_type);
        }
 out:
        /* Release the socket (locked by linx_spid_to_sock). */
        sock_put(to);
        
        return err;
}

static int linx_ioctl_legacy_receive(struct sock *sk, unsigned long arg)
{
        uint32_t from_spid, size, sigselect_size, sig_attr;
        unsigned long buffer;
        struct iovec to;
        
        int err = 0;
        struct sk_buff *skb;
        struct linx_skb_cb *cb;
        int flags = 0;
        uint32_t timeo = 0;
        
        const struct linx_sndrcv_legacy_param __user *sndrcv =
                (struct linx_sndrcv_legacy_param *)arg;
        
        LINX_ASSERT(access_ok(VERFIFY_READ, sndrcv,
                              sizeof(struct linx_sndrcv_legacy_param)));
        
        LINX_ASSERT(access_ok(VERFIFY_WRITE, sndrcv,
                              sizeof(struct linx_sndrcv_legacy_param)));
        
        /* Get needed params from user-land */
        get_user(from_spid, &sndrcv->from);
        get_user(size, &sndrcv->size);
        get_uptr(buffer, &sndrcv->buffer);
        get_user(sigselect_size, &sndrcv->sigselect_size);
        get_user(sig_attr, &sndrcv->sig_attr);
        get_user(timeo, &sndrcv->tmo);

        if (unlikely(size < sizeof(LINX_SIGSELECT))) {
                err = -EINVAL;
                goto out;
        }
        
        if (unlikely(sigselect_size != 0 || from_spid != LINX_ILLEGAL_SPID)) {
                LINX_SIGSELECT *filter = NULL, *old_filter;
                if (likely(sigselect_size != 0)) {
                        unsigned long sigselect;
                        /* Set filter, also set from spid if set */
                        filter = linx_kmalloc(sigselect_size);
                        if (unlikely(filter == NULL)) {
                                err = -ENOMEM;
                                goto out;
                        }
                        
                        /* Get ptr to sigselect mask from user-land. */
                        get_uptr(sigselect, &sndrcv->sigselect);

                        /* Copy the sigselect mask from user-land. */
                        if (unlikely(0 != copy_from_user(filter,
                                                         (void *)sigselect,
                                                         sigselect_size))) {
                                linx_kfree(filter);
                                err = -EFAULT;
                                goto out;
                        }
                }
                old_filter = linx_sk(sk)->filter;
                
                spin_lock_bh(&sk->sk_receive_queue.lock);
                linx_sk(sk)->filter = filter;
                linx_sk(sk)->from_filter = from_spid;
                spin_unlock_bh(&sk->sk_receive_queue.lock);
                
                if (old_filter) {
                        linx_kfree(old_filter);
                }

                if (unlikely(from_spid != LINX_ILLEGAL_SPID)) {
                        struct sock *sk_from = linx_spid_to_sock(from_spid);
                        if (unlikely(sk_from == NULL)) {
                                if (!linx_is_zombie_spid(from_spid)) {
                                        err = -EINVAL;
                                        goto out;
                                }
                        } else {
                                sock_put(sk_from);
                        }
                }
        } else {
                /* Reseting the filters forces the default behavior. */
                reset_receive_filter(sk);
        }

        /* Receive the first datagram of the receive queue. */
        if(unlikely(timeo != (uint32_t)~0)) {
                skb = linx_recv_datagram(sk, flags, &err,
                                         size, msecs_to_jiffies(timeo));
        
        } else {
                skb = linx_recv_datagram(sk, flags, &err,
                                         size, sk->sk_rcvtimeo);
        }
        
        if (unlikely(err != 0)) {
                linx_debug(LINX_TRACEGROUP_AF_LINX,
                           "linx_recv_datagram() failed, "
                           "err=%d.", err);
                goto out;
        }

        /* Timeout */
        if (unlikely(skb == NULL)) {
                put_user(0, (uint32_t *)&sndrcv->tmo);
                /* Let caller know that no signal was received. */
                put_user(0, (uint32_t *)buffer);
                goto out;
        }
                
        /* If the size of the receive buffer is larger than the datagram, the
         * size is decreased to the size of the datagram. If the receive buffer
         * can not hold the datagram, the signal is trucated and the truncated
         * data is lost.
         */
        cb = (struct linx_skb_cb *)skb->cb;
        if (unlikely(size < cb->payload_size)) {
                put_user(cb->payload_size, (uint32_t *)buffer);
                goto out;
        }
        size = cb->payload_size;

        /* Copy signal to user-land */
        to.iov_base = (void *)buffer;
        to.iov_len = (size_t)size;
        err = skb_copy_datagram_iovec(skb, 0, &to, size);
        if (unlikely(err < 0)) {
                linx_debug(LINX_TRACEGROUP_AF_LINX,
                           "skb_copy_datagram_iovec() failed, "
                           "err=%d.", err);
                goto out;
        }
        
        /* Put the endian converted signo in the signal */
        put_user(cb->signo, (uint32_t *)buffer);

        /* Copy signal attributes to user-land */
        put_user(cb->flags, (uint32_t *)&sndrcv->sig_attr);
        put_user(cb->from_spid, (uint32_t *)&sndrcv->from);
        put_user(size, (uint32_t *)&sndrcv->size);
        
#ifdef SOCK_STAT
        if (cb->type == LINX_TYPE_REMOTE) {
                LINX_SOCK_STAT_RECV_REMOTE_SIGNAL(sk, (uint64_t)size);
        } else {
                LINX_SOCK_STAT_RECV_LOCAL_SIGNAL(sk, (uint64_t)size);
        }
        LINX_SOCK_STAT_DEQUEUE_SIGNAL(sk, (uint64_t)size);
#endif

        if (unlikely(cb->destructor != NULL)) {
                cb->destructor(cb->ref);
        } else {
                spin_lock_bh(&sk->sk_receive_queue.lock);
                __skb_unlink_compat(skb, sk);
                spin_unlock_bh(&sk->sk_receive_queue.lock);
                
                kfree_skb(skb);
                atomic_dec(&linx_no_of_queued_signals);
        }
        
        if (unlikely(sigselect_size != 0 || from_spid != LINX_ILLEGAL_SPID))
                reset_receive_filter(sk);

        /* Return the size of the received datagram. */
        return size;
        
 out:
        if (unlikely(sigselect_size != 0 || from_spid != LINX_ILLEGAL_SPID))
                reset_receive_filter(sk);
        
        return err;
}

static int linx_ioctl_send(struct sock *sk, unsigned long arg)
{
	uint32_t from_spid, to_spid, size, sig_attr;
	uint32_t buffer_type = BUFFER_TYPE_USER;
	unsigned long buffer;
	struct sock *to = NULL;
	int err = 0;
	uint32_t consumed = 0;
	
	const struct linx_sndrcv_param __user *sndrcv =
		(struct linx_sndrcv_param *)arg;

	LINX_ASSERT(access_ok(VERFIFY_READ, sndrcv,
			      sizeof(struct linx_sndrcv_param)));
	
	linx_check_spid(sk);
	
	/* Get needed params from user-land */
	get_user(to_spid, &sndrcv->to);
	get_user(from_spid, &sndrcv->from);
	get_user(size, &sndrcv->size);
	get_uptr(buffer, &sndrcv->buffer);
	get_user(sig_attr, &sndrcv->sig_attr);

	LINX_ASSERT(size >= sizeof(LINX_SIGSELECT));
	LINX_ASSERT(buffer != 0x0);
	
	to = linx_spid_to_sock(to_spid);
	if (unlikely(to == NULL)) {
		/* NOTE: Sending to an already killed process is accepted and
		 *       shall be silent. The user detect this by checking the
		 *       return value -1 and errno -ECONNRESET. */
		if (!linx_is_zombie_spid(to_spid)) {
			linx_trace(LINX_TRACE_WARNING,
				   LINX_TRACEGROUP_AF_LINX,
				   "Illegal destination spid.");
			return -EINVAL;
		}
		return -ECONNRESET;
	}
	
	/* If the sender is not bound, the signal can not be sent. */
	if (unlikely(!linx_sk(sk)->addr)) {
		err = -EOPNOTSUPP;
		goto out;
	}

	/* Append attributes */
	if (unlikely(sig_attr & MSG_OOB))
		buffer_type |= BUFFER_TYPE_OOB;
	
	if (unlikely(from_spid != linx_sock_to_spid(sk))) {
		/* linx_send_w_s(...) */
		struct sock *from = linx_spid_to_sock(from_spid);
		if (unlikely(from == NULL)) {
			if (!linx_is_zombie_spid(from_spid)) {
				err = -EINVAL;
				goto out;
			}
			err = -ECONNRESET;
			goto out;
		}
		err = linx_do_sendmsg(sk, (void *)buffer, size, to,
				      to_spid, from, from_spid, buffer_type,
				      &consumed);
		sock_put(from);
	} else {
		/* linx_send(...) */
		err = linx_do_sendmsg(sk, (void *)buffer, size, to,
				      to_spid, sk, from_spid, buffer_type,
				      &consumed);
	}
	if (consumed) {
		err = 1;
	}
 out:
	/* Release the socket (locked by linx_spid_to_sock). */
	sock_put(to);
	
	return err;
}

static int linx_ioctl_receive(struct sock *sk, unsigned long arg)
{
	uint32_t from_spid, size, sigselect_size, sig_attr;
	unsigned long buffer;
	struct iovec to;
	
	int err = 0;
	struct sk_buff *skb;
	struct linx_skb_cb *cb;
	int flags = 0;
	uint32_t timeo = 0;
	
	const struct linx_sndrcv_param __user *sndrcv =
		(struct linx_sndrcv_param *)arg;
	
	LINX_ASSERT(access_ok(VERFIFY_READ, sndrcv,
			      sizeof(struct linx_sndrcv_param)));
	
	LINX_ASSERT(access_ok(VERFIFY_WRITE, sndrcv,
			      sizeof(struct linx_sndrcv_param)));
	
	/* Get needed params from user-land */
	get_user(from_spid, &sndrcv->from);
	get_user(size, &sndrcv->size);
	get_uptr(buffer, &sndrcv->buffer);
	get_user(sigselect_size, &sndrcv->sigselect_size);
	get_user(sig_attr, &sndrcv->sig_attr);
	get_user(timeo, &sndrcv->tmo);

	if (unlikely(size < sizeof(LINX_SIGSELECT))) {
		err = -EINVAL;
		goto out;
	}
	
	if (unlikely(sigselect_size != 0 || from_spid != LINX_ILLEGAL_SPID)) {
		LINX_SIGSELECT *filter = NULL, *old_filter;
		if (likely(sigselect_size != 0)) {
			unsigned long sigselect;
			/* Set filter, also set from spid if set */
			filter = linx_kmalloc(sigselect_size);
			if (unlikely(filter == NULL)) {
				err = -ENOMEM;
				goto out;
			}
			
			/* Get ptr to sigselect mask from user-land. */
			get_uptr(sigselect, &sndrcv->sigselect);

			/* Copy the sigselect mask from user-land. */
			if (unlikely(0 != copy_from_user(filter,
							 (void *)sigselect,
							 sigselect_size))) {
				linx_kfree(filter);
				err = -EFAULT;
				goto out;
			}
		}
		old_filter = linx_sk(sk)->filter;
		
		spin_lock_bh(&sk->sk_receive_queue.lock);
		linx_sk(sk)->filter = filter;
		linx_sk(sk)->from_filter = from_spid;
		spin_unlock_bh(&sk->sk_receive_queue.lock);
		
		if (old_filter) {
			linx_kfree(old_filter);
		}

		if (unlikely(from_spid != LINX_ILLEGAL_SPID)) {
			struct sock *sk_from = linx_spid_to_sock(from_spid);
			if (unlikely(sk_from == NULL)) {
				if (!linx_is_zombie_spid(from_spid)) {
					err = -EINVAL;
					goto out;
				}
			} else {
				sock_put(sk_from);
			}
		}
	} else {
		/* Reseting the filters forces the default behavior. */
		reset_receive_filter(sk);
	}

	/* Receive the first datagram of the receive queue. */
	if(unlikely(timeo != (uint32_t)~0)) {
		skb = linx_recv_datagram(sk, flags, &err,
					 size, msecs_to_jiffies(timeo));
	
	} else {
		skb = linx_recv_datagram(sk, flags, &err,
					 size, sk->sk_rcvtimeo);
	}
	
	if (unlikely(err != 0)) {
		linx_debug(LINX_TRACEGROUP_AF_LINX,
			   "linx_recv_datagram() failed, "
			   "err=%d.", err);
		goto out;
	}

	/* Timeout */
	if (unlikely(skb == NULL)) {
		put_user(0, (uint32_t *)&sndrcv->tmo);
		/* Let caller know that no signal was received. */
		put_user(0, (uint32_t *)buffer);
		goto out;
	}
		
	/* If the size of the receive buffer is larger than the datagram, the
	 * size is decreased to the size of the datagram. If the receive buffer
	 * can not hold the datagram, the signal is trucated and the truncated
	 * data is lost.
	 */
	cb = (struct linx_skb_cb *)skb->cb;
	if (unlikely(size < cb->payload_size)) {
		put_user(cb->payload_size, (uint32_t *)buffer);
		goto out;
	}
	size = cb->payload_size;

	if (!cb->pass_ptr) {
		/* Copy signal to user-land */
		to.iov_base = (void *)buffer;
		to.iov_len = (size_t)size;
		err = skb_copy_datagram_iovec(skb, 0, &to, size);
		if (unlikely(err < 0)) {
			linx_debug(LINX_TRACEGROUP_AF_LINX,
				   "skb_copy_datagram_iovec() failed, "
				   "err=%d.", err);
			goto out;
		}
		/* Put the endian converted signo in the signal */
		put_user(cb->signo, (uint32_t *)buffer);
	}

	/* Copy signal attributes to user-land */
	put_user(cb->flags, (uint32_t *)&sndrcv->sig_attr);
	put_user(cb->from_spid, (uint32_t *)&sndrcv->from);
	put_user(size, (uint32_t *)&sndrcv->size);

	if (cb->pass_ptr) 
		put_uptr(((unsigned long *)(skb->data))[0],
			 (unsigned long *)&sndrcv->real_buf);
	
	
#ifdef SOCK_STAT
	if (cb->type == LINX_TYPE_REMOTE) {
		LINX_SOCK_STAT_RECV_REMOTE_SIGNAL(sk, (uint64_t)size);
	} else {
		LINX_SOCK_STAT_RECV_LOCAL_SIGNAL(sk, (uint64_t)size);
	}
	LINX_SOCK_STAT_DEQUEUE_SIGNAL(sk, (uint64_t)size);
#endif

	if (unlikely(cb->destructor != NULL)) {
		cb->destructor(cb->ref);
	} else {
		spin_lock_bh(&sk->sk_receive_queue.lock);
		__skb_unlink_compat(skb, sk);
		spin_unlock_bh(&sk->sk_receive_queue.lock);
		
		kfree_skb(skb);
		atomic_dec(&linx_no_of_queued_signals);
	}
	
	if (unlikely(sigselect_size != 0 || from_spid != LINX_ILLEGAL_SPID))
		reset_receive_filter(sk);

	/* Return the size of the received datagram. */
	return size;
	
 out:
	if (unlikely(sigselect_size != 0 || from_spid != LINX_ILLEGAL_SPID))
		reset_receive_filter(sk);
	
	return err;
}

/* The linx_recvmsg function is called when either recvmsg or recvfrom are
 * called by the user. */
static int linx_recvmsg(struct kiocb *iocb, struct socket *sock,
			struct msghdr *msg, size_t size, int flags)
{
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	int ret = 0;
	char cmsg[CMSG_SPACE(sizeof(struct linx_receive_filter_param))];
	struct linx_receive_filter_param *rfp;
	struct linx_skb_cb *cb;
	LINX_SIGSELECT *signop;

	linx_check_socket(sock);
	linx_check_spid(sk);

	if ((ret = linx_sk_trylock(sk)) < 0) {
		return ret;
	}
	
	LINX_ASSERT(msg->msg_iovlen == 1);
	
	linx_trace_enter(LINX_TRACEGROUP_AF_LINX,
			 "%p, %p, %p, %Zd, %d", iocb, sock, msg, size, flags);

	/* Sanity check the parameters. */

#ifdef ERRORCHECKS
	if (unlikely(size < sizeof(LINX_SIGSELECT))) {
		ret = -EINVAL;
		goto out;
	}
#endif

#ifdef ERRORCHECKS
	if (unlikely(msg->msg_namelen < sizeof(struct sockaddr_linx))) {
		ret = -EINVAL;
		goto out;
	}
#endif

	if (unlikely(!msg->msg_name)) {
		ret = -EINVAL;
		goto out;
	}
#ifdef ERRORCHECKS
	if (unlikely(flags & MSG_PEEK)) {
		ret = -EOPNOTSUPP;
		goto out;
	}
#endif

	if (likely(msg->msg_controllen != 0)) {
		if (unlikely(msg->msg_controllen > sizeof(cmsg)) ||
		    unlikely(0 != copy_from_user(cmsg, msg->msg_control,
		    msg->msg_controllen))) {
			ret = -EFAULT;
			goto out;
		}
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
		if (unlikely(flags & MSG_CMSG_COMPAT)) {
			rfp = ((struct linx_receive_filter_param *)
			       (CMSG_COMPAT_DATA(((struct cmsghdr *)cmsg))));
			linx_compat_linx_receive_filter_param(rfp);
		} else
#endif
#endif
			rfp = ((struct linx_receive_filter_param *)
			       (CMSG_DATA(((struct cmsghdr *)cmsg))));

		ret = setup_receive_filter(sk, rfp);
		if (unlikely(ret < 0)) {
			goto out;
		}
		if (unlikely(rfp->from != LINX_ILLEGAL_SPID)) {
			struct sock *sk_from = linx_spid_to_sock(rfp->from);
			if (sk_from == NULL) {
				if (!linx_is_zombie_spid(rfp->from)) {
					ret = -EINVAL;
					goto out;
				}
			} else {
				sock_put(sk_from);
			}
		}
	} else {
		/* Reseting the filters forces the default behavior. */
		reset_receive_filter(sk);
	}

	/* Receive the first datagram of the receive queue. */
	skb = linx_recv_datagram(sk, flags, &ret, size,sk->sk_rcvtimeo);
	if (unlikely(ret != 0)) {
		linx_debug(LINX_TRACEGROUP_AF_LINX, "linx_recv_datagram() "
			   "failed, err=%d.", ret);
		goto out;
	}
	LINX_ASSERT(skb != NULL);

	/* If the size of the receive buffer is larger than the datagram, the
	 * size is decreased to the size of the datagram. If the receive buffer
	 * can not hold the datagram, the signal is trucated and the truncated
	 * data is lost.
	 */

	cb = (struct linx_skb_cb *)skb->cb;

	if (likely(size > cb->payload_size)) {
		size = cb->payload_size;
	} else if (unlikely(size < cb->payload_size)) {
		put_user(cb->payload_size,
			 (int __user *)(msg->msg_iov->iov_base));
		ret = 0;
		goto out;
	}

	/* Copy the senders sockaddr_linx information to the msg header. */
	linx_copy_addr(msg, skb->sk, cb->from_spid);

	/* Save a pointer to the signo, skb_copy_datagram_iovec updates
	 * msg-msg_iov->iov_base while copying and we need the original. */
	signop = (LINX_SIGSELECT *) msg->msg_iov->iov_base;

	/* Copy the payload of the signal to the receive buffer. */
	ret = skb_copy_datagram_iovec(skb, 0, msg->msg_iov, size);
	if (unlikely(ret < 0)) {
		goto out;
	}

	ret = put_user(cb->signo, (int __user *)(signop));
	if (unlikely(ret < 0)) {
		ret = -EFAULT;
		goto out;
	}
#ifdef SOCK_STAT
	if (cb->type == LINX_TYPE_REMOTE) {
		LINX_SOCK_STAT_RECV_REMOTE_SIGNAL(sk, (uint64_t) size);
	} else {
		LINX_SOCK_STAT_RECV_LOCAL_SIGNAL(sk, (uint64_t) size);
	}
	LINX_SOCK_STAT_DEQUEUE_SIGNAL(sk, (uint64_t) size);
#endif
	/* Return the size of the received datagram. */
	ret = size;

	/* Is this signal OOB? */
	if(cb->flags & MSG_OOB)
		msg->msg_flags |= MSG_OOB;

	if (unlikely(cb->destructor != NULL)) {
		cb->destructor(cb->ref);
	} else {
		spin_lock_bh(&sk->sk_receive_queue.lock);
		__skb_unlink_compat(skb, sk);
		spin_unlock_bh(&sk->sk_receive_queue.lock);
		
		/* Free the received datagram kernel resources. */
		skb_free_datagram(sk, skb);
		
		atomic_dec(&linx_no_of_queued_signals);
	}

      out:
	if (likely(msg->msg_controllen != 0))
		reset_receive_filter(sk);

	linx_sk_unlock(sk);
	
	return ret;
}

/*
 *
 * Ioctl i.e. misc handling.
 *
 */

static int linx_ioctl_hunt(struct sock *sk, unsigned long arg, int compat)
{
	LINX_SPID hunt_spid, spid = linx_sock_to_spid(sk);
	int err = 0;
	struct linx_hunt_param hunt_param;
	int hunt_param_size = sizeof(struct linx_hunt_param);

#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		hunt_param_size = linx_compat_size(linx_hunt_param);
#endif
#endif

	linx_trace_enter(LINX_TRACEGROUP_AF_LINX, "%p, %lu", sk, arg);

	/* NOTE: linx_hunt will make sure the owner and from pids
	 *       are correct. */

	/* Copy the hunt_param structure from user space to kernel space. */
	if (0 != copy_from_user(&hunt_param, (void *)arg, hunt_param_size)) {
		return -EFAULT;
	}
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		linx_compat_linx_hunt_param(&hunt_param);
#endif
#endif

	err = linx_hunt(sk, hunt_param.name, hunt_param.namelen, hunt_param.sig,
			hunt_param.sigsize, spid, hunt_param.from, &hunt_spid,
			LINX_FALSE);
	return err;
}

static int linx_ioctl_attach(struct sock *sk, unsigned long arg, int compat)
{
	struct linx_attach_param attach_param;
	LINX_OSATTREF attref;
	int err;
	int attach_param_size = sizeof(struct linx_attach_param);

#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		attach_param_size = linx_compat_size(linx_attach_param);
#endif
#endif

	linx_trace_enter(LINX_TRACEGROUP_AF_LINX, "%p, %lu", sk, arg);

	/* Copy the attach_param structure from user space to kernel space. */
	if (0 != copy_from_user(&attach_param, (void *)arg,
				attach_param_size)) {
		return -EFAULT;
	}
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		linx_compat_linx_attach_param(&attach_param);
#endif
#endif

	err = linx_attach(sk,
			  attach_param.spid,
			  attach_param.sig,
			  attach_param.sigsize, &attref, LINX_FALSE);

	if (err != 0)
		return err;

#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat)) {
		put_user(attref, (int __user *)
			 ((char *)(arg) +
			  linx_compat_offsetof(linx_attach_param, attref)));
	} else
#endif
#endif
		put_user(attref, (int __user *)
			 &((struct linx_attach_param *)arg)->attref);
	return 0;
}

static int linx_ioctl_detach(struct sock *sk, unsigned long arg)
{
	struct linx_detach_param detach_param;
	int err;

	linx_trace_enter(LINX_TRACEGROUP_AF_LINX, "%p, %lu", sk, arg);

	/* Copy the attach_param structure from user space to kernel space. */
	if (0 != copy_from_user(&detach_param, (void *)arg,
				sizeof(struct linx_detach_param))) {
		return -EFAULT;
	}

	err = linx_detach(sk, detach_param.attref);

	return err;
}

static int linx_ioctl_receive_filter(struct sock *sk,
				     unsigned long arg, int compat)
{
	struct linx_receive_filter_param rfp;
	int rfp_size = sizeof(struct linx_receive_filter_param);

#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		rfp_size = linx_compat_size(linx_receive_filter_param);
#endif
#endif

	linx_trace_enter(LINX_TRACEGROUP_AF_LINX, "%p, %lu", sk, arg);

	/* Copy the hunt_param structure from user space to kernel space. */
	if (0 != copy_from_user(&rfp, (void *)arg, rfp_size)) {
		return -EFAULT;
	}
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		linx_compat_linx_receive_filter_param(&rfp);
#endif
#endif

	if (rfp.from != LINX_ILLEGAL_SPID) {
		struct sock *sk_from = linx_spid_to_sock(rfp.from);
		if (sk_from == NULL) {
			if (!linx_is_zombie_spid(rfp.from)) {
				return -EINVAL;
			}
		} else {
			sock_put(sk_from);
		}
	}

	linx_sk(sk)->state = LINX_STATE_POLL;

	return setup_receive_filter(sk, &rfp);
}

static int linx_ioctl_request_tmo(struct sock *sk,
				  unsigned long arg, int compat)
{
	struct linx_tmo_param tmo_param;
	LINX_OSTMOREF tmoref;
	int err;
	int tmo_param_size = sizeof(struct linx_tmo_param);

	linx_trace_enter(LINX_TRACEGROUP_AF_LINX, "%p, %lu", sk, arg);

#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		tmo_param_size = linx_compat_size(linx_tmo_param);
#endif
#endif
	/* Copy the tmo_param structure from user space to kernel space. */
	if (0 != copy_from_user(&tmo_param, (void *)arg, tmo_param_size)) {
		return -EFAULT;
	}
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		linx_compat_linx_tmo_param(&tmo_param);
#endif
#endif
	err = linx_request_tmo(sk,
			       tmo_param.tmo,
			       tmo_param.sig, tmo_param.sigsize, &tmoref);
	if (err != 0)
		return err;

#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat)) {
		put_user(tmoref, (int __user *)
			 ((char *)(arg) +
			  linx_compat_offsetof(linx_tmo_param, tmoref)));
	} else
#endif
#endif
		put_user(tmoref, (int __user *)
			 &((struct linx_tmo_param *)arg)->tmoref);
	return 0;
}

static int linx_ioctl_cancel_tmo(struct sock *sk, unsigned long arg, int compat)
{
	struct linx_tmo_param tmo_param;
	int err;
	int tmo_param_size = sizeof(struct linx_tmo_param);

	linx_trace_enter(LINX_TRACEGROUP_AF_LINX, "%p, %lu", sk, arg);

#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		tmo_param_size = linx_compat_size(linx_tmo_param);
#endif
#endif
	/* Copy the tmo_param structure from user space to kernel space. */
	if (0 != copy_from_user(&tmo_param, (void *)arg, tmo_param_size)) {
		return -EFAULT;
	}
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		linx_compat_linx_tmo_param(&tmo_param);
#endif
#endif
	err = linx_cancel_tmo(sk, tmo_param.tmoref);

	return err;
}

static int linx_ioctl_modify_tmo(struct sock *sk, unsigned long arg, int compat)
{
	struct linx_tmo_param tmo_param;
	int err;
	int tmo_param_size = sizeof(struct linx_tmo_param);

	linx_trace_enter(LINX_TRACEGROUP_AF_LINX, "%p, %lu", sk, arg);

#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		tmo_param_size = linx_compat_size(linx_tmo_param);
#endif
#endif
	/* Copy the tmo_param structure from user space to kernel space. */
	if (0 != copy_from_user(&tmo_param, (void *)arg, tmo_param_size)) {
		return -EFAULT;
	}
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		linx_compat_linx_tmo_param(&tmo_param);
#endif
#endif
	err = linx_modify_tmo(sk, tmo_param.tmo, tmo_param.tmoref);
	return err;
}

static int linx_ioctl_request_new_link(struct sock *sk, unsigned long arg)
{
	struct linx_new_link_param request_new_link_param;
	int err;
	
	/* Copy the new_link structure from user space to kernel space. */
	if (0 != copy_from_user(&request_new_link_param, (void *)arg,
				sizeof(struct linx_new_link_param))) {
		return -EFAULT;
	}
	
	err = linx_request_new_link(sk, request_new_link_param.token,
				    &request_new_link_param.new_link_ref);

	if (!err) {
		put_user(request_new_link_param.token, (uint32_t *)
			 &((struct linx_new_link_param *)arg)->token);
		
		put_user(request_new_link_param.new_link_ref, (uint32_t *)
			 &((struct linx_new_link_param *)arg)->
			 new_link_ref);
	}
	
	return err;
}

static int linx_ioctl_cancel_new_link(struct sock *sk, unsigned long arg)
{
	struct linx_new_link_param request_new_link_param;
	/* Copy the new_link structure from user space to kernel space. */
	if (0 != copy_from_user(&request_new_link_param, (void *)arg,
				sizeof(struct linx_new_link_param))) {
		return -EFAULT;
	}
	return linx_cancel_new_link(sk, request_new_link_param.new_link_ref);
}

static int linx_ioctl_info(struct sock *sk, unsigned long arg, int compat)
{
	struct linx_info info;
	int info_size = sizeof(struct linx_info);

#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		info_size = linx_compat_size(linx_info);
#endif
#endif

	linx_trace_enter(LINX_TRACEGROUP_AF_LINX, "%p, %lu", sk, arg);

	/* Copy the hunt_param structure from user space to kernel space. */
	if (0 != copy_from_user(&info, (void *)arg, info_size)) {
		return -EFAULT;
	}
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		linx_compat_linx_info(&info);
#endif
#endif

	switch (info.type) {
	case LINX_INFO_SUMMARY:
		return linx_ioctl_info_summary(&info, compat);
		break;

	case LINX_INFO_STAT:
		return linx_ioctl_info_stat(&info, compat);
		break;

	case LINX_INFO_SOCKETS:
		return linx_ioctl_info_sockets(&info, compat);
		break;

	case LINX_INFO_NAME:
		return linx_ioctl_info_name(&info, compat);
		break;

	case LINX_INFO_TYPE:
		return linx_ioctl_info_type(&info, compat);
		break;

	case LINX_INFO_STATE:
		return linx_ioctl_info_state(&info, compat);
		break;

	case LINX_INFO_OWNER:
		return linx_ioctl_info_owner(&info, compat);
		break;

	case LINX_INFO_RECV_QUEUE:
		return linx_ioctl_info_recv_queue(&info, compat);
		break;

	case LINX_INFO_RECV_QUEUE_2:
		return linx_ioctl_info_recv_queue_2(&info, compat);
		break;

	case LINX_INFO_PEND_ATTACH:
		return linx_ioctl_info_pend_attach(&info, compat);
		break;

	case LINX_INFO_PEND_HUNT:
		return linx_ioctl_info_pend_hunt(&info, compat);
		break;

	case LINX_INFO_PEND_TMO:
		return linx_ioctl_info_pend_tmo(&info, compat);
		break;

	case LINX_INFO_FILTERS:
		return linx_ioctl_info_filters(&info, compat);
		break;

	case LINX_INFO_SIGNAL_PAYLOAD:
		return linx_ioctl_info_signal_payload(&info, compat);
		break;

	default:
		break;
	}
	return -EINVAL;
}

int linx_do_ioctl_name(struct sock *sk, struct linx_huntname *huntname)
{
	struct linx_huntname *addr;

	int err = 0;

	linx_trace_enter(LINX_TRACEGROUP_AF_LINX, "%p, %p", sk, huntname);

	/* Make sure the address is not already bound. */
	if (linx_sk(sk)->addr != NULL) {
		err = -EOPNOTSUPP;
		goto out_up;
	}

	/* Allocate an internal buffer to hold the (hunt) name of the
	   socket. */
	addr = linx_kmalloc(sizeof(*addr) + huntname->namelen + 1);
	if (!addr) {
		err = -ENOMEM;
		goto out_up;
	}

	/* Calculate the location of the hunt name in the internal
	 * socket buffer. */
	addr->name = (char *)addr + sizeof(*addr);
	addr->namelen = huntname->namelen;

	/* Copy the name_param structure from user space to kernel space. */
	if (strncpy((char *)addr->name, (char *)huntname->name,
		    huntname->namelen) != addr->name) {
		err = -EINVAL;
		goto out_release;
	}

	addr->name[huntname->namelen] = '\0';

	/* Create and store the spid of the socket. */
	addr->spid = huntname->spid = linx_sock_to_spid(sk);

	/* Publish the hunt name of the bound socket for hunt requests. */
	linx_publish(sk, addr);

	/* linx_publish() must be done first, it sets linx_sk(sk)->addr! */
        err = linx_sock_stats_add(linx_sk(sk));
        if (err != 0) {
                goto out_release;
        }

	/* NOTE: The order which hunt signals are sent to the hunters is not
	 *       specified, therefore the socket can be published before
	 *       pending hunts are resolved. */

	/* Resolve pending hunts that match the hunt name of the socket. */
	linx_resolve_pend_hunt(addr->name, sk);

	/* Sanity check the new spid. */
	linx_check_spid(sk);

	return err;

      out_release:
	linx_free_linx_name(addr);
      out_up:
	return err;
}

static int linx_ioctl_name(struct sock *sk, unsigned long arg, int compat)
{
	struct linx_huntname name;
	char *huntname, *userspace_name;
	int nlen, err = 0;
	int huntname_size = sizeof(struct linx_huntname);

#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		huntname_size = linx_compat_size(linx_huntname);
#endif
#endif

	linx_trace_enter(LINX_TRACEGROUP_AF_LINX, "%p, %lu", sk, arg);

	if (arg == 0) {
		return -EINVAL;
	}

	if (0 != copy_from_user(&name, (void *)arg, huntname_size)) {
		return -EFAULT;
	}
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		linx_compat_linx_huntname(&name);
#endif
#endif

	if (name.namelen == 0) {
		return -EINVAL;
	}

	if (name.name == NULL) {
		return -EFAULT;
	}

	huntname = linx_kmalloc(name.namelen + 1);
	if (!huntname) {
		return -ENOMEM;
	}

	nlen = strncpy_from_user(huntname, name.name, name.namelen + 1);
	if (nlen != name.namelen) {
		linx_kfree(huntname);
		if (nlen <= 0)
			/* Bad name.name address */
			return -EFAULT;
		else
			/* Bad name.namelen */
			return -EINVAL;
	}

	/* This is needed to allow check of the sockaddr_linx struct. */
	userspace_name = name.name;
	name.name = huntname;

	err = linx_do_ioctl_name(sk, &name);

	linx_kfree(huntname);

	name.name = userspace_name;

#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat)) {
		put_user(name.spid, (int __user *)
			 ((char *)(arg) +
			  linx_compat_offsetof(linx_huntname, spid)));
	} else
#endif
#endif
		put_user(name.spid, (int __user *)
			 ((char *)(arg) +
			  offsetof(struct linx_huntname, spid)));

	return err;
}

/* The linx_ioctl function is called when the user calls ioctl on an LINX
 * socket. The cmd indicate what specific command is issued. */
static int linx_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct sock *sk = sock->sk;
	int err;
        LINX_SPID spid;
	
	linx_check_sock(sk);
	linx_trace_enter(LINX_TRACEGROUP_AF_LINX, "%p, %d, %lu", sk, cmd, arg);

	if ((err = linx_sk_trylock(sk)) < 0) {
		return err;
	}
	
	switch (cmd) {
	case LINX_IOCTL_HUNT:
		err = linx_ioctl_hunt(sk, arg, LINX_FALSE);
		break;

	case LINX_IOCTL_ATTACH:
		err = linx_ioctl_attach(sk, arg, LINX_FALSE);
		break;

	case LINX_IOCTL_DETACH:
		err = linx_ioctl_detach(sk, arg);
		break;

	case LINX_IOCTL_SET_RECEIVE_FILTER:
		err = linx_ioctl_receive_filter(sk, arg, LINX_FALSE);
		break;

	case LINX_IOCTL_REGISTER_LINK_SUPERVISOR:
		/* Replaced by LINX_IOCTL_REQUEST_NEW_LINK */
		err = -EINVAL;
		break;

	case LINX_IOCTL_UNREGISTER_LINK_SUPERVISOR:
		/* Replaced by LINX_IOCTL_CANCEL_NEW_LINK */
		err = -EINVAL;
		break;

	case LINX_IOCTL_VERSION:
		err = put_user(linx_version(), (int __user *)arg);
		break;

	case LINX_IOCTL_INFO:
		err = linx_ioctl_info(sk, arg, LINX_FALSE);
		break;

	case LINX_IOCTL_HUNTNAME:
		err = linx_ioctl_name(sk, arg, LINX_FALSE);
		break;

	case LINX_IOCTL_REQUEST_TMO:
		err = linx_ioctl_request_tmo(sk, arg, LINX_FALSE);
		break;

	case LINX_IOCTL_CANCEL_TMO:
		err = linx_ioctl_cancel_tmo(sk, arg, LINX_FALSE);
		break;

	case LINX_IOCTL_MODIFY_TMO:
		err = linx_ioctl_modify_tmo(sk, arg, LINX_FALSE);
		break;

	case LINX_IOCTL_REQUEST_NEW_LINK:
		err = linx_ioctl_request_new_link(sk, arg);
		break;

	case LINX_IOCTL_CANCEL_NEW_LINK:
		err = linx_ioctl_cancel_new_link(sk, arg);
		break;
		
	case LINX_IOCTL_LEGACY_SEND:
		err = linx_ioctl_legacy_send(sk, arg);
		break;
		
	case LINX_IOCTL_LEGACY_RECEIVE:
		err = linx_ioctl_legacy_receive(sk, arg);
		break;

	case LINX_IOCTL_SEND:
		err = linx_ioctl_send(sk, arg);
		break;
		
	case LINX_IOCTL_RECEIVE:
		err = linx_ioctl_receive(sk, arg);
		break;
		
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	case LINX_IOCTL_HUNT_32:
		err = linx_ioctl_hunt(sk, arg, LINX_TRUE);
		break;

	case LINX_IOCTL_ATTACH_32:
		err = linx_ioctl_attach(sk, arg, LINX_TRUE);
		break;

	case LINX_IOCTL_SET_RECEIVE_FILTER_32:
		err = linx_ioctl_receive_filter(sk, arg, LINX_TRUE);
		break;

	case LINX_IOCTL_INFO_32:
		err = linx_ioctl_info(sk, arg, LINX_TRUE);
		break;

	case LINX_IOCTL_HUNTNAME_32:
		err = linx_ioctl_name(sk, arg, LINX_TRUE);
		break;

	case LINX_IOCTL_REQUEST_TMO_32:
		err = linx_ioctl_request_tmo(sk, arg, LINX_TRUE);
		break;

	case LINX_IOCTL_CANCEL_TMO_32:
		err = linx_ioctl_cancel_tmo(sk, arg, LINX_TRUE);
		break;

	case LINX_IOCTL_MODIFY_TMO_32:
		err = linx_ioctl_modify_tmo(sk, arg, LINX_TRUE);
		break;
#endif
#endif
	default:
                spid = linx_sock_to_spid(sk);
			err = linx_rlnh_ioctl(spid, cmd, arg);
			break;
	}
	
	linx_sk_unlock(sk);
	
	return err;
}

/* This is implemented because in the Linux kernel sock_no_sendpage calls
 * kernel_sendmsg(), sendpage() should return EOPNOTSUPP for LINX sockets. */
static ssize_t linx_sock_no_sendpage(struct socket *sock,
				     struct page *page,
				     int offset, size_t size, int flags)
{
	return -EOPNOTSUPP;
}

/* This structure specify all socket operations implemented by linx, except
 * linx_create The sock_no_* pointers mean that no such operation is
 * implemented. */
static struct proto_ops linx_ops = {
	.family = PF_LINX,
	.owner = THIS_MODULE,
	.release = linx_release,
	.bind = sock_no_bind,
	.connect = sock_no_connect,
	.socketpair = sock_no_socketpair,
	.accept = sock_no_accept,
	.getname = sock_no_getname,
	.poll = linx_poll,
	.ioctl = linx_ioctl,
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,17))
	.compat_ioctl = linx_ioctl,
#endif
#endif
#endif
	.listen = sock_no_listen,
	.shutdown = sock_no_shutdown,
	.setsockopt = sock_no_setsockopt,
	.getsockopt = sock_no_getsockopt,
	.sendmsg = linx_sendmsg,
	.recvmsg = linx_recvmsg,
	.mmap = sock_no_mmap,
	.sendpage = linx_sock_no_sendpage,
};

/* The linx_create function is called as part of the socket() call when the
 * protocol is defined to PF_LINX. The create function create a socket and
 * initialize its data structures. When the linx_create has successfully
 * returned, an unbound socket has been created. The socket is placed in the
 * list of unbound sockets and will be futher initialized when the
 * bind()function is called on the created socket is called.
 */
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
static int linx_create(struct socket *sock, int protocol)
#elif(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32))
static int linx_create(struct net *net, struct socket *sock, int protocol)
#else
static int linx_create(struct net *net, struct socket *sock, int protocol,
		       int kern)
#endif
{
	int i;
	struct sock *sk = NULL;
	void *net_p = NULL;

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24))
	if (net != &init_net)
		return -EAFNOSUPPORT;
	net_p = net;
#endif
	linx_trace_enter(LINX_TRACEGROUP_AF_LINX, "%p", sock);
	linx_debug(LINX_TRACEGROUP_AF_LINX, "Creating sock %p", sock);

	if (protocol && protocol != PF_LINX) {
		return -EPROTONOSUPPORT;
	}

	/* Set the socket state to unconnected.  The socket state is really
	 * not used at all in the net/core or socket.c but the
	 * initialization makes sure that sock->state is not uninitialized.
	 * An LINX socket is always unconnected, since it is connectionless.
	 */
	sock->state = SS_UNCONNECTED;

	/* Allocate the LINX sock structure from the socket cache.  Upon
	 * success the struct sock data structure is zeroed and thus partially
	 * initialized. The linx specific part of the data structure is left as
	 * is to avoid clearing the spid instance number.
	 */
	sk = sk_alloc_compat(net_p, PF_LINX, GFP_KERNEL, linx_sk_cachep);
	if (sk == NULL) {
		/* The socket cache is out of memory. */
		return -ENOMEM;
	}

	/* Set linx_sk(sk)->spid to a valid spid. */
	create_spid(sk);
	if (linx_sk(sk)->spid == LINX_ILLEGAL_SPID) {
		sk_free(sk);
		return -ENOBUFS; /* ENOBUFS is more correct than ENOMEM */
	}

	/* The sock->type specifies the socket type to use. The LINX socket is
	 * a datagram in the sence that it is packet based. The reliability of
	 * the LINX socket is not a typical SOCK_DGRAM characteristic, but
	 * SOCK_DGRAM is close enough. */
	switch (sock->type) {
	case SOCK_DGRAM:
		/* NOTE: After this line, linx_release() will be called for
		 *       this socket if this linx_create fails. */
		sock->ops = &linx_ops;
		break;
	default:
		destroy_spid(linx_sk(sk)->spid);
		sk_free(sk);
		return -ESOCKTNOSUPPORT;
	}

	/* Increase the number of sockets created. */
	atomic_inc(&linx_nr_socks);

	/* Initialize the nozero default sock structure data. */
	sock_init_data(sock, sk);

	sk_set_owner_compat(sk, THIS_MODULE);

	/* Initialize LINX specific sock stuff. */
	sk->sk_data_ready = linx_data_ready;	/* Callback to
						 * indicate a polling
						 * thread needs to
						 * wake up. */
#ifdef ERRORCHECKS
	/* Initialize the LINX socket stuff. */
	linx_sk(sk)->magic = LINX_SK_MAGIC;	/* Magic for sanity
						   checks. */
#endif

	linx_sk(sk)->type = LINX_TYPE_LOCAL;
	linx_sk(sk)->state = LINX_STATE_RUNNING;
	/* No address until the socket is bound. */
	linx_sk(sk)->addr = NULL;
	sk->sk_destruct = linx_sock_destructor;

	linx_sk(sk)->from_filter = LINX_ILLEGAL_SPID;
	linx_sk(sk)->filter = NULL;

	for (i = 0; i < linx_max_links; i++)
		linx_sk(sk)->rlnh_sender_hd[i] = 0;

	linx_sk(sk)->rlnh = 0x0;
	linx_sk(sk)->rlnh_dst_addr = 0;
	linx_sk(sk)->rlnh_peer_addr = 0;

	/* Initialize new link data */
	linx_sk(sk)->new_link_called = 0;
	
	/* Initialize attach specific data. */
	linx_init_attach(sk);

	/* Lock to synchronize allocation of skb buffers from tasklet
	 * context. */
	spin_lock_init(&linx_sk(sk)->skb_alloc_lock);

	/* Only allow exclusive access to the socket. */
	atomic_set(&linx_sk(sk)->in_use, 0);
	
	/* Store the pid of the creator for trace purposes. */
	linx_sk(sk)->owner_pid = current->pid;
	linx_sk(sk)->owner_tgid = current->tgid;

	/* Store the unbound socket in the unbound socket list. */
	linx_store_unbound(sk);

	atomic_inc(&linx_no_of_local_sockets);

	sk->sk_sndbuf = LINX_MAX_INT;
	sk->sk_rcvbuf = LINX_MAX_INT;

	/* Initialize LINX timoeout mechanism. */
	linx_init_tmo(sk);

#ifdef SOCK_STAT
	/* Init LINX socket statistics if used. */
	memset(&linx_sk(sk)->stat, 0, sizeof(linx_sk(sk)->stat));
#endif
	
	return 0;
}

/* The definition of the LINX socket protocol family. */
static struct net_proto_family linx_family_ops = {
	.family = PF_LINX,
	.create = linx_create,
	.owner = THIS_MODULE,
};

/* The responsibility of this function is to initialize the AF_LINX socket
 * layer. When this function returns, the linx socket shall be available. */
int af_linx_init(void)
{
	int err;

	/* Check the size of the cb char array defined in linux/skbuff.h. */
	ERROR_ON(sizeof(struct linx_skb_cb) > (sizeof((struct sk_buff *) 0)->cb));

#ifdef ERRORCHECKS_MEM
	linx_mem_init();
#endif
	linx_trace_init();

	linx_sk_cachep = kmem_cache_create_compat("linx_sock",
						  sizeof(struct linx_sock) +
						  (sizeof(uint32_t) *
						   linx_max_links), 0,
						  SLAB_HWCACHE_ALIGN, NULL,
						  NULL);
	if (!linx_sk_cachep) {
		linx_trace_exit(LINX_TRACEGROUP_AF_LINX, "");
		return -ENOMEM;
	}

	err = sock_register(&linx_family_ops);
	if (err != 0) {
		kmem_cache_destroy(linx_sk_cachep);

		linx_trace_exit(LINX_TRACEGROUP_AF_LINX, "");
		return err;
	}

	linx_workqueue = create_singlethread_workqueue("linx");

	/* Create a queue for routed messages, used by rlnh */
	skb_queue_head_init(&routed_skb_list);

	err = linx_init_spid_array();
	if (err)
		return err;

	err = linx_init_attref_array();
	if (err)
		return err;

	err = linx_init_tmoref_array();
	if (err)
		return err;

#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11))
	register_ioctl32_conversion(LINX_IOCTL_SET_RECEIVE_FILTER_32, NULL);
	register_ioctl32_conversion(LINX_IOCTL_HUNT_32, NULL);
	register_ioctl32_conversion(LINX_IOCTL_ATTACH_32, NULL);
	register_ioctl32_conversion(LINX_IOCTL_DETACH, NULL);
	register_ioctl32_conversion(LINX_IOCTL_REQUEST_TMO_32, NULL);
	register_ioctl32_conversion(LINX_IOCTL_REGISTER_LINK_SUPERVISOR, NULL);
	register_ioctl32_conversion(LINX_IOCTL_UNREGISTER_LINK_SUPERVISOR,
				    NULL);
	register_ioctl32_conversion(LINX_IOCTL_INFO_32, NULL);
	register_ioctl32_conversion(LINX_IOCTL_HUNTNAME_32, NULL);
	register_ioctl32_conversion(LINX_IOCTL_VERSION, NULL);
#endif
#endif
#endif

#ifdef LINX_MESSAGE_TRACE
	if (linx_message_trace_init())
		linx_err("LINXTRACE trace device registration failed.");
#endif
#ifdef LINX_RBLOG
#define LINX_RBLOG_SIZE 80 * 1024 /* approx 1024 lines */
	if (rblog_create(LINX_RBLOG_SIZE))
		printk("LINX_RBLOG initialization failed.");
#endif
	linx_trace_exit(LINX_TRACEGROUP_AF_LINX, "");
	return 0;
}
#ifdef LINX_RBLOG
EXPORT_SYMBOL(rblog); /* make rblog accessible from other modules */
#endif

/* The responsibility of this function is to finalize the AF_LINX socket
 * layer. When this function returns, the linx socket shall be unavailable.
 */
int af_linx_exit(void)
{
	int rv = 0;

#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20))
	static kmem_cache_t *linx_sk_cachep_tmp;
#else
	static struct kmem_cache *linx_sk_cachep_tmp;
#endif
	linx_sk_cachep_tmp = linx_sk_cachep;

	linx_sk_cachep = NULL;

	sock_unregister(PF_LINX);

	/* At this point no new AF_LINX socket requests will end up in this
	 * module. */

	/* Remove the workqueue. */
	flush_workqueue(linx_workqueue);
	destroy_workqueue(linx_workqueue);

	/* Cancel all pending hunts including RLNH hunts. */
	linx_unpublish_all();

	/* Remove any leftover hunt paths the RLNH may leave behind. */
	linx_remove_all_hunt_paths();

	/* Destroy the LINX socket cache. */
	kmem_cache_destroy(linx_sk_cachep_tmp);

	linx_exit_spid_array();

	linx_exit_attref_array();

	linx_exit_tmoref_array();

#ifdef LINX_MESSAGE_TRACE
	if (linx_message_trace_exit())
		linx_err("LINXTRACE trace device unregistration failed.");
#endif

	if (linx_validate_kmallocs() != 0) {
		linx_warn("Memory leak.");
		rv = -1;
	}
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11))
	unregister_ioctl32_conversion(LINX_IOCTL_ATTACH_32);
	unregister_ioctl32_conversion(LINX_IOCTL_DETACH);
	unregister_ioctl32_conversion(LINX_IOCTL_HUNTNAME_32);
	unregister_ioctl32_conversion(LINX_IOCTL_HUNT_32);
	unregister_ioctl32_conversion(LINX_IOCTL_INFO_32);
	unregister_ioctl32_conversion(LINX_IOCTL_REGISTER_LINK_SUPERVISOR);
	unregister_ioctl32_conversion(LINX_IOCTL_REQUEST_TMO_32);
	unregister_ioctl32_conversion(LINX_IOCTL_SET_RECEIVE_FILTER_32);
	unregister_ioctl32_conversion(LINX_IOCTL_UNREGISTER_LINK_SUPERVISOR);
	unregister_ioctl32_conversion(LINX_IOCTL_VERSION);
#endif
#endif
#endif

#ifdef LINX_RBLOG
#undef LINX_RBLOG_SIZE
	rblog_destroy();
#endif

	return rv;
}
