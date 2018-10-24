/*
 * Copyright (c) 2006-2009, Enea Software AB
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

#include <asm/atomic.h>   
#include <asm/uaccess.h>  

#include <af_linx.h>
#include <linx_mem.h>

#include <linux/linx_ioctl.h>

#include <linx_trace.h>
#include <linx_compat32.h>

#include <ipc/attach_detach.h>
#include <ipc/hunt.h>
#include <ipc/tmo.h>

extern atomic_t linx_no_of_local_sockets;
extern atomic_t linx_no_of_remote_sockets;
extern atomic_t linx_no_of_link_sockets;
extern atomic_t linx_no_of_pend_attach;
extern atomic_t linx_no_of_pend_hunt;
extern atomic_t linx_no_of_queued_signals;
extern atomic_t linx_no_of_pend_tmo;

int linx_ioctl_info_summary(struct linx_info *info, int compat)
{
	struct linx_info_summary sum;
	sum.no_of_local_sockets = (int)atomic_read(&linx_no_of_local_sockets);
	sum.no_of_remote_sockets = (int)atomic_read(&linx_no_of_remote_sockets);
	sum.no_of_link_sockets = (int)atomic_read(&linx_no_of_link_sockets);
	sum.no_of_pend_attach = (int)atomic_read(&linx_no_of_pend_attach);
	sum.no_of_pend_hunt = (int)atomic_read(&linx_no_of_pend_hunt);
	sum.no_of_pend_tmo = (int)atomic_read(&linx_no_of_pend_tmo);
	sum.no_of_queued_signals = (int)atomic_read(&linx_no_of_queued_signals);
	if (0 != copy_to_user(info->type_spec, &sum,
			      sizeof(struct linx_info_summary))) {
		return -EFAULT;
	}

	return 0;
}

int linx_ioctl_info_stat(struct linx_info *info, int compat)
{
#ifndef SOCK_STAT
	return -ENOSYS;		/* errno.h - "Function not supported." */
#else
	struct linx_info_stat sock_stat;
	struct sock *sk;

	if (0 != copy_from_user(&sock_stat, info->type_spec,
				sizeof(struct linx_info_stat))) {
		return -EFAULT;
	}

	sk = linx_spid_to_sock(sock_stat.spid);
	if (sk == NULL) {
		if (!linx_is_zombie_spid(sock_stat.spid)) {
			return -EINVAL;
		}
		return -ECONNRESET;
	}
	sock_stat.no_sent_signals =
	    linx_sk(sk)->stat.no_sent_local_signals +
	    linx_sk(sk)->stat.no_sent_remote_signals;

	sock_stat.no_sent_bytes =
	    linx_sk(sk)->stat.no_sent_local_bytes +
	    linx_sk(sk)->stat.no_sent_remote_bytes;

	sock_stat.no_recv_signals =
	    linx_sk(sk)->stat.no_recv_local_signals +
	    linx_sk(sk)->stat.no_recv_remote_signals;

	sock_stat.no_recv_bytes =
	    linx_sk(sk)->stat.no_recv_local_bytes +
	    linx_sk(sk)->stat.no_recv_remote_bytes;

	sock_stat.no_sent_local_signals =
	    linx_sk(sk)->stat.no_sent_local_signals;
	sock_stat.no_recv_local_signals =
	    linx_sk(sk)->stat.no_recv_local_signals;
	sock_stat.no_sent_local_bytes = linx_sk(sk)->stat.no_sent_local_bytes;
	sock_stat.no_recv_local_bytes = linx_sk(sk)->stat.no_recv_local_bytes;

	sock_stat.no_sent_remote_signals =
	    linx_sk(sk)->stat.no_sent_remote_signals;
	sock_stat.no_recv_remote_signals =
	    linx_sk(sk)->stat.no_recv_remote_signals;
	sock_stat.no_sent_remote_bytes = linx_sk(sk)->stat.no_sent_remote_bytes;
	sock_stat.no_recv_remote_bytes = linx_sk(sk)->stat.no_recv_remote_bytes;

	sock_stat.no_queued_bytes = linx_sk(sk)->stat.no_queued_bytes;
	sock_stat.no_queued_signals = linx_sk(sk)->stat.no_queued_signals;

	if (0 != copy_to_user(info->type_spec,
			      &sock_stat, sizeof(struct linx_info_stat))) {
		sock_put(sk);
		return -EFAULT;
	}

	sock_put(sk);

	return 0;
#endif
}

int linx_ioctl_info_sockets(struct linx_info *info, int compat)
{
	struct linx_info_sockets isockets;
	int no_of_sockets;
	int isocket_size = sizeof(struct linx_info_sockets);

#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		isocket_size = linx_compat_size(linx_info_sockets);
#endif
#endif

	if (0 != copy_from_user(&isockets, info->type_spec, isocket_size)) {
		return -EFAULT;
	}
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		linx_compat_linx_info_sockets(&isockets);
#endif
#endif

	no_of_sockets = linx_info_sockets(&isockets, isockets.buffer);

	if (no_of_sockets == -1) {
		return -EINVAL;
	}
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat)) {
		put_user(no_of_sockets,
			 (int __user *)((char *)(info->type_spec) +
					linx_compat_offsetof(linx_info_sockets,
							     no_of_sockets)));
	} else
#endif
#endif
		put_user(no_of_sockets,
			 (int __user *)((char *)(info->type_spec) +
					offsetof(struct linx_info_sockets,
						 no_of_sockets)));
	return 0;
}

int linx_ioctl_info_name(struct linx_info *info, int compat)
{
	struct linx_info_name iname;
	struct sock *sk;
	int namelen;
	int iname_size = sizeof(struct linx_info_name);
	char *name;

#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		iname_size = linx_compat_size(linx_info_name);
#endif
#endif

	if (0 != copy_from_user(&iname, info->type_spec, iname_size)) {
		return -EFAULT;
	}
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		linx_compat_linx_info_name(&iname);
#endif
#endif

	sk = linx_spid_to_sock(iname.spid);
	if (sk == NULL) {
		if (!linx_is_zombie_spid(iname.spid)) {
			return -EINVAL;
		}
		return -ECONNRESET;
	}
	spin_lock_bh(&sk->sk_receive_queue.lock);
	if (unlikely(linx_sk(sk)->addr == NULL)) {
		namelen = 0;
	} else {
		LINX_ASSERT(linx_sk(sk)->addr->name != NULL);
		LINX_ASSERT(linx_sk(sk)->addr->spid == iname.spid);
		LINX_ASSERT(linx_sk(sk)->addr->namelen != 0);
		namelen = linx_sk(sk)->addr->namelen;
	}

	/* If namelen zero return the namelength */
	if (iname.namelen == 0) {
		spin_unlock_bh(&sk->sk_receive_queue.lock);
		sock_put(sk);
		return namelen + 1;
	}
	if (namelen >= iname.namelen) {
		spin_unlock_bh(&sk->sk_receive_queue.lock);
		sock_put(sk);
		return -EINVAL;
	}

	spin_unlock_bh(&sk->sk_receive_queue.lock);
	name = linx_kmalloc(namelen + 1);
	if (name == NULL) {
		sock_put(sk);
		return -ENOMEM;
	}
	spin_lock_bh(&sk->sk_receive_queue.lock);

	/* Check if huntname was removed while memory was allocated. */
	if (linx_sk(sk)->addr == NULL)
		namelen = 0;

	if (likely(namelen))
		memcpy(name, linx_sk(sk)->addr->name, namelen + 1);
	else
		name[0] = '\0';

	spin_unlock_bh(&sk->sk_receive_queue.lock);

	if (0 != copy_to_user(iname.name, name, namelen + 1)) {
		linx_kfree(name);
		sock_put(sk);
		return -EFAULT;
	}

	linx_kfree(name);
	sock_put(sk);
	return namelen;
}

int linx_ioctl_info_type(struct linx_info *info, int compat)
{
	struct linx_info_type itype;
	struct sock *sk;
	int type = LINX_TYPE_UNKNOWN;

	if (0 != copy_from_user(&itype, info->type_spec,
				sizeof(struct linx_info_type))) {
		return -EFAULT;
	}
	sk = linx_spid_to_sock(itype.spid);
	if (sk == NULL) {
		if (linx_is_zombie_spid(itype.spid)) {
			type = LINX_TYPE_ZOMBIE;
		} else {
			type = LINX_TYPE_ILLEGAL;
		}
		itype.type = type;
	} else {
		itype.type = linx_sk(sk)->type;
	}

	if (0 != copy_to_user(info->type_spec, &itype,
			      sizeof(struct linx_info_type))) {
		if (sk)
			sock_put(sk);
		return -EFAULT;
	}

	if (sk)
		sock_put(sk);
	return 0;
}

int linx_ioctl_info_state(struct linx_info *info, int compat)
{
	struct linx_info_state istate;
	struct sock *sk;

	if (0 != copy_from_user(&istate, info->type_spec,
				sizeof(struct linx_info_state))) {
		return -EFAULT;
	}
	sk = linx_spid_to_sock(istate.spid);
	if (sk == NULL) {
		if (!linx_is_zombie_spid(istate.spid)) {
			return -EINVAL;
		}
		return -ECONNRESET;
	}
	istate.state = linx_sk(sk)->state;

	if (0 != copy_to_user(info->type_spec, &istate,
			      sizeof(struct linx_info_state))) {
		sock_put(sk);
		return -EFAULT;
	}

	sock_put(sk);
	return 0;
}


int linx_ioctl_info_owner(struct linx_info *info, int compat)
{
	struct linx_info_owner iowner;
	struct sock *sk;

	if (0 != copy_from_user(&iowner, info->type_spec,
				sizeof(struct linx_info_owner))) {
		return -EFAULT;
	}
	sk = linx_spid_to_sock(iowner.spid);
	if (sk == NULL) {
		if (!linx_is_zombie_spid(iowner.spid)) {
			return -EINVAL;
		}
		return -ECONNRESET;
	}
	iowner.owner = linx_sk(sk)->owner_pid;

	if (0 != copy_to_user(info->type_spec, &iowner,
			      sizeof(struct linx_info_owner))) {
		sock_put(sk);
		return -EFAULT;
	}

	sock_put(sk);
	return 0;
}

int linx_ioctl_info_recv_queue(struct linx_info *info, int compat)
{
	struct sk_buff *skb;
	struct linx_info_recv_queue irecv_queue;
	struct sock *sk;
	int size = 0;
	struct linx_info_signal *usignal;
	int irecv_queue_size = sizeof(struct linx_info_recv_queue);
	int sig_info_size = sizeof(struct linx_info_signal);

#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		irecv_queue_size = linx_compat_size(linx_info_recv_queue);
#endif
#endif

	if (0 != copy_from_user(&irecv_queue, info->type_spec,
				irecv_queue_size)) {
		return -EFAULT;
	}
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		linx_compat_linx_info_recv_queue(&irecv_queue);
#endif
#endif

	sk = linx_spid_to_sock(irecv_queue.spid);
	if (sk == NULL) {
		if (!linx_is_zombie_spid(irecv_queue.spid)) {
			return -EINVAL;
		}
		return -ECONNRESET;
	}

	spin_lock_bh(&sk->sk_receive_queue.lock);

	/* Walk through the receive queue to calc the size of the
	 * needed buffer. */
	skb_queue_walk(&sk->sk_receive_queue, skb) {
		size += sig_info_size;
	}

	if (irecv_queue.buffer_size >= sig_info_size && size > 0) {
		int buffer_size =
		    size > irecv_queue.buffer_size ?
		    irecv_queue.buffer_size : size;
		usignal = linx_kmalloc(buffer_size);
		if (usignal == NULL) {
			spin_unlock_bh(&sk->sk_receive_queue.lock);
			sock_put(sk);
			return -ENOMEM;
		}

		size = 0;

		skb_queue_walk(&sk->sk_receive_queue, skb) {
			struct linx_info_signal isignal;
			struct linx_skb_cb *cb = (struct linx_skb_cb *)skb->cb;

			if (size + sig_info_size <= buffer_size) {
				isignal.signo = cb->signo;
				isignal.size = cb->payload_size;
				isignal.from = cb->from_spid;
				memcpy(((char *)usignal) + size, &isignal,
				       sig_info_size);
			}
			size += sig_info_size;
		}
		spin_unlock_bh(&sk->sk_receive_queue.lock);
		if (0 != copy_to_user(irecv_queue.buffer, usignal, buffer_size)) {
			sock_put(sk);
			linx_kfree(usignal);
			return -EFAULT;
		}
		linx_kfree(usignal);
	} else
		spin_unlock_bh(&sk->sk_receive_queue.lock);

	irecv_queue.no_of_signals = size / sig_info_size;

#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat)) {
		put_user(irecv_queue.no_of_signals,
			 (int __user *)((char *)(info->type_spec) +
					linx_compat_offsetof
					(linx_info_recv_queue, no_of_signals)));
	} else
#endif
#endif
		put_user(irecv_queue.no_of_signals,
			 (int __user *)((char *)(info->type_spec) +
					offsetof(struct linx_info_recv_queue,
						 no_of_signals)));
	sock_put(sk);
	return 0;
}

int linx_ioctl_info_recv_queue_2(struct linx_info *info, int compat)
{
	struct sk_buff *skb;
	struct linx_info_recv_queue_2 irecv_queue;
	struct sock *sk;
	int size = 0;
	struct linx_info_signal *usignal;
	int irecv_queue_size = sizeof(struct linx_info_recv_queue_2);
	int sig_info_size = sizeof(struct linx_info_signal_2);

#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		irecv_queue_size = linx_compat_size(linx_info_recv_queue);
#endif
#endif

	if (0 != copy_from_user(&irecv_queue, info->type_spec,
				irecv_queue_size)) {
		return -EFAULT;
	}
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		linx_compat_linx_info_recv_queue(&irecv_queue);
#endif
#endif

	sk = linx_spid_to_sock(irecv_queue.spid);
	if (sk == NULL) {
		if (!linx_is_zombie_spid(irecv_queue.spid)) {
			return -EINVAL;
		}
		return -ECONNRESET;
	}

	spin_lock_bh(&sk->sk_receive_queue.lock);

	/* Walk through the receive queue to calc the size of the
	 * needed buffer. */
	skb_queue_walk(&sk->sk_receive_queue, skb) {
		size += sig_info_size;
	}

	if (irecv_queue.buffer_size >= sig_info_size && size > 0) {
		int buffer_size =
		    size > irecv_queue.buffer_size ?
		    irecv_queue.buffer_size : size;
		usignal = linx_kmalloc(buffer_size);
		if (usignal == NULL) {
			spin_unlock_bh(&sk->sk_receive_queue.lock);
			sock_put(sk);
			return -ENOMEM;
		}

		size = 0;

		skb_queue_walk(&sk->sk_receive_queue, skb) {
			struct linx_info_signal_2 isignal;
			struct linx_skb_cb *cb = (struct linx_skb_cb *)skb->cb;

			if (size + sig_info_size <= buffer_size) {
				isignal.signo = cb->signo;
				isignal.size = cb->payload_size;
				isignal.from = cb->from_spid;
				isignal.flags = cb->flags;
				memcpy(((char *)usignal) + size, &isignal,
				       sig_info_size);
			}
			size += sig_info_size;
		}
		spin_unlock_bh(&sk->sk_receive_queue.lock);
		if (0 != copy_to_user(irecv_queue.buffer, usignal, buffer_size)) {
			sock_put(sk);
			linx_kfree(usignal);
			return -EFAULT;
		}
		linx_kfree(usignal);
	} else
		spin_unlock_bh(&sk->sk_receive_queue.lock);

	irecv_queue.no_of_signals = size / sig_info_size;

#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat)) {
		put_user(irecv_queue.no_of_signals,
			 (int __user *)((char *)(info->type_spec) +
					linx_compat_offsetof
					(linx_info_recv_queue,
					 no_of_signals)));
	} else
#endif
#endif
		put_user(irecv_queue.no_of_signals,
			 (int __user *)((char *)(info->type_spec) +
					offsetof(struct linx_info_recv_queue_2,
						 no_of_signals)));
	sock_put(sk);
	return 0;
}

int linx_ioctl_info_pend_attach(struct linx_info *info, int compat)
{
	struct linx_info_pend_attach ipend_attach;
	int no_of_attaches;
	int ipend_attach_size = sizeof(struct linx_info_pend_attach);

#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		ipend_attach_size = linx_compat_size(linx_info_pend_attach);
#endif
#endif

	if (0 != copy_from_user(&ipend_attach, info->type_spec,
				ipend_attach_size)) {
		return -EFAULT;
	}
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		linx_compat_linx_info_pend_attach(&ipend_attach);
#endif
#endif

	no_of_attaches = linx_info_pend_attach(&ipend_attach,
					       ipend_attach.buffer);
	if (no_of_attaches < 0) {
		return no_of_attaches;
	}
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat)) {
		put_user(no_of_attaches, (int __user *)
			 ((char *)(info->type_spec) +
			  linx_compat_offsetof(linx_info_pend_attach,
					       no_of_attaches)));
	} else
#endif
#endif
		put_user(no_of_attaches,
			 (int __user *)((char *)(info->type_spec) +
					offsetof(struct linx_info_pend_attach,
						 no_of_attaches)));
	return 0;
}

int linx_ioctl_info_pend_hunt(struct linx_info *info, int compat)
{
	struct linx_info_pend_hunt ipend_hunt;
	struct linx_info_hunt *hunts;
	int no_of_hunts, strings_offset;
	int ipend_hunt_size = sizeof(struct linx_info_pend_hunt);

#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		ipend_hunt_size = linx_compat_size(linx_info_pend_hunt);
#endif
#endif

	if (0 != copy_from_user(&ipend_hunt, info->type_spec, ipend_hunt_size)) {
		return -EFAULT;
	}
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		linx_compat_linx_info_pend_hunt(&ipend_hunt);
#endif
#endif

	hunts = ipend_hunt.buffer;
	no_of_hunts = linx_info_pend_hunt(&ipend_hunt, hunts,
					  &strings_offset, compat);
	if (no_of_hunts < 0) {
		return no_of_hunts;
	}
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat)) {
		put_user(no_of_hunts, (int __user *)
			 ((char *)(info->type_spec) +
			  linx_compat_offsetof(linx_info_pend_hunt,
					       no_of_hunts)));
		put_user(strings_offset, (int __user *)
			 ((char *)(info->type_spec) +
			  linx_compat_offsetof(linx_info_pend_hunt,
					       strings_offset)));
	} else
#endif
#endif
	{
		put_user(no_of_hunts,
			 (int __user *)((char *)(info->type_spec) +
					offsetof(struct linx_info_pend_hunt,
						 no_of_hunts)));
		put_user(strings_offset,
			 (int __user *)((char *)(info->type_spec) +
					offsetof(struct linx_info_pend_hunt,
						 strings_offset)));
	}

	return 0;
}

int linx_ioctl_info_pend_tmo(struct linx_info *info, int compat)
{
	struct linx_info_pend_tmo ipend_tmo;
	int no_of_timeouts;
	int ipend_tmo_size = sizeof(struct linx_info_pend_tmo);

#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		ipend_tmo_size = linx_compat_size(linx_info_pend_tmo);
#endif
#endif

	if (0 != copy_from_user(&ipend_tmo, info->type_spec, ipend_tmo_size)) {
		return -EFAULT;
	}
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		linx_compat_linx_info_pend_tmo(&ipend_tmo);
#endif
#endif

	no_of_timeouts = linx_info_pend_tmo(&ipend_tmo, ipend_tmo.buffer);
	if (no_of_timeouts < 0) {
		return no_of_timeouts;
	}
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat)) {
		put_user(no_of_timeouts,
			 (int __user *)((char *)(info->type_spec) +
					linx_compat_offsetof(linx_info_pend_tmo,
							     no_of_timeouts)));
	} else
#endif
#endif
		put_user(no_of_timeouts,
			 (int __user *)((char *)(info->type_spec) +
					offsetof(struct linx_info_pend_tmo,
						 no_of_timeouts)));
	return 0;
}

int linx_ioctl_info_filters(struct linx_info *info, int compat)
{
	struct linx_info_filters ifilters;
	struct sock *sk;
	int err = 0;
	int ifilters_size = sizeof(struct linx_info_filters);
	int filter_size;

#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		ifilters_size = linx_compat_size(linx_info_filters);
#endif
#endif

	if (0 != copy_from_user(&ifilters, info->type_spec, ifilters_size)) {
		return -EFAULT;
	}
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		linx_compat_linx_info_filters(&ifilters);
#endif
#endif

	sk = linx_spid_to_sock(ifilters.spid);
	if (sk == NULL) {
		if (!linx_is_zombie_spid(ifilters.spid)) {
			return -EINVAL;
		}
		return -ECONNRESET;
	}

	if (linx_sk(sk)->state == LINX_STATE_RUNNING) {
		err = -EINVAL;
		goto linx_info_filters_out;
	}

	spin_lock_bh(&sk->sk_receive_queue.lock);

	ifilters.from_filter = linx_sk(sk)->from_filter;
	if (linx_sk(sk)->filter == NULL) {
		ifilters.no_of_sigselect = 1;
	} else {
		ifilters.no_of_sigselect =
		    abs((int32_t) linx_sk(sk)->filter[0]) + 1;
	}

	filter_size = ifilters.no_of_sigselect * sizeof(LINX_SIGSELECT);
	if (filter_size > ifilters.buffer_size) {
		filter_size = ifilters.buffer_size;
		/* we need to update no_of_sigselect */
		ifilters.no_of_sigselect =
			ifilters.buffer_size / sizeof(LINX_SIGSELECT);
	}
	if (filter_size > 0) {
		LINX_SIGSELECT *filter = NULL;

		filter = linx_kmalloc(filter_size);
		if (filter == NULL) {
			err = -ENOMEM;
			spin_unlock_bh(&sk->sk_receive_queue.lock);
			goto linx_info_filters_out;
		}

		if (linx_sk(sk)->filter == NULL) {
			*filter = 0;
		} else {
			memcpy(filter, linx_sk(sk)->filter, filter_size);
		}

		spin_unlock_bh(&sk->sk_receive_queue.lock);

		if (0 != copy_to_user(ifilters.buffer, filter, filter_size)) {
			linx_kfree(filter);
			err = -EFAULT;
			goto linx_info_filters_out;
		}
		linx_kfree(filter);
	} else {
		spin_unlock_bh(&sk->sk_receive_queue.lock);
	}

#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat)) {
		put_user(ifilters.from_filter,
			 (int __user *)((char *)(info->type_spec) +
					linx_compat_offsetof(linx_info_filters,
							     from_filter)));
		put_user(ifilters.no_of_sigselect, (int __user *)
			 ((char *)(info->type_spec) +
			  linx_compat_offsetof(linx_info_filters,
					       no_of_sigselect)));
	} else
#endif
#endif
	{
		put_user(ifilters.from_filter,
			 (int __user *)((char *)(info->type_spec) +
					offsetof(struct linx_info_filters,
						 from_filter)));
		put_user(ifilters.no_of_sigselect,
			 (int __user *)((char *)(info->type_spec) +
					offsetof(struct linx_info_filters,
						 no_of_sigselect)));
	}

      linx_info_filters_out:
	sock_put(sk);
	return err;
}

int linx_ioctl_info_signal_payload(struct linx_info *info, int compat)
{
	int ret = 0;
	struct sk_buff *skb;
	struct sock *sk;
	struct linx_info_signal_payload isigp;
	struct linx_info_signal isig;
	int isigp_len = sizeof(struct linx_info_signal_payload);
	
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		isigp_len = linx_compat_size(linx_info_signal_payload);
#endif
#endif
	
	if (0 != copy_from_user(&isigp, info->type_spec, isigp_len)) {
		return -EFAULT;
	}

#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		linx_compat_linx_info_signal_payload(&isigp);
#endif
#endif
	/* Socket sk is locked here */
	sk = linx_spid_to_sock(isigp.spid);
	if (sk == NULL) {
		if (!linx_is_zombie_spid(isigp.spid)) {
			return -EINVAL;
		}
		return -ECONNRESET;
	}
	isig = isigp.signal;
	
	/* Check receive queue */
	spin_lock_bh(&sk->sk_receive_queue.lock);
	skb_queue_walk(&sk->sk_receive_queue, skb) {
		struct linx_skb_cb *cb = (struct linx_skb_cb *)skb->cb;
		if (isig.signo == cb->signo &&
		    isig.size == cb->payload_size &&
		    isig.from == cb->from_spid) {
			struct iovec to;
			int size;
			size = isig.size > isigp.buffer_size ?
				isigp.buffer_size : isig.size;
			to.iov_base = isigp.buffer;
			to.iov_len = size;
			/* Increase the users count for this skb to prevent if
			 * from being freed after releasing the spinlock. */
			atomic_inc(&skb->users);
			spin_unlock_bh(&sk->sk_receive_queue.lock);
			ret = skb_copy_datagram_iovec(skb, 0, &to, size);
			/* Decrease the users count/free the skb */
			kfree_skb(skb);
			if (unlikely(ret < 0)) {
				goto out;
			}
			ret = size;
			goto match_found;
		}
	}
	spin_unlock_bh(&sk->sk_receive_queue.lock);
	
	/* Check the pending hunts */
	if ((ret = linx_info_pend_hunt_payload(sk, &isigp)) < 0) {	
		goto out;
	}

	/* Check pending attaches */
	if (!ret && (ret = linx_info_pend_attach_payload(sk, &isigp)) < 0) {	
		goto out;
	}

	/* Check pending timeouts */
	if (!ret && (ret = linx_info_pend_tmo_payload(sk, &isigp)) < 0) {
		goto out;
	}
	
 match_found:
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat)) {
		put_user(ret, (int __user *)
			 ((char *)(info->type_spec) + linx_compat_offsetof
			  (linx_info_signal_payload, payload_size)));
	} else
#endif
#endif
		put_user(ret, (int __user *)
			 ((char *)(info->type_spec) + offsetof
			  (struct linx_info_signal_payload, payload_size)));

	ret = 0;
 out:
	sock_put(sk);
	return ret;
}
