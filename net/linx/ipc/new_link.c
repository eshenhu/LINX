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

#include <af_linx.h>
#include <linx_compat.h>
#include <linx_mem.h>
#include <linux/list.h>
#include <buf_types.h>
#include <ipc/new_link.h>
#include <linx_trace.h>

extern atomic_t linx_no_of_queued_signals;

#ifndef DEFINE_SPINLOCK
#define DEFINE_SPINLOCK(x)	spinlock_t x = SPIN_LOCK_UNLOCKED
#endif

/* Linked list of waiting processes */
LIST_HEAD(new_link_req_list);

/* Lock for updating the list of waiting processes needed since
 * two callers from user-space otherwise can operate on the list
 * simultaniously */
DEFINE_SPINLOCK(new_link_req);

/* Linked list of active links, no lock needed since links are added
 * and removed from the same context, the workerthread. */
LIST_HEAD(new_link_links_list);

/* Each registered link receives a unique index starting from zero */
static uint32_t new_link_index = 0;

/* Reference used by caller to cancel out-standing requests */
static uint32_t new_link_ref = 0;

/* List entry for each registered link */
struct link_entry {
	struct list_head list; 
	LINX_SPID spid; /* The SPID of the link socket */
	uint32_t idx; /* Index of the link */
	int attr; /* Offset into skb where attribute string starts */
	int skb_size; /* Size of the skb buffer */
	struct sk_buff *skb; /* contains the linkname + attribute string */
};

/* List entry for each requesting socket */
struct request_entry {
	struct list_head list;
	LINX_SPID spid; /* The SPID of the requesting LINX socket. */
	struct sk_buff *skb; /* preallocated new_link signal w/o linkname */
	uint32_t token; /* token sent by the new link requester */
	uint32_t ref; /* handle used to cancel pending new link request */
	int signal_sent; /* state of the request */
};

/*
 * linx_request_new_link
 *
 * Request a new link, called by a user application via the ioctl() interface.
 * The function checks the token value and if a link is present with a higher
 * index number a new_link signal is sent immediately, if not then the request
 * is placed in a queue and resolved when a new link is registered.
 */

int linx_request_new_link(struct sock *sk, uint32_t token, uint32_t *ref)
{
	int err = 0;
	struct linx_new_link new_link_sig = { .signo = LINX_OS_NEW_LINK_SIG };
	int sigsize = offsetof(struct linx_new_link, buf);
	struct sk_buff *skb;
	struct linx_skb_cb *cb;
	struct list_head *node, *tmp;
	struct link_entry *link_e;
	struct linx_new_link *sig;
	struct request_entry *req;
	struct sock *from;
	
	/* Allocate an skb for the new_link signal */
	err = linx_skb_create(&new_link_sig, sigsize, sk,
			      BUFFER_TYPE_KERNEL, &skb, 0);
	if (err != 0)
		return -ENOMEM;
	
	cb = (struct linx_skb_cb *)(skb->cb);
	cb->signo = LINX_OS_NEW_LINK_SIG;

	/* Check if this is the first time newlink is called, if so don't care
	 * about the token value and use zero. */
	if (linx_sk(sk)->new_link_called == 0) {
		linx_sk(sk)->new_link_called = 1;
		token = 0;
	}

	req = linx_kmalloc(sizeof(struct request_entry));
	if (req == NULL) {
		kfree_skb(skb);
		return -ENOMEM;
	}
	
	req->spid = linx_sock_to_spid(sk);
	req->skb = skb;
	req->token = token;
	req->signal_sent = 0;
	
	/* Traverse the list of active links to see if there exist a link not
	 * known by the requester, i.e. if a link with a index higher than the
	 * supplied token value exists. */
	
	spin_lock_bh(&new_link_req);
	
	req->ref = *ref = ++ new_link_ref;
	
	list_for_each_safe(node, tmp, &new_link_links_list) {
		int rv;
		link_e = (struct link_entry *)node;

		/* Compare the index of the link entry against the supplied
		 * token, if the index is higher a new link is available. */
		if (link_e->idx <= token)
			continue;
		
		/* A new link was found, prepare and send the signal to the
		 * requesting socket. */
		sig = (struct linx_new_link *)skb->data;
		sig->token = link_e->idx;
		sig->name = 0;
		sig->attr = link_e->attr;

		from = linx_spid_to_sock(link_e->spid);
		if (from == NULL) {
			if (!linx_is_zombie_spid(link_e->spid)) {
				linx_err("Request new link sent from invalid "
					 "spid, 0x%x.", link_e->spid);
			}
			spin_unlock_bh(&new_link_req);
			linx_kfree(req);
			return 0;
		}
		
		/* Link the linkname + attribute string to the signal */
		atomic_inc(&link_e->skb->users);
		skb_shinfo(skb)->frag_list = link_e->skb;

		rv = __linx_do_sendmsg_skb_to_local_sk(
			sk, skb, sigsize + link_e->skb_size, from,
			link_e->spid,
			linx_remove_new_link_request, *ref);

		if (rv < 0) {
			spin_unlock_bh(&new_link_req);
			sock_put(from);
			linx_skb_queue_purge(sk, &sk->sk_receive_queue);
			linx_kfree(req);
			return 0;
		}
		req->signal_sent = 1;

		sock_put(from);
		
		break;
	}
	
	/* Update the list of requestors */
	list_add_tail(&req->list, &new_link_req_list);
	spin_unlock_bh(&new_link_req);
	
	return 0;
}


/*
 * linx_cancel_new_link
 *
 * Cancels a pending request for a new link signal, called by a user application
 * via the ioctl() interface.
 */

int linx_cancel_new_link(struct sock *sk, uint32_t ref)
{
	struct list_head *node, *tmp;
	struct request_entry *req;
	
	/* Traverse the list of requests */
	spin_lock_bh(&new_link_req);
	list_for_each_safe(node, tmp, &new_link_req_list) {
		req = (struct request_entry *)node;
		
		if (req->ref != ref)
			continue;

		/* Make sure the canceller is the owning socket */
		if (req->spid != linx_sock_to_spid(sk)) {
			spin_unlock_bh(&new_link_req);
			return -EINVAL;
		}
		
		/* Requester found, remove from the requesters list and free all
		 * resources. */
		list_del(&req->list);
		spin_unlock_bh(&new_link_req);

		/* Remove the new_link signal from the requesting
		 * sockets in-queue. */
		spin_lock_bh(&sk->sk_receive_queue.lock);
		if(req->skb->next != NULL && req->skb->prev != NULL) {
			__skb_unlink_compat(req->skb, sk);
			atomic_dec(&linx_no_of_queued_signals);
		}
		spin_unlock_bh(&sk->sk_receive_queue.lock);
		
		kfree_skb(req->skb);
		linx_kfree(req);
		return 0;
	}
	
	/* Tried to cancel a non-existing/old request */ 
	spin_unlock_bh(&new_link_req);
	return -EINVAL;
}


/*
 * linx_add_link
 *
 * Adds an active link to the linked list of known links and checks
 * if there are any pending requests for new link signals and resolves
 * them, called by the LINX IPC layer when a link is available.
 */

int linx_add_new_link(struct sock *sk, const char *hunt_p, const char *attr)
{
	struct link_entry *link_e;
	struct list_head *node, *tmp;	
	struct request_entry *req;
	struct linx_new_link *sig;
	void *skb_data_buffer;
	int sigsize = offsetof(struct linx_new_link, buf);
	int rv;
	struct sock *to;
	
	/* Allocate an entry for the new link and place it in the list of active
	 * links. If the alloc fails an error is returned and the caller should
	 * make sure that the link is destroyed. */
	link_e = linx_kmalloc(sizeof(struct link_entry));
	if (link_e == NULL) {
		return -ENOMEM;
	}
	link_e->idx = ++ new_link_index;
	link_e->spid = linx_sock_to_spid(sk);
	link_e->skb_size = strlen(hunt_p) + 1;
	link_e->attr = 0;
	
	/* If the link carries attributes make room for them */
	if (attr != NULL) {
		link_e->attr = link_e->skb_size;
		link_e->skb_size += strlen(attr) + 1;
	}
	
	/* Allocate and copy the linkname and attributes to a skb buffer */
	link_e->skb = alloc_skb(link_e->skb_size, GFP_KERNEL);
	if (link_e->skb == NULL) {
		linx_kfree(link_e);
		return -ENOMEM;
	}
	skb_data_buffer = skb_put(link_e->skb, link_e->skb_size);
	memcpy(skb_data_buffer, hunt_p, strlen(hunt_p) + 1);
	if (attr != NULL)
		memcpy(skb_data_buffer + link_e->attr, attr, strlen(attr) + 1);

	/* Add link entry to the linked list of links */
	list_add_tail(&link_e->list, &new_link_links_list);

	/* Traverse the list if requesters and resolve all pending new link
	 * requests. */

 again:
	spin_lock_bh(&new_link_req);
	list_for_each_safe(node, tmp, &new_link_req_list) {
		req = (struct request_entry *)node;

		/* Make sure the token is higher than the index of the link */
		if (req->token >= link_e->idx || req->signal_sent == 1)
			continue;

		
		sig = (struct linx_new_link *)req->skb->data;
		sig->token = link_e->idx;
		sig->name = 0;
		sig->attr = link_e->attr;

		to = linx_spid_to_sock(req->spid);
		if (to == NULL) {
			if (!linx_is_zombie_spid(req->spid)) {
				linx_err("Request new link from invalid spid, "
					 "0x%x.", req->spid);
			}
			spin_unlock_bh(&new_link_req);
			goto again;
		}		
		
		/* Link the linkname + attribute string to the signal */
		atomic_inc(&link_e->skb->users);
		skb_shinfo(req->skb)->frag_list = link_e->skb;

		rv = __linx_do_sendmsg_skb_to_local_sk(
			to, req->skb, sigsize + link_e->skb_size, sk,
			linx_sock_to_spid(sk), linx_remove_new_link_request,
			req->ref);

		if (rv < 0) {
			spin_unlock_bh(&new_link_req);
			sock_put(to);
			linx_skb_queue_purge(to, &to->sk_receive_queue);
			goto again;
		}

		sock_put(to);
		
		req->signal_sent = 1;
	}
	spin_unlock_bh(&new_link_req);
	
	return 0;
}

/*
 * linx_remove_link
 *
 * Removes a link from the list of active links, called from the LINX IPC layer
 * when a link has been lost.
 */

int linx_remove_new_link(struct sock *sk)
{
	struct list_head *node, *tmp;
	struct link_entry *link_e;

	spin_lock_bh(&new_link_req);
	
	/* Traverse the list of active links */
	list_for_each_safe(node, tmp, &new_link_links_list) {
		link_e = (struct link_entry *)node;
		if (link_e->spid != linx_sock_to_spid(sk))
			continue;
		
		/* Match was found, remove the entry from the list and free the
		 * used resources. */
		list_del(&link_e->list);
		
		spin_unlock_bh(&new_link_req);
			
		kfree_skb(link_e->skb);
		linx_kfree(link_e);
		return 0;
	}
	
	spin_unlock_bh(&new_link_req);
	
	/* No match was found */
	return -1;
}

/*
 * linx_remove_new_link_request
 *
 * Removes a request after the new_link signal has been delivered to
 * the user.
 */

void linx_remove_new_link_request(uint32_t ref)
{
	struct list_head *node, *tmp;
	struct request_entry *req;
	
	spin_lock_bh(&new_link_req);
	
	/* Traverse the list of requests */
	list_for_each_safe(node, tmp, &new_link_req_list) {
		req = (struct request_entry *)node;
		if (req->ref != ref)
			continue;

		/* Request found, remove the it from the list */
		list_del(&req->list);
		spin_unlock_bh(&new_link_req);

		/* Remove the new_link signal from the requesting
		 * sockets in-queue. */
		spin_lock_bh(&req->skb->sk->sk_receive_queue.lock);
		if(req->skb->next != NULL && req->skb->prev != NULL) {
			__skb_unlink_compat(req->skb, req->skb->sk);
			atomic_dec(&linx_no_of_queued_signals);
		}
		spin_unlock_bh(&req->skb->sk->sk_receive_queue.lock);

		/* Free the skb buffer and req entry */
		kfree_skb(req->skb);
		linx_kfree(req);
		
		return;
	}
	spin_unlock_bh(&new_link_req);

	linx_warn("Match not found when removing new link request\n");
}

/*
 * linx_remove_new_link_requests
 *
 * Removes all requests done from a specific socket.
 */

void linx_remove_new_link_requests(struct sock *sk)
{
	struct list_head *node, *tmp;
	struct request_entry *req;
	
again:	
	spin_lock_bh(&new_link_req);
	/* Traverse the list of requests */
	list_for_each_safe(node, tmp, &new_link_req_list) {
		req = (struct request_entry *)node;
		if (req->spid != linx_sock_to_spid(sk))
			continue;

		/* Request found, remove the it from the list */
		list_del(&req->list);
		spin_unlock_bh(&new_link_req);
		
		/* Remove the new_link signal from the requesting
		 * sockets in-queue. */
		spin_lock_bh(&req->skb->sk->sk_receive_queue.lock);
		if(req->skb->next != NULL && req->skb->prev != NULL) {
			__skb_unlink_compat(req->skb, req->skb->sk);
			atomic_dec(&linx_no_of_queued_signals);
		}
		spin_unlock_bh(&req->skb->sk->sk_receive_queue.lock);
		
		/* Free the skb buffer and req entry */
		kfree_skb(req->skb);
		linx_kfree(req);

		goto again;
	}
	spin_unlock_bh(&new_link_req);
}
