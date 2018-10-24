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
#include <ipc/hunt.h>
#include <ipc/rlnh.h>
#include <linx_mem.h>
#include <linx_assert.h>
#include <linux/linx_types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <net/sock.h>
#include <rlnh.h>
#include <ipc/new_link.h>
#include <linx_trace.h>
#include <linx_compat.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22))
#else
#include <linux/ioctl32.h>
#endif
#include <linx_compat32.h>
#include <buf_types.h>

#ifndef DEFINE_RWLOCK
#define DEFINE_RWLOCK(x)	rwlock_t x = RW_LOCK_UNLOCKED
#endif

/* This is the size (number of elements) of the hunt name hash table.
 */
#define LINX_HASH_SIZE  256

/* A hash table used for hunt lookup. */
struct hlist_head linx_sockets_bound[LINX_HASH_SIZE];
HLIST_HEAD(linx_sockets_unbound);
DEFINE_RWLOCK(linx_socket_bound_unbound_lock);

/* A list used to store pending hunts. */
HLIST_HEAD(linx_pend_hunt);
DEFINE_RWLOCK(linx_pend_hunt_lock);

/* A data structure that hold information about a pending hunt. */
struct pend_hunt {
	struct hlist_node node;	/* Linked list information. */
	LINX_SPID hunter;	/* The spid of the hunting
				   entity. */
	LINX_SPID owner;	/* The spid of the owning entity. */
	char *name;		/* Pointer to the pending hunt
				   name. */
	int namelen;		/* The length of the name. */
	LINX_OSBUFSIZE sigsize;
	struct sk_buff *skb;    /* skb with the hunt signal or
				 * NULL if the hunt is done by
				 * RLNH. */
};

/* A list used to store remote hunt paths. */
struct hlist_head linx_hunt_path;
DEFINE_RWLOCK(linx_hunt_path_lock);

/* A list used to store link supervisors. */
struct hlist_head linx_link_supervisor;
DEFINE_RWLOCK(linx_link_supervisor_lock);

/* A data structure that hold information about a RLNH hunt path. */
struct hunt_path {
	struct hlist_node node;	/* Linked list information. */
	LINX_SPID spid;		/* Hunt path owner. */
	char name[1];           /* Hunt path */
};

/* A data structure that hold information about a RLNH link supervisor. */
struct link_supervisor {
	struct hlist_node node;	/* Linked list information. */
	LINX_SPID spid;		/* The supervisor spid. */
};

static struct hunt_path *hunt_path_head(void);
static struct hunt_path *hunt_path_next(struct hunt_path *hp);
static struct pend_hunt *alloc_pend_hunt(int namelen,
					 LINX_SPID hunter_spid,
					 LINX_SPID owner_spid);

/*
 *
 * Pending hunt utilities
 *
 */

static void check_pend_hunt(struct pend_hunt *ph)
{
	if (ph == NULL)
		return;
	LINX_INTERNAL_KCHECK(ph, __FILE__, __LINE__);
	LINX_ASSERT(ph->skb == NULL || ph->sigsize != 0);
	LINX_ASSERT(ph->name != NULL);
	LINX_ASSERT(ph->namelen != 0 && ph->namelen == strlen(ph->name));
	LINX_ASSERT(ph->hunter != LINX_ILLEGAL_SPID);
	LINX_ASSERT(ph->owner != LINX_ILLEGAL_SPID);
}

/* Return the first element in the list. */
static inline struct pend_hunt *pend_hunt_head(void)
{
	struct pend_hunt *ph;

	ph = hlist_empty(&linx_pend_hunt) ?
	    NULL : hlist_entry(linx_pend_hunt.first, struct pend_hunt, node);
	check_pend_hunt(ph);

	return ph;
}

/* Move to the next node in the pending hunt list. */
static inline struct pend_hunt *pend_hunt_next(struct pend_hunt *ph)
{
	struct pend_hunt *ph_next;

	check_pend_hunt(ph);
	ph_next = ph->node.next ?
	    hlist_entry(ph->node.next, struct pend_hunt, node) : NULL;
	check_pend_hunt(ph_next);

	return ph_next;
}

/* Lock the pending hunt list and remove a pending hunt from the
 * pending hunt list.
 *
 * NOTE: Must be called with linx_pend_hunt_lock write locked. */
static inline void __remove_pend_hunt(struct pend_hunt *ph)
{
	check_pend_hunt(ph);

	/* Only remove if the node is part of a list. */
	if (ph->node.pprev != NULL) {
		/* Remove the list information. */
		__hlist_del(&ph->node);
		/* Unhash the node. */
		ph->node.pprev = NULL;
	}
	atomic_dec(&linx_no_of_pend_hunt);
}

/* Lock the pending hunt list and add a new element. */
static inline void __add_pend_hunt(struct pend_hunt *ph)
{
	check_pend_hunt(ph);
	hlist_add_head(&ph->node, &linx_pend_hunt);
	atomic_inc(&linx_no_of_pend_hunt);
}

/* Lock the pending hunt list and add a new element. */
static inline void add_pend_hunt(struct pend_hunt *ph)
{
	check_pend_hunt(ph);
	write_lock_bh(&linx_pend_hunt_lock);
	__add_pend_hunt(ph);
	write_unlock_bh(&linx_pend_hunt_lock);
}

/* This function is called as part of bind, it resolve pending hunts
   that match the bind name. */
void linx_resolve_pend_hunt(const char *name, struct sock *sk)
{
	HLIST_HEAD(pend_hunt_tmp);
	struct pend_hunt *ph, *phtmp;
	int namelen;

	LINX_ASSERT(name != NULL);
	linx_check_sock(sk);

	namelen = strlen(name);

	/* Lock the pending hunt list while traversing it. */
	write_lock_bh(&linx_pend_hunt_lock);

	/* Get the first element in the pend hunt list. */
	ph = pend_hunt_head();

	/* Traverse all elements of the list and resolve matching pending
	   hunts. */
	while (ph != NULL) {
		check_pend_hunt(ph);

		/* Compare the new name with the name of the pending hunt. */
		if (ph->namelen == namelen &&
		    !memcmp(name, ph->name, namelen + 1)) {
			/* Prepare move to the next element in the list. */
			phtmp = pend_hunt_next(ph);

			/* Remove the pending hunt from the list. */
			__remove_pend_hunt(ph);

			hlist_add_head(&ph->node, &pend_hunt_tmp);

			/* Move to the next element in the list. */
			ph = phtmp;
		} else {
			/* The pending hunt do not match, try the next one. */
			ph = pend_hunt_next(ph);
		}
	}

	/* Unlock the pending hunt table. */
	write_unlock_bh(&linx_pend_hunt_lock);

	ph = hlist_empty(&pend_hunt_tmp) ?
	    NULL : hlist_entry(pend_hunt_tmp.first, struct pend_hunt, node);
	while (ph != NULL) {
		/* A match was found. */
		struct sock *hunter_sk = linx_spid_to_sock(ph->hunter);
		if (hunter_sk == NULL) {
			LINX_ASSERT(linx_is_zombie_spid(ph->hunter));
			goto next_pend_hunt;
		}

		if (ph->sigsize > 0) {
			int rv;
			/* A local pending hunt was resolved. */
			LINX_SPID hunted = linx_sock_to_spid(sk);
			LINX_ASSERT(hunter_sk != NULL);

			LINX_ASSERT(ph->skb != NULL);
			LINX_ASSERT(ph->sigsize != 0);
			
			/* Send the signal to the socket that issued the
			   pending hunt. */
			rv = __linx_do_sendmsg_skb_to_local_sk(
				hunter_sk, ph->skb, ph->sigsize, sk, hunted,
				NULL, 0);
			
			if (rv < 0) {
				linx_skb_queue_purge(
					hunter_sk,
					&hunter_sk->sk_receive_queue);
			}
			
			ph->skb = NULL;
		} else {
			/* A rlnh pending hunt is resolved. */
			LINX_ASSERT(NULL != hunter_sk);
			(void)
			    linx_rlnh_hunt_resolved(linx_sk
						    (hunter_sk)->rlnh,
						    name,
						    linx_sock_to_spid
						    (sk), ph->hunter);
		}

		sock_put(hunter_sk);

	      next_pend_hunt:
		/* Prepare move to the next element in the list. */
		phtmp = ph->node.next ?
		    hlist_entry(ph->node.next, struct pend_hunt, node) : NULL;

		/* Remove the pending hunt from the list. */
		__hlist_del(&ph->node);
		
		if(ph->skb)
			kfree_skb(ph->skb);
		
		/* Free the pending hunt resources. */
		linx_kfree(ph);

		/* Move to the next element in the list. */
		ph = phtmp;
	}
}

int resolve_new_hunt_path(const char *path, LINX_SPID spid)
{
	HLIST_HEAD(pend_hunt_tmp);
	struct pend_hunt *ph;
	int pathlen;
	int status = 0;

	LINX_ASSERT(path != NULL);
	LINX_ASSERT(spid != LINX_ILLEGAL_SPID);

	pathlen = strlen(path);
	/* Lock the pending hunt list while traversing it. */
	read_lock_bh(&linx_pend_hunt_lock);

	/* Get the first element in the pend hunt list. */
	ph = pend_hunt_head();

	/* Traverse all elements of the list and resolve matching pending
	   hunts. */
	while (ph != NULL) {
		check_pend_hunt(ph);

		/* Compare the new name with the name of the pending hunt. */
		if (ph->namelen > pathlen &&
		    ph->name[pathlen] == '/' &&
		    !memcmp(path, ph->name, pathlen)) {
			struct pend_hunt *ph_clone =
			    alloc_pend_hunt(ph->namelen, ph->hunter, ph->owner);
			if (ph_clone == NULL) {
				status = -ENOMEM;
				goto resolve_new_hunt_path_failed_unlock;
			}
			memcpy(ph_clone->name, ph->name, ph->namelen + 1);

			hlist_add_head(&ph_clone->node, &pend_hunt_tmp);

			/* Move to the next element in the list. */
			ph = pend_hunt_next(ph);
		} else {
			/* Move to the next pending hunt. */
			ph = pend_hunt_next(ph);
		}
	}

	/* Unlock the pending hunt table. */
	read_unlock_bh(&linx_pend_hunt_lock);

	/* Get the first element in the tmp pend hunt list. */
	ph = hlist_empty(&pend_hunt_tmp) ?
	    NULL : hlist_entry(pend_hunt_tmp.first, struct pend_hunt, node);

	/* Traverse all elements of the list and resolve matching pending
	   hunts. */
	while (ph != NULL) {
		struct pend_hunt *phtmp;

		/* Prepare move to the next element in the list. */
		phtmp = ph->node.next ?
		    hlist_entry(ph->node.next, struct pend_hunt, node) : NULL;

		__hlist_del(&ph->node);
		
		if (status == 0)
			status = linx_rlnh_hunt(ph->name, spid, ph->hunter);

		linx_kfree(ph);

		ph = phtmp;

	}
	return status;

      resolve_new_hunt_path_failed_unlock:
	/* Unlock the pending hunt table. */
	read_unlock_bh(&linx_pend_hunt_lock);

	return status;
}

/* This function is called as part of release, Cancel all pending
 * hunts from a specific socket.  If sk == NULL, all pending hunts are
 * removed.
 */
static inline void cancel_pend_hunt(struct sock *sk)
{
	LINX_SPID spid = sk == NULL ? LINX_ILLEGAL_SPID : linx_sock_to_spid(sk);
	struct pend_hunt *ph, *phtmp;

	if (sk != NULL)
		linx_check_sock(sk);

	/* Lock the pending hunt list while traversing it. */
	write_lock_bh(&linx_pend_hunt_lock);

	/* Get the first element in the pend hunt list. */
	ph = pend_hunt_head();

	/* Traverse all elements of the list and "
	   "resolve matching pending hunts. */
	while (ph != NULL) {
		check_pend_hunt(ph);

		/* Remove all pend hunt if spid == LINX_ILLEGAL_SPID or just
		 * remove those that are requested from spid. */
		if (spid == LINX_ILLEGAL_SPID ||
		    ph->hunter == spid || ph->owner == spid) {
			/* Prepare move to the next element in the list. */
			phtmp = pend_hunt_next(ph);

			/* Remove the pending hunt from the list. */
			__remove_pend_hunt(ph);

			/* Free the pending hunt resources. */
			if(ph->skb) {
				kfree_skb(ph->skb);
			}
			
			linx_kfree(ph);

			/* Move to the next element in the list. */
			ph = phtmp;
		} else {
			/* The pending hunt do not match, try the next one. */
			ph = pend_hunt_next(ph);
		}
	}

	/* Unlock the pending hunt table. */
	write_unlock_bh(&linx_pend_hunt_lock);
}

/* Allocate and initialize a struct pend_hunt, sig and name are left
 * pointing at ok locations, but with no contents. The name ans sig
 * has to be filled in later. The allocated pend_hunt is freed as part
 * of resolve. */
#define ALIGN_TO_4(len)   (((len) & 3) ? (((len) & (~3)) + 4) : (len))

static struct pend_hunt *alloc_pend_hunt(int namelen,
					 LINX_SPID hunter_spid,
					 LINX_SPID owner_spid)
{
	struct pend_hunt *ph;

	LINX_ASSERT(namelen > 0);
	LINX_ASSERT(hunter_spid != LINX_ILLEGAL_SPID);
	LINX_ASSERT(owner_spid != LINX_ILLEGAL_SPID);

	ph = linx_kmalloc(sizeof(*ph) + ALIGN_TO_4(namelen + 1));
	if (ph == NULL)
		return NULL;

	/* Calculate the location of the name of the pending hunt (last in
	   the ph data structure). */
	ph->name = (char *)ph + sizeof(struct pend_hunt);

	/* Fill in the hunter spid to make it possible to clean up pending
	   hunts. */
	ph->hunter = hunter_spid;
	ph->owner = owner_spid;
	ph->skb = NULL;
	ph->sigsize = 0;
	ph->namelen = namelen;

	return ph;
}

/*
 *
 * Hunt path utilities
 *
 */

#ifdef ERRORCHECKS
static LINX_OSBOOLEAN validate_hunt_path(struct hunt_path *hp)
{
	if (strlen(hp->name) == 0)
		return LINX_FALSE;
	if (hp->spid == LINX_ILLEGAL_SPID)
		return LINX_FALSE;
	return LINX_TRUE;
}
#endif

static void check_hunt_path(struct hunt_path *hp)
{
	if (hp == NULL)
		return;
	LINX_ASSERT(LINX_FALSE != validate_hunt_path(hp));
}

/* Return the first element in the list. */
static struct hunt_path *hunt_path_head(void)
{
	struct hunt_path *hp;

	hp = hlist_empty(&linx_hunt_path) ?
	    NULL : hlist_entry(linx_hunt_path.first, struct hunt_path, node);
	check_hunt_path(hp);

	return hp;
}

/* Move to the next node in the hunt path list. */
static struct hunt_path *hunt_path_next(struct hunt_path *hp)
{
	struct hunt_path *hp_next;

	check_hunt_path(hp);
	hp_next = hp->node.next ?
	    hlist_entry(hp->node.next, struct hunt_path, node) : NULL;
	check_hunt_path(hp_next);

	return hp_next;
}

static inline int resolve_hunt_path(const char *name, LINX_SPID from)
{
	int namelen;
	struct hunt_path *hunt_p;
	LINX_SPID hunter = LINX_ILLEGAL_SPID;
	int err = 0;

	LINX_ASSERT(name != NULL);
	LINX_ASSERT(from != LINX_ILLEGAL_SPID);

	linx_trace_enter(LINX_TRACEGROUP_IPC, "%s, 0x%x", name, from);

	namelen = strlen(name);

	read_lock_bh(&linx_hunt_path_lock);
	hunt_p = hunt_path_head();
	while (hunt_p != NULL) {
		int len = strlen(hunt_p->name);
		check_hunt_path(hunt_p);
		if (namelen > len && name[len] == '/' &&
		    !strncmp(name, hunt_p->name, len)) {
			hunter = hunt_p->spid;
			break;
		}
		hunt_p = hunt_path_next(hunt_p);
	}
	read_unlock_bh(&linx_hunt_path_lock);

	if (hunter != LINX_ILLEGAL_SPID) {
		err = linx_rlnh_hunt(name, hunter, from);
	}
	return err;
}

/* Add a hunt path.
 * This function is public since it is used by the RLNH.
 * returns -errno on failure else 0.
 */
int linx_add_hunt_path(const char *hunt_path,
		       LINX_SPID owner, struct sock *owner_sk, const char *attr)
{
	unsigned int h_len, strtab_size;
	struct hunt_path *hunt_p, *hunt_p_new;
	int err;
	
	linx_trace_enter(LINX_TRACEGROUP_IPC,
			 "%s, 0x%x, %p", hunt_path, owner, owner_sk);

	linx_check_sock(owner_sk);
	LINX_ASSERT(owner != LINX_ILLEGAL_SPID);
	LINX_ASSERT(hunt_path != NULL);
	LINX_ASSERT(strlen(hunt_path) != 0);
	LINX_ASSERT(strchr(hunt_path, '/') == NULL);
	
	h_len = strlen(hunt_path);

	strtab_size = h_len + 1;

	hunt_p_new = linx_kmalloc(sizeof(*hunt_p_new) + strtab_size);
	if (hunt_p_new == NULL) {
		return -ENOMEM;
	}

	hunt_p_new->spid = owner;
	strncpy(hunt_p_new->name, hunt_path, h_len + 1);		

	check_hunt_path(hunt_p_new);
	
	write_lock_bh(&linx_hunt_path_lock);
	hunt_p = hunt_path_head();
	while (hunt_p != NULL) {
		check_hunt_path(hunt_p);
		if (hunt_p->spid == owner) {
			write_unlock_bh(&linx_hunt_path_lock);
			linx_kfree(hunt_p_new);
			linx_err("Attempt to make the same spid (0x%x) "
				 "own two hunt paths.", hunt_p->spid);
			return -EINVAL;
		}
		if (!memcmp(&hunt_p->name, hunt_path, h_len + 1)) {
			write_unlock_bh(&linx_hunt_path_lock);
			linx_err("Attempt to add a non-unique hunt "
				 "path ('%s').", hunt_p->name);
			linx_kfree(hunt_p_new);
			return -EINVAL;
		}
		hunt_p = hunt_path_next(hunt_p);
	}

	hlist_add_head(&hunt_p_new->node, &linx_hunt_path);
	write_unlock_bh(&linx_hunt_path_lock);

	LINX_ASSERT(linx_sk(owner_sk)->type == LINX_TYPE_REMOTE);
	atomic_dec(&linx_no_of_remote_sockets);
	atomic_inc(&linx_no_of_link_sockets);
	linx_sk(owner_sk)->type = LINX_TYPE_LINK;

        /*
         * Note: the socket type must be changed before the new link signals are
         * sent, otherwise we may have a race with LINX_IOCTL_INFO(type) call
         * for the link phantom.
         */
	err = linx_add_new_link(owner_sk, hunt_path, attr);
	if(err != 0) {
                /* Oops! Undo and return error... */
                atomic_inc(&linx_no_of_remote_sockets);
                atomic_dec(&linx_no_of_link_sockets);
                linx_sk(owner_sk)->type = LINX_TYPE_REMOTE;
		linx_kfree(hunt_p_new);
		return err;
	}

	resolve_new_hunt_path(hunt_path, owner);

	return 0;
}

/* Remove a hunt path.  This function is public since it is used by
 * the RLNH.  returns -1 on failure else 0.
 */
static inline void remove_hunt_path(struct hunt_path *hp)
{
	check_hunt_path(hp);

	/* Only remove if the node is part of a list. */
	if (hp->node.pprev != NULL) {
		/* Remove the list information. */
		__hlist_del(&hp->node);
		/* Unhash the node. */
		hp->node.pprev = NULL;
	}
	linx_kfree(hp);
}

/* Remove a previously added hunt path. */
int linx_remove_hunt_path(struct sock *owner_sk, LINX_SPID owner)
{
	int err;
	struct hunt_path *hunt_p, *hunt_p_tmp;
	LINX_ASSERT(owner != LINX_ILLEGAL_SPID);
	write_lock_bh(&linx_hunt_path_lock);
	hunt_p = hunt_path_head();
	while (hunt_p != NULL) {
		check_hunt_path(hunt_p);
		hunt_p_tmp = hunt_path_next(hunt_p);
		if (hunt_p->spid == owner)
			remove_hunt_path(hunt_p);
		hunt_p = hunt_p_tmp;
	}
	write_unlock_bh(&linx_hunt_path_lock);
	err = linx_remove_new_link(owner_sk);
	return err;
}

/* Remove all hunt paths in the system, this is typically called from
 * the kernel module exit handler. */
void linx_remove_all_hunt_paths(void)
{
	struct hunt_path *hunt_p, *hunt_p_tmp;
	write_lock_bh(&linx_hunt_path_lock);
	hunt_p = hunt_path_head();
	while (hunt_p != NULL) {
		check_hunt_path(hunt_p);
		hunt_p_tmp = hunt_path_next(hunt_p);
		remove_hunt_path(hunt_p);
		hunt_p = hunt_p_tmp;
	}
	write_unlock_bh(&linx_hunt_path_lock);
}

/*
 *
 * Hunt name table utilities
 *
 */

/* Remove a socket from any list and prepare it for insertion to a new
 * list without locking the hunt name table.
 */
static void remove_socket_no_lock(struct sock *sk)
{
	linx_check_sock(sk);
	(void)sk_del_node_init(sk);
	linx_check_sock(sk);
}

/* Add a socket to a hunt table slot list. */
static void insert_socket_no_lock(struct hlist_head *list, struct sock *sk)
{
	linx_check_sock(sk);
	LINX_ASSERT(sk_unhashed(sk));
	sk_add_node(sk, list);
	linx_check_sock(sk);
}

/* Lock the hunt name table and remove-reinitialize a socket. */
static inline void remove_socket(struct sock *sk)
{
	linx_check_sock(sk);
	write_lock_bh(&linx_socket_bound_unbound_lock);
	remove_socket_no_lock(sk);
	write_unlock_bh(&linx_socket_bound_unbound_lock);
	linx_check_sock(sk);
}

/* Lock the hunt name table and add the socket to it. */
static inline void insert_socket(struct hlist_head *list, struct sock *sk)
{
	linx_check_sock(sk);
	write_lock_bh(&linx_socket_bound_unbound_lock);
	insert_socket_no_lock(list, sk);
	write_unlock_bh(&linx_socket_bound_unbound_lock);
	linx_check_sock(sk);
}

/* Lock the hash table and locate a socket by hunt name, return NULL
 * if not found.  If a socket was found, hold it (to avoid race with
 * close).  The exclude makes it possible to avoid matching one
 * specific socket.
 */
static inline struct sock *__locate_name(const char *name,
					 int len,
					 unsigned hash, uint32_t hunter_spid)
{
	struct sock *s, *s_found = NULL;
	struct hlist_node *node;

	linx_trace_enter(LINX_TRACEGROUP_IPC,
			 "%s, %d, 0x%x, 0x%x", name, len, hash, hunter_spid);
	LINX_ASSERT(name != NULL);
	LINX_ASSERT(strlen(name) == len);
	LINX_ASSERT(hash <= LINX_HASH_SIZE);

	/* Traverse the list of sockets in the specified hash slot to find a
	   match. */
	sk_for_each(s, node, &linx_sockets_bound[hash]) {
		linx_check_sock(s);

/* If the length of the aname are the same, potential match was found. */
		if (linx_sk(s)->addr->namelen == len &&
/* Compare the names to make sure the match is met. */
		    !memcmp(linx_sk(s)->addr->name, name, len + 1)) {
			s_found = s;

			/* If we found a match that has the same spid as
			 * hunter_spid then continue search. (If no other match
			 * is found return the result anyway otherwise return
			 * the next first match.) */
			if (hunter_spid != linx_sk(s_found)->addr->spid)
				break;
		}
	}

	/* Lock the socket to avoid it being reclaimed. */
	if (s_found != NULL)
		sock_hold(s_found);

	/* Return NULL since the name was not found or the hunt is pending
	 * in the RLNH. */
	return s_found;
}

/* The linx_hunt function takes a name and a signal to hunt
 * for a specific socket.  The sigsize shall be set to 0 and sig shall
 * be set to NULL if no hunt signal is provided.  If the hunt is made
 * from RLNH rlnh is set to LINX_TRUE the spid parameter contain the
 * spid of the hunter. Found point at the found spid or
 * LINX_ILLEGAL_SPID if no match was found. */
int linx_hunt(struct sock *sk,
	      const char *name,
	      int namelen,
	      void *sig,
	      LINX_OSBUFSIZE sigsize,
	      LINX_SPID hunter_spid,
	      LINX_SPID owner_spid,
	      LINX_SPID * hunted_spid, LINX_OSBOOLEAN rlnh)
{
	struct sock *hunt_sk = NULL;
	struct sock *hunter_sk = NULL;
	struct sock *owner_sk = NULL;
	unsigned hash;
	struct pend_hunt *ph;
	int err = 0;
	char *hunt_name = NULL;

	linx_trace_enter(LINX_TRACEGROUP_IPC,
			 "%s, %d, %p, %d, 0x%x, %p, %d",
			 name, namelen, sig, (int)sigsize,
			 hunter_spid, hunted_spid, rlnh);

	LINX_ASSERT(namelen != 0);
	LINX_ASSERT(name != NULL);
	LINX_ASSERT(sigsize != 0 || sig == NULL);
	LINX_ASSERT(sigsize == 0 || sig != NULL);
	LINX_ASSERT(rlnh == LINX_TRUE || rlnh == LINX_FALSE);

	hunter_sk = linx_spid_to_sock(hunter_spid);
	if (hunter_sk == NULL) {
		if (!linx_is_zombie_spid(hunter_spid))
			linx_err("Info hunt for illegal spid.");
		return -EINVAL;
	}
	linx_check_spid(hunter_sk);

	if (owner_spid != hunter_spid) {
		owner_sk = linx_spid_to_sock(owner_spid);
		if (owner_sk == NULL) {
			if (!linx_is_zombie_spid(owner_spid)) {
				linx_err("Info hunt for illegal spid.");
				sock_put(hunter_sk);
				return -EINVAL;
			}
			sock_put(hunter_sk);
			return -ECONNRESET;
		}
		linx_check_spid(owner_sk);
	} else {
		owner_sk = hunter_sk;
	}

	/* Allocate the pend_hunt structure to be inserted in the pending
	 * hunt list, The pend_hunt structure store both the name and the
	 * hunt signal.  The ph structure is needed also if the hunt will
	 * not pend, to hold the hunt signal.
	 */
	ph = alloc_pend_hunt(namelen, hunter_spid, owner_spid);
	if (ph == NULL) {
		err = -ENOMEM;
		goto linx_hunt_done;
	}

	if (rlnh == LINX_FALSE) {
		/* Copy the hunt name to the pend_hunt data structure, The come
		 * from userspace, and needs to be copyied using the user to
		 * kernel copy method. */
		if (strncpy_from_user(ph->name, name, namelen + 1) != namelen) {
			linx_err("Failed to copy hunt name to kernel.");
			err = -EINVAL;
			goto linx_hunt_done;
		}

		/* Prepare the hunt signal for transmit or pending. */
		if (sig != NULL) {
			struct linx_skb_cb *cb;
			/* Copy the hunt signal to the pend_hunt data
			 * structure. */
			err = linx_skb_create(sig, sigsize, hunter_sk,
					      BUFFER_TYPE_USER, &ph->skb,
					      linx_mem_frag);
			if(err != 0)
				goto linx_hunt_done;
			cb = (struct linx_skb_cb *)(ph->skb->cb);
			get_user(cb->signo, (LINX_SIGSELECT *)sig);
			ph->sigsize = sigsize;
		} else {
			struct linx_skb_cb *cb;
			LINX_SIGSELECT default_hunt_signo = LINX_OS_HUNT_SIG;
			sigsize = sizeof(LINX_SIGSELECT);
			err = linx_skb_create(&default_hunt_signo, sigsize,
					      hunter_sk, BUFFER_TYPE_KERNEL,
					      &ph->skb, 0);
			if(err != 0)
				goto linx_hunt_done;
			cb = (struct linx_skb_cb *)(ph->skb->cb);
			cb->signo = default_hunt_signo;
			ph->sigsize = sigsize;
		}
	} else if (strncpy(ph->name, name, namelen + 1) != ph->name) {
		linx_err("Failed to copy hunt name.");
		err = -EINVAL;
		goto linx_hunt_done;
	}

	if (ph->name[namelen] != '\0' || strlen(ph->name) != namelen) {
		linx_err("Illegal name length specified.");
		err = -EINVAL;
		goto linx_hunt_done;
	}

	check_pend_hunt(ph);

	/* Create a hash number for fast lookup of the hunted name. */
	hash = hash_name(ph->name, namelen, LINX_HASH_SIZE);
	LINX_ASSERT(hash <= LINX_HASH_SIZE);

	/* Make a copy of the hunt name to avoid a race with RLNH when
	 * the pending hunt is resolved and freed before the
	 * resolve_hunt_path call is made. */
	hunt_name = linx_kmalloc(namelen + 1);
	if (hunt_name == NULL) {
		err = -ENOMEM;
		goto linx_hunt_done;
	}

	/* Unlock the hunt table to allow other operations on it. */
	write_lock_bh(&linx_socket_bound_unbound_lock);

	/* Search for the name in the hash of existing names.  locate_name
	 * calls sock_hold() on the found socket if the socket was found.
	 */
	hunt_sk = __locate_name(ph->name, namelen, hash, hunter_spid);

	if (hunt_sk == NULL) {

		struct pend_hunt *ph_backup;

		strncpy(hunt_name, ph->name, namelen + 1);

		/* A socket with the requested name was not found,
		 * place the hunt in the pending hunt queue until a
		 * socket is bound to the specific name.
		 */

		/* Add the hunt pend_hunt structure in the pend_hunt
		 * list. */
		add_pend_hunt(ph);

		/* Unlock the hunt table to allow other operations on
		 * it. */
		write_unlock_bh(&linx_socket_bound_unbound_lock);

		/* Avoid freeing the ph structure. */
		ph_backup = ph;
		ph = NULL;

		/* Try to find a hunt path for the name and in
		 * that case send the hunt to the RLNH. */
		/* NOTE: Make sure to resolve the hunt after
		 * the pending hunt is added to avoid a race
		 * between the RLNH and hunt. */
		err = resolve_hunt_path(hunt_name, hunter_spid);
		if (err == -ECONNRESET) {
			/* The ECONNRESET error indicate that the link is down,
			 * in that case the hunt should be pending until 
			 * the link is up again. */
			err = 0;
		} else if (err != 0) {
			struct pend_hunt *ph_tmp;

			/* Lock the pending hunt list while
			 * traversing it. */
			write_lock_bh(&linx_pend_hunt_lock);

			/* Get the first element in the pend
			 * hunt list. */
			ph_tmp = pend_hunt_head();

			/* Traverse all elements of the list
			 * and resolve matching pending hunts. */
			while (ph_tmp != NULL) {
				check_pend_hunt(ph_tmp);

				/* Compare the new name with the name
				 * of the pending hunt. */
				if (ph_tmp == ph_backup) {
					/* Remove the pending hunt
					 * from the list. */
					__remove_pend_hunt(ph_backup);
					/* Make sure the ph is freed. */
					ph = ph_backup;
					break;
				}
				/* Move to the next element
				 * in the list. */
				ph_tmp = pend_hunt_next(ph_tmp);
			}

			/* Unlock the pending hunt table. */
			write_unlock_bh(&linx_pend_hunt_lock);
		}
		*hunted_spid = LINX_ILLEGAL_SPID;
	} else if (rlnh == LINX_TRUE) {
		write_unlock_bh(&linx_socket_bound_unbound_lock);
		*hunted_spid = linx_sock_to_spid(hunt_sk);

		/* The hunted socket exists. */
		(void)linx_rlnh_hunt_resolved(linx_sk(hunter_sk)->
					      rlnh,
					      ph->name,
					      *hunted_spid, hunter_spid);
	} else {
		int rv;
		
		/* The hunted socket exists, send the hunt signal to the hunter
		 * if specified, and initialize the spid. */

		write_unlock_bh(&linx_socket_bound_unbound_lock);

		/* Set *from to the spid of the found socket. */
		*hunted_spid = linx_sock_to_spid(hunt_sk);

		LINX_ASSERT(ph->skb != NULL);
		LINX_ASSERT(ph->sigsize != 0);
		
		/* Send the hunt signal to the caller. */
		rv = __linx_do_sendmsg_skb_to_local_sk(
				hunter_sk, ph->skb, ph->sigsize, hunt_sk,
				*hunted_spid, NULL, 0);

		if (rv < 0) {
			linx_skb_queue_purge(
				hunter_sk, &hunter_sk->sk_receive_queue);
		}
		ph->skb = NULL;
	}

      linx_hunt_done:
	if (hunt_name)
		linx_kfree(hunt_name);
	
	if (ph != NULL) {
		if(ph->skb)
			kfree_skb(ph->skb);
		linx_kfree(ph);
	}
	/* The sock_put is needed to balance the sock_hold of locate_name. */
	if (hunt_sk != NULL)
		sock_put(hunt_sk);
	if (hunter_sk != NULL)
		sock_put(hunter_sk);
	if (owner_sk != NULL && owner_sk != hunter_sk)
		sock_put(owner_sk);

	return err;
}

/* Publish a socket so its name can be hunted for. */
void linx_publish(struct sock *sk, struct linx_huntname *huntname)
{
	unsigned hash;
	struct hlist_head *list;

	linx_check_sock(sk);
	LINX_ASSERT(huntname != NULL);

	linx_trace_enter(LINX_TRACEGROUP_IPC, "%p, %p", sk, huntname);

	/* Create a hash for the specific name (needed in hunt). */
	hash = hash_name(huntname->name, huntname->namelen, LINX_HASH_SIZE);
	LINX_ASSERT(hash <= LINX_HASH_SIZE);

	/* Insert the socket in the hash table of bound sockets. */
	write_lock_bh(&linx_socket_bound_unbound_lock);
	list = &linx_sockets_bound[hash];

	/* Init the socket for list insertion */

	/* Remove the socket from the unbound list. */
	remove_socket_no_lock(sk);

	linx_sk(sk)->addr = huntname;

	/* Put the socket in the hunt name table. */
	insert_socket_no_lock(list, sk);

	write_unlock_bh(&linx_socket_bound_unbound_lock);
}

/* Store an unbound socket in the list of unbound sockets. */
void linx_store_unbound(struct sock *sk)
{
	linx_check_sock(sk);
	LINX_ASSERT(linx_sk(sk)->addr == NULL);

	/* Put the socket in the unbound list. */
	insert_socket(&linx_sockets_unbound, sk);
}

/* Unpublish a specific hunt name. */
void linx_unpublish(struct sock *sk)
{
	linx_check_sock(sk);
	/* Remove pending hunts. */
	cancel_pend_hunt(sk);
	/* Put the socket in the unbound list. */
	remove_socket(sk);
}

/* Unpublish all hunt names. */
void linx_unpublish_all(void)
{
	/* Remove all pending hunts. */
	cancel_pend_hunt(NULL);

	/* NOTE: Remove all sockets is not really needed. */
}

int linx_info_sockets(struct linx_info_sockets *isockets,
		      LINX_SPID __user * spids)
{
	struct sock *sk;
	const struct hlist_node *node;
	int i, tot_sockets = 0, tot_sockets_tmp = 0, max_sockets;

	LINX_ASSERT(isockets != NULL);

	max_sockets = isockets->buffer_size / sizeof(LINX_SPID);

	read_lock_bh(&linx_socket_bound_unbound_lock);
	/* Count the number of sockets the needs to be returned. */
	sk_for_each(sk, node, &linx_sockets_unbound) {
		if (linx_sk(sk)->type == LINX_TYPE_REMOTE && isockets->remote) {
			tot_sockets_tmp++;
		} else if (linx_sk(sk)->type == LINX_TYPE_LOCAL &&
			   isockets->local) {
			tot_sockets_tmp++;
		} else if (linx_sk(sk)->type == LINX_TYPE_LINK &&
			   isockets->link) {
			tot_sockets_tmp++;
		}
	}
	tot_sockets += tot_sockets_tmp;
	if (tot_sockets_tmp > 0 && max_sockets > 0) {
		LINX_SPID *buffer;

		buffer =
		    (LINX_SPID *) linx_kmalloc(tot_sockets_tmp *
					       sizeof(LINX_SPID));
		if (buffer == NULL) {
			read_unlock_bh(&linx_socket_bound_unbound_lock);
			return -ENOMEM;
		}

		tot_sockets_tmp = 0;

		sk_for_each(sk, node, &linx_sockets_unbound) {
			LINX_SPID spid = linx_sock_to_spid(sk);
			if (linx_sk(sk)->type == LINX_TYPE_REMOTE &&
			    isockets->remote) {
				buffer[tot_sockets_tmp] = spid;
				tot_sockets_tmp++;
			} else if (linx_sk(sk)->type == LINX_TYPE_LOCAL &&
				   isockets->local) {
				buffer[tot_sockets_tmp] = spid;
				tot_sockets_tmp++;
			} else if (linx_sk(sk)->type == LINX_TYPE_LINK &&
				   isockets->link) {
				buffer[tot_sockets_tmp] = spid;
				tot_sockets_tmp++;
			}
		}

		read_unlock_bh(&linx_socket_bound_unbound_lock);

		if (0 != copy_to_user(spids,
				      buffer,
				      max_sockets < tot_sockets_tmp ?
				      max_sockets * sizeof(LINX_SPID) :
				      tot_sockets_tmp * sizeof(LINX_SPID))) {
			linx_kfree(buffer);
			linx_err("Failed to copy hunt information "
				 "to user space.");
			return -EFAULT;
		}
		linx_kfree(buffer);
		spids += max_sockets < tot_sockets_tmp ?
		    max_sockets : tot_sockets_tmp;
		max_sockets -= max_sockets < tot_sockets_tmp ?
		    max_sockets : tot_sockets_tmp;
	} else {
		read_unlock_bh(&linx_socket_bound_unbound_lock);
	}

	for (i = 0; i < LINX_HASH_SIZE; i++) {
		tot_sockets_tmp = 0;
		read_lock_bh(&linx_socket_bound_unbound_lock);
		sk_for_each(sk, node, &linx_sockets_bound[i]) {
			if (linx_sk(sk)->type == LINX_TYPE_REMOTE &&
			    isockets->remote) {
				tot_sockets_tmp++;
			} else if (linx_sk(sk)->type == LINX_TYPE_LOCAL &&
				   isockets->local) {
				tot_sockets_tmp++;
			} else if (linx_sk(sk)->type == LINX_TYPE_LINK &&
				   isockets->link) {
				tot_sockets_tmp++;
			}
		}
		tot_sockets += tot_sockets_tmp;

		if (tot_sockets_tmp > 0 && max_sockets > 0) {
			LINX_SPID *buffer;
			buffer =
			    (LINX_SPID *) linx_kmalloc(tot_sockets_tmp
						       * sizeof(LINX_SPID));
			if (buffer == NULL) {
				read_unlock_bh(&linx_socket_bound_unbound_lock);
				return -ENOMEM;
			}

			tot_sockets_tmp = 0;
			sk_for_each(sk, node, &linx_sockets_bound[i]) {
				LINX_SPID spid = linx_sock_to_spid(sk);
				if (linx_sk(sk)->type == LINX_TYPE_REMOTE &&
				    isockets->remote) {
					buffer[tot_sockets_tmp] = spid;
					tot_sockets_tmp++;
				} else if (linx_sk(sk)->type ==
					   LINX_TYPE_LOCAL && isockets->local) {
					buffer[tot_sockets_tmp] = spid;
					tot_sockets_tmp++;
				} else if (linx_sk(sk)->type ==
					   LINX_TYPE_LINK && isockets->link) {
					buffer[tot_sockets_tmp] = spid;
					tot_sockets_tmp++;
				}
			}
			read_unlock_bh(&linx_socket_bound_unbound_lock);

			if (0 != copy_to_user(spids,
					      buffer,
					      max_sockets < tot_sockets_tmp ?
					      max_sockets * sizeof(LINX_SPID) :
					      tot_sockets_tmp *
					      sizeof(LINX_SPID))) {
				linx_kfree(buffer);
				linx_err("Failed to copy hunt information "
					 "to user space.");
				return -EFAULT;
			}
			linx_kfree(buffer);
			spids += max_sockets < tot_sockets_tmp ?
			    max_sockets : tot_sockets_tmp;
			max_sockets -= max_sockets < tot_sockets_tmp ?
			    max_sockets : tot_sockets_tmp;
		} else {
			read_unlock_bh(&linx_socket_bound_unbound_lock);
		}
	}
	return tot_sockets;
}

int linx_info_pend_hunt(struct linx_info_pend_hunt *ipend_hunt,
			struct linx_info_hunt __user * hunts,
			int *strings_offset, int compat)
{
	struct sock *sk;
	struct linx_info_hunt ihunt;
	struct pend_hunt *ph;
	int hunt_length = 0;
	int strings_length = 0;
	int hunt_offset = 0;
	int string_offset = 0;
	int no_of_hunts = 0;
	int ihunt_size = 0;

	LINX_ASSERT(ipend_hunt != NULL);
	LINX_ASSERT(strings_offset != NULL);

	sk = linx_spid_to_sock(ipend_hunt->spid);
	if (sk == NULL) {
		if (!linx_is_zombie_spid(ipend_hunt->spid)) {
			linx_err("Illegal spid, 0x%x.", ipend_hunt->spid);
			return -EFAULT;
		}
		return -ECONNRESET;
	}

	read_lock_bh(&linx_pend_hunt_lock);

	ihunt_size = sizeof(struct linx_info_hunt);
#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT
	if (unlikely(compat))
		ihunt_size = linx_compat_size(linx_info_hunt);
#endif
#endif

	ph = pend_hunt_head();
	while (ph != NULL) {
		check_pend_hunt(ph);
		if (ph->hunter == ipend_hunt->spid) {
			no_of_hunts++;
			hunt_length += ihunt_size;
			strings_length += ph->namelen + 1;
		}
		ph = pend_hunt_next(ph);
	}

	if (ipend_hunt->buffer_size < hunt_length + strings_length ||
	    no_of_hunts == 0) {
		read_unlock_bh(&linx_pend_hunt_lock);
		*strings_offset = 0;
	} else if (no_of_hunts > 0) {
		void *buffer;
		buffer = linx_kmalloc(hunt_length + strings_length);
		if (buffer == NULL) {
			read_unlock_bh(&linx_pend_hunt_lock);
			sock_put(sk);
			return -ENOMEM;
		}
		*strings_offset = string_offset = hunt_length;
		ph = pend_hunt_head();
		while (ph != NULL) {
			if (ph->hunter == ipend_hunt->spid) {
				struct linx_skb_cb *cb;
				cb = (struct linx_skb_cb *)(ph->skb->cb);
				ihunt.hunt_signal.signo = ph->skb == NULL ?
				    0 : cb->signo;
				ihunt.hunt_signal.size = ph->sigsize;
				ihunt.hunt_signal.from = ph->hunter;
				ihunt.owner = ph->owner;
				ihunt.hunt_name =
				    ((char *)hunts) + string_offset;
				memcpy(((char *)buffer) + hunt_offset,
				       &ihunt, ihunt_size);
				memcpy(((char *)buffer) + string_offset,
				       ph->name, ph->namelen + 1);
				hunt_offset += ihunt_size;
				string_offset += ph->namelen + 1;
			}
			ph = pend_hunt_next(ph);
		}

		read_unlock_bh(&linx_pend_hunt_lock);

		if (0 != copy_to_user(hunts, buffer, string_offset)) {
			sock_put(sk);
			linx_kfree(buffer);
			linx_err("Failed to copy hunt information "
				 "to user space.");
			return -EFAULT;
		}
		linx_kfree(buffer);
	}

	sock_put(sk);
	return no_of_hunts;
}

int linx_info_pend_hunt_payload(struct sock *sk,
				struct linx_info_signal_payload *isig_payload)

{
	int err;
	struct pend_hunt *ph;
	struct iovec to;
	struct linx_info_signal *isignal;
	int size;
	
	LINX_ASSERT(isig_payload != NULL);

	isignal = &isig_payload->signal;
	read_lock_bh(&linx_pend_hunt_lock);
	ph = pend_hunt_head();
	while (ph != NULL) {
		struct linx_skb_cb *cb;
		check_pend_hunt(ph);
		cb = (struct linx_skb_cb *)(ph->skb->cb);
		if (isignal->signo == cb->signo &&
		    isig_payload->buffer_size == ph->sigsize &&
		    isig_payload->spid == ph->owner) {
			size = isignal->size > isig_payload->buffer_size ?
				isig_payload->buffer_size : isignal->size;
			/* bump users count to prevent freeing after
			 * releasing spinlock */
			atomic_inc(&ph->skb->users);
			to.iov_base = isig_payload->buffer;
			to.iov_len = size;
			read_unlock_bh(&linx_pend_hunt_lock);
			err = skb_copy_datagram_iovec(ph->skb, 0, &to, size);
			/* decrease users count/free skb */
			kfree_skb(ph->skb);
			if (unlikely(err < 0)) {
				linx_err("skb_copy_datagram_iovec() "
					 "failed, err=%d.", err);
				return err;
			}
			return size;
		}
		ph = pend_hunt_next(ph);
	}
	read_unlock_bh(&linx_pend_hunt_lock);
	return 0;
}
