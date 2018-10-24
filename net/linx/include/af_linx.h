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
 *  AF_LINX socket type declaration
 */

#ifndef __AF_LINX_H__
#define __AF_LINX_H__

#include <net/sock.h>
#include <linux/linx_types.h>
#include <linx_assert.h>
#include <ipc/stat.h>

struct RlnhObj;

/* Kernel module arguments */
#define LINX_MAX_SPIDS_DEFAULT 512
#define LINX_MAX_SPIDS_ALLOWED 65536
extern int linx_max_spids;

#define LINX_MAX_ATTREFS_DEFAULT 1024
#define LINX_MAX_ATTREFS_ALLOWED 65536
extern int linx_max_attrefs;

#define LINX_MAX_SOCKETS_PER_LINK_MIN 2
#define LINX_MAX_SOCKETS_PER_LINK_DEFAULT 1024
#define LINX_MAX_SOCKETS_PER_LINK_ALLOWED 65536
extern int linx_max_sockets_per_link;

#define LINX_MAX_LINKS_DEFAULT 32
#define LINX_MAX_LINKS_ALLOWED 1024
extern int linx_max_links;

#define LINX_MAX_INT 0x7fffffff

#define LINX_MAX_TMOREFS_DEFAULT 1024
#define LINX_MAX_TMOREFS_ALLOWED 65536
extern int linx_max_tmorefs;

extern int linx_mem_frag;

/* Not a kernel module parameter */
#define LINX_SPID_INSTANCE_MAX_DEFAULT 65536

/* The AF_LINX socket */
struct linx_sock {
	/* NOTE: sk has to be the first member */
	struct sock sk;		/* sock pointer. */
#ifdef ERRORCHECKS
#define LINX_SK_MAGIC	0x89697901
	uint32_t magic;		/* magic == LINX_SK_MAGIC */
#endif
	LINX_SPID spid;		/* The SPID of this socket */
	struct linx_huntname *addr;	/* sock name. */
	int type;		/* The socket type. */
	int state;		/* The execution state of the socket. */

	/* The following three fields are only used for
	 * LINX_TYPE_REMOTE (peer) sockets. */
	LINX_RLNH rlnh;		/* Reference to the RLNH link on which
				 * the represented remote endpoint
				 * is located. */
	uint32_t rlnh_dst_addr;	/* RLNH addressing id
				 * associated with
				 * this socket when used as
				 * dst */
	uint32_t rlnh_peer_addr;	/* If this remote LINX endpoint
					 * is used as a sender and the
					 * receiving LINX endpoint
					 * exists on the same remote
					 * node, this peer address is
					 * published and used as the
					 * sending linkaddress
					 * representing the local LINX
					 * endpoint that this remote
					 * LINX endpoint represents. */

	LINX_SPID from_filter;	/* The receive from filter. */
	LINX_SIGSELECT *filter;	/* The receive all signals
				 * filter. */
	struct hlist_head attach_callers;	/* List of pending attachs to
						 * the socket. */
	struct hlist_head attach_victims;	/* List of pending attachs
						 * from the socket. */
	LINX_OSBOOLEAN resolved;	/* LINX_TRUE if the socket is
					 * being closed and
					 * attaches are handled
					 * (canceled or resolved). */
	spinlock_t skb_alloc_lock;	/* Lock to synchronize
					 * allocation of skb buffers
					 * from tasklet context. */
	atomic_t in_use;                /* Socket in use */
	struct work_struct close_work;
	pid_t owner_pid;
	pid_t owner_tgid;

	struct list_head timeouts;	/* List of pending timeouts
					 * from this socket. */

	uint8_t new_link_called;        /* Last sent new link signal */
	
#ifdef SOCK_STAT
	struct linx_sock_stat stat;
	LINX_SPID link_spid;	/* This is the spid of the LINX socket
				   representing the link. */
#endif

	/* Sender info needed by RLNH. Each RLNH link
	 * stores a sender id for the socket
	 * in a unique slot in the array. */

	uint32_t rlnh_sender_hd[1];
};

struct linx_skb_cb { /* max 40 bytes, depending on kernel version */
	LINX_SPID from_spid;
	LINX_SPID to_spid;
	LINX_OSBUFSIZE payload_size;
	LINX_SIGSELECT signo;
	uint32_t flags;
	uint32_t ref;
	void (*destructor)(uint32_t);
	uint16_t type;
	uint16_t pass_ptr;
};

/* Translate sock to linx_sock address. */
#define linx_sk(sock) container_of(sock, struct linx_sock, sk)

/*
 *
 * Misc error check utilities
 *
 */

#define linx_check_sockaddr_linx(sa) do { \
	LINX_ASSERT(sa != NULL); \
	LINX_ASSERT(sa->family == AF_LINX); \
} while(0)

#define linx_check_linx_huntname(hname) do { \
	if (hname->namelen != 0) { \
		LINX_ASSERT(strlen(name->name) == name->namelen); \
	}\
	LINX_ASSERT(name->namelen != 0 || name->name == NULL); \
} while(0)

#define linx_check_linx_sock(u)	  do { \
	LINX_ASSERT(u != NULL); \
	LINX_ASSERT(u->magic == LINX_SK_MAGIC); \
} while(0)

#define linx_check_sock(sk)	  linx_check_linx_sock(linx_sk(sk))
#define linx_check_socket(sock)	  linx_check_linx_sock(linx_sk(sock->sk));
#define linx_check_spid(sk)	  do { \
	LINX_ASSERT(sk != NULL); \
	linx_check_sock(sk); \
	LINX_ASSERT(linx_sk(sk)->addr->spid != LINX_ILLEGAL_SPID); \
} while(0)

extern atomic_t linx_no_of_remote_sockets;
extern atomic_t linx_no_of_link_sockets;
extern atomic_t linx_no_of_pend_hunt;

static inline LINX_SPID linx_sock_to_spid(struct sock *sk)
{
	linx_check_sock(sk);
	return linx_sk(sk)->spid;
}

/* Translate a spid to a sock struct. */
struct sock *linx_spid_to_sock(LINX_SPID spid);

int
linx_do_sendmsg(struct sock *sk,
		void *payload,
		LINX_OSBUFSIZE payload_size,
		struct sock *to,
		LINX_SPID to_spid,
		struct sock *from,
		LINX_SPID from_spid,
		uint32_t buffer_type,
		uint32_t *consumed);

int
__linx_do_sendmsg_skb_to_local_sk(struct sock *to,
				  struct sk_buff *skb,
				  LINX_OSBUFSIZE payload_size,
				  struct sock *from,
				  LINX_SPID from_spid,
				  void (*destructor)(uint32_t),
				  uint32_t ref);

void linx_skb_queue_purge(struct sock *sk, struct sk_buff_head *list);

int linx_is_zombie_spid(LINX_SPID spid);

struct linx_huntname *linx_alloc_huntname(LINX_SPID spid, const char *name);

void linx_free_linx_name(struct linx_huntname *huntname);

int linx_do_ioctl_name(struct sock *sk, struct linx_huntname *name);

int af_linx_init(void);

int af_linx_exit(void);

int
linx_skb_copy_bits(const struct sk_buff *skb, int offset, void *to, int len);

int
linx_skb_create(void *payload, LINX_OSBUFSIZE payload_size,
		struct sock *to, uint32_t buffer_type,
		struct sk_buff **skb, int frag);

void skb_insert_oob(struct sk_buff *oob_skb, struct sk_buff_head *list);

#endif
