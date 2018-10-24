/*
 * Copyright (c) 2009-2010, Enea Software AB
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

#ifndef __RIO_H__
#define __RIO_H__

#include <asm/atomic.h>
#include <linux/if_ether.h>
#include <linux/linx_types.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/linx_ioctl.h>

#include <rio_lock.h>

#define RIO_VERSION LINX_VERSION

/* minimum MTU accepted value in bytes */
#define RIOCM_MIN_MTU    64
#define RIO_DEFAULT_MTU 256

#define FRAG_ARRAY_SIZE 32
#define REORDER_ARRAY_SIZE 64

struct rio_work;

struct rio_device { /* RIO container for a network device. */
	struct list_head node;
        struct list_head conn_list;
	struct packet_type pt;
        struct net_device *dev;
};

/* rio control block in skb */
struct rio_cb {
	uint32_t src;
	uint32_t dst;
	uint32_t size;
	uint16_t msgid;
	uint16_t frags; 
	uint16_t patches;
};

struct RlnhLinkObj {
        char *con_name;
        uint64_t con_cookie;
        void *lo; /* Link reference */
        struct RlnhLinkUCIF *uc; /* Link upcalls */

        struct timer_list conn_timer;
        unsigned long next_conn_tmo;
 	unsigned int connect_tmo;
        atomic_t conn_timer_lock;
        atomic_t conn_alive_count;

        atomic_t use_count;
        struct list_head node;

        atomic_t disc_count;
        struct rio_work *w_disc;

        struct rio_device *rio_dev;
	uint16_t peer_ID;
	uint8_t peer_mbox;
	uint16_t peer_port;
	uint16_t my_id;
	uint16_t my_port;
	char *dev_name;

        unsigned int conn_tmo;
        unsigned int user_tmo;
	uint16_t user_mtu;
	uint16_t wanted_mtu;
	uint16_t conn_mtu;
	int single_len;
	int frag_start_len;
	int frag_len;
	int patch_start_len;
	
	uint8_t generation;
	uint8_t peer_generation;
	uint16_t peer_cid;
	uint16_t cid;
        uint16_t state;
	
	/* tx */
        struct rio_lock tx_lock;
	struct sk_buff_head tx_list;
	struct tasklet_struct tx;
	
	/* rx */
        struct rio_lock rx_lock;
	struct sk_buff_head rx_list;
	struct tasklet_struct rx;
	struct rio_lock conn_rx_lock;

	/* fragmentation and reordering*/
	uint16_t rx_expected_seqno; /* no need for atomic */
	struct sk_buff **reorder_array;
	atomic_t tx_seqno; /* needed? all data sent from tasklet... */
	atomic_t msgid;
	struct sk_buff **frag_array;
	struct sk_buff_head frag_list;
	
	/* statistics */
	unsigned long tx_packets;
	unsigned long tx_bytes;
	unsigned long rx_packets;
	unsigned long rx_bytes;
	unsigned long num_connections;
};

/* two macros for managing rio headers in skb's */
#define rio_header_type(skb) (*(uint8_t *)skb->data)
#define rio_header(skb, type) ((typeof(type))skb->data)

/* Keepalive values */
#define RIO_CONN_DEFAULT_HEARTBEAT 500
#define RIO_CONN_ALIVE_RESET_VALUE 3
static inline void rio_mark_conn_alive(struct RlnhLinkObj *co)
{
        atomic_set(&co->conn_alive_count, RIO_CONN_ALIVE_RESET_VALUE);
}

#ifdef RIO_COMPAT
extern int rio_rx(struct sk_buff *skb, struct net_device *dev,
		  struct packet_type *pt, struct net_device *orig_dev);
#else
extern int rio_rx(struct sk_buff *skb, struct net_device *dev,
		  struct packet_type *pt);
#endif

extern int rio_submit_conn_pkt(struct RlnhLinkObj *co, struct net_device *dev,
			       struct sk_buff *skb);

extern int rio_submit_disconnect(struct RlnhLinkObj *co);

extern void rio_send_conn_pkt(struct RlnhLinkObj *co, gfp_t flags, int type);
extern void rio_send_hb(struct RlnhLinkObj *co, gfp_t flags);

extern void rio_start_tx(struct RlnhLinkObj *co);
extern void rio_stop_tx(struct RlnhLinkObj *co);
extern int  rio_start_rx(struct RlnhLinkObj *co);
extern void rio_stop_rx(struct RlnhLinkObj *co);
extern void rio_deliver_queued_pkts(struct RlnhLinkObj *co);

extern struct RlnhLinkObj *
get_rio_conn(struct sk_buff *skb, struct rio_device *dev);

extern void put_rio_connection(struct RlnhLinkObj *co);

#endif
