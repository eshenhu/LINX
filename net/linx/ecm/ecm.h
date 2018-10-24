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

#ifndef __ECM_H__
#define __ECM_H__

#include <asm/atomic.h>
#include <linux/if_ether.h>
#include <linux/linx_ioctl.h>
#include <linux/linx_types.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>

#include <ecm_lock.h>

#define ECM_VERSION LINX_VERSION

/* swdq - rx and tx */
#define MODULUS_MASK 4095
#define WINDOW_SIZE 128
#define DEFERRED_QUEUE_SIZE 2048
#define FRAG_ARRAY_SIZE 32

#define REQUEST_ACK 1
#define NO_REQUEST_ACK 0

struct ecm_work;

struct ecm_device { /* ECM container for a network device. */
	struct list_head node;
        struct list_head conn_list;
	struct packet_type pt;
        struct net_device *dev;
};

struct RlnhLinkObj {
        char *con_name;
        uint64_t con_cookie;
        void *lo; /* Link reference */
        struct RlnhLinkUCIF *uc; /* Link upcalls */

        struct timer_list conn_timer;
        unsigned long next_conn_tmo;
        unsigned int conn_tmo;
        atomic_t conn_timer_lock;
        atomic_t conn_alive_count;

        atomic_t use_count;
        struct list_head node;

        atomic_t disc_count;
        struct ecm_work *w_disc;

        struct ecm_device *ecm_dev;
	uint8_t peer_mac[ETH_ALEN];
	char *dev_name;
        char *features;
        size_t features_len;
	int user_mtu;
	int data_len;
	int udata_len;
	int frag_len;
        int peer_version;
	int peer_coreid;
	int peer_cid;
	int cid;
        int state;
	int mhdr_len;
	
	/* tx */
        struct ecm_lock tx_lock;
	struct sk_buff_head tx_list;
	struct tasklet_struct tx;
	
	/* rx */
        struct ecm_lock rx_lock;
	struct sk_buff_head rx_list;
	struct tasklet_struct rx;
	struct ecm_lock conn_rx_lock;
	
	/* rx and tx swdq */
	int preferred_wsize;
	int wsize;
	
	/* rx swdq */	
	struct sk_buff **rx_queue;
	uint32_t rx_queue_start;
	uint32_t rx_queue_size;
	uint32_t rx_next;

	/* tx swdq */
	struct sk_buff_head tx_queue;
	uint32_t tx_queue_size;
	uint32_t tx_next;
	atomic_t tx_last_ack;
	
	/* tx deferred queue */
	struct sk_buff_head tx_def_queue;
	uint32_t tx_def_queue_size;
	uint32_t tx_def_queue_max_size;

	/* tx timer */
	struct timer_list tx_timer;
	atomic_t tx_tmo;
	int tx_last_timer_ack;

	/* rx timer */
	struct timer_list rx_timer;
	atomic_t rx_tmo;
	int rx_last_queue_start;

	/* fragmentation */
	atomic_t fragno;
	struct sk_buff **frag_array;
	struct sk_buff_head frag_list;

	/* tx nack queue */
	struct sk_buff_head nack_queue;
	
	/* tx statistics */
	unsigned long tx_packets;
	unsigned long tx_bytes;
	unsigned long tx_resent_packets;
	unsigned long tx_resent_bytes;

	/* rx statistics */
	unsigned long rx_packets;
	unsigned long rx_bytes;
	unsigned long rx_nacks;
	unsigned long bad_packets;
	
	/* conn statistics */
	unsigned long num_connections;
};

/* Keepalive values */
#define ECM_ACKR_PER_TMO 3
#define ECM_CONN_ALIVE_RESET_VALUE (ECM_ACKR_PER_TMO + 1)
static inline void ecm_mark_conn_alive(struct RlnhLinkObj *co)
{
        atomic_set(&co->conn_alive_count, ECM_CONN_ALIVE_RESET_VALUE);
}

#ifdef ECM_COMPAT
extern int ecm_rx(struct sk_buff *skb, struct net_device *dev,
		  struct packet_type *pt, struct net_device *orig_dev);
#else
extern int ecm_rx(struct sk_buff *skb, struct net_device *dev,
		  struct packet_type *pt);
#endif

extern int ecm_submit_conn_pkt(struct RlnhLinkObj *co, struct net_device *dev,
			       struct sk_buff *skb);

extern int ecm_submit_disconnect(struct RlnhLinkObj *co);

extern void ecm_send_conn_pkt(struct RlnhLinkObj *co, gfp_t flags, int type);
extern void ecm_send_ack(struct RlnhLinkObj *co, gfp_t flags, int request_ack);
extern void ecm_send_nack(struct RlnhLinkObj *co, gfp_t flags, int seqno,
			  int nacknum);
extern void ecm_handle_nack(struct RlnhLinkObj *co, struct sk_buff *skb);
extern void ecm_update_last_ackno(struct RlnhLinkObj *co, int ackno);

extern void ecm_start_tx(struct RlnhLinkObj *co);
extern void ecm_stop_tx(struct RlnhLinkObj *co);
extern int  ecm_start_rx(struct RlnhLinkObj *co);
extern void ecm_stop_rx(struct RlnhLinkObj *co);

extern struct RlnhLinkObj *get_ecm_connection(unsigned int cid, uint8_t *mac,
					      struct ecm_device *dev,
					      int peer_coreid);
extern void put_ecm_connection(struct RlnhLinkObj *co);

#endif
