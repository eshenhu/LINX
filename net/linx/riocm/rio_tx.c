/*
 * Copyright (c) 2008-2009, Enea Software AB
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


#include <rio.h>
#include <rio_proto.h>
#include <buf_types.h>
#include <rio_kutils.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/if_ether.h>
#include <linux/interrupt.h>
#include <linux/jiffies.h>
#include <linux/netdevice.h>
#include <linux/version.h>

/* reserves space in the skb for the rapid io header */
static void reserve_rio_hdr(struct sk_buff *skb)
{
	skb_reserve(skb, RIO_SW_HLEN);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	skb_reset_network_header(skb);
#else
	skb->nh.raw = skb->data;
#endif
}

static void fill_rio_hdr(struct RlnhLinkObj *co, struct sk_buff *skb)
{
	struct net_device *dev;
	struct {
		uint16_t dest_ID;
		uint8_t dest_mbox;
		uint8_t pad;
	} daddr;

	/* this is how the srio needs it */

	daddr.dest_ID = co->peer_ID;
	daddr.dest_mbox = co->peer_mbox;
	daddr.pad = 0;

	dev = co->rio_dev->dev;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	dev->hard_header(skb, dev, RIO_PROTOCOL, &daddr,
			 co->rio_dev->dev->dev_addr, skb->len);
#else
	dev_hard_header(skb, dev, RIO_PROTOCOL, &daddr,
			co->rio_dev->dev->dev_addr, skb->len);
#endif
}

static void fill_heartbeat_hdr(struct sk_buff *skb, struct RlnhLinkObj *co)
{
	struct rio_heartbeat *h = rio_header(skb, h);

	h->type = RIO_HEARTBEAT;
	h->pad = 0;
	h->rsvd = 0;
	h->dst_port = htons(co->peer_port);
	h->dst_cid = htons(co->peer_cid);
	h->sender = htons(co->my_id);
	h->src_port = htons(co->my_port);
}

static void
fill_gen_conn_hdr(struct sk_buff *skb, struct RlnhLinkObj *co, uint8_t type)
{
	struct rio_gen_conn *gen = rio_header(skb, gen);

	gen->type = type;
	gen->generation = co->generation;
	/* gen->mtu filled in later */
	gen->dst_port = htons(co->peer_port);
	/* gen->rsvd filled in later */
	gen->sender = htons(co->my_id);
	gen->src_port = htons(co->my_port);
}

static void
fill_conn_hdr(struct sk_buff *skb, struct RlnhLinkObj *co, uint8_t type)
{
	struct rio_conn_ack *ack;
	struct rio_conn_req *req;
	struct rio_conn_reset *reset;

	fill_gen_conn_hdr(skb, co, type);

	switch(type) {
	case RIO_CONN_REQ:
		req = rio_header(skb, req);
		req->mtu = htons(co->wanted_mtu);
		req->rsvd = 0;
		req->hb_tmo = (uint8_t)(co->user_tmo / 100);
		break;
	case RIO_CONN_ACK:
		ack = rio_header(skb, ack);
		ack->mtu_ack = htons(co->conn_mtu);
		ack->generation_ack = co->peer_generation;
		ack->hb_tmo_ack = (uint8_t)(co->conn_tmo / 100);
		ack->my_cid = htons(co->cid);
		break;
	case RIO_CONN_RESET:
		reset = rio_header(skb, reset);
		reset->rsvd = 0; /* not used */
		reset->mtu = 0; /* not used */
		break;
	default:
		BUG();
		break;
	}
}

static void fill_gen_udata_hdr(struct sk_buff *skb, struct RlnhLinkObj *co,
			       uint8_t type, uint8_t msgid)
{
	struct rio_gen_udata *h = rio_header(skb, h);

	h->type = type;
	h->msgid = msgid;
	/* h->seqno set later */
	h->dst_port = htons(co->peer_port);
	h->dst_cid = htons(co->peer_cid);
	h->sender = htons(co->my_id);
	h->src_port = htons(co->my_port);
}

static void fill_single_hdr(struct sk_buff *skb, struct RlnhLinkObj *co,
			    uint8_t msgid, uint32_t src, uint32_t dst,
			    uint32_t size)
{
	struct rio_single *s = rio_header(skb, s);

	fill_gen_udata_hdr(skb, co, RIO_SINGLE, msgid);
	s->src = htonl(src);
	s->dst = htonl(dst);
	s->payl_size = htonl(size);
}

static void fill_frag_start_hdr(struct sk_buff *skb, struct RlnhLinkObj *co,
				uint16_t msgid, uint32_t src, uint32_t dst,
				uint32_t size)
{
	struct rio_frag_start *fs = rio_header(skb, fs);

	fill_gen_udata_hdr(skb, co, RIO_FRAG_START, msgid);
	fs->src = htonl(src);  
	fs->dst = htonl(dst);  	
	fs->payl_size = htonl(size);
}

static void fill_frag_hdr(struct sk_buff *skb, struct RlnhLinkObj *co,
			  uint16_t msgid)
{
	fill_gen_udata_hdr(skb, co, RIO_FRAG, msgid);
}

static int fill_udata(struct sk_buff *skb, unsigned int buf_type, void *buffer,
		      unsigned int size, unsigned int offset)
{
	if (likely(BUF_TYPE_USER(buf_type)))
		return copy_from_user((char *)skb->data + offset, buffer, size);
	memcpy((char *)skb->data + offset, buffer, size);
	return 0;
}

/* get a new exclusive seqno */
static inline uint16_t get_exclusive_seqno(atomic_t *seqno)
{
	int new;
	int last;
	int old;

	last = atomic_read(seqno);
	for (;;) {
		new = (last + 1) & 0xffff;
		old = atomic_cmpxchg(seqno, last, new);
		if (likely(old == last))
			return (uint16_t)new;
		last = old;
	}
}

static inline void xmit_data_pkt(struct RlnhLinkObj *co, struct sk_buff *skb)
{
	struct rio_gen_udata *h = rio_header(skb, h);
	
	skb->dev = co->rio_dev->dev;
	fill_rio_hdr(co, skb);
	co->tx_packets++;
	co->tx_bytes += skb->len;

	/* tag the data pkt with a seqno. last thing before xmit! */
	h->seqno = htons(get_exclusive_seqno(&co->tx_seqno));

	/* dev_queue_xmit consumes skb. dont check return value */
	(void)dev_queue_xmit(skb);
}

static inline void xmit_maint_pkt(struct RlnhLinkObj *co, struct sk_buff *skb)
{
	skb->dev = co->rio_dev->dev;
	fill_rio_hdr(co, skb);
	co->tx_packets++;
	co->tx_bytes += skb->len;

	/* dev_queue_xmit consumes skb. dont check return value */
	(void)dev_queue_xmit(skb);
}

static void tx_tasklet_send_queued_pkts(struct RlnhLinkObj *co)
{
	struct sk_buff *skb;

	/* process pkts in the tx list */
	skb = skb_dequeue(&co->tx_list);
	while (likely(skb != NULL)) {
		xmit_data_pkt(co, skb);
		skb = skb_dequeue(&co->tx_list);
	}
}

static void tx_tasklet(unsigned long data)
{
	struct RlnhLinkObj *co;

	co = (struct RlnhLinkObj *)data;
	tx_tasklet_send_queued_pkts(co);
        rio_unlock(&co->tx_lock);
}

static inline void schedule_tx_tasklet(struct RlnhLinkObj *co)
{
	if (likely(test_and_set_bit(TASKLET_STATE_SCHED, &co->tx.state) == 0)) {
		if (unlikely(rio_trylock(&co->tx_lock) == 0))
			clear_bit(TASKLET_STATE_SCHED, &co->tx.state);
		else
			__tasklet_schedule(&co->tx);
	}
}

/* get a new exclusive msgid */
static inline uint8_t get_exclusive_msgid(atomic_t *msgid)
{
	int new;
	int last;
	int old;

	last = atomic_read(msgid);
	for (;;) {
		new = (last + 1) & 0xff;
		old = atomic_cmpxchg(msgid, last, new);
		if (likely(old == last))
			return (uint8_t)new;
		last = old;
	}
}

static int send_single(struct RlnhLinkObj *co, unsigned int buffer_type,
		       unsigned int src,
		       unsigned int dst, unsigned int size, char *buffer)
{
	struct sk_buff *skb;
	int skb_size;
	int err;
	int msgid;

	err = 0;
	skb_size = size + SINGLE_HSIZE;
	/* get a msgid. all udata has a msgid */
	msgid = get_exclusive_msgid(&co->msgid);

	skb = alloc_skb(RIO_SW_HLEN + skb_size, GFP_KERNEL);
	if (unlikely(skb == NULL)) {
		rio_submit_disconnect(co);
		err = -ENOMEM;
		goto out;
	}

	reserve_rio_hdr(skb);
	skb_put(skb, skb_size);
	fill_single_hdr(skb, co, msgid, src, dst, size);

	err = fill_udata(skb, buffer_type, buffer, size, SINGLE_HSIZE);
	if (unlikely(err != 0)) {
		kfree_skb(skb);
		rio_submit_disconnect(co);
		goto out;
	}

	skb_queue_tail(&co->tx_list, skb);
	schedule_tx_tasklet(co);
 out:
	return err;
}

static int
send_frag_start(struct RlnhLinkObj *co, unsigned int buffer_type,
		unsigned int src, unsigned int dst, unsigned int size,
		uint16_t msgid, char *buffer)
{
	struct sk_buff *skb;
	int skb_size;
	int err;

	err = 0;
	skb_size = co->frag_start_len + FRAG_START_HSIZE;

	skb = alloc_skb(RIO_SW_HLEN + skb_size, GFP_KERNEL);
	if (unlikely(skb == NULL)) {
		rio_submit_disconnect(co);
		err = -ENOMEM;
		goto out;
	}

	reserve_rio_hdr(skb);
	skb_put(skb, skb_size);
	fill_frag_start_hdr(skb, co, msgid, src, dst, size);

	err = fill_udata(skb, buffer_type, buffer, co->frag_start_len,
			 FRAG_START_HSIZE);
	if (unlikely(err != 0)) {
		kfree_skb(skb);
		rio_submit_disconnect(co);
		goto out;
	}

	skb_queue_tail(&co->tx_list, skb);
	schedule_tx_tasklet(co);
 out:
	return err;
}

static int send_frag(struct RlnhLinkObj *co, unsigned int buffer_type,
		     unsigned int size, uint16_t msgid, char *buffer)
{
	struct sk_buff *skb;
	int skb_size;
	int err;

	err = 0;
	skb_size = size + FRAG_HSIZE;

	skb = alloc_skb(RIO_SW_HLEN + skb_size, GFP_KERNEL);
	if (unlikely(skb == NULL)) {
		rio_submit_disconnect(co);
		err = -ENOMEM;
		goto out;
	}

	reserve_rio_hdr(skb);
	skb_put(skb, skb_size);
	fill_frag_hdr(skb, co, msgid);

	err = fill_udata(skb, buffer_type, buffer, size, FRAG_HSIZE);
	if (unlikely(err != 0)) {
		kfree_skb(skb);
		rio_submit_disconnect(co);
		goto out;
	}

	skb_queue_tail(&co->tx_list, skb);
	schedule_tx_tasklet(co);
 out:
	return err;
}

static int send_fragmented_udata(struct RlnhLinkObj *co,
				 unsigned int buffer_type, unsigned int src,
				 unsigned int dst, unsigned int size,
				 char *buffer)
{
	int err;
	int data_left;
	int msgid;
	
	err = 0;
	data_left = size;
	/* get a msgid that will tag all fragments of this message */
	msgid = get_exclusive_msgid(&co->msgid);
	/* first frag */
	err = send_frag_start(co, buffer_type, src, dst,
			      size, msgid, buffer);
	if (unlikely(err < 0))
		goto out;
	buffer += co->frag_start_len;
	data_left -= co->frag_start_len;
	while (data_left > co->frag_len) {
		/* all frags except first and last */
		err = send_frag(co, buffer_type, co->frag_len,
				msgid, buffer);
		if (unlikely(err < 0))
			goto out;
		buffer += co->frag_len;
		data_left -= co->frag_len;
	}
	/* last frag */
	err = send_frag(co, buffer_type, data_left, msgid, buffer);
 out:
	return err;
}

void rio_send_hb(struct RlnhLinkObj *co, gfp_t flags)
{
	struct sk_buff *skb;

	if (unlikely(rio_trylock(&co->tx_lock) == 0))
		return;

	skb = alloc_skb(RIO_SW_HLEN + HEARTBEAT_HSIZE, flags);
	if (unlikely(skb == NULL)) {
		rio_unlock(&co->tx_lock);
		rio_submit_disconnect(co);
		return;
	}

	reserve_rio_hdr(skb);
	skb_put(skb, HEARTBEAT_HSIZE);

	fill_heartbeat_hdr(skb, co);
	xmit_maint_pkt(co, skb);

        rio_unlock(&co->tx_lock);
}

void rio_send_conn_pkt(struct RlnhLinkObj *co, gfp_t flags, int type)
{
	struct sk_buff *skb;
	int hsize;

	switch(type) {
	case RIO_CONN_REQ:
		hsize = CONN_REQ_HSIZE;
		break;
	case RIO_CONN_ACK:
		hsize = CONN_ACK_HSIZE;
		break;
	case RIO_CONN_RESET:
		hsize = CONN_RESET_HSIZE;
		break;
	default:
		BUG();
		return;
	}		

	if (unlikely(rio_trylock(&co->tx_lock) == 0))
		return;

	skb = alloc_skb(RIO_SW_HLEN + hsize, flags);
	if (unlikely(skb == NULL)) {
		rio_unlock(&co->tx_lock);
		rio_submit_disconnect(co);
		return;
	}

	reserve_rio_hdr(skb);
	skb_put(skb, hsize);

	fill_conn_hdr(skb, co, type);
	xmit_maint_pkt(co, skb);

        rio_unlock(&co->tx_lock);
}

/* downcall from rlnh */
int rio_dc_transmit(struct RlnhLinkObj *co, unsigned int type, unsigned int src,
		    unsigned int dst, unsigned int size, void *buffer)
{
	int err;

	if (unlikely(rio_trylock(&co->tx_lock) == 0))
		return 0;

	if (likely(size <= co->single_len))
		err = send_single(co, type, src, dst, size, buffer);
	else
		err = send_fragmented_udata(co, type, src, dst, size, buffer);
	
	rio_unlock(&co->tx_lock);

	return err;
}

void rio_start_tx(struct RlnhLinkObj *co)
{		
	skb_queue_head_init(&co->tx_list);
        atomic_set(&co->tx_seqno, ~0);
        atomic_set(&co->msgid, 0);
        tasklet_init(&co->tx, tx_tasklet, (unsigned long)co);
}

void rio_stop_tx(struct RlnhLinkObj *co)
{
	tasklet_disable(&co->tx);
	tasklet_kill(&co->tx);

	skb_queue_purge(&co->tx_list);
}
