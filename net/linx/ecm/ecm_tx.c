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


#include <ecm.h>
#include <ecm_proto.h>
#include <buf_types.h>
#include <ecm_kutils.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/if_ether.h>
#include <linux/interrupt.h>
#include <linux/jiffies.h>
#include <linux/netdevice.h>
#include <linux/version.h>

#define TX_TIMER 100 /* tx timeout in ms */

#define MORE_FRAGS 1
#define NO_MORE_FRAGS 0

/* reserves space in the skb for the ethernet header */
/* the ETH_HLEN value creates problems if the underlying
 * device is a 8021Q one. The solution is to use the 
 * hard_header_len value set by the corresponding network
 * device driver; however, the skb->dev member must be
 * set in order for this to work */
static void reserve_eth_hdr(struct sk_buff *skb, int size, int multicore_size)
{
	unsigned short header_len = ETH_HLEN;

	if (skb->dev)
		header_len = skb->dev->hard_header_len;
	if (multicore_size)
		header_len += multicore_size;
	skb_reserve(skb, header_len);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	skb_reset_network_header(skb);
#else
	skb->nh.raw = skb->data;
#endif
	skb_put(skb, size);
}

static void fill_eth_hdr(struct RlnhLinkObj *co, struct sk_buff *skb)
{
	struct net_device *dev;

	dev = co->ecm_dev->dev;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	dev->hard_header(skb, dev, ECM_PROTOCOL, co->peer_mac,
			 co->ecm_dev->dev->dev_addr, skb->len);
#else
	dev_hard_header(skb, dev, ECM_PROTOCOL, co->peer_mac,
			co->ecm_dev->dev->dev_addr, skb->len);
#endif
}

static void fill_multicore_hdr(struct sk_buff *skb, int coreid, int peer_coreid)
{   
	uint32_t w;
	w = 0;
	w = set_dst_coreid(w, peer_coreid);
	w = set_src_coreid(w, coreid);
	skb_push(skb, HDR_MULTICORE_SIZE);
	hton_unaligned(skb->data, w, MULTICORE_HDR_OFFSET);
}


static void fill_main_hdr(struct sk_buff *skb, unsigned int next_hdr,
			  unsigned int size, unsigned int cid, unsigned int ver)
{
	uint32_t w;
	w = 0;
	w = set_next(w, next_hdr);
	w = set_ver(w, ver);
	w = set_packet_size(w, size);
	w = set_cid(w, cid);
	hton_unaligned(skb->data, w, MAIN_HDR_OFFSET);
}

static void fill_ack_hdr(struct sk_buff *skb, unsigned int next_hdr,
			 unsigned int request, unsigned int ackno,
			 unsigned int seqno)
{
	uint32_t w;
	w = 0;
	w = set_next(w, next_hdr);
	w = set_request(w, request);
	w = set_ackno(w, ackno);
	w = set_seqno(w, seqno);
	hton_unaligned(skb->data, w, ACK_HDR_OFFSET);
}

static void fill_nack_hdr(struct sk_buff *skb, unsigned int next_hdr,
			  unsigned int count, unsigned int seqno)
{
	uint32_t w;
	w = 0;
	w = set_next(w, next_hdr);
	w = set_count(w, count);
	w = set_seqno_n(w, seqno);
	hton_unaligned(skb->data, w, NACK_HDR_OFFSET);
}

static void fill_udata_hdr(struct sk_buff *skb, unsigned int next_hdr,
			  unsigned int more, unsigned int fragno,
			  unsigned int type)
{
	uint32_t w;
	w = 0;
	w = set_next(w, next_hdr);
	w = set_more(w, more);
	w = set_fragno(w, fragno);
	if (unlikely(BUF_TYPE_OOB(type)))
		w = set_oob(w, 1);
	hton_unaligned(skb->data, w, UDATA_HDR_OFFSET);
}

static void fill_frag_hdr(struct sk_buff *skb, unsigned int next_hdr,
			 unsigned int more, unsigned int fragno)
{
	uint32_t w;
	w = 0;
	w = set_next(w, next_hdr);
	w = set_more(w, more);
	w = set_fragno(w, fragno);
	hton_unaligned(skb->data, w, FRAG_HDR_OFFSET);
}

static void fill_conn_hdr(struct sk_buff *skb, unsigned int type,
			 unsigned int wsize, unsigned int cid, uint8_t *mac,
			 uint8_t *peer_mac, uint8_t *feat_str, int feat_str_len,
			 int version)
{
	uint32_t w;
	w = 0;
	w = set_next(w, HDR_NONE);
	w = set_conn_type(w, type);
	w = set_connect_size(w,HW_ADDRESS_SIZE);
	w = set_window_size(w, ffs(wsize) - 1);
	w = set_publish_conn_id(w, cid);	
	hton_unaligned(skb->data, w, CONN_HDR_OFFSET);
	set_dst_hw_addr(skb->data, peer_mac);
	set_src_hw_addr(skb->data, mac);
	if (unlikely(version == 2))
		return;
	if (type == CONN_ACK || type == CONN_CONNECT_ACK)
		set_feat_str(skb->data, feat_str, feat_str_len + 1);
	else {
		char empty_str[] = "\0";
		uint8_t *p = (uint8_t *)empty_str;
		set_feat_str(skb->data, p, 1);
	}
}

static void fill_linkaddresses(struct sk_buff *skb, unsigned int ver,
			      unsigned int src, unsigned int dst)
{
	uint32_t w;
	w = 0;
	if (unlikely(ver == 2)) {
		w = set_src(w, src);
		w = set_dst(w, dst);
		hton_unaligned(skb->data, w, UDATA_HDR_ADDR_OFFSET);
	} else {
		hton_unaligned(skb->data, dst, UDATA_HDR_DST_OFFSET);
		hton_unaligned(skb->data, src, UDATA_HDR_SRC_OFFSET);
	}
}

static int fill_udata(struct sk_buff *skb, unsigned int buf_type, void *buffer,
		     unsigned int size, unsigned int offset)
{
	if (likely(BUF_TYPE_USER(buf_type)))
		return copy_from_user((char *)skb->data + offset, buffer, size);
	memcpy((char *)skb->data + offset, buffer, size);
	return 0;
}

static inline void xmit_pkt(struct RlnhLinkObj *co, struct sk_buff *skb)
{
	skb->dev = co->ecm_dev->dev;

	if (co->mhdr_len)
		fill_multicore_hdr(skb, 0, co->peer_coreid);

	fill_eth_hdr(co, skb);
	co->tx_packets++;
	co->tx_bytes += skb->len;
	/*
	 * return value is not checked from dev_queue_xmit, the skb is always
	 * consumed and packetloss is detected by the keep-alive mechanism.
	 */
	(void)dev_queue_xmit(skb);
}

static void tx_tasklet_redirect(unsigned long data)
{
	struct RlnhLinkObj *co = (struct RlnhLinkObj *)data;
	ecm_unlock(&co->tx_lock);
}

static void tx_queue_add(struct RlnhLinkObj *co, struct sk_buff *skb)
{
	struct sk_buff *skb_head_copy;
	uint32_t ack_hdr;

	/*
	 * fill ack_hdr with ackno and seqno headers, set the request ack
	 * bit if the sliding window queue is becomming full
	 */
	ack_hdr = ntoh_unaligned(skb->data, ACK_HDR_OFFSET);
	fill_ack_hdr(skb, get_next(ack_hdr),
		     (co->tx_queue_size > (co->wsize >> 1) ? 1 : 0) ||
		     (co->wsize == 1 ? 1 : 0), co->rx_next, co->tx_next);
	
	/*
	 * clone the skb head (data is not copied) to prevent skb being freed
	 * by the driver in dev_queue_xmit which calls kfree_skb.
	 */
	skb_head_copy = skb_clone(skb, GFP_ATOMIC);
	if (unlikely(skb_head_copy == NULL)) {
		kfree_skb(skb);
		ecm_submit_disconnect(co);
		return;
	}

	/* add skb to sliding window queue */
	__skb_queue_tail(&co->tx_queue, skb_head_copy);
	co->tx_queue_size++;

	/* update sequence number */
	co->tx_next = (co->tx_next + 1) & MODULUS_MASK;
}

static void tx_tasklet_free_acknowledged_pkts(struct RlnhLinkObj *co)
{
	struct sk_buff *skb;
	uint32_t ack_hdr;

	while (co->tx_queue_size > 0) {
		skb = skb_peek(&co->tx_queue);
		ack_hdr = ntoh_unaligned(skb->data, ACK_HDR_OFFSET);
		if (get_seqno(ack_hdr) == atomic_read(&co->tx_last_ack))
			break;
		__skb_unlink(skb, &co->tx_queue);
		kfree_skb(skb);
		co->tx_queue_size--;
	}
}

static struct sk_buff *tx_tasklet_resend_pkts(struct RlnhLinkObj *co,
					      struct sk_buff *skb,
					      int seqno, int count)
{
	struct sk_buff *skb_head_copy;
	uint32_t ack_hdr;

	/* traverse tx queue for the nacked packet and resend if found */
	while (skb != (struct sk_buff *)&co->tx_queue && count != 0) {
		ack_hdr = ntoh_unaligned(skb->data, ACK_HDR_OFFSET);
		if (get_seqno(ack_hdr) != seqno) {
			skb = skb->next;
			continue;
		}
		fill_ack_hdr(skb, get_next(ack_hdr), 0, co->rx_next,
			     get_seqno(ack_hdr));
		skb_head_copy = skb_clone(skb, GFP_ATOMIC);
		if (unlikely(skb_head_copy == NULL)) {
			ecm_submit_disconnect(co);
			return NULL;
		}
		co->tx_resent_packets++;
		co->tx_resent_bytes += skb->len;
		xmit_pkt(co, skb_head_copy);
		count--;
		seqno = (seqno + 1) & MODULUS_MASK;
		skb = skb->next;
	}
	return skb;
}

static void tx_tasklet_handle_nacks(struct RlnhLinkObj *co)
{
	struct sk_buff *skb;
	struct sk_buff *nack_skb;
	uint32_t nack_hdr;
	int seqno;
	int count;

	skb = skb_peek(&co->tx_queue);

	/* go through list of nacked packets */
	nack_skb = skb_dequeue(&co->nack_queue);
	while (unlikely(nack_skb != NULL)) {
		nack_hdr = ntoh_unaligned(nack_skb->data, NACK_HDR_OFFSET);
		kfree_skb(nack_skb);
		seqno = get_seqno_n(nack_hdr);
		count = get_count(nack_hdr);
		/* resend nacked packets */
		if (likely(skb != NULL))
			skb = tx_tasklet_resend_pkts(co, skb, seqno, count);
		nack_skb = skb_dequeue(&co->nack_queue);
	}
}

static void tx_tasklet_handle_tmo(struct RlnhLinkObj *co)
{
	struct sk_buff *skb;
	struct sk_buff *skb_head_copy;
	uint32_t ack_hdr;

	/* tx timeout? */
	if (likely(atomic_cmpxchg(&co->tx_tmo, 1, 0) == 0))
		return;

	/*
	 * tx queue empty (i.e. nothing to resend), or no ack has been
	 * received since last tx timeout.
	 */
	if (likely(co->tx_queue_size == 0 ||
		   (co->tx_last_timer_ack != atomic_read(&co->tx_last_ack)))) {
		co->tx_last_timer_ack = atomic_read(&co->tx_last_ack);
		return;
	}

	/* resend first packet in tx queue */
	skb = skb_peek(&co->tx_queue);
	ack_hdr = ntoh_unaligned(skb->data, ACK_HDR_OFFSET);
	fill_ack_hdr(skb, get_next(ack_hdr), 0, co->rx_next,
		     get_seqno(ack_hdr));
	skb_head_copy = skb_clone(skb, GFP_ATOMIC);
	if (unlikely(skb_head_copy == NULL)) {
		ecm_submit_disconnect(co);
		return;
	}
	co->tx_resent_packets++; /* for statistics */
	co->tx_resent_bytes += skb->len; /* for statistics */
	xmit_pkt(co, skb_head_copy);
}

static void tx_tasklet_send_deferred_pkts(struct RlnhLinkObj *co)
{
	struct sk_buff *skb;

	/* send from deferred queue if sliding window queue is not full */
	while (unlikely(co->tx_def_queue_size != 0 &&
			co->tx_queue_size < co->wsize)) {
		skb = __skb_dequeue(&co->tx_def_queue);
		co->tx_def_queue_size--;
		tx_queue_add(co, skb);
		xmit_pkt(co, skb);
	}
}

static void tx_tasklet_send_queued_pkts(struct RlnhLinkObj *co)
{
	struct sk_buff *skb;

	/* process pkts in the tx list */
	skb = skb_dequeue(&co->tx_list);
	while (likely(skb != NULL)) {
		if (likely(co->tx_queue_size < co->wsize)) {
			/* put pkt into tx queue and send */
			tx_queue_add(co, skb);
			xmit_pkt(co, skb);
		} else if (likely(co->tx_def_queue_size <
				  co->tx_def_queue_max_size)) {
			/* put pkt into deferred queue */
			__skb_queue_tail(&co->tx_def_queue, skb);
			co->tx_def_queue_size++;
		} else {
			/* both queues are full */
			printk("queues full => disconnect %s\n", co->con_name);
			co->tx.func = tx_tasklet_redirect;
			skb_queue_purge(&co->tx_list);
			ecm_submit_disconnect(co);
			kfree_skb(skb);
			break;
		}
		skb = skb_dequeue(&co->tx_list);
	}
}

static void tx_tasklet(unsigned long data)
{
	struct RlnhLinkObj *co;

	co = (struct RlnhLinkObj *)data;
	tx_tasklet_free_acknowledged_pkts(co);
	tx_tasklet_handle_nacks(co);
	tx_tasklet_handle_tmo(co);
	tx_tasklet_send_deferred_pkts(co);
	tx_tasklet_send_queued_pkts(co);
        ecm_unlock(&co->tx_lock);
}

static inline void schedule_tx_tasklet(struct RlnhLinkObj *co)
{
	if (likely(test_and_set_bit(TASKLET_STATE_SCHED, &co->tx.state) == 0)) {
		if (unlikely(ecm_trylock(&co->tx_lock) == 0))
			clear_bit(TASKLET_STATE_SCHED, &co->tx.state);
		else
			__tasklet_schedule(&co->tx);
	}
}

void ecm_handle_nack(struct RlnhLinkObj *co, struct sk_buff *skb)
{
	skb_queue_tail(&co->nack_queue, skb);
	schedule_tx_tasklet(co);
}

/*
 * atomic update of last ackno, update only if the new ackno is newer, i.e the
 * ackno is higher than last ackno but not higher than the last ackno plus the
 * size of the sliding windows queue (i.e too new or really old).
 */
void ecm_update_last_ackno(struct RlnhLinkObj *co, int new)
{
	int last;
	int old;
	
	last = atomic_read(&co->tx_last_ack);
	for (;;) {
		if (unlikely(new == last))
			return;
		if (likely(new > last)) {
			if (unlikely(new - last > co->wsize))
				return;
		} else if (unlikely(new - last + MODULUS_MASK + 1 > co->wsize))
			return;
		old = atomic_cmpxchg(&co->tx_last_ack, last, new);
		if (likely(old == last)) {
			schedule_tx_tasklet(co);
			return;
		}
		last = old;
	}
}

/* get a new exclusive fragno */
static inline int get_exclusive_fragno(atomic_t *fragno)
{
	int new;
	int last;
	int old;

	last = atomic_read(fragno);
	for (;;) {
		new = (last + 1) & 0x7ff;
		old = atomic_cmpxchg(fragno, last, new);
		if (likely(old == last))
			return new;
		last = old;
	}
}

static int send_udata(struct RlnhLinkObj *co, unsigned int buffer_type,
		      unsigned int hdr_type, unsigned int src, unsigned int dst,
		      unsigned int size, unsigned int fragno, unsigned int more,
		      char *buffer)
{
	struct sk_buff *skb;
	int skb_size;
	int err;
	unsigned short dev_header_len = co->ecm_dev->dev->hard_header_len;
	
	err = 0;
	skb_size = (hdr_type == HDR_UDATA ? UDATA_HSIZE : FRAG_HSIZE) + size +
		co->mhdr_len;
	
	/*
	 * fixme: in_atomic shouldn't be used but right now there is no way of
	 * knowing in what context the send_udata() was done.
	 */
	if (in_atomic())
		skb = alloc_skb(dev_header_len + skb_size, GFP_ATOMIC);
	else
		skb = alloc_skb(dev_header_len + skb_size, GFP_KERNEL);

	if (unlikely(skb == NULL)) {
		ecm_submit_disconnect(co);
		err = -ENOMEM;
		goto out;
	}
	skb->dev = co->ecm_dev->dev;

	reserve_eth_hdr(skb, skb_size - co->mhdr_len, co->mhdr_len);
	fill_main_hdr(skb, HDR_ACK, skb_size, co->peer_cid, co->peer_version);
	fill_ack_hdr(skb, hdr_type, 0, 0, 0);

	if (likely(hdr_type == HDR_UDATA)) {
		fill_udata_hdr(skb, HDR_NONE, more, fragno, buffer_type);
		fill_linkaddresses(skb, co->peer_version, src, dst);
		err = fill_udata(skb, buffer_type, buffer, size, UDATA_HSIZE);
	} else {
		fill_frag_hdr(skb, HDR_NONE, more, fragno);
		err = fill_udata(skb, buffer_type, buffer, size, FRAG_HSIZE);
	}

	if (unlikely(err != 0)) {
		kfree_skb(skb);
		ecm_submit_disconnect(co);
		goto out;
	}

	skb_queue_tail(&co->tx_list, skb);
	schedule_tx_tasklet(co);
 out:
	return err;
}

static int send_fragmented_udata(struct RlnhLinkObj *co, unsigned int type,
				 unsigned int src, unsigned int dst,
				 unsigned int size, char *buffer)
{
	int err;
	int left;
	int fragno;
	
	err = 0;
	left = size;
	/* get a fragno that will tag all fragments of this message */
	fragno = get_exclusive_fragno(&co->fragno);
	/* first frag */
	err = send_udata(co, type, HDR_UDATA, src, dst, co->udata_len, fragno,
			 MORE_FRAGS, buffer);
	if (unlikely(err < 0))
		goto out;
	buffer += co->udata_len;
	left -= co->udata_len;
	while (left > co->frag_len) {
		/* all frags except first and last */
		err = send_udata(co, type, HDR_FRAG, 0, 0, co->frag_len, fragno,
				 MORE_FRAGS, buffer);
		if (unlikely(err < 0))
			goto out;
		buffer += co->frag_len;
		left -= co->frag_len;
	}
	/* last frag */
	err = send_udata(co, type, HDR_FRAG, 0, 0, left, fragno,
			 NO_MORE_FRAGS, buffer);
 out:
	return err;
}

void ecm_send_conn_pkt(struct RlnhLinkObj *co, gfp_t flags, int type)
{
	struct sk_buff *skb;
	int size = CONN_HSIZE;
	unsigned short dev_header_len = co->ecm_dev->dev->hard_header_len;

	if (unlikely(ecm_trylock(&co->tx_lock) == 0))
		return;

	if (likely(co->peer_version > 2))
		size += co->features_len + 1;

	skb = alloc_skb(dev_header_len + size, flags);
	if (unlikely(skb == NULL)) {
		ecm_unlock(&co->tx_lock);
		ecm_submit_disconnect(co);
		return;
	}
	skb->dev = co->ecm_dev->dev;

	reserve_eth_hdr(skb, size, co->mhdr_len);

	/* note: peer connection id is zero for all connection messages */
	fill_main_hdr(skb, HDR_CONN, size, 0, co->peer_version);
	fill_conn_hdr(skb, type, co->preferred_wsize, co->cid,
		      co->ecm_dev->dev->dev_addr, co->peer_mac,
		      (uint8_t *)co->features, co->features_len,
		      co->peer_version);
	xmit_pkt(co, skb);

        ecm_unlock(&co->tx_lock);
}

void ecm_send_ack(struct RlnhLinkObj *co, gfp_t flags, int request_ack)
{
	struct sk_buff *skb;
	unsigned short dev_header_len = co->ecm_dev->dev->hard_header_len;

	if (unlikely(ecm_trylock(&co->tx_lock) == 0))
		return;

	skb = alloc_skb(dev_header_len + ACK_HSIZE + co->mhdr_len, flags);
	if (unlikely(skb == NULL)) {
		ecm_unlock(&co->tx_lock);
		ecm_submit_disconnect(co);
		return;
	}
	skb->dev = co->ecm_dev->dev;

	reserve_eth_hdr (skb, ACK_HSIZE, co->mhdr_len);
	fill_main_hdr(skb, HDR_ACK, ACK_HSIZE + co->mhdr_len, co->peer_cid,
		      co->peer_version);
	fill_ack_hdr(skb, HDR_NONE, request_ack, co->rx_next, 0);
	xmit_pkt(co, skb);
	ecm_unlock(&co->tx_lock);
}

void ecm_send_nack(struct RlnhLinkObj *co, gfp_t flags, int seqno,
		   int nack_num)
{
	struct sk_buff *skb;
	unsigned short dev_header_len = co->ecm_dev->dev->hard_header_len;

	if (unlikely(ecm_trylock(&co->tx_lock) == 0))
		return;

	skb = alloc_skb(dev_header_len + NACK_HSIZE + co->mhdr_len, flags);
	if (unlikely(skb == NULL)) {
		ecm_unlock(&co->tx_lock);
		ecm_submit_disconnect(co);
		return;
	}
	skb->dev = co->ecm_dev->dev;

	co->rx_nacks++; /* for statistics */
	reserve_eth_hdr (skb, NACK_HSIZE, co->mhdr_len);
	fill_main_hdr(skb, HDR_ACK, NACK_HSIZE + co->mhdr_len, co->peer_cid,
		      co->peer_version);
	fill_ack_hdr(skb, HDR_NACK, 0, co->rx_next, 0);
	fill_nack_hdr(skb, HDR_NONE, nack_num, seqno);
	xmit_pkt(co, skb);
        ecm_unlock(&co->tx_lock);
}

/* tx timeout => set tx_tmo to "true" and schedule tasklet */
static void tx_tmo(unsigned long arg)
{
	struct RlnhLinkObj *co;

	co = (struct RlnhLinkObj *)arg;
	atomic_set(&co->tx_tmo, 1);
	schedule_tx_tasklet(co);
	mod_timer(&co->tx_timer, jiffies + msecs_to_jiffies(TX_TIMER));
}

/* downcall from rlnh */
int ecm_dc_transmit(struct RlnhLinkObj *co, unsigned int type, unsigned int src,
		    unsigned int dst, unsigned int size, void *buffer)
{
	int err;

	if (unlikely(ecm_trylock(&co->tx_lock) == 0))
		return 0;

	if (likely(size <= co->udata_len))
		err = send_udata(co, type, HDR_UDATA, src, dst, size,
				 /* mark as not being a frag */ 0x7fff,
				 NO_MORE_FRAGS, buffer);
	else
		err = send_fragmented_udata(co, type, src, dst, size, buffer);
	
	ecm_unlock(&co->tx_lock);

	return err;
}

void ecm_start_tx(struct RlnhLinkObj *co)
{		
	co->tx_next = 0;	
	co->tx_last_timer_ack = -1;	
	co->tx_def_queue_size = 0;
	co->tx_queue_size = 0;
	
	skb_queue_head_init(&co->tx_list);
	skb_queue_head_init(&co->tx_def_queue);
	skb_queue_head_init(&co->tx_queue);	
	skb_queue_head_init(&co->nack_queue);
	
	atomic_set(&co->tx_last_ack, 0);
	atomic_set(&co->tx_tmo, 0);
	atomic_set(&co->fragno, 0);
	
	setup_timer(&co->tx_timer, tx_tmo, (unsigned long)co);
	tasklet_init(&co->tx, tx_tasklet, (unsigned long)co);
	mod_timer(&co->tx_timer, jiffies + msecs_to_jiffies(TX_TIMER));
}

void ecm_stop_tx(struct RlnhLinkObj *co)
{
	/* timer must be stopped before killing the tasklet */
	del_timer_sync(&co->tx_timer);

	tasklet_disable(&co->tx);
	tasklet_kill(&co->tx);

	skb_queue_purge(&co->tx_list);
	skb_queue_purge(&co->tx_queue);
	skb_queue_purge(&co->tx_def_queue);
	skb_queue_purge(&co->nack_queue);
}
