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
#include <rlnh/rlnh_link.h>

#include <linux/netdevice.h>
#include <linux/version.h>

#define RX_TIMER 100 /* ms */

#define FRAGNO(skb)   (((uint32_t *)(skb)->cb)[0])
#define FRAGSIZE(skb) (((uint32_t *)(skb)->cb)[1])

static void rx_tasklet_frag_list_add(struct sk_buff *rq, struct sk_buff *skb)
{
	struct skb_shared_info *si;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	si = (struct skb_shared_info *)skb_end_pointer(rq);
#else
	si = (struct skb_shared_info *)rq->end;
#endif

	if (si->frag_list == NULL) {
		/* first fragment */
		si->frag_list = skb;
		skb->prev = skb;
	} else {
		/* add fragment last */
		si->frag_list->prev->next = skb;
		si->frag_list->prev = skb;
	}
}

static struct sk_buff *rx_tasklet_frag(struct RlnhLinkObj *co,
				       struct sk_buff *skb)
{
	uint32_t main_hdr;
	uint32_t frag_hdr;
	uint32_t ack_hdr;
	int fragno;
	int more_fragments;
	int index;
	int size;
	struct sk_buff *head; /* reassembly queue */

	main_hdr = ntoh_unaligned(skb->data, MAIN_HDR_OFFSET);
	frag_hdr = ntoh_unaligned(skb->data, FRAG_HDR_OFFSET);
	ack_hdr = ntoh_unaligned(skb->data, ACK_HDR_OFFSET);

	fragno = get_fragno(frag_hdr);
	index = fragno % FRAG_ARRAY_SIZE;

	if (get_next(ack_hdr) == HDR_UDATA) {
		/* first frag */
		size = get_packet_size(main_hdr) - UDATA_HSIZE -
			co->mhdr_len;
		FRAGSIZE(skb) = size;
		FRAGNO(skb) = fragno;
		if (likely(co->frag_array[index] == NULL))
			/* put first frag in reassembly array */
			co->frag_array[index] = skb;
		else
			/* put first frag in reassembly queue */
			__skb_queue_tail(&co->frag_list, skb);
		return skb;
	}

	more_fragments = get_more(frag_hdr);
	size = get_packet_size(main_hdr) - FRAG_HSIZE - co->mhdr_len;
	skb_pull(skb, FRAG_HSIZE);
	skb_trim(skb, size);

	head = co->frag_array[index];

	if (likely(head != NULL && fragno == FRAGNO(head))) {
		/* last fragment? => remove from array */
		if (more_fragments == 0)
			co->frag_array[index] = NULL;
	} else {
		skb_queue_walk(&co->frag_list, head) {
			if (fragno == FRAGNO(head))
				goto found;
		}
		/* No fraglist head found for packet, drop it */
		co->bad_packets++;
		kfree_skb(skb);
		return NULL;
	found:
		if (more_fragments == 0)
			__skb_unlink(head, &co->frag_list);
	}
	FRAGSIZE(head) += size;
	/* add skb to the frag_list of head */
	rx_tasklet_frag_list_add(head, skb);
	return head;
}

static int rx_tasklet_recv(struct RlnhLinkObj *co, struct sk_buff *skb)
{
	uint32_t main_hdr;
	uint32_t udata_hdr;
	uint32_t ack_hdr;
	uint32_t addr_hdr;
	int src;
	int dst;
	int size;
	int type;
	int next_hdr;
	int more_fragments;

	udata_hdr = ntoh_unaligned(skb->data, UDATA_HDR_OFFSET);
	ack_hdr = ntoh_unaligned(skb->data, ACK_HDR_OFFSET);
	next_hdr = get_next(ack_hdr);
	more_fragments = get_more(udata_hdr);

	if (unlikely(more_fragments || next_hdr == HDR_FRAG)) {
		skb = rx_tasklet_frag(co, skb);
		if (skb == NULL)
			return -1;
		if (unlikely(more_fragments != 0))
			return 0;
	}

	if (unlikely(co->peer_version == 2)) {
		addr_hdr = ntoh_unaligned(skb->data, UDATA_HDR_ADDR_OFFSET);
		src = get_src(addr_hdr);
		dst = get_dst(addr_hdr);
	} else {
		dst = ntoh_unaligned(skb->data, UDATA_HDR_DST_OFFSET);
		src = ntoh_unaligned(skb->data, UDATA_HDR_SRC_OFFSET);
	}

	main_hdr = ntoh_unaligned(skb->data, MAIN_HDR_OFFSET);
	size = get_packet_size(main_hdr);
	size -= UDATA_HSIZE + co->mhdr_len;
	skb_pull(skb, UDATA_HSIZE);
	skb_trim(skb, size);

	type = BUFFER_TYPE_SKB | (get_oob(udata_hdr) ? BUFFER_TYPE_OOB : 0);
	size = (next_hdr == HDR_FRAG ? FRAGSIZE(skb) : size);

	/* deliver the message to rlnh */
	co->uc->deliver(co->lo, type, src, dst, size, skb);
	return 0;
}

/* rx_tasklet_nack_pkts - traverses the rx queue and nacks all "holes" found */
static void rx_tasklet_nack_pkts(struct RlnhLinkObj *co)
{
	int c;
	int idx;
	int seqno;
	int nack_num;
	int nack_seqno;

	seqno = co->rx_next;
	nack_num = 0;
	nack_seqno = 0;

	for (idx = co->rx_queue_start, c = 0; c < co->rx_queue_size;) {
		if (co->rx_queue[idx] == NULL) {
			nack_seqno = (nack_num == 0 ? seqno : nack_seqno);
			nack_num++;
		} else if (nack_num != 0) {
			ecm_send_nack(co, GFP_ATOMIC, nack_seqno, nack_num);
			nack_num = 0;
		}
		c += (co->rx_queue[idx] == NULL ? 0 : 1);
		idx = (idx + 1) % co->wsize;
		seqno = (seqno + 1) & MODULUS_MASK;
	}
}

static void rx_tasklet_flush_swdq(struct RlnhLinkObj *co)
{
	struct sk_buff *skb;

	skb = co->rx_queue[co->rx_queue_start];
	while (skb != NULL) {
		/* consume packet and update sliding window queue */
		co->rx_queue[co->rx_queue_start] = NULL;
		co->rx_queue_size--;

		/* send packet to next layer */
		if (unlikely(rx_tasklet_recv(co, skb) < 0))
			return;

		co->rx_queue_start = (co->rx_queue_start + 1) % co->wsize;
		co->rx_next = (co->rx_next + 1) & MODULUS_MASK;

		skb = co->rx_queue[co->rx_queue_start];
	}
}

/*
 * SEQNO_IN_WINDOW
 *
 * If sequence number (s) is within the receive window this macro
 * returns 1 otherwise 0.
 *
 * The receive window starts at n and ends at n + w - 1 where w is
 * the width of the receive window. If s is greater than n then
 * s must be (s - n) < w to be within the window.
 *
 * Sequence numbers wrap after s = MODULUS_MASK so s can be less
 * than n and then (s - n + MODULUS_MASK + 1) < w must be true.
 */

#define SEQNO_IN_WINDOW(s,n,w) \
	(((s) - (n) + ((s) < (n) ? MODULUS_MASK + 1 : 0)) < (w))

static void rx_tasklet_swdq(struct RlnhLinkObj *co, struct sk_buff *skb,
			    int seqno)
{
	int index;
	int nack_num;

	index = seqno % co->wsize;

	/* discard already received packets */
	if (unlikely(co->rx_queue[index] != NULL)) {
		kfree_skb(skb);
		return;
	}
	if (unlikely(!SEQNO_IN_WINDOW(seqno, co->rx_next, co->wsize)))
	{
		kfree_skb(skb);
		ecm_send_ack(co, GFP_ATOMIC, NO_REQUEST_ACK);
		return;
	}

	co->rx_queue[index] = skb;
	co->rx_queue_size++;

	if (unlikely(co->rx_queue_size > 1)) {
		rx_tasklet_flush_swdq(co);
		rx_tasklet_nack_pkts(co);
	} else {
		/* calculate number of missing packets */
		co->rx_queue_start = co->rx_next % co->wsize;
		if (seqno > co->rx_next)
			nack_num = seqno - co->rx_next;
		else
			nack_num = MODULUS_MASK + 1 - co->rx_next + seqno;
		ecm_send_nack(co, GFP_ATOMIC, co->rx_next, nack_num);
	}
}

static void rx_tasklet_handle_tmo(struct RlnhLinkObj *co)
{
	/* timeout occured? */
	if (likely(atomic_cmpxchg(&co->rx_tmo, 1, 0) == 0))
		return;

	/* Send nacks for the missing packets */
	if (likely(co->rx_queue_size != 0 &&
		   co->rx_queue_start == co->rx_last_queue_start))
		rx_tasklet_nack_pkts(co);

	co->rx_last_queue_start = co->rx_queue_start;
}

/* rx tasklet */
static void rx_tasklet(unsigned long data)
{
	struct sk_buff *skb;
	struct RlnhLinkObj *co;
	uint32_t ack_hdr;
	int seqno;

	co = (struct RlnhLinkObj *)data;

	rx_tasklet_handle_tmo(co);

	skb = skb_dequeue(&co->rx_list);
	while (skb != NULL) {
		ack_hdr = ntoh_unaligned((uint32_t *)skb->data, ACK_HDR_OFFSET);
		seqno = get_seqno(ack_hdr);
		if (unlikely(co->rx_queue_size > 0 || co->rx_next != seqno))
			rx_tasklet_swdq(co, skb, seqno);
		else {
			if (!rx_tasklet_recv(co, skb))
				co->rx_next = (co->rx_next + 1) & MODULUS_MASK;
		}
		skb = skb_dequeue(&co->rx_list);
	}
        ecm_unlock(&co->rx_lock);
}

static inline void schedule_rx_tasklet(struct RlnhLinkObj *co)
{
	if (likely(test_and_set_bit(TASKLET_STATE_SCHED, &co->rx.state) == 0)) {
		if (unlikely(ecm_trylock(&co->rx_lock) == 0))
			clear_bit(TASKLET_STATE_SCHED, &co->rx.state);
		else
			__tasklet_schedule(&co->rx);
	}
}

/* ecm_rx_hdr_ack, called from ecm_rx that run in the RX interrupt */
static void ecm_rx_hdr_ack(struct RlnhLinkObj *co, struct sk_buff *skb)
{
	uint32_t ack_hdr;

	if (unlikely(ecm_trylock(&co->rx_lock) == 0)) {
		kfree_skb(skb);
		return;
	}

	ack_hdr = ntoh_unaligned(skb->data, ACK_HDR_OFFSET);
	ecm_mark_conn_alive(co);
	ecm_update_last_ackno(co, get_ackno(ack_hdr));

	if (unlikely(get_request(ack_hdr)))
		ecm_send_ack(co, GFP_ATOMIC, NO_REQUEST_ACK);

	switch (get_next(ack_hdr)) {
	case HDR_UDATA:
	case HDR_FRAG:
		skb_queue_tail(&co->rx_list, skb);
		schedule_rx_tasklet(co);
		break;
	case HDR_NACK:
		ecm_handle_nack(co, skb);
		break;
	case HDR_NONE:
		kfree_skb(skb);
		break;
	default:
		printk("unknown hdr (%d)\n", get_next(ack_hdr));
		co->bad_packets++;
		kfree_skb(skb);
		break;
	}

	ecm_unlock(&co->rx_lock);
}

/* ecm_rx_hdr_conn, called from ecm_rx that runs in the RX interrupt  */
static void ecm_rx_hdr_conn(struct RlnhLinkObj *co, struct net_device *dev,
			    struct sk_buff *skb)
{
	if (unlikely(ecm_trylock(&co->conn_rx_lock) == 0)) {
		kfree_skb(skb);
		return;
	}
	ecm_submit_conn_pkt(co, dev, skb);
	ecm_unlock(&co->conn_rx_lock);
}

/* ecm_rx, called by the driver in the RX interrurt */
#ifdef ECM_COMPAT
int ecm_rx(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
           struct net_device *orig_dev)
#else
int ecm_rx(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt)
#endif
{
	unsigned int cid;
	uint32_t main_hdr;
	uint32_t multicore_hdr;
	struct RlnhLinkObj *co;
	struct ethhdr *eth_hdr;
	struct ecm_device *ecm_dev;
	int next_hdr;
	int peer_coreid = -1;

	/* check if the packet is meant for us */
	if (unlikely(skb->pkt_type != PACKET_HOST)) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}
	multicore_hdr = ntoh_unaligned(skb->data, MULTICORE_HDR_OFFSET);
	next_hdr = get_next(multicore_hdr);
	/* check if it is a multicore header*/
	if (next_hdr == HDR_MAIN)
	{
		/* it is a multicore header */
		peer_coreid = get_src_coreid(multicore_hdr);
		skb_pull(skb, HDR_MULTICORE_SIZE);
	}
	main_hdr = ntoh_unaligned(skb->data, MAIN_HDR_OFFSET);
	cid = get_cid(main_hdr);
	ecm_dev = (struct ecm_device *)pt->af_packet_priv;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	eth_hdr = (struct ethhdr *)skb_mac_header(skb);
#else
	eth_hdr = (struct ethhdr *)skb->mac.raw;
#endif
	co = get_ecm_connection(cid, eth_hdr->h_source, ecm_dev, peer_coreid);
	if (unlikely(co == NULL)) {
             kfree_skb(skb);
             return NET_RX_DROP;
	}

	co->rx_packets++;
	co->rx_bytes += skb->len;

	next_hdr = get_next(main_hdr);
	switch (next_hdr) {
        case HDR_ACK:
                ecm_rx_hdr_ack(co, skb);
		break;
	case HDR_CONN:
		ecm_rx_hdr_conn(co, dev, skb);
		break;
	default:
		printk("unknown msg hdr (%d)\n", next_hdr);
		co->bad_packets++;
		kfree_skb(skb);
		break;
	}

	put_ecm_connection(co);
	return 0;
}

static struct sk_buff **alloc_skb_array(int len)
{
	struct sk_buff **q;
	int size;

	size = sizeof(struct sk_buff *) * len;
	q = (struct sk_buff **)kmalloc(size, GFP_KERNEL);
	if (q != NULL)
		memset(q, 0x0, size);
	return q;
}

static void free_skb_array(struct sk_buff **q, int len)
{
	int i;

	if (q == NULL)
		return;
	for (i = 0; i < len; i++) {
		if (q[i] == NULL)
			continue;
		kfree_skb(q[i]);
		q[i] = NULL;
	}
	kfree(q);
}

/* rx_tmo, sets rx_tmo to "true" and schedules the rx tasklet */
static void rx_tmo(unsigned long arg)
{
	struct RlnhLinkObj *co;

	co = (struct RlnhLinkObj *)arg;
	atomic_set(&co->rx_tmo, 1);
	schedule_rx_tasklet(co);
	mod_timer(&co->rx_timer, jiffies + msecs_to_jiffies(RX_TIMER));
}

int ecm_start_rx(struct RlnhLinkObj *co)
{
	co->rx_next = 0;
	co->rx_queue_size = 0;
	co->rx_last_queue_start = -1;

	skb_queue_head_init(&co->rx_list);
	skb_queue_head_init(&co->frag_list);

	co->rx_queue = alloc_skb_array(co->preferred_wsize);
	if (unlikely(co->rx_queue == NULL)) {
		ecm_submit_disconnect(co);
		return -ENOMEM;
	}

	co->frag_array = alloc_skb_array(FRAG_ARRAY_SIZE);
	if (unlikely(co->frag_array == NULL)) {
		free_skb_array(co->rx_queue, co->preferred_wsize);
		ecm_submit_disconnect(co);
		return -ENOMEM;
	}

	atomic_set(&co->rx_tmo, 0);
	setup_timer(&co->rx_timer, rx_tmo, (unsigned long)co);
	tasklet_init(&co->rx, rx_tasklet, (unsigned long)co);
	mod_timer(&co->rx_timer, jiffies + msecs_to_jiffies(RX_TIMER));

	return 0;
}

void ecm_stop_rx(struct RlnhLinkObj *co)
{
	/* timer must be stopped before killing the tasklet */
	del_timer_sync(&co->rx_timer);

	tasklet_disable(&co->rx);
	tasklet_kill(&co->rx);

	skb_queue_purge(&co->rx_list);
	free_skb_array(co->rx_queue, co->preferred_wsize);
	free_skb_array(co->frag_array, FRAG_ARRAY_SIZE);
	skb_queue_purge(&co->frag_list);
}
