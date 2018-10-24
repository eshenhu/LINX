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
#include <rlnh/rlnh_link.h>

#include <linux/netdevice.h>
#include <linux/version.h>

/* macros for skb layer specific data access */
#define SRC(skb)              (((uint32_t *)(skb)->cb)[0])
#define DST(skb)              (((uint32_t *)(skb)->cb)[1])
#define SIZE(skb)             (((uint32_t *)(skb)->cb)[2])
#define MSGID(skb)            (((uint16_t *)(skb)->cb)[6])
#define FRAGS_LEFT(skb)       (((uint16_t *)(skb)->cb)[7])
#define PATCHES_LEFT(skb)     (((uint16_t *)(skb)->cb)[8])
#define PATCH_FRAGS(skb)      (((uint16_t *)(skb)->cb)[9])
#define FIRST_PATCH_DONE(skb) (((uint8_t *)(skb)->cb)[20])

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

static void rx_tasklet_patch_list_add(struct sk_buff *head, struct sk_buff *skb)
{
	if(head->next == NULL) {
		head->next = skb;
		head->prev = skb;
	} else {
		head->prev->next = skb;
		head->prev = skb;
	}
}

static struct sk_buff *rx_tasklet_patch_list_get(struct sk_buff *head)
{
	struct sk_buff *skb;

	skb = head->next;
	if(skb != NULL)
		head->next = skb->next;
	return skb;
}

static int rx_tasklet_patch_data(struct sk_buff *head, struct sk_buff *patch)
{
	struct sk_buff *frag;

	skb_pull(patch, PATCH_HSIZE);

	/* the first patch has a patch for the head */
	if(!FIRST_PATCH_DONE(head)) {
		FIRST_PATCH_DONE(head) = 1;
		/* overwrite header of head with patch data */
		memcpy(head->data, patch->data, PATCH_START_HSIZE + RIO_HLEN);
		skb_pull(patch, PATCH_START_HSIZE + RIO_HLEN);
	}

	/* only patch a fragment if there are fragments left */
	while(patch->len >= (FRAG_HSIZE + RIO_HLEN) && PATCH_FRAGS(head)) {
		PATCH_FRAGS(head)--;
		frag = rx_tasklet_patch_list_get(head);
		if(frag == NULL) {
			printk("LINX riocm: Out of fragments!\n");
			return -1;
		}

		/* overwrite header of frag with patch data */
		memcpy(frag->data, patch->data, FRAG_HSIZE + RIO_HLEN);
		skb_pull(patch, FRAG_HSIZE + RIO_HLEN);

		/* add skb to the frag_list of head */
		rx_tasklet_frag_list_add(head, frag);
	}

	if(patch->len != 0) {
		/* the last user data. just add the patch to the frag list */
		/* can do this since the skb has been pulled all the way here */
		rx_tasklet_frag_list_add(head, patch);
		return 0;
	} else {
		/* the data was even. no need to keep this skb */
		kfree_skb(patch);
	}
	return 0;
}

static void rx_tasklet_patch(struct RlnhLinkObj *co, struct sk_buff *skb)
{
	int msgid;
	int index;
	struct rio_patch *h;
	struct sk_buff *head; /* reassembly queue */

	h = rio_header(skb, h);
	msgid = ntohs(h->msgid);
	index = msgid % FRAG_ARRAY_SIZE;

	/* find the head of the fragmented message */
	head = co->frag_array[index];
	if (likely(head != NULL && msgid == MSGID(head))) {
		/* last patch packet => remove from array */
		if (--PATCHES_LEFT(head) == 0)
			co->frag_array[index] = NULL;
	} else {
		skb_queue_walk(&co->frag_list, head) {
			if (msgid == MSGID(head))
				break;
		}
		/* last patch packet => remove from array */
		if (--PATCHES_LEFT(head) == 0)
			__skb_unlink(head, &co->frag_list);
	}
	if (unlikely(head == NULL)) {
		printk("no reassembly queue found for received patch\n");
		rio_submit_disconnect(co);
		return;
	}

	/* apply the patches in the patch skb to the data */
	if(rx_tasklet_patch_data(head, skb) != 0) {
		rio_submit_disconnect(co);
		return;
	}

	if (PATCHES_LEFT(head) != 0)
		return;

	/* deliver the message to rlnh */
	co->uc->deliver(co->lo, BUFFER_TYPE_SKB, SRC(head),
			DST(head), SIZE(head), head);
}

static void rx_tasklet_frag(struct RlnhLinkObj *co, struct sk_buff *skb)
{
	int msgid;
	int index;
	struct rio_frag *h;
	struct sk_buff *head; /* reassembly queue */

	h = rio_header(skb, h);
	msgid = ntohs(h->msgid);
	index = msgid % FRAG_ARRAY_SIZE;

	/* find the head of the fragmented message */
	head = co->frag_array[index];
	if (likely(head != NULL && msgid == MSGID(head))) {
		/* last fragment and no patches needed => remove from array */
		if (--FRAGS_LEFT(head) == 0 && PATCHES_LEFT(head) == 0)
			co->frag_array[index] = NULL;
	} else {
		skb_queue_walk(&co->frag_list, head) {
			if (msgid == MSGID(head))
				break;
		}
		/* last fragment and no patches needed => remove from array */
		if (--FRAGS_LEFT(head) == 0 && PATCHES_LEFT(head) == 0)
			__skb_unlink(head, &co->frag_list);
	}
	if (unlikely(head == NULL)) {
		printk("no reassembly queue found for received fragment\n");
		rio_submit_disconnect(co);
		return;
	}

	/* prepare fragment for delivery, if no patch is expected */
	if (PATCHES_LEFT(head) == 0) {
		skb_pull(skb, FRAG_HSIZE);
		if(FRAGS_LEFT(head) == 0)
			skb_trim(skb, skb->len); /* nop */
		else
			skb_trim(skb, co->frag_len); /* correct? */

		/* add skb to the frag_list of head */
		rx_tasklet_frag_list_add(head, skb);

		/* return if the message is incomplete */
		if (FRAGS_LEFT(head) != 0)
			return;
	} else {
		/* push skb to make room for the patch */
		skb_push(skb, RIO_HLEN);
		PATCH_FRAGS(head)++;
		/* use a temporary list for fragments that need patches */
		rx_tasklet_patch_list_add(head, skb);
		return;
	}

	/* deliver the message to rlnh */
	co->uc->deliver(co->lo, BUFFER_TYPE_SKB, SRC(head),
			DST(head), SIZE(head), head);
}

static void rx_tasklet_patch_start(struct RlnhLinkObj *co, struct sk_buff *skb)
{
	int index;
	struct rio_patch_start *h;

	h = rio_header(skb, h);
	index = ntohs(h->msgid) % FRAG_ARRAY_SIZE;

	/* first skb in chain. keep info in cb */
	DST(skb) = ntohl(h->dst);
	SRC(skb) = ntohl(h->src);
	SIZE(skb) = ntohl(h->payl_size);
	MSGID(skb) = ntohs(h->msgid);
	FRAGS_LEFT(skb) = ntohs(h->count_frag);
	PATCHES_LEFT(skb) = ntohs(h->count_patch);
	PATCH_FRAGS(skb) = 0;
	FIRST_PATCH_DONE(skb) = 0;

	/* set next and prev to NULL. use them later for temporary frag list */
	skb->next = NULL;
	skb->prev = NULL;

	/* push skb to make room for the patch */
	skb_push(skb, RIO_HLEN);

	if (likely(co->frag_array[index] == NULL))
		/* put first frag in reassembly array */
		co->frag_array[index] = skb;
	else
		/* put first frag in reassembly queue */
		__skb_queue_tail(&co->frag_list, skb);
}

static void rx_tasklet_frag_start(struct RlnhLinkObj *co, struct sk_buff *skb)
{
	int index;
	struct rio_frag_start *h;

	h = rio_header(skb, h);
	index = ntohs(h->msgid) % FRAG_ARRAY_SIZE;

	/* first skb in chain. keep info in cb */
	DST(skb) = ntohl(h->dst);
	SRC(skb) = ntohl(h->src);
	SIZE(skb) = ntohl(h->payl_size);
	MSGID(skb) = ntohs(h->msgid);
	FRAGS_LEFT(skb) = (SIZE(skb) - co->frag_start_len-1) / co->frag_len+1;
	/* not used for ordinary fragmented messages. set to zero. */
	PATCHES_LEFT(skb) = 0;
	PATCH_FRAGS(skb) = 0;
	FIRST_PATCH_DONE(skb) = 0;

	skb_pull(skb, FRAG_START_HSIZE);
	skb_trim(skb, co->frag_start_len);

	if (likely(co->frag_array[index] == NULL))
		/* put first frag in reassembly array */
		co->frag_array[index] = skb;
	else
		/* put first frag in reassembly queue */
		__skb_queue_tail(&co->frag_list, skb);
}

static void rx_tasklet_single(struct RlnhLinkObj *co, struct sk_buff *skb)
{
	int src;
	int dst;
	int size;
	struct rio_single *h;

	h = rio_header(skb, h);

	src = ntohl(h->src);
	dst = ntohl(h->dst);
	size = ntohl(h->payl_size);

	skb_pull(skb, SINGLE_HSIZE);
	skb_trim(skb, size);

	/* deliver the message to rlnh */
	co->uc->deliver(co->lo, BUFFER_TYPE_SKB, src, dst, size, skb);
}

/* rx tasklet */
static void rx_tasklet(unsigned long data)
{
	struct sk_buff *skb;
	struct RlnhLinkObj *co;

	co = (struct RlnhLinkObj *)data;

	skb = skb_dequeue(&co->rx_list);

        /* switch on header type. call tasklet for correct header... */
	while (skb != NULL) {
		switch (rio_header_type(skb)) {
		case RIO_SINGLE:
			rx_tasklet_single(co, skb);
			break;
		case RIO_FRAG_START:
			rx_tasklet_frag_start(co, skb);
			break;
		case RIO_FRAG:
			rx_tasklet_frag(co, skb);
			break;
		case RIO_PATCH_START:
			rx_tasklet_patch_start(co, skb);
			break;
		case RIO_PATCH:
			rx_tasklet_patch(co, skb);
			break;
		default:
			printk("unknown msg hdr %d\n", rio_header_type(skb));
			kfree_skb(skb);
			break;
		}
		skb = skb_dequeue(&co->rx_list);
	}
        /* this unlock is for the lock taken by the sheduler below */
        rio_unlock(&co->rx_lock);
}

static inline void schedule_rx_tasklet(struct RlnhLinkObj *co)
{
	if (likely(test_and_set_bit(TASKLET_STATE_SCHED, &co->rx.state) == 0)) {
		if (unlikely(rio_trylock(&co->rx_lock) == 0))
			clear_bit(TASKLET_STATE_SCHED, &co->rx.state);
		else
			__tasklet_schedule(&co->rx);
	}
}

static void queue_from_array(struct RlnhLinkObj *co)
{
	int pos;
	pos = co->rx_expected_seqno % REORDER_ARRAY_SIZE;
	while(co->reorder_array[pos] != NULL) {
		skb_queue_tail(&co->rx_list, co->reorder_array[pos]);
		co->reorder_array[pos] = NULL;
		co->rx_expected_seqno = (co->rx_expected_seqno + 1) & 0xffff;
		pos = co->rx_expected_seqno % REORDER_ARRAY_SIZE;
	}
}

/* called from rio_conn when connection is considered up */
void rio_deliver_queued_pkts(struct RlnhLinkObj *co)
{
/* 	if any pkts were received before calling connected(), deliver here */
	schedule_rx_tasklet(co);
}

/* rio_rx_hdr_udata, called from rio_rx that run in the RX interrupt */
static void rio_rx_hdr_udata(struct RlnhLinkObj *co, struct sk_buff *skb)
{
	int pos;
	struct rio_gen_udata *uh = rio_header(skb, uh);

	if (ntohs(uh->sender) != co->peer_ID ||
	    ntohs(uh->src_port) != co->peer_port) {
		/* pkt belongs to old connection. special scenario */
		kfree_skb(skb);
		return;
	}

	if (unlikely(rio_trylock(&co->rx_lock) == 0)) {
		/* queue packet if it is expected (RLNH_INIT) */
		if (ntohs(uh->seqno) == 0 &&
		    rio_header_type(skb) == RIO_SINGLE) {
			skb_queue_tail(&co->rx_list, skb);
			co->rx_expected_seqno =
				(co->rx_expected_seqno + 1) & 0xffff;
		} else {
			kfree_skb(skb);
		}
		return;
	}

	rio_mark_conn_alive(co);

	if(co->rx_expected_seqno == ntohs(uh->seqno)) {
		skb_queue_tail(&co->rx_list, skb);
		co->rx_expected_seqno = (co->rx_expected_seqno + 1) & 0xffff;
		queue_from_array(co);
		schedule_rx_tasklet(co);
	} else {
		pos = ntohs(uh->seqno) % REORDER_ARRAY_SIZE;
		if (co->reorder_array[pos] != NULL) {
			kfree_skb(skb);
			printk("LINX: rio_cm reorder queue exhausted\n");
			rio_submit_disconnect(co);
		} else {
			co->reorder_array[pos] = skb;
		}
	}
	rio_unlock(&co->rx_lock);
}

static void rio_rx_heartbeat(struct RlnhLinkObj *co, struct sk_buff *skb)
{
	struct rio_heartbeat *hb = rio_header(skb, hb);

	if (ntohs(hb->sender) != co->peer_ID ||
	    ntohs(hb->src_port) != co->peer_port) {
		/* pkt belongs to old connection. special scenario */
		goto out;
	}
	
	rio_mark_conn_alive(co);
out:
	kfree_skb(skb);
}

/* rio_rx_hdr_conn, called from rio_rx that runs in the RX interrupt  */
static void rio_rx_hdr_conn(struct RlnhLinkObj *co, struct net_device *dev,
			    struct sk_buff *skb)
{
	if (unlikely(rio_trylock(&co->conn_rx_lock) == 0)) {
		kfree_skb(skb);
		return;
	}
	rio_submit_conn_pkt(co, dev, skb);
	rio_unlock(&co->conn_rx_lock);
}

/* rio_rx, called by the driver in the RX interrupt */
#ifdef RIO_COMPAT
int rio_rx(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
           struct net_device *orig_dev)
#else
int rio_rx(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt)
#endif
{
	struct RlnhLinkObj *co;
	struct rio_device *rio_dev;

	/* check if the packet is meant for us */
	if (unlikely(skb->pkt_type != PACKET_HOST))
		goto out;

        rio_dev = (struct rio_device *)pt->af_packet_priv;

	co = get_rio_conn(skb, rio_dev);
        if (unlikely(co == NULL))
		goto out;

	co->rx_packets++;
	co->rx_bytes += skb->len;

	switch (rio_header_type(skb)) {
	case RIO_CONN_REQ:
	case RIO_CONN_ACK:
	case RIO_CONN_RESET:
		rio_rx_hdr_conn(co, dev, skb);
		break;
	case RIO_HEARTBEAT:
		rio_rx_heartbeat(co, skb);
		break;
	case RIO_SINGLE:
	case RIO_FRAG_START:
	case RIO_FRAG:
	case RIO_PATCH_START:
	case RIO_PATCH:
		rio_rx_hdr_udata(co, skb);
		break;
	default:
		printk("unknown msg hdr (%d)\n", rio_header_type(skb));
		kfree_skb(skb);
		break;
	}

	put_rio_connection(co);
	return 0;
out:
	kfree_skb(skb);
	return NET_RX_DROP;
}

static void free_skb_frags(struct sk_buff *head)
{
	struct sk_buff *frag;
	
	frag = rx_tasklet_patch_list_get(head);
	while(frag != NULL) {
		kfree_skb(frag);
		frag = rx_tasklet_patch_list_get(head);
	}
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
		free_skb_frags(q[i]);
		kfree_skb(q[i]);
		q[i] = NULL;
	}
	kfree(q);
}

int rio_start_rx(struct RlnhLinkObj *co)
{
	skb_queue_head_init(&co->rx_list);
	skb_queue_head_init(&co->frag_list);

	co->rx_expected_seqno = 0;

	co->frag_array = alloc_skb_array(FRAG_ARRAY_SIZE);
	if (unlikely(co->frag_array == NULL)) {
		rio_submit_disconnect(co);
		return -ENOMEM;
	}

	co->reorder_array = alloc_skb_array(REORDER_ARRAY_SIZE);
	if (unlikely(co->reorder_array == NULL)) {
		free_skb_array(co->frag_array, FRAG_ARRAY_SIZE);
		rio_submit_disconnect(co);
		return -ENOMEM;
	}

	tasklet_init(&co->rx, rx_tasklet, (unsigned long)co);
	return 0;
}

void rio_stop_rx(struct RlnhLinkObj *co)
{
	tasklet_disable(&co->rx);
	tasklet_kill(&co->rx);

	skb_queue_purge(&co->rx_list);
	free_skb_array(co->reorder_array, REORDER_ARRAY_SIZE);
	free_skb_array(co->frag_array, FRAG_ARRAY_SIZE);
	skb_queue_purge(&co->frag_list);
}
