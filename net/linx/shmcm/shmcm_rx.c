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

#include <linux/list.h>
#include <linux/skbuff.h>

#include <buf_types.h>
#include <shmcm.h>
#include <shmcm_lock.h>
#include <shmcm_proto.h>
#include <shmcm_kutils.h>

#ifdef SHMCM_TRACE
static void log_deliver(struct RlnhLinkObj *co, struct shmcm_uhdr *uhdr);
#else
#define log_deliver(co, uhdr)
#endif

static int packet_type_ok(unsigned int type)
{
        return ((type == CON_PKT) || (type == UDATA_1_PKT));
}

static void ntoh_mhdr(struct shmcm_mhdr *mhdr)
{
        mhdr->type = ntohl(mhdr->type);
        mhdr->size = ntohl(mhdr->size);
}

static void ntoh_chdr(struct shmcm_chdr *chdr)
{
        chdr->type = ntohl(chdr->type);
        chdr->cno = ntohs(chdr->cno);
        chdr->spare = ntohs(chdr->spare);
}

static void ntoh_uhdr(struct shmcm_uhdr *uhdr)
{
        uhdr->cno = ntohs(uhdr->cno);
        uhdr->msgid = ntohs(uhdr->msgid);
        uhdr->src = ntohl(uhdr->src);
        uhdr->dst = ntohl(uhdr->dst);
        uhdr->size = ntohl(uhdr->size);
}

static struct sk_buff *copy_to_skb(const void *data)
{
        struct shmcm_mhdr *mhdr;
        struct sk_buff *skb;
        unsigned int type;
        unsigned int size;

        mhdr = (struct shmcm_mhdr *)data;
        type = ntohl(mhdr->type);
        size = ntohl(mhdr->size);

        if (!packet_type_ok(type))
                return NULL;

        skb = alloc_skb(size, GFP_ATOMIC);
        if (skb == NULL)
                return NULL;
        skb_reserve(skb, sizeof(*mhdr));
        skb_put(skb, size - sizeof(*mhdr));
        memcpy(skb->head, mhdr, size);

        ntoh_mhdr((struct shmcm_mhdr *)skb->head);
        if (type == CON_PKT)
                ntoh_chdr((struct shmcm_chdr *)skb->data);
        else
                ntoh_uhdr((struct shmcm_uhdr *)skb->data);

        return skb;
}

static int old_udata(struct RlnhLinkObj *co, struct sk_buff *skb)
{
        struct shmcm_uhdr *uhdr;

        uhdr = (struct shmcm_uhdr *)skb->data;
        return (uhdr->cno != co->peer_cno);
}

static unsigned int sizeof_udata(struct sk_buff *skb)
{
        struct shmcm_mhdr *mhdr;
        struct shmcm_uhdr *uhdr;
        unsigned int size;

        mhdr = (struct shmcm_mhdr *)skb->head;
        size = mhdr->size - sizeof(*mhdr) - sizeof(*uhdr);
        return size; /* Number of user data bytes in a packet. */
}

static int fragmented_udata(struct sk_buff *skb)
{
        struct shmcm_uhdr *uhdr;

        uhdr = (struct shmcm_uhdr *)skb->data;
        return (sizeof_udata(skb) != (unsigned int)uhdr->size);
}

static unsigned int *skb_more_ind(struct sk_buff *skb)
{
        /* Store more indicator first in skb's scratch pad area. */
        return (unsigned int *)&skb->cb[0];
}

static void set_more_indicator(struct sk_buff *skb)
{
        struct shmcm_uhdr *uhdr;

        uhdr = (struct shmcm_uhdr *)skb->data;
        *skb_more_ind(skb) = uhdr->size - sizeof_udata(skb);
}

static unsigned int get_more_indicator(struct sk_buff *skb)
{
        return *skb_more_ind(skb);
}

static void dec_more_indicator(struct sk_buff *skb, unsigned int size)
{
        *skb_more_ind(skb) -= size;
}

static struct sk_buff *lookup_frag_head(struct sk_buff_head *fl, unsigned int msgid)
{
        struct sk_buff *skb;
        struct shmcm_uhdr *uhdr;

        skb_queue_walk(fl, skb) {
                uhdr = (struct shmcm_uhdr *)skb->data;
                if (uhdr->msgid == msgid)
                        return skb;
        }
        return NULL;
}

static void add_frag_head(struct sk_buff_head *fl, struct sk_buff *skb)
{
        set_more_indicator(skb);
        __skb_queue_tail(fl, skb);
}

static void add_next_frag(struct sk_buff *head, struct sk_buff *skb)
{
        struct skb_shared_info *head_si;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
        head_si = (struct skb_shared_info *)skb_end_pointer(head);
#else
        head_si = (struct skb_shared_info *)head->end;
#endif
        if (head_si->frag_list == NULL) {
                head_si->frag_list = skb;
                skb->prev = skb;
        } else {
                head_si->frag_list->prev->next = skb;
                head_si->frag_list->prev = skb;
        }
        dec_more_indicator(head, sizeof_udata(skb));

        /*
         * Note: Every fragment must have its data pointer set to start of
         *       udata, when it's going to be delivered. Do it here...
         *       The head's data pointer is set just before the deliver call,
         *       i.e. no difference from a non-fragment udata delivery.
         */
        skb_pull(skb, sizeof(struct shmcm_uhdr));
}

static void unlink_frag_head(struct sk_buff_head *fl, struct sk_buff *skb)
{
        __skb_unlink(skb, fl);
}

static void free_udata_fragments(struct shmcm_rx *p)
{
        int n;
        struct sk_buff *skb;
        struct sk_buff *tmp;

        for (n = 0; n < ARRAY_SIZE(p->frag_array); n++) {
                skb_queue_walk_safe(&p->frag_array[n], skb, tmp) {
                        unlink_frag_head(&p->frag_array[n], skb);
                        kfree_skb(skb); /* Also frees fragments... */
                }
        }
}

static struct sk_buff *reassemble_udata_fragments(struct RlnhLinkObj *co, struct sk_buff *skb)
{
        struct shmcm_uhdr *uhdr;
        struct sk_buff_head *frag_list;
        struct sk_buff *head;

        uhdr = (struct shmcm_uhdr *)skb->data;
        frag_list = &co->rx.frag_array[uhdr->msgid % FRAG_ARRAY_SIZE];

        head = lookup_frag_head(frag_list, uhdr->msgid);
        if (head == NULL) {
                add_frag_head(frag_list, skb);
                return NULL;
        } else {
                add_next_frag(head, skb);
                if (get_more_indicator(head) == 0) {
                        unlink_frag_head(frag_list, head);
                        return head;
                } else {
                        return NULL;
                }
        }
}

static void deliver_udata_pkt(struct RlnhLinkObj *co, struct sk_buff *skb)
{
        struct shmcm_uhdr *uhdr;

        if (old_udata(co, skb)) {
                kfree_skb(skb);
                return; /* Drop it! */
        }
        if (fragmented_udata(skb)) {
                skb = reassemble_udata_fragments(co, skb);
                if (skb == NULL)
                        return; /* Done for now! */
        }

        uhdr = (struct shmcm_uhdr *)skb->data;
        skb_pull(skb, sizeof(*uhdr));
        log_deliver(co, uhdr);
	co->uc->deliver(co->lo, BUFFER_TYPE_SKB, uhdr->src, uhdr->dst,
                        uhdr->size, skb);
}

static void deliver_pending_udata_pkt(struct RlnhLinkObj *co)
{
        struct list_head *pos, *tmp;
        struct sk_buff *skb;

        if (list_empty(&co->rx.pendq))
                return;

        list_for_each_safe(pos, tmp, &co->rx.pendq) {
                list_del(pos);
                skb = list_entry((char *)pos, struct sk_buff, cb[0]);
                deliver_udata_pkt(co, skb);
        }
}

static void queue_udata_pkt(struct list_head *l, struct sk_buff *skb)
{
        struct list_head *new;

        /*
         * Use SKB's scratch pad area to store a list head. Later on cb[0] is
         * used to store a more indicator, no problemos!
         */
        new = (struct list_head *)(&skb->cb[0]);
        list_add_tail(new, l);
}

static void deliver_skb(struct RlnhLinkObj *co, struct sk_buff *skb)
{
        struct shmcm_mhdr *mhdr;
        struct shmcm_chdr *chdr;
        unsigned int size;
	
        mhdr = (struct shmcm_mhdr *)skb->head;
        size = mhdr->size;

        /*
         * Note: after any deliver call, skb may be freed etc, so don't
         * dereference it!
         */
        switch (mhdr->type) {
        case CON_PKT:
                if (shmcm_trylock(&co->rx.con_pkt_lock) != 0) {
                        /*
                         * Use CON_ALV to drain any pending UDATA packets.
                         */
                        chdr = (struct shmcm_chdr *)skb->data;
                        if ((chdr->type == CON_ALV) &&
                            (shmcm_trylock(&co->rx.uc_deliver_lock) != 0)) {
                                deliver_pending_udata_pkt(co);
                                shmcm_unlock(&co->rx.uc_deliver_lock);
                        }
                        shmcm_deliver_con_pkt(co, skb);
                        shmcm_unlock(&co->rx.con_pkt_lock);
                } else {
                        kfree_skb(skb);
                }
                break;
        case UDATA_1_PKT:
                if (shmcm_trylock(&co->rx.uc_deliver_lock) != 0) {
                        shmcm_peer_alive(co);
                        deliver_pending_udata_pkt(co);
                        deliver_udata_pkt(co, skb);
                        shmcm_unlock(&co->rx.uc_deliver_lock);
                } else {
                        /* FIXME: need a upper queue limit! */
                        queue_udata_pkt(&co->rx.pendq, skb);
                }
                break;
        default:
                BUG(); /* copy_to_skb() has already verified type field. */
                break;
        }
        co->rx.num_bytes += size;
        co->rx.num_pkts++;
}

static void rx(struct mb *mb, void *data)
{
        struct RlnhLinkObj *co;
        struct sk_buff *skb;
        void *slot;

        co = (struct RlnhLinkObj *)data;
        shmcm_get_con(co);

        for (;;) {
                slot = mb_get_slot(mb);
                if (slot == NULL)
                        break;
                skb = copy_to_skb(slot);
                mb_done(mb, slot);
                if (skb == NULL) {
                        shmcm_disconnect(co, -ENOMEM, SHMCM_RX);
                        break;
                }
                deliver_skb(co, skb);
        }

        shmcm_put_con(co);
}

void shmcm_enable_uc_deliver(struct RlnhLinkObj *co)
{
        reset_shmcm_lock(&co->rx.uc_deliver_lock, 1);
}

void shmcm_disable_uc_deliver(struct RlnhLinkObj *co)
{
        /* Finish on-going delivers and block new ones. */
        synchronize_shmcm_lock(&co->rx.uc_deliver_lock);

        /* Now it's safe to do some cleanup... */
        free_udata_fragments(&co->rx);
}

int shmcm_init_rx(struct RlnhLinkObj *co, unsigned int nslot, unsigned int mru)
{
        int n;

        co->rx.mru = mru;
        co->rx.nslot = nslot;
        INIT_LIST_HEAD(&co->rx.pendq);
        init_shmcm_lock(&co->rx.uc_deliver_lock, 0); /* Block deliver up-call. */
        init_shmcm_lock(&co->rx.con_pkt_lock, 1); /* Allow delivery of con pkts. */

        for (n = 0; n < ARRAY_SIZE(co->rx.frag_array); n++)
                skb_queue_head_init(&co->rx.frag_array[n]);

        /* Note: as soon as rx() has been registered it may be called! */
        co->rx.mb = mb_register_rx_client(co->mailbox, co->rx.mru, co->rx.nslot,
                                          rx, co);
        if (co->rx.mb == NULL) {
                printk(KERN_WARNING "shmcm: couldn't register RX mailbox\n");
                return -EINVAL;
        }
        return 0;
}

void shmcm_cleanup_rx(struct RlnhLinkObj *co)
{
        struct list_head *pos, *tmp;

        /* Once unregister has returned rx() isn't called any more. */
        mb_unregister_rx_client(co->mailbox);

        /* Synchronize, there may still be someone inside rx(). */
        synchronize_shmcm_lock(&co->rx.con_pkt_lock);

        list_for_each_safe(pos, tmp, &co->rx.pendq) {
                list_del(pos);
                kfree_skb(list_entry((char *)pos, struct sk_buff, cb[0]));
        }
}

/*
 * =============================================================================
 * Some trace functions...
 * =============================================================================
 */
#ifdef SHMCM_TRACE
static void log_deliver(struct RlnhLinkObj *co, struct shmcm_uhdr *uhdr)
{
        printk("%s(%d): SHMCM_UC_DELIVER(%d, %d, %d)\n", co->con_name,
               co->state, uhdr->src, uhdr->dst, uhdr->size);
}
#endif
