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

#ifndef __SHMCM_H__
#define __SHMCM_H__

#include <asm/atomic.h>
#include <linux/mailbox.h>
#include <linux/skbuff.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/linx_ioctl.h>

#include <rlnh/rlnh_link.h>
#include <shmcm_lock.h>
#include <shmcm_proto.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16))
#include <asm/semaphore.h>
#else
#include <linux/mutex.h>
#endif

#define SHMCM_VERSION LINX_VERSION

/*
 * This array is used for fast look-up of messages that is undergoing
 * reassembly. If the CM can't allocate a free slot, fragments are
 * put into a "slow" linked list. For example a size of 32 means that
 * the CM can handle 32 simultaneous fragmented messages (i.e. senders)
 * per connection before it starts using the linked list.
 */
#define FRAG_ARRAY_SIZE 32

struct shmcm_work;

struct shmcm_rx {
        unsigned long num_bytes;
        unsigned long num_pkts;
        unsigned int mru;
        unsigned int nslot;
        struct mb *mb;
        struct shmcm_lock uc_deliver_lock;
        struct shmcm_lock con_pkt_lock;
        struct list_head pendq;
        struct sk_buff_head frag_array[FRAG_ARRAY_SIZE];
};

struct shmcm_tx {
        unsigned long num_bytes;
        unsigned long num_pkts;
        unsigned int mtu;
        unsigned int nslot;
        struct mb *mb;
        atomic_t msgid;
        atomic_t dc_transmit_ok;
        struct shmcm_lock dc_transmit_lock;
	
	struct list_head defq;
	atomic_t defq_size;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16))
	struct semaphore defq_lock;
#else
        struct mutex defq_lock;
#endif
};

struct RlnhLinkObj {
        char *con_name;
        uint64_t con_cookie;
        void *lo;
        struct RlnhLinkUCIF *uc;
        int state;
        int mailbox;
        unsigned int cno;
        unsigned int peer_cno;
        unsigned int con_attempts;
        struct timer_list con_timer;
        atomic_t con_timer_lock;
        unsigned long con_tmo;
        atomic_t alive_count;
        atomic_t use_count;

        struct shmcm_rx rx;
        struct shmcm_tx tx;
};

extern unsigned int shmcm_defq_max_size;

/* shmcm_disconnect's origin codes. */
#define SHMCM_TX 1
#define SHMCM_RX 2
#define SHMCM_MGMT 3

/* Special CON packet transmit shmcm_disconnect cause. */
#define EXMITCPKT(pkt, eno) (0x06660000 | ((pkt) << 8) | ((eno) & 0xff))

#define shmcm_peer_dead(co) atomic_dec_and_test(&(co)->alive_count)
#define shmcm_peer_alive(co) atomic_set(&(co)->alive_count, ALIVE_RESET_VALUE)

extern void shmcm_get_con(struct RlnhLinkObj *co);
extern void shmcm_put_con(struct RlnhLinkObj *co);

extern void shmcm_disconnect(struct RlnhLinkObj *co, int cause, int origin);
extern void shmcm_deliver_con_pkt(struct RlnhLinkObj *co, struct sk_buff *skb);
extern void shmcm_send_con_pkt(struct RlnhLinkObj *co, int type,
                               unsigned int cno);
extern int shmcm_dc_transmit(struct RlnhLinkObj *co, uint32_t type,
                             uint32_t src, uint32_t dst, uint32_t size,
                             void *data);

extern void shmcm_enable_uc_deliver(struct RlnhLinkObj *co);
extern void shmcm_disable_uc_deliver(struct RlnhLinkObj *co);
extern int shmcm_init_rx(struct RlnhLinkObj *co, unsigned int nslot,
                         unsigned int mru);
extern void shmcm_cleanup_rx(struct RlnhLinkObj *co);

extern void shmcm_enable_dc_transmit(struct RlnhLinkObj *co);
extern void shmcm_disable_dc_transmit(struct RlnhLinkObj *co);
extern int shmcm_init_tx(struct RlnhLinkObj *co, unsigned int nslot,
                         unsigned int mtu);
extern void shmcm_cleanup_tx(struct RlnhLinkObj *co);
#endif
