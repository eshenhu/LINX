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

#include <asm/uaccess.h>
#include <linux/err.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/version.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include <cfg/db.h>
#include <cfg/db_proc.h>
#include <linux/shmcm_db_ioctl.h>
#include <shmcm.h>
#include <shmcm_proto.h>
#include <shmcm_kutils.h>
#include <asm/atomic.h>

MODULE_AUTHOR("ENEA");
MODULE_DESCRIPTION("LINX Shared Memory Connection Manager");
MODULE_LICENSE("GPL");
MODULE_VERSION(SHMCM_VERSION);

/* Max deferred queue size, global for all connections, default zero bytes. */
unsigned int shmcm_defq_max_size = 0;
module_param(shmcm_defq_max_size, uint, S_IRUGO);
MODULE_PARM_DESC(shmcm_defq_max_size, "Max deferred queue size per connection");

#define uptr(p, n) ((u8 __user *)(p) + (n))
#define kptr(p, n) ((u8 *)(p) + (n))

#define tmo_ms(ms) (jiffies + msecs_to_jiffies(ms))

#ifdef SHMCM_TRACE
static void log_w(struct shmcm_work *w);
#else
#define log_w(w) (w)
#endif

static int get_dc(const void *cookie, void **dc);
static int get_alive_count(const void *cookie, void **cnt);
static int get_defq_size(const void *cookie, void **size);
static void *shmcm_create(void __user *arg);
static int shmcm_destroy(void *cookie, void __user *arg);

static const struct db_param shmcm_params[] = {
        DB_PARAM("con_name", DB_PTR | DB_STRING, con_name, struct RlnhLinkObj),
        DB_PARAM("con_cookie", DB_HEX | DB_UINT64, con_cookie,
                 struct RlnhLinkObj),
        DB_META_PARAM("con_dc", DB_HEX | DB_UINT64, sizeof(u64), 1, get_dc,
                      NULL),
        DB_PARAM("con_tmo", DB_ULONG, con_tmo, struct RlnhLinkObj),
        DB_PARAM("state", DB_INT, state, struct RlnhLinkObj),
        DB_PARAM("cno", DB_UINT, cno, struct RlnhLinkObj),
        DB_PARAM("peer_cno", DB_UINT, peer_cno, struct RlnhLinkObj),
        DB_PARAM("mtu", DB_UINT, tx.mtu, struct RlnhLinkObj),
        DB_PARAM("mru", DB_UINT, rx.mru, struct RlnhLinkObj),
        DB_META_PARAM("alive_count", DB_INT, sizeof(int), 1, get_alive_count,
                      NULL),
        DB_PARAM("con_reqs", DB_UINT, con_attempts, struct RlnhLinkObj),
        DB_PARAM("mailbox", DB_INT, mailbox, struct RlnhLinkObj),
        DB_PARAM("tx_nslot", DB_UINT, tx.nslot, struct RlnhLinkObj),
        DB_PARAM("rx_nslot", DB_UINT, rx.nslot, struct RlnhLinkObj),
        DB_PARAM("sent_bytes", DB_ULONG, tx.num_bytes, struct RlnhLinkObj),
        DB_PARAM("sent_pkts", DB_ULONG, tx.num_pkts, struct RlnhLinkObj),
        DB_PARAM("recv_bytes", DB_ULONG, rx.num_bytes, struct RlnhLinkObj),
        DB_PARAM("recv_pkts", DB_ULONG, rx.num_pkts, struct RlnhLinkObj),
	DB_META_PARAM("defq_size", DB_INT, sizeof(int), 1, get_defq_size, NULL),
	
        DB_PARAM_END
};

static const struct db_template shmcm_template = {
        .owner = THIS_MODULE,
        .create = shmcm_create,
        .destroy = shmcm_destroy,
        .param = shmcm_params
};

static struct workqueue_struct *shmcm_workq;
static void shmcm_workq_func(struct work_struct *w);
static wait_queue_head_t shmcm_waitq;

#define SHMCM_WORK_CREATE 0
struct shmcm_work_create {
        struct shmcm_ioctl_create *arg;
        struct RlnhLinkObj *co;
};

#define SHMCM_WORK_DESTROY 1
#define SHMCM_WORK_CLEANUP 2
struct shmcm_work_destroy {
        struct RlnhLinkObj *co;
};

#define SHMCM_WORK_DC_INIT 3
struct shmcm_work_dc_init {
        struct RlnhLinkObj *co;
        void *lo;
        struct RlnhLinkUCIF *uc;
};

#define SHMCM_WORK_DC_CONNECT 4
struct shmcm_work_dc_connect {
        struct RlnhLinkObj *co;
};

#define SHMCM_WORK_DC_DISCONNECT 5
struct shmcm_work_dc_disconnect {
        struct RlnhLinkObj *co;
};

#define SHMCM_WORK_DC_FINALIZE 6
struct shmcm_work_dc_finalize {
        struct RlnhLinkObj *co;
};

#define SHMCM_WORK_CON_PKT 7
struct shmcm_work_con_pkt {
        struct RlnhLinkObj *co;
        struct sk_buff *skb;
};

#define SHMCM_WORK_CON_TMO 8
struct shmcm_work_con_tmo {
        struct RlnhLinkObj *co;
};

#define SHMCM_WORK_DISCONNECT 9
struct shmcm_work_disconnect {
        struct RlnhLinkObj *co;
        int cause;
        int origin;
};

#define SHMCM_WORK_WAITFOR_COMPLETED 1

struct shmcm_work {
        int opcode;
        int status;
        struct work_struct work;
        void *data;
};

static void con_tmo_func(unsigned long data);

static void setup_shmcm_work(struct shmcm_work *w, void *p, int opcode)
{
        w->opcode = opcode;
        w->data = p;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20))
        INIT_WORK(&w->work, shmcm_workq_func);
#else
        INIT_WORK(&w->work, (void (*)(void *))shmcm_workq_func, w);
#endif
}

static struct shmcm_work *alloc_shmcm_work(size_t size, int opcode, gfp_t flags)
{
        struct shmcm_work *w;
        void *p;

        w = kmalloc(sizeof(*w), flags);
        if (w == NULL)
                return NULL;
        p = kmalloc(size, flags);
        if (p == NULL) {
                kfree(w);
                return NULL;
        }
        setup_shmcm_work(w, p, opcode);
        return w;
}

static void free_shmcm_work(struct shmcm_work *w)
{
        if (w != NULL) {
                kfree(w->data);
                kfree(w);
        }
}

static void init_waitfor_shmcm_work(struct shmcm_work *w)
{
        w->status = SHMCM_WORK_WAITFOR_COMPLETED;
}

static void queue_shmcm_work(struct shmcm_work *w)
{
        queue_work(shmcm_workq, &w->work);
}

static int waitfor_shmcm_work(struct shmcm_work *w)
{
        wait_event(shmcm_waitq, w->status != SHMCM_WORK_WAITFOR_COMPLETED);
        return w->status;
}

static void wakeup_shmcm_work(struct shmcm_work *w, int status)
{
        BUG_ON(w->status != SHMCM_WORK_WAITFOR_COMPLETED);
        BUG_ON(status > 0);

        /*
         * Submitter is waiting for the work to be carried out,
         * wake him up... Submitter must call free_db_work()!
         */
        w->status = status;
        wake_up(&shmcm_waitq);
}

static void free_shmcm_con(struct RlnhLinkObj *co)
{
        if (co != NULL) {
                kfree(co->con_name);
                kfree(co);
        }
}

static struct RlnhLinkObj *alloc_shmcm_con(struct shmcm_ioctl_create *p)
{
        struct RlnhLinkObj *co;
        size_t size;

        co = kzalloc(sizeof(*co), GFP_KERNEL);
        if (co == NULL)
                goto out;

        size = strlen((char *)kptr(p, p->name)) + 1;
        co->con_name = kzalloc(size, GFP_KERNEL);
        if (co->con_name == NULL)
                goto out;

        atomic_set(&co->use_count, 1);

        return co;
  out:
        free_shmcm_con(co);
        return NULL;
}

static int init_shmcm_con(struct RlnhLinkObj *co, struct shmcm_ioctl_create *p)
{
        int status;

        strcpy(co->con_name, (char *)kptr(p, p->name));
        co->con_cookie = (uint64_t)((unsigned long)co);
        co->state = STATE_DISCONNECTED;
        co->con_tmo = (unsigned long)max(100U / ALIVES_PER_TMO,
                                         p->con_tmo / ALIVES_PER_TMO);
        setup_timer(&co->con_timer, con_tmo_func, (unsigned long)co);
        atomic_set(&co->alive_count, 0);

        co->mailbox = p->mbox;
        /*
         * Note: Once shmcm_init_rx is called (i.e. before it returns), packets
         * from peer may be recived!
         */
        status = shmcm_init_rx(co, p->rx_nslot, p->mru);
        if (status != 0)
                return status;
        status = shmcm_init_tx(co, p->tx_nslot, p->mtu);
        if (status != 0)
                return status;

        return 0;
}

static void handle_dc_connect(struct RlnhLinkObj *co)
{
        switch (co->state) {
        case STATE_DISCONNECTED:
                co->cno++; /* Increment connection generation number. */
                co->con_attempts++;
                shmcm_send_con_pkt(co, CON_REQ, co->cno);
                co->state = STATE_CONNECTING;
                break;
        default:
                BUG(); /* RLNH has done something bad... */
                break;
        }
}

static void handle_dc_disconnect(struct RlnhLinkObj *co)
{
        switch (co->state) {
        case STATE_DISCONNECTED:
                break; /* Sit tight, disconnected already called... */
        case STATE_CONNECTING:
                shmcm_disable_uc_deliver(co);
                shmcm_disable_dc_transmit(co);
                co->uc->disconnected(co->lo);
                co->state = STATE_DISCONNECTED;
                break;
        case STATE_CONNECTED:
                shmcm_disable_uc_deliver(co);
                shmcm_disable_dc_transmit(co);
                shmcm_send_con_pkt(co, CON_RST, co->cno);
                co->uc->disconnected(co->lo);
                co->state = STATE_DISCONNECTED;
                break;
        default:
                BUG();
                break;
        }
}

static void handle_internal_disconnect(struct RlnhLinkObj *co)
{
        switch (co->state) {
        case STATE_DISCONNECTED: /* Already disconnected... */
                break;
        case STATE_CONNECTING: /* Keep trying to connect... */
                /*
                 * FIXME:
                 * Hmm... we must restart the connecting phase, i.e. send a new
                 * CON_REQ. However, we need to delay it a little bit, otherwise
                 * we may end-up in a shmcm_send_con_pkt()/shmcm_disconnect()
                 * loop, hogging the CPU... The delay should probably have some
                 * randomness.
                 */
                break;
        case STATE_CONNECTED:
                shmcm_disable_uc_deliver(co);
                shmcm_disable_dc_transmit(co);
                shmcm_send_con_pkt(co, CON_RST, co->cno);
                co->uc->disconnected(co->lo);
                co->state = STATE_DISCONNECTED;
                break;
        default:
                BUG();
                break;
        }
}

static void handle_con_req(struct RlnhLinkObj *co, unsigned int peer_cno)
{
        switch (co->state) {
        case STATE_DISCONNECTED:
                break;
        case STATE_CONNECTING:
                shmcm_peer_alive(co);
                shmcm_enable_dc_transmit(co);
                shmcm_send_con_pkt(co, CON_ACK, co->cno);
                co->uc->connected(co->lo);
                co->state = STATE_CONNECTED;
                co->peer_cno = peer_cno; /* Do it before deliver is enabled. */
                shmcm_enable_uc_deliver(co);
                break;
        case STATE_CONNECTED:
                shmcm_disable_uc_deliver(co);
                shmcm_disable_dc_transmit(co);
                shmcm_send_con_pkt(co, CON_RST, co->cno);
                co->uc->disconnected(co->lo);
                co->state = STATE_DISCONNECTED;
                break;
        default:
                BUG();
                break;
        }
}

static void handle_con_ack(struct RlnhLinkObj *co, unsigned int peer_cno)
{
        switch (co->state) {
        case STATE_CONNECTING:
                shmcm_peer_alive(co);
                shmcm_enable_dc_transmit(co);
                co->uc->connected(co->lo);
                co->state = STATE_CONNECTED;
                co->peer_cno = peer_cno; /* Do it before deliver is enabled. */
                shmcm_enable_uc_deliver(co);
                break;
        case STATE_DISCONNECTED:
        case STATE_CONNECTED:
                break;
        default:
                BUG();
                break;
        }
}

static void handle_con_rst(struct RlnhLinkObj *co)
{
        switch (co->state) {
        case STATE_DISCONNECTED:
        case STATE_CONNECTING:
                break;
        case STATE_CONNECTED:
                shmcm_disable_uc_deliver(co);
                shmcm_disable_dc_transmit(co);
                co->uc->disconnected(co->lo);
                co->state = STATE_DISCONNECTED;
                break;
        default:
                BUG();
                break;
        }
}

static void handle_con_alv(struct RlnhLinkObj *co)
{
        switch (co->state) {
        case STATE_DISCONNECTED:
        case STATE_CONNECTING:
                break;
        case STATE_CONNECTED:
                shmcm_peer_alive(co);
                break;
        default:
                BUG();
                break;
        }
}

static void handle_con_tmo(struct RlnhLinkObj *co)
{
        switch (co->state) {
        case STATE_DISCONNECTED:
        case STATE_CONNECTING:
                break;
        case STATE_CONNECTED:
                if (!shmcm_peer_dead(co)) {
                        shmcm_send_con_pkt(co, CON_ALV, co->cno);
                } else {
                        shmcm_disable_uc_deliver(co);
                        shmcm_disable_dc_transmit(co);
                        shmcm_send_con_pkt(co, CON_RST, co->cno);
                        co->uc->disconnected(co->lo);
                        co->state = STATE_DISCONNECTED;
                }
                break;
        default:
                BUG();
                break;
        }

        /* Make sure that the timer isn't restarted after a del_timer_sync(). */
        if (atomic_read(&co->con_timer_lock) != 0)
                mod_timer(&co->con_timer, tmo_ms(co->con_tmo));
}

static void handle_shmcm_work_create(struct shmcm_work *w)
{
        struct shmcm_work_create *p;
        struct RlnhLinkObj *co;
        int status;

        p = w->data;
        status = 0;

        co = alloc_shmcm_con(p->arg);
        if (co == NULL) {
                status = -ENOMEM;
                goto out;
        }
        status = init_shmcm_con(co, p->arg);
        if (status != 0) {
                free_shmcm_con(co);
                goto out;
        }
        atomic_set(&co->con_timer_lock, 1);
        mod_timer(&co->con_timer, tmo_ms(co->con_tmo));
        status = 0; /* Note: wakeup_shmcm_work requires that status is <= 0. */
  out:
        p->co = co;
        wakeup_shmcm_work(w, status);
}

static void handle_shmcm_work_destroy(struct shmcm_work *w)
{
        struct shmcm_work_destroy *p;

        p = w->data;
        /*
         * We must stop users from submitting any more jobs for this
         * connection.
         */
        atomic_set(&p->co->con_timer_lock, 0);
        del_timer_sync(&p->co->con_timer);
        shmcm_cleanup_rx(p->co);
        shmcm_cleanup_tx(p->co);

        /*
         * Re-submit the destroy work, this allows any jobs already in
         * the workqueue to finish before the connection is destroyed.
         *
         * We must re-use struct shmcm_work, since shmcm_destroy() waits
         * on the status variable...
         */
        setup_shmcm_work(w, p, SHMCM_WORK_CLEANUP);
        queue_work(shmcm_workq, &w->work);
}

static void handle_shmcm_work_cleanup(struct shmcm_work *w)
{
        struct shmcm_work_destroy *p;

        p = w->data;
        shmcm_put_con(p->co); /* Free it, if no one uses it. */
        wakeup_shmcm_work(w, 0);
}

static void handle_shmcm_work_dc_init(struct shmcm_work *w)
{
        struct shmcm_work_dc_init *p;

        p = w->data;
        p->co->lo = p->lo;
        p->co->uc = p->uc;
        free_shmcm_work(w);
}

static void handle_shmcm_work_dc_connect(struct shmcm_work *w)
{
        struct shmcm_work_dc_connect *p;

        p = w->data;
        handle_dc_connect(p->co);
        free_shmcm_work(w);
}

static void handle_shmcm_work_dc_disconnect(struct shmcm_work *w)
{
        struct shmcm_work_dc_disconnect *p;

        p = w->data;
        handle_dc_disconnect(p->co);
        free_shmcm_work(w);
}

static void handle_shmcm_work_dc_finalize(struct shmcm_work *w)
{
        free_shmcm_work(w);
}

static void handle_shmcm_work_con_pkt(struct shmcm_work *w)
{
        struct shmcm_work_con_pkt *p;
        struct shmcm_chdr *chdr;
        unsigned int type;
        unsigned int peer_cno;

        p = w->data;
        chdr = (struct shmcm_chdr *)p->skb->data;
        type = (unsigned int)chdr->type;
        peer_cno = (unsigned int)chdr->cno;

        switch (type) {
        case CON_REQ:
                handle_con_req(p->co, peer_cno);
                break;
        case CON_ACK:
                handle_con_ack(p->co, peer_cno);
                break;
        case CON_RST:
                handle_con_rst(p->co);
                break;
        case CON_ALV:
                handle_con_alv(p->co);
                break;
        default:
                BUG(); /* FIXME: remove this, just for now... */
                break;
        }
        kfree_skb(p->skb);
        free_shmcm_work(w);
}

static void handle_shmcm_work_con_tmo(struct shmcm_work *w)
{
        struct shmcm_work_con_tmo *p;

        p = w->data;
        handle_con_tmo(p->co);
        free_shmcm_work(w);
}

static void handle_shmcm_work_disconnect(struct shmcm_work *w)
{
        struct shmcm_work_dc_disconnect *p;

        p = w->data;
        handle_internal_disconnect(p->co);
        free_shmcm_work(w);
}

static void shmcm_workq_func(struct work_struct *w)
{
        static void (*workq_func[])(struct shmcm_work *) = {
                handle_shmcm_work_create,
                handle_shmcm_work_destroy,
                handle_shmcm_work_cleanup,
                handle_shmcm_work_dc_init,
                handle_shmcm_work_dc_connect,
                handle_shmcm_work_dc_disconnect,
                handle_shmcm_work_dc_finalize,
                handle_shmcm_work_con_pkt,
                handle_shmcm_work_con_tmo,
                handle_shmcm_work_disconnect,
        };
        struct shmcm_work *p;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20))
        log_w(p = container_of(w, struct shmcm_work, work));
#else
        log_w(p = (struct shmcm_work *)w);
#endif
        BUG_ON(p->opcode >= ARRAY_SIZE(workq_func));
        workq_func[p->opcode](p);
}

static void shmcm_dc_init(struct RlnhLinkObj *co, void *lo, struct RlnhLinkUCIF *uc)
{
        struct shmcm_work *w;
        struct shmcm_work_dc_init *p;

        w = alloc_shmcm_work(sizeof(*p), SHMCM_WORK_DC_INIT, GFP_KERNEL);
        if (w == NULL) {
                printk(KERN_CRIT "shmcm: out-of-memory...\n");
                return;
        }
        p = w->data;
        p->co = co;
        p->lo = lo;
        p->uc = uc;
        queue_shmcm_work(w);
}

static void shmcm_dc_connect(struct RlnhLinkObj *co)
{
        struct shmcm_work *w;
        struct shmcm_work_dc_connect *p;

        w = alloc_shmcm_work(sizeof(*p), SHMCM_WORK_DC_CONNECT, GFP_KERNEL);
        if (w == NULL) {
                printk(KERN_CRIT "shmcm: out-of-memory...\n");
                return;
        }
        p = w->data;
        p->co = co;
        queue_shmcm_work(w);
}

static void shmcm_dc_disconnect(struct RlnhLinkObj *co)
{
        struct shmcm_work *w;
        struct shmcm_work_dc_disconnect *p;

        /*
         * FIXME:
         * This function can be called from atomic context, use pre-allocated
         * memory since kmalloc can't sleep...
         *
         * Note: shmcm_disconnect and shmcm_dc_disconnect MUST NOT use
         *       the same pre-allocated memory!!!!
         */
        w = alloc_shmcm_work(sizeof(*p), SHMCM_WORK_DC_DISCONNECT, GFP_ATOMIC);
        BUG_ON(w == NULL);

        p = w->data;
        p->co = co;
        queue_shmcm_work(w);
}

static void shmcm_dc_finalize(struct RlnhLinkObj *co)
{
        struct shmcm_work *w;
        struct shmcm_work_dc_finalize *p;

        w = alloc_shmcm_work(sizeof(*p), SHMCM_WORK_DC_FINALIZE, GFP_KERNEL);
        if (w == NULL) {
                printk(KERN_CRIT "shmcm: out-of-memory...\n");
                return;
        }
        p = w->data;
        p->co = co;
        queue_shmcm_work(w);
}

void shmcm_disconnect(struct RlnhLinkObj *co, int cause, int origin)
{
        struct shmcm_work *w;
        struct shmcm_work_disconnect *p;

        /*
         * FIXME:
         * This function can be called from atomic context, use pre-allocated
         * memory since kmalloc can't sleep...
         *
         * Note: shmcm_disconnect and shmcm_dc_disconnect MUST NOT use
         *       the same pre-allocated memory!!!!
         */
        w = alloc_shmcm_work(sizeof(*p), SHMCM_WORK_DISCONNECT, GFP_ATOMIC);
        BUG_ON(w == NULL);

        p = w->data;
        p->co = co;
        p->cause = cause;
        p->origin = origin;
        queue_shmcm_work(w);
}

void shmcm_deliver_con_pkt(struct RlnhLinkObj *co, struct sk_buff *skb)
{
        struct shmcm_work *w;
        struct shmcm_work_con_pkt *p;

        /* Can be called from softirq... */
        w = alloc_shmcm_work(sizeof(*p), SHMCM_WORK_CON_PKT, GFP_ATOMIC);
        if (w == NULL) {
                kfree_skb(skb);
                shmcm_disconnect(co, -ENOMEM, SHMCM_MGMT);
                return;
        }

        p = w->data;
        p->co = co;
        p->skb = skb;
        queue_shmcm_work(w);
}

void shmcm_get_con(struct RlnhLinkObj *co)
{
        atomic_inc(&co->use_count);
}

void shmcm_put_con(struct RlnhLinkObj *co)
{
        if (atomic_dec_return(&co->use_count) == 0)
                free_shmcm_con(co);
}

static void con_tmo_func(unsigned long data)
{
        struct shmcm_work *w;
        struct shmcm_work_con_tmo *p;
        struct RlnhLinkObj *co;

        co = (struct RlnhLinkObj *)data;

        w = alloc_shmcm_work(sizeof(*p), SHMCM_WORK_CON_TMO, GFP_ATOMIC);
        if (w == NULL) {
                /* Must NOT restart timer here! */
                shmcm_disconnect(co, -ENOMEM, SHMCM_MGMT);
                return;
        }

        p = w->data;
        p->co = co;
        queue_shmcm_work(w);
}

static int get_dc(const void *cookie, void **dc)
{
        static struct RlnhLinkIF shmcm_dc = {
                RLNH_LINK_IF_VERSION,
                shmcm_dc_init,
                shmcm_dc_finalize,
                shmcm_dc_connect,
                shmcm_dc_disconnect,
                shmcm_dc_transmit
        };

        u64 *p;
        unsigned long ul;

        (void)cookie;

        p = kmalloc(sizeof(*p), GFP_KERNEL); /* Note: DB calls kfree! */
        if (p == NULL)
                return -ENOMEM;

        ul = (unsigned long)&shmcm_dc; /* Cast to avoid 32/64 bit trouble. */
        *p = (u64)ul;
        *dc = p;

        return (DB_TMP | DB_HEX | DB_UINT64);
}

static int get_alive_count(const void *cookie, void **cnt)
{
        struct RlnhLinkObj *co;
        int *p;

        p = kmalloc(sizeof(*p), GFP_KERNEL); /* Note: DB calls kfree! */
        if (p == NULL)
                return -ENOMEM;

        co = (struct RlnhLinkObj *)cookie;
        *p = (int)atomic_read(&co->alive_count);
        *cnt = p;

        return (DB_TMP | DB_INT);
}

static int get_defq_size(const void *cookie, void **size)
{
	struct RlnhLinkObj *co;
	int *p;

	p = kmalloc(sizeof(*p), GFP_KERNEL); /* Note: DB calls kfree! */
        if (p == NULL)
                return -ENOMEM;
    
	co = (struct RlnhLinkObj *)cookie;
	*p = (int)atomic_read(&co->tx.defq_size);
	*size = p;

	return (DB_TMP | DB_INT);
}

static struct shmcm_ioctl_create *copy_args_from_user(void __user *arg)
{
        struct shmcm_ioctl_create k, *kp;
        size_t size;

        if (copy_from_user(&k, arg, sizeof(k)) != 0)
                return ERR_PTR(-EFAULT);

        size = sizeof(*kp) + k.name_len + 1;
        kp = kzalloc(size, GFP_KERNEL);
        if (kp == NULL)
                return ERR_PTR(-ENOMEM);

        if (copy_from_user(kp, arg, size) != 0) {
                kfree(kp);
                return ERR_PTR(-EFAULT);
        }
        return kp;
}

static int check_args(struct shmcm_ioctl_create *p)
{
        size_t pktsz;

        pktsz = sizeof(struct shmcm_mhdr);
        pktsz += max(sizeof(struct shmcm_uhdr), sizeof(struct shmcm_chdr));
        pktsz += sizeof(uint32_t); /* Must be room for the signal number. */
        if ((p->mtu < pktsz) || (p->mru < pktsz))
                return -EINVAL;

        return 0;
}

static void *shmcm_create(void __user *arg)
{
        struct shmcm_ioctl_create *karg;
        struct shmcm_work *w;
        struct shmcm_work_create *p;
        struct RlnhLinkObj *co;
        int status;

        if (try_module_get(THIS_MODULE) == 0)
                return ERR_PTR(-EINVAL);

        karg = copy_args_from_user(arg);
        if (IS_ERR(karg)) {
                status = (int)PTR_ERR(karg);
                goto out_20;
        }
        status = check_args(karg);
        if (status != 0)
                goto out_10;

        w = alloc_shmcm_work(sizeof(*p), SHMCM_WORK_CREATE, GFP_KERNEL);
        if (w == NULL) {
                status = -ENOMEM;
                goto out_10;
        }
        p = w->data;
        p->arg = karg;
        p->co = NULL;
        init_waitfor_shmcm_work(w);
        queue_shmcm_work(w);

        status = waitfor_shmcm_work(w);
        co = p->co;
        free_shmcm_work(w);
        if (status != 0)
                goto out_10;
        kfree(karg);
        return co;
  out_10:
        kfree(karg);
  out_20:
        module_put(THIS_MODULE);
        return ERR_PTR((long)status);
}

static int shmcm_destroy(void *cookie, void __user *arg)
{
        struct shmcm_work *w;
        struct shmcm_work_destroy *p;
        int status;

        (void)arg;

        w = alloc_shmcm_work(sizeof(*p), SHMCM_WORK_DESTROY, GFP_KERNEL);
        if (w == NULL)
                return -ENOMEM;

        p = w->data;
        p->co = cookie;
        init_waitfor_shmcm_work(w);
        queue_work(shmcm_workq, &w->work);

        status = waitfor_shmcm_work(w);
        free_shmcm_work(w);
        if (status != 0)
                return status;
        module_put(THIS_MODULE);
        return 0;
}

static int __init shmcm_init(void)
{
        init_waitqueue_head(&shmcm_waitq);

        shmcm_workq = create_singlethread_workqueue("shmcm");
        if (shmcm_workq == NULL)
                return -ENOMEM;

        db_add_template(DB_KEY_SHMCM, &shmcm_template);
        db_proc_add(DB_KEY_SHMCM);

        mb_init();

        return 0;
}
module_init(shmcm_init);

static void __exit shmcm_cleanup(void)
{
        db_proc_del(DB_KEY_SHMCM);
        db_del_template(DB_KEY_SHMCM);

        /*
         * At this point, no one is submitting jobs to the workqueue. All
         * connections are destroyed (module's use count is used to make sure
         * of this). It is safe to flush and destroy the workqueue.
         */
        flush_workqueue(shmcm_workq);
        destroy_workqueue(shmcm_workq);
}
module_exit(shmcm_cleanup);

/*
 * =============================================================================
 * Some trace functions...
 * =============================================================================
 */
#ifdef SHMCM_TRACE
static void log_w(struct shmcm_work *w)
{
        static const char *wd[] = {
                "SHMCM_WORK_CREATE",
                "SHMCM_WORK_DESTROY",
                "SHMCM_WORK_CLEANUP",
                "SHMCM_WORK_DC_INIT",
                "SHMCM_WORK_DC_CONNECT",
                "SHMCM_WORK_DC_DISCONNECT",
                "SHMCM_WORK_DC_FINALIZE",
                "SHMCM_WORK_CON_PKT",
                "SHMCM_WORK_CON_TMO",
                "SHMCM_WORK_DISCONNECT",
        };
        struct RlnhLinkObj *co;
        struct shmcm_ioctl_create *arg;
        struct sk_buff *skb;
        struct shmcm_chdr *chdr;
        int cause, origin;

        switch (w->opcode) {
        case SHMCM_WORK_CREATE:
                arg = ((struct shmcm_work_create *)w->data)->arg;
                printk("%s(-): %s mbtx_%u(%u) mbrx_%u(%u)\n",
                       kptr(arg, arg->name), wd[w->opcode], arg->mbox, arg->mtu,
                       arg->mbox, arg->mru);
                break;
        case SHMCM_WORK_DESTROY:
        case SHMCM_WORK_CLEANUP:
        case SHMCM_WORK_DC_INIT:
        case SHMCM_WORK_DC_CONNECT:
        case SHMCM_WORK_DC_DISCONNECT:
        case SHMCM_WORK_DC_FINALIZE:
        case SHMCM_WORK_CON_TMO:
                /* Hmm... co is the 1:st member in all these structs... */
                co = ((struct shmcm_work_destroy *)w->data)->co;
                printk("%s(%d): %s\n", co->con_name, co->state, wd[w->opcode]);
                break;
        case SHMCM_WORK_DISCONNECT:
                co = ((struct shmcm_work_disconnect *)w->data)->co;
                cause = ((struct shmcm_work_disconnect *)w->data)->cause;
                origin = ((struct shmcm_work_disconnect *)w->data)->origin;
                printk("%s(%d): %s(%d, %d)\n", co->con_name, co->state,
                       wd[w->opcode], cause, origin);
                break;
        case SHMCM_WORK_CON_PKT:
                co = ((struct shmcm_work_con_pkt *)w->data)->co;
                skb = ((struct shmcm_work_con_pkt *)w->data)->skb;
                chdr = (struct shmcm_chdr *)skb->data;
                printk("%s(%d): %s(%d)\n", co->con_name, co->state,
                       wd[w->opcode], chdr->type);
                break;
        default:
                BUG();
                break;
        }
}
#endif
