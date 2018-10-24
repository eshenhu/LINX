/*
 * Copyright (c) 2010-2011, Enea Software AB
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

#include <linux/linx_ioctl.h>

#include <linx_assert.h>
#include <buf_types.h>
#include <rlnh/rlnh_link.h>
#include <cfg/db.h>
#include <cfg/db_proc.h>
#include <linux/cmcl_db_ioctl.h>

#define CMCL_VERSION LINX_VERSION

MODULE_AUTHOR("ENEA");
MODULE_DESCRIPTION("LINX Connection Manager Control Layer");
MODULE_LICENSE("GPL");
MODULE_VERSION(CMCL_VERSION);

#define STATE_DISCONNECTED  1
#define STATE_CONNECTING_1  2
#define STATE_CONNECTING_2  3
#define STATE_CONNECTED     4
#define STATE_DISCONNECTING 5
#define STATE_FINALIZED     6

#define ALIVES_PER_TMO 3
#define ALIVE_RESET_VALUE (2 + (ALIVES_PER_TMO - 1))

#define CONN_REQ 1
#define CONN_ACK 2
#define CONN_RST 3
#define CONN_ALV 4

struct conn_pkt
{
	uint32_t type;
	struct RlnhLinkObj *co;
};

struct data_pkt
{
	struct list_head head;
	uint32_t buf_type;
	uint32_t src;
	uint32_t dst;
	uint32_t size;
	void *data;
};

struct RlnhLinkObj
{
	char *name;
        uint64_t con_cookie;
        void *lo;
        struct RlnhLinkUCIF *uc;
        char *con_name;
	void *dco;
        struct RlnhLinkIF *dc;
        int state;
        unsigned int con_attempts;
        struct timer_list con_timer;
        atomic_t con_timer_lock;
        unsigned long con_tmo;
	int alive_cnt;
        atomic_t use_count;
	struct list_head deliver_queue;
};

#define uptr(p, n) ((u8 __user *)(p) + (n))
#define kptr(p, n) ((u8 *)(p) + (n))

#define tmo_ms(ms) (jiffies + msecs_to_jiffies(ms))

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14))
#if defined(GFP_IS_INT)
#define gfp_t int
#else
#define gfp_t unsigned int
#endif
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15))
static inline void setup_timer(struct timer_list * timer,
                               void (*function)(unsigned long),
                               unsigned long data)
{
        timer->function = function;
        timer->data = data;
        init_timer(timer);
}
#endif

#ifdef CMCL_KZALLOC
void *kzalloc(size_t size, gfp_t flags)
{
        void *ret = kmalloc(size, flags);

        if (ret)
                memset(ret, 0, size);
        return ret;
}
#endif

static int get_dc(const void *cookie, void **dc);
static void *cmcl_create(void __user *arg);
static int cmcl_destroy(void *cookie, void __user *arg);
static int get_uc(const void *cookie, void **uc);
static const struct db_param cmcl_params[] = {
        DB_PARAM("con_name", DB_PTR|DB_STRING, name, struct RlnhLinkObj),
        DB_PARAM("con_cookie",DB_HEX|DB_UINT64, con_cookie, struct RlnhLinkObj),
        DB_META_PARAM("con_dc", DB_HEX|DB_UINT64, sizeof(u64), 1, get_dc, NULL),
        DB_META_PARAM("con_uc", DB_HEX|DB_UINT64, sizeof(u64), 1, get_uc, NULL),
        DB_PARAM("dc_name", DB_PTR|DB_STRING, con_name, struct RlnhLinkObj),
        DB_PARAM("uc_cookie", DB_HEX|DB_UINT64, lo, struct RlnhLinkObj),
        DB_PARAM("uc",DB_HEX|DB_UINT64, uc, struct RlnhLinkObj),
        DB_PARAM("dc_cookie", DB_HEX|DB_UINT64, dco, struct RlnhLinkObj),
        DB_PARAM("dc",DB_HEX|DB_UINT64, dc, struct RlnhLinkObj),
        DB_PARAM("con_tmo", DB_ULONG, con_tmo, struct RlnhLinkObj),
        DB_PARAM("state", DB_INT, state, struct RlnhLinkObj),
        DB_PARAM_END
};

static const struct db_template cmcl_template = {
        .owner = THIS_MODULE,
        .create = cmcl_create,
        .destroy = cmcl_destroy,
        .param = cmcl_params
};

static struct workqueue_struct *cmcl_workq;
static void cmcl_workq_func(struct work_struct *w);
static wait_queue_head_t cmcl_waitq;

#define CMCL_WORK_CREATE 0
struct cmcl_work_create {
        struct cmcl_ioctl_create *arg;
        struct RlnhLinkObj *co;
};

#define CMCL_WORK_DESTROY 1
#define CMCL_WORK_CLEANUP 2
struct cmcl_work_destroy {
        struct RlnhLinkObj *co;
};

#define CMCL_WORK_DC_INIT 3
struct cmcl_work_dc_init {
        struct RlnhLinkObj *co;
        void *lo;
        struct RlnhLinkUCIF *uc;
};

#define CMCL_WORK_DC_CONNECT 4
struct cmcl_work_dc_connect {
        struct RlnhLinkObj *co;
};

#define CMCL_WORK_DC_DISCONNECT 5
struct cmcl_work_dc_disconnect {
        struct RlnhLinkObj *co;
};

#define CMCL_WORK_DC_FINALIZE 6
struct cmcl_work_dc_finalize {
        struct RlnhLinkObj *co;
};

#define CMCL_WORK_UC_CONNECTED 7
struct cmcl_work_uc_connected {
        struct RlnhLinkObj *co;
};

#define CMCL_WORK_UC_DISCONNECTED 8
struct cmcl_work_uc_disconnected {
        struct RlnhLinkObj *co;
};

#define CMCL_WORK_CON_PKT 9
struct cmcl_work_con_pkt {
        struct RlnhLinkObj *co;
	int type;
};

#define CMCL_WORK_CON_TMO 10
struct cmcl_work_con_tmo {
        struct RlnhLinkObj *co;
};

#define CMCL_WORK_DISCONNECT 11
struct cmcl_work_disconnect {
        struct RlnhLinkObj *co;
        int cause;
        int origin;
};

#define CMCL_WORK_WAITFOR_COMPLETED 1

struct cmcl_work {
        int opcode;
        int status;
        struct work_struct work;
        void *data;
};

#ifdef CMCL_DEBUG
static void log_w(struct cmcl_work *w);
#else
#define log_w(w) (w)
#endif

static void cmcl_put_con(struct RlnhLinkObj *co);
static void con_tmo_func(unsigned long data);

static void setup_cmcl_work(struct cmcl_work *w, int opcode)
{
        w->opcode = opcode;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20))
        INIT_WORK(&w->work, cmcl_workq_func);
#else
        INIT_WORK(&w->work, (void (*)(void *))cmcl_workq_func, w);
#endif
}

static struct cmcl_work *alloc_cmcl_work(size_t size, int opcode, gfp_t flags)
{
        struct cmcl_work *w;

        w = kmalloc(sizeof(*w), flags);
        if (w == NULL)
                return NULL;
        w->data = kmalloc(size, flags);
	if (w->data == NULL) {
		kfree(w);
		return NULL;
	}
        setup_cmcl_work(w, opcode);
        return w;
}

static void free_cmcl_work(struct cmcl_work *w)
{
        if (w != NULL) {
		kfree(w->data);
                kfree(w);
        }
}

static void init_waitfor_cmcl_work(struct cmcl_work *w)
{
        w->status = CMCL_WORK_WAITFOR_COMPLETED;
}

static void queue_cmcl_work(struct cmcl_work *w)
{
        queue_work(cmcl_workq, &w->work);
}

static int waitfor_cmcl_work(struct cmcl_work *w)
{
        wait_event(cmcl_waitq, w->status != CMCL_WORK_WAITFOR_COMPLETED);
        return w->status;
}

static void wakeup_cmcl_work(struct cmcl_work *w, int status)
{
        ERROR_ON(w->status != CMCL_WORK_WAITFOR_COMPLETED);
        ERROR_ON(status > 0);

        /*
         * Submitter is waiting for the work to be carried out,
         * wake him up... Submitter must call free_db_work()!
         */
        w->status = status;
        wake_up(&cmcl_waitq);
}

static struct db_value *get_value(const char *conn_name, const char *var_name,
                                  size_t var_size)
{
        size_t len;
        char *name;
        struct db_value *v;
        int status;

        len = strlen(conn_name) + strlen(var_name) + 2; /* Extra / and \0 */
        name = kmalloc(len, GFP_KERNEL);
        if (name == NULL)
                return ERR_PTR(-ENOMEM);

        sprintf(name, "%s/%s", conn_name, var_name);

        v = kmalloc(sizeof(*v) + var_size, GFP_KERNEL);
        if (v == NULL) {
                kfree(name);
                return ERR_PTR(-ENOMEM);
        }

        status = db_get_value(name, v, v->buf, var_size);
        if (status != 0) {
                kfree(name);
                kfree(v);
                return ERR_PTR(status);
        }

        kfree(name);
        return v;
}

static int get_u64(const char *conn_name, const char *var_name, u64 *v64)
{
        struct db_value *v;

        v = get_value(conn_name, var_name, sizeof(*v64));
        if (IS_ERR(v))
                return (int)PTR_ERR(v);

        memcpy(v64, v->buf, sizeof(*v64));

        kfree(v);
        return 0;
}

static struct RlnhLinkObj *get_cookie(const char *conn_name)
{
        u64 cookie;
        int status;

        status = get_u64(conn_name, "con_cookie", &cookie);
        if (status != 0)
                return ERR_PTR(status);

        return (struct RlnhLinkObj *)((unsigned long)cookie);
}

static struct RlnhLinkIF *get_downcalls(const char *conn_name)
{
        u64 dc;
        int status;

        status = get_u64(conn_name, "con_dc", &dc);
        if (status != 0)
                return ERR_PTR(status);

        return (struct RlnhLinkIF *)((unsigned long)dc);
}

static void free_cmcl_con(struct RlnhLinkObj *co)
{
        if (co != NULL) {
		if (co->name)
			kfree(co->name);
		if (co->con_name)
			kfree(co->con_name);
                kfree(co);
        }
}

static struct RlnhLinkObj *alloc_cmcl_con(struct cmcl_ioctl_create *p)
{
        struct RlnhLinkObj *co;
        size_t size;

        co = kzalloc(sizeof(*co), GFP_KERNEL);
        if (co == NULL)
                goto out;

        size = strlen((char *)kptr(p, p->name)) + 1 ;
        co->name = kzalloc(size, GFP_KERNEL);
        if (co->name == NULL)
                goto out;

        size = strlen((char *)kptr(p, p->con_name)) + 1 ;
        co->con_name = kzalloc(size, GFP_KERNEL);
        if (co->con_name == NULL)
                goto out;

        atomic_set(&co->use_count, 1);

        return co;
out:
        free_cmcl_con(co);
        return NULL;
}

static int init_cmcl_con(struct RlnhLinkObj *co, struct cmcl_ioctl_create *p)
{
        strcpy(co->name, (char *)kptr(p, p->name));
        strcpy(co->con_name, (char *)kptr(p, p->con_name));
        co->con_cookie = (uint64_t)((unsigned long)co);
	co->dco = get_cookie(co->con_name);
	if(IS_ERR(co->dco))
		return (int)PTR_ERR(co->dco);
	co->dc = get_downcalls(co->con_name);
	if(IS_ERR(co->dc))
		return (int)PTR_ERR(co->dco);

        co->state = STATE_DISCONNECTED;
        co->con_tmo = (unsigned long)max(300U / ALIVES_PER_TMO,
                                         p->con_tmo / ALIVES_PER_TMO);
        setup_timer(&co->con_timer, con_tmo_func, (unsigned long)co);
        co->alive_cnt = ALIVE_RESET_VALUE;
	INIT_LIST_HEAD(&co->deliver_queue);

        return 0;
}

static void send_conn_pkt(struct RlnhLinkObj *co, uint32_t type)
{
	struct conn_pkt pkt;
	
	memset(&pkt, 0x0, sizeof(pkt));
	pkt.type = type;

	(void)co->dc->transmit(co->dco, BUFFER_TYPE_KERNEL,
			       0, type, sizeof(pkt), (void *)&pkt);

}

void enqueue_packet(struct RlnhLinkObj *co, uint32_t buffer_type,
		    uint32_t src, uint32_t dst, uint32_t size, void *data)
{
	struct data_pkt *tmp;
	/* fixme. put this on a preallocated list instead */
	tmp = kmalloc(sizeof(*tmp), GFP_ATOMIC);
	ERROR_ON(tmp == NULL);
	tmp->buf_type = buffer_type;
	tmp->src = src;
	tmp->dst = dst;
	tmp->size = size;
	tmp->data = data;
	list_add_tail(&tmp->head, &co->deliver_queue);
}

struct data_pkt *dequeue_packet(struct RlnhLinkObj *co)
{
	struct data_pkt *tmp;

	tmp = NULL;
	if (list_empty(&co->deliver_queue))
		return NULL;
	tmp = container_of((&co->deliver_queue)->next, struct data_pkt, head);
	list_del(&tmp->head);

	return tmp;
}

void flush_packets(struct RlnhLinkObj *co)
{
	struct data_pkt *tmp;

	tmp = dequeue_packet(co);
	while (tmp != NULL) {
		kfree(tmp);
		tmp = dequeue_packet(co);
	}
}

void deliver_packets(struct RlnhLinkObj *co)
{
	struct data_pkt *tmp;

	tmp = dequeue_packet(co);
	while (tmp != NULL) {
		co->uc->deliver(co->lo, tmp->buf_type,
				tmp->src, tmp->dst, tmp->size, tmp->data);
		kfree(tmp);
		tmp = dequeue_packet(co);
	}
}

/* state machine functions */
static void handle_cmcl_work_create(struct cmcl_work *w)
{
        struct cmcl_work_create *p;
        struct RlnhLinkObj *co;
        int status;

        p = w->data;
        status = 0;

        co = alloc_cmcl_con(p->arg);
        if (co == NULL) {
                status = -ENOMEM;
                goto out;
        }
        status = init_cmcl_con(co, p->arg);
        if (status != 0) {
                free_cmcl_con(co);
                goto out;
        }
        atomic_set(&co->con_timer_lock, 1);
        mod_timer(&co->con_timer, tmo_ms(co->con_tmo));
        status = 0; /* Note: wakeup_cmcl_work requires that status is <= 0. */
out:
        p->co = co;
        wakeup_cmcl_work(w, status);
}

static void handle_cmcl_work_destroy(struct cmcl_work *w)
{
        struct cmcl_work_destroy *p;

        p = w->data;
        /*
         * We must stop users from submitting any more jobs for this
         * connection.
         */
        atomic_set(&p->co->con_timer_lock, 0);
        del_timer_sync(&p->co->con_timer);

        /*
         * Re-submit the destroy work, this allows any jobs already in
         * the workqueue to finish before the connection is destroyed.
         *
         * We must re-use struct cmcl_work, since cmcl_destroy() waits
         * on the status variable...
         */
        setup_cmcl_work(w, CMCL_WORK_CLEANUP);
        queue_work(cmcl_workq, &w->work);
}

static struct RlnhLinkUCIF cmcl_uc;

static void handle_dc_init(struct RlnhLinkObj *co, void *lo,
                           struct RlnhLinkUCIF *uc)
{
	switch (co->state) {
	case STATE_FINALIZED:
		co->state = STATE_DISCONNECTED; /* recreation of link */
	case STATE_DISCONNECTED:
		co->lo = lo;
		co->uc = uc;
		co->dc->init(co->dco, (void *)co, &cmcl_uc);
		break;
	default:
		ERROR();
		break;
	}
}

static void handle_dc_finalize(struct RlnhLinkObj *co)
{
	switch (co->state) {
	case STATE_DISCONNECTED:
		co->lo = NULL;
		co->uc = NULL;
		co->dc->finalize(co->dco);
		flush_packets(co);
		co->state = STATE_FINALIZED;
		break;
	default:
		ERROR();
		break;
	}
}

static void handle_dc_conn(struct RlnhLinkObj *co)
{
	switch (co->state)
	{
	case STATE_DISCONNECTED:
		co->dc->connect(co->dco);
		co->state = STATE_CONNECTING_1;
		break;
	default:
		ERROR();
		break;
	}
}

static void handle_dc_disc(struct RlnhLinkObj *co)
{
	switch (co->state)
	{
	case STATE_DISCONNECTED:
		break;
	case STATE_CONNECTING_1:
	case STATE_CONNECTING_2:
		co->dc->disconnect(co->dco);
		co->state = STATE_DISCONNECTING;
		break;
	case STATE_CONNECTED:
		send_conn_pkt(co, CONN_RST);
		co->dc->disconnect(co->dco);
		co->state = STATE_DISCONNECTING;
		break;
	case STATE_FINALIZED:
	default:
		ERROR();
		break;
	}
}

static void handle_uc_conn(struct RlnhLinkObj *co)
{
	switch (co->state)
	{
	case STATE_DISCONNECTED:
	case STATE_DISCONNECTING:
		break;
	case STATE_CONNECTING_2:
	case STATE_CONNECTED:
		co->dc->disconnect(co->dco);
		co->state = STATE_DISCONNECTING;
		break;
	case STATE_CONNECTING_1:
		send_conn_pkt(co, CONN_REQ);
		co->state = STATE_CONNECTING_2;
		break;
	case STATE_FINALIZED:
	default:
		ERROR();
		break;
	}
}

static void handle_uc_disc(struct RlnhLinkObj *co)
{
	switch (co->state)
	{
	case STATE_DISCONNECTED:
		break;
	case STATE_DISCONNECTING:
	case STATE_CONNECTING_1:
	case STATE_CONNECTING_2:
	case STATE_CONNECTED:
		flush_packets(co);
		co->uc->disconnected(co->lo);
		co->state = STATE_DISCONNECTED;
		break;
	case STATE_FINALIZED:
	default:
		ERROR();
		break;
	}
}

static void handle_conn_req(struct RlnhLinkObj *co)
{
	switch (co->state) {
	case STATE_DISCONNECTED:
	case STATE_DISCONNECTING:
	case STATE_CONNECTING_1:
	case STATE_FINALIZED:
		break;
	case STATE_CONNECTED:
		send_conn_pkt(co, CONN_RST);
		co->dc->disconnect(co->dco);
		co->state = STATE_DISCONNECTING;
		break;
	case STATE_CONNECTING_2:
		co->alive_cnt = ALIVE_RESET_VALUE;
		send_conn_pkt(co, CONN_ACK);
		co->uc->connected(co->lo);
		co->state = STATE_CONNECTED;
		break;
	default:
		ERROR();
		break;
	}
}

static void handle_conn_ack(struct RlnhLinkObj *co)
{
	switch (co->state)
	{
	case STATE_DISCONNECTED:
	case STATE_CONNECTING_1:
	case STATE_DISCONNECTING:
	case STATE_CONNECTED:
	case STATE_FINALIZED:
		break;
	case STATE_CONNECTING_2:
		co->alive_cnt = ALIVE_RESET_VALUE;
		co->uc->connected(co->lo);
		co->state = STATE_CONNECTED;
		break;
	default:
		ERROR();
		break;
	}
}

static void handle_conn_rst(struct RlnhLinkObj *co)
{
	switch (co->state) {
	case STATE_DISCONNECTED:
	case STATE_CONNECTING_1:
	case STATE_DISCONNECTING:
	case STATE_CONNECTING_2:
	case STATE_FINALIZED:
		break;
	case STATE_CONNECTED:
		co->dc->disconnect(co->dco);
		co->state = STATE_DISCONNECTING;
		break;
	default:
		ERROR();
		break;
	}
}

static void handle_conn_alv(struct RlnhLinkObj *co)
{
	switch (co->state)
	{
	case STATE_DISCONNECTED:
	case STATE_CONNECTING_1:
	case STATE_CONNECTING_2:
	case STATE_DISCONNECTING:
	case STATE_FINALIZED:
		break;
	case STATE_CONNECTED:
		co->alive_cnt = ALIVE_RESET_VALUE;
		break;
	default:
		ERROR();
		break;
	}
}

static void handle_conn_tmo(struct RlnhLinkObj *co)
{
        switch (co->state) {
	case STATE_DISCONNECTED:
	case STATE_CONNECTING_1:
	case STATE_CONNECTING_2:
	case STATE_DISCONNECTING:
	case STATE_FINALIZED:
		break;
	case STATE_CONNECTED:
                if (co->alive_cnt-- > 0) {
                        send_conn_pkt(co, CONN_ALV);
                } else {
                        send_conn_pkt(co, CONN_RST);
			co->dc->disconnect(co->dco);
                        co->state = STATE_DISCONNECTING;
                }
                break;
        default:
                ERROR();
                break;
        }

        /* Make sure that the timer isn't restarted after a del_timer_sync(). */
        if (atomic_read(&co->con_timer_lock) != 0)
                mod_timer(&co->con_timer, tmo_ms(co->con_tmo));
}

static void handle_internal_disconnect(struct RlnhLinkObj *co)
{
        switch (co->state) {
	case STATE_DISCONNECTED:
	case STATE_DISCONNECTING:
	case STATE_FINALIZED:
		break;
	case STATE_CONNECTING_1:
	case STATE_CONNECTING_2:
	case STATE_CONNECTED:
		send_conn_pkt(co, CONN_RST);
		co->dc->disconnect(co->dco);
		co->state = STATE_DISCONNECTING;
                break;
        default:
                ERROR();
                break;
        }
}

static void handle_cmcl_work_cleanup(struct cmcl_work *w)
{
        struct cmcl_work_destroy *p;

        p = w->data;
        cmcl_put_con(p->co); /* Free it, if no one uses it. */
        wakeup_cmcl_work(w, 0);
}

static void handle_cmcl_work_dc_init(struct cmcl_work *w)
{
        struct cmcl_work_dc_init *p;

        p = w->data;
	handle_dc_init(p->co, p->lo, p->uc);
        free_cmcl_work(w);
}

static void handle_cmcl_work_dc_finalize(struct cmcl_work *w)
{
        struct cmcl_work_dc_finalize *p;

        p = w->data;
	handle_dc_finalize(p->co);
        free_cmcl_work(w);
}
static void handle_cmcl_work_dc_connect(struct cmcl_work *w)
{
        struct cmcl_work_dc_connect *p;

        p = w->data;
        handle_dc_conn(p->co);
        free_cmcl_work(w);
}

static void handle_cmcl_work_dc_disconnect(struct cmcl_work *w)
{
        struct cmcl_work_dc_disconnect *p;

        p = w->data;
        handle_dc_disc(p->co);
        free_cmcl_work(w);
}

static void handle_cmcl_work_uc_connected(struct cmcl_work *w)
{
        struct cmcl_work_uc_connected *p;

        p = w->data;
        handle_uc_conn(p->co);
        free_cmcl_work(w);
}

static void handle_cmcl_work_uc_disconnected(struct cmcl_work *w)
{
        struct cmcl_work_uc_disconnected *p;

        p = w->data;
        handle_uc_disc(p->co);
        free_cmcl_work(w);
}

static void handle_cmcl_work_con_pkt(struct cmcl_work *w)
{
        struct cmcl_work_con_pkt *p;

        p = w->data;

        switch (p->type) {
        case CONN_REQ:
                handle_conn_req(p->co);
                break;
        case CONN_ACK:
                handle_conn_ack(p->co);
                break;
        case CONN_RST:
                handle_conn_rst(p->co);
                break;
        case CONN_ALV:
                handle_conn_alv(p->co);
                break;
        default:
                ERROR();
                break;
        }
        free_cmcl_work(w);
}

static void handle_cmcl_work_conn_tmo(struct cmcl_work *w)
{
        struct cmcl_work_con_tmo *p;

        p = w->data;
        handle_conn_tmo(p->co);
        free_cmcl_work(w);
}

static void handle_cmcl_work_disconnect(struct cmcl_work *w)
{
        struct cmcl_work_dc_disconnect *p;

        p = w->data;
        handle_internal_disconnect(p->co);
        free_cmcl_work(w);
}

static void cmcl_workq_func(struct work_struct *w)
{
        static void (*workq_func[])(struct cmcl_work *) = {
                handle_cmcl_work_create,
                handle_cmcl_work_destroy,
                handle_cmcl_work_cleanup,
                handle_cmcl_work_dc_init,
                handle_cmcl_work_dc_connect,
                handle_cmcl_work_dc_disconnect,
                handle_cmcl_work_dc_finalize,
		handle_cmcl_work_uc_connected,
		handle_cmcl_work_uc_disconnected,
                handle_cmcl_work_con_pkt,
                handle_cmcl_work_conn_tmo,
                handle_cmcl_work_disconnect,
        };
        struct cmcl_work *p;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20))
        log_w(p = container_of(w, struct cmcl_work, work));
#else
        log_w(p = (struct cmcl_work *)w);
#endif
        ERROR_ON(p->opcode >= ARRAY_SIZE(workq_func));
        workq_func[p->opcode](p);
}

static void cmcl_dc_init(struct RlnhLinkObj *co, void *lo,
			 struct RlnhLinkUCIF *uc)
{
        struct cmcl_work *w;
        struct cmcl_work_dc_init *p;

        w = alloc_cmcl_work(sizeof(*p), CMCL_WORK_DC_INIT, GFP_KERNEL);
        if (w == NULL) {
                printk(KERN_CRIT "cmcl: out-of-memory...\n");
                return;
        }
        p = w->data;
        p->co = co;
        p->lo = lo;
        p->uc = uc;
        queue_cmcl_work(w);
}

static void cmcl_dc_connect(struct RlnhLinkObj *co)
{
        struct cmcl_work *w;
        struct cmcl_work_dc_connect *p;

        w = alloc_cmcl_work(sizeof(*p), CMCL_WORK_DC_CONNECT, GFP_KERNEL);
        if (w == NULL) {
                printk(KERN_CRIT "cmcl: out-of-memory...\n");
                return;
        }
        p = w->data;
        p->co = co;
        queue_cmcl_work(w);
}

static int cmcl_dc_transmit(struct RlnhLinkObj *co, uint32_t buf_type,
			    uint32_t src, uint32_t dst,
			    uint32_t size, void *data)
{
	return co->dc->transmit(co->dco, buf_type, src, dst, size, data);
}


static void cmcl_dc_disconnect(struct RlnhLinkObj *co)
{
        struct cmcl_work *w;
        struct cmcl_work_dc_disconnect *p;

        /*
         * FIXME:
         * This function can be called from atomic context, use pre-allocated
         * memory since kmalloc can't sleep...
         *
         * Note: cmcl_disconnect and cmcl_dc_disconnect MUST NOT use
         *       the same pre-allocated memory!!!!
         */
        w = alloc_cmcl_work(sizeof(*p), CMCL_WORK_DC_DISCONNECT, GFP_ATOMIC);
        ERROR_ON(w == NULL);

        p = w->data;
        p->co = co;
        queue_cmcl_work(w);
}

static void cmcl_dc_finalize(struct RlnhLinkObj *co)
{
        struct cmcl_work *w;
        struct cmcl_work_dc_finalize *p;

        w = alloc_cmcl_work(sizeof(*p), CMCL_WORK_DC_FINALIZE, GFP_KERNEL);
        if (w == NULL) {
                printk(KERN_CRIT "cmcl: out-of-memory...\n");
                return;
        }
        p = w->data;
        p->co = co;
        queue_cmcl_work(w);
}

void cmcl_disconnect(struct RlnhLinkObj *co, int cause, int origin)
{
        struct cmcl_work *w;
        struct cmcl_work_disconnect *p;

        /*
         * FIXME:
         * This function can be called from atomic context, use pre-allocated
         * memory since kmalloc can't sleep...
         *
         * Note: cmcl_disconnect and cmcl_dc_disconnect MUST NOT use
         *       the same pre-allocated memory!!!!
         */
        w = alloc_cmcl_work(sizeof(*p), CMCL_WORK_DISCONNECT, GFP_ATOMIC);
        ERROR_ON(w == NULL);

        p = w->data;
        p->co = co;
        p->cause = cause;
        p->origin = origin;
        queue_cmcl_work(w);
}

int cmcl_uc_deliver(void *rlnh_obj, uint32_t buffer_type, uint32_t src,
		    uint32_t dst, uint32_t size, void *data)
{
	struct RlnhLinkObj *co = (struct RlnhLinkObj *)rlnh_obj;

	/* CMCL Control signalling - source is zero and destination is type */
	if (src == 0 && dst != 0)
	{
		struct cmcl_work *w;
		struct cmcl_work_con_pkt *p;

		if (buffer_type == BUFFER_TYPE_KERNEL)
			co->uc->free(co->lo, buffer_type, data);
		else
			kfree_skb(data);
		w = alloc_cmcl_work(sizeof(*p), CMCL_WORK_CON_PKT, GFP_ATOMIC);
		ERROR_ON(w == NULL);

		p = w->data;
		p->co = co;
		p->type = dst;
		queue_cmcl_work(w);
		if (co->state == STATE_CONNECTED)
		{
			deliver_packets(co);
		}
	}
	else if (co->state == STATE_CONNECTED)
	{
		deliver_packets(co);
		co->uc->deliver(co->lo, buffer_type, src, dst, size, data);
	}
	else
	{
		enqueue_packet(co, buffer_type, src, dst, size, data);
	}
	return 0;
}

void *cmcl_uc_alloc(void *rlnh_obj, uint32_t buffer_type, uint32_t size)
{
	struct RlnhLinkObj *co = (struct RlnhLinkObj *)rlnh_obj;
	return co->uc->alloc(co->lo, buffer_type, size);
}

void cmcl_uc_free(void *rlnh_obj, uint32_t buffer_type, void *ptr)
{
	struct RlnhLinkObj *co = (struct RlnhLinkObj *)rlnh_obj;
	return co->uc->free(co->lo, buffer_type, ptr);
}

void cmcl_uc_error(void *rlnh_obj, void *error_info)
{
	struct RlnhLinkObj *co = (struct RlnhLinkObj *)rlnh_obj;
	return co->uc->error(co->lo, error_info);
}

void cmcl_uc_connected(void *co)
{
        struct cmcl_work *w;
        struct cmcl_work_dc_finalize *p;

        w = alloc_cmcl_work(sizeof(*p), CMCL_WORK_UC_CONNECTED, GFP_KERNEL);
        if (w == NULL) {
                printk(KERN_CRIT "cmcl: out-of-memory...\n");
                return;
        }
        p = w->data;
        p->co = co;
        queue_cmcl_work(w);
	return;
}

void cmcl_uc_disconnected(void *co)
{
        struct cmcl_work *w;
        struct cmcl_work_uc_disconnected *p;

        w = alloc_cmcl_work(sizeof(*p), CMCL_WORK_UC_DISCONNECTED, GFP_KERNEL);
        if (w == NULL) {
                printk(KERN_CRIT "cmcl: out-of-memory...\n");
                return;
        }
        p = w->data;
        p->co = co;
        queue_cmcl_work(w);
	return;
}

void cmcl_get_con(struct RlnhLinkObj *co)
{
        atomic_inc(&co->use_count);
}

void cmcl_put_con(struct RlnhLinkObj *co)
{
        if (atomic_dec_return(&co->use_count) == 0)
                free_cmcl_con(co);
}

static void con_tmo_func(unsigned long data)
{
        struct cmcl_work *w;
        struct cmcl_work_con_tmo *p;
        struct RlnhLinkObj *co;

        co = (struct RlnhLinkObj *)data;

        w = alloc_cmcl_work(sizeof(*p), CMCL_WORK_CON_TMO, GFP_ATOMIC);
        if (w == NULL) {
                /* Must NOT restart timer here! */
                cmcl_disconnect(co, -ENOMEM, 666);
                return;
        }

        p = w->data;
        p->co = co;
        queue_cmcl_work(w);
}

static int get_dc(const void *cookie, void **dc)
{
        static struct RlnhLinkIF cmcl_dc = {
                RLNH_LINK_IF_VERSION,
                cmcl_dc_init,
                cmcl_dc_finalize,
                cmcl_dc_connect,
                cmcl_dc_disconnect,
                cmcl_dc_transmit
        };

        u64 *p;
        unsigned long ul;

        (void)cookie;

        p = kmalloc(sizeof(*p), GFP_KERNEL); /* Note: DB calls kfree! */
        if (p == NULL)
                return -ENOMEM;

        ul = (unsigned long)&cmcl_dc; /* Cast to avoid 32/64 bit trouble. */
        *p = (u64)ul;
        *dc = p;

        return (DB_TMP | DB_HEX | DB_UINT64);
}

static struct RlnhLinkUCIF cmcl_uc = {
	RLNH_LINK_UC_IF_VERSION,
	cmcl_uc_deliver,
	cmcl_uc_alloc,
	cmcl_uc_free,
	cmcl_uc_error,
	cmcl_uc_connected,
	cmcl_uc_disconnected
};

static int get_uc(const void *cookie, void **uc)
{
        u64 *p;
        unsigned long ul;

        (void)cookie;

        p = kmalloc(sizeof(*p), GFP_KERNEL); /* Note: DB calls kfree! */
        if (p == NULL)
                return -ENOMEM;

        ul = (unsigned long)&cmcl_uc; /* Cast to avoid 32/64 bit trouble. */
        *p = (u64)ul;
        *uc = p;

        return (DB_TMP | DB_HEX | DB_UINT64);
}

static struct cmcl_ioctl_create *copy_args_from_user(void __user *arg)
{
        struct cmcl_ioctl_create k, *kp;
        size_t size;

        if (copy_from_user(&k, arg, sizeof(k)) != 0)
                return ERR_PTR(-EFAULT);

        size = sizeof(*kp) + k.name_len + 1 + k.con_name_len + 1;
        kp = kzalloc(size, GFP_KERNEL);
        if (kp == NULL)
                return ERR_PTR(-ENOMEM);

        if (copy_from_user(kp, arg, size) != 0) {
                kfree(kp);
                return ERR_PTR(-EFAULT);
        }
        return kp;
}

static void *cmcl_create(void __user *arg)
{
        struct cmcl_ioctl_create *karg;
        struct cmcl_work *w;
        struct cmcl_work_create *p;
        struct RlnhLinkObj *co;
        int status;

        if (try_module_get(THIS_MODULE) == 0)
                return ERR_PTR(-EINVAL);

        karg = copy_args_from_user(arg);
        if (IS_ERR(karg)) {
                status = (int)PTR_ERR(karg);
                goto out_20;
        }

        w = alloc_cmcl_work(sizeof(*p), CMCL_WORK_CREATE, GFP_KERNEL);
        if (w == NULL) {
                status = -ENOMEM;
                goto out_10;
        }
        p = w->data;
        p->arg = karg;
        p->co = NULL;
        init_waitfor_cmcl_work(w);
        queue_cmcl_work(w);

        status = waitfor_cmcl_work(w);
        co = p->co;
        free_cmcl_work(w);
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

static int cmcl_destroy(void *cookie, void __user *arg)
{
        struct cmcl_work *w;
        struct cmcl_work_destroy *p;
        int status;

        (void)arg;

        w = alloc_cmcl_work(sizeof(*p), CMCL_WORK_DESTROY, GFP_KERNEL);
        if (w == NULL)
                return -ENOMEM;

        p = w->data;
        p->co = cookie;
        init_waitfor_cmcl_work(w);
        queue_work(cmcl_workq, &w->work);

        status = waitfor_cmcl_work(w);
        free_cmcl_work(w);
        if (status != 0)
                return status;
        module_put(THIS_MODULE);
        return 0;
}

static int __init cmcl_init(void)
{
        init_waitqueue_head(&cmcl_waitq);

        cmcl_workq = create_singlethread_workqueue("cmcl");
        if (cmcl_workq == NULL)
                return -ENOMEM;

        db_add_template(DB_KEY_CMCL, &cmcl_template);
        db_proc_add(DB_KEY_CMCL);

        return 0;
}
module_init(cmcl_init);

static void __exit cmcl_cleanup(void)
{
        db_proc_del(DB_KEY_CMCL);
        db_del_template(DB_KEY_CMCL);

        /*
         * At this point, no one is submitting jobs to the workqueue. All
         * connections are destroyed (module's use count is used to make sure
         * of this). It is safe to flush and destroy the workqueue.
         */
        flush_workqueue(cmcl_workq);
        destroy_workqueue(cmcl_workq);
}
module_exit(cmcl_cleanup);

/*
 * =============================================================================
 * Some trace functions...
 * =============================================================================
 */
#ifdef CMCL_DEBUG
static void log_w(struct cmcl_work *w)
{
        static const char *wd[] = {
                "CMCL_WORK_CREATE",
                "CMCL_WORK_DESTROY",
                "CMCL_WORK_CLEANUP",
                "CMCL_WORK_DC_INIT",
                "CMCL_WORK_DC_CONNECT",
                "CMCL_WORK_DC_DISCONNECT",
                "CMCL_WORK_DC_FINALIZE",
		"CMCL_WORK_UC_CONNECTED",
		"CMCL_WORK_UC_DISCONNECTED",
                "CMCL_WORK_CON_PKT",
                "CMCL_WORK_CON_TMO",
                "CMCL_WORK_DISCONNECT",
        };
        struct RlnhLinkObj *co;
        struct cmcl_ioctl_create *arg;
        int cause, origin, type;

        switch (w->opcode) {
        case CMCL_WORK_CREATE:
                arg = ((struct cmcl_work_create *)w->data)->arg;
                printk("%s(-): %s\n", kptr(arg, arg->name), wd[w->opcode]);
                break;
        case CMCL_WORK_DESTROY:
        case CMCL_WORK_CLEANUP:
        case CMCL_WORK_DC_INIT:
        case CMCL_WORK_DC_CONNECT:
        case CMCL_WORK_DC_DISCONNECT:
        case CMCL_WORK_DC_FINALIZE:
        case CMCL_WORK_UC_CONNECTED:
        case CMCL_WORK_UC_DISCONNECTED:
        case CMCL_WORK_CON_TMO:
                /* Hmm... co is the 1:st member in all these structs... */
                co = ((struct cmcl_work_destroy *)w->data)->co;
                printk("%s(%d): %s\n", co->name, co->state, wd[w->opcode]);
                break;
        case CMCL_WORK_DISCONNECT:
                co = ((struct cmcl_work_disconnect *)w->data)->co;
                cause = ((struct cmcl_work_disconnect *)w->data)->cause;
                origin = ((struct cmcl_work_disconnect *)w->data)->origin;
                printk("%s(%d): %s(%d, %d)\n", co->name, co->state,
                       wd[w->opcode], cause, origin);
                break;
        case CMCL_WORK_CON_PKT:
                co = ((struct cmcl_work_con_pkt *)w->data)->co;
                type = ((struct cmcl_work_con_pkt *)w->data)->type;
                printk("%s(%d): %s(%d)\n", co->name, co->state,
                       wd[w->opcode], type);
                break;
        default:
                ERROR();
                break;
        }
}
#endif
