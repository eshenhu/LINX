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

#include <linux/errno.h>
#include <linux/ethcm_db_ioctl.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/notifier.h>
#include <linux/random.h>
#include <linux/timer.h>
#include <linux/version.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include <cfg/db.h>
#include <cfg/db_proc.h>
#include <rlnh/rlnh_link.h>
#include <ecm.h>
#include <ecm_proto.h>
#include <ecm_kutils.h>

MODULE_AUTHOR("ENEA");
MODULE_DESCRIPTION("LINX Ethernet Connection Manager");
MODULE_LICENSE("GPL");
MODULE_VERSION(ECM_VERSION);

#define uptr(p, n) ((u8 __user *)(p) + (n))
#define kptr(p, n) ((u8 *)(p) + (n))

#define DC_CONN 98 /* Must not interfer with CONN_<x> in ecm_prot.h! */
#define DC_DISC 99 /* Must not interfer with CONN_<x> in ecm_prot.h! */

#define STATE_DISCONNECTED 1
#define STATE_CONNECTING_0 2
#define STATE_CONNECTING_1 3
#define STATE_CONNECTING_2 4
#define STATE_CONNECTED    5

#define ECM_RELEASE_CID_0 ((struct RlnhLinkObj *)(~0ul))
#define ECM_RELEASE_CID_1 ((struct RlnhLinkObj *)(~0ul - 1))

#define GFP_TRYHARD (__GFP_REPEAT | GFP_KERNEL) /* Ask MM to really really try! */

static void do_the_gory_stuff(struct RlnhLinkObj *co, int event);
static void conn_tmo_func(unsigned long data);

static struct workqueue_struct *ecm_workq;
static void ecm_workq_func(struct work_struct *w);

static wait_queue_head_t ecm_waitq;

static int net_event(struct notifier_block *nb, unsigned long event, void *data);
static struct notifier_block ecm_notifier = {
        .notifier_call = net_event,
};

static int get_dc(const void *cookie, void **dc);
static void *ecm_create(void __user *arg);
static int ecm_destroy(void *cookie, void __user *arg);
static const struct db_param ecm_params[] = {
        DB_PARAM("con_name", DB_PTR | DB_STRING, con_name, struct RlnhLinkObj),
        DB_PARAM("con_cookie", DB_HEX | DB_UINT64, con_cookie, struct RlnhLinkObj),
        DB_META_PARAM("con_dc", DB_HEX | DB_UINT64, sizeof(u64), 1, get_dc, NULL),
        DB_PARAM("device", DB_PTR | DB_STRING, dev_name, struct RlnhLinkObj),
        DB_PARAM_ARR("peer_mac", DB_HEX | DB_UINT8, peer_mac, struct RlnhLinkObj),
        DB_PARAM("peer_cid", DB_INT, peer_cid, struct RlnhLinkObj),
	DB_PARAM("peer_coreid", DB_INT, peer_coreid, struct RlnhLinkObj),
        DB_PARAM("cid", DB_INT, cid, struct RlnhLinkObj),
        DB_PARAM("user_mtu", DB_INT, user_mtu, struct RlnhLinkObj),
        DB_PARAM("data_len", DB_INT, data_len, struct RlnhLinkObj),
        DB_PARAM("conn_tmo", DB_UINT, conn_tmo, struct RlnhLinkObj),
        DB_PARAM("version", DB_INT, peer_version, struct RlnhLinkObj),
        DB_PARAM("state", DB_INT, state, struct RlnhLinkObj),
        DB_PARAM("deferred_queue_size", DB_UINT32, tx_def_queue_max_size,
                 struct RlnhLinkObj),
        DB_PARAM("sliding_window_preferred_size", DB_UINT32, preferred_wsize, struct RlnhLinkObj),
        DB_PARAM("sliding_window_size", DB_UINT32, wsize, struct RlnhLinkObj),

        DB_PARAM("pkts_recv_queue", DB_UINT32, rx_queue_size, struct RlnhLinkObj),
        DB_PARAM("pkts_send_queue", DB_UINT32, tx_queue_size, struct RlnhLinkObj),
        DB_PARAM("pkts_deferred_queue", DB_UINT32, tx_def_queue_size,
                 struct RlnhLinkObj),
        DB_PARAM("sent_packets", DB_ULONG, tx_packets, struct RlnhLinkObj),
        DB_PARAM("sent_bytes", DB_ULONG, tx_bytes, struct RlnhLinkObj),
        DB_PARAM("recv_packets", DB_ULONG, rx_packets, struct RlnhLinkObj),
        DB_PARAM("recv_bytes", DB_ULONG, rx_bytes, struct RlnhLinkObj),
        DB_PARAM("resent_packets", DB_ULONG, tx_resent_packets, struct RlnhLinkObj),
        DB_PARAM("resent_bytes", DB_ULONG, tx_resent_bytes, struct RlnhLinkObj),
        DB_PARAM("sent_nacks", DB_ULONG, rx_nacks, struct RlnhLinkObj),
        DB_PARAM("num_connects", DB_ULONG, num_connections, struct RlnhLinkObj),
	DB_PARAM("bad_packets", DB_ULONG, bad_packets, struct RlnhLinkObj),
	
        DB_PARAM_END
};
static const struct db_template ecm_template = {
        .owner = THIS_MODULE,
        .create = ecm_create,
        .destroy = ecm_destroy,
        .param = ecm_params
};

static struct list_head ecm_device_list; /* Registered network devices. */
static struct list_head ecm_orphan_list; /* CO not assigned to a network device. */

static DEFINE_SPINLOCK(ecm_lock); /* The one and only... */
static struct RlnhLinkObj *ecm_connection_array[256];
struct timer_list ecm_release_cid_timer;

#define ECM_WORK_NET_EVENT 1
struct ecm_work_net_event {
        unsigned long event;
        struct net_device *dev;
        struct ecm_device *ecm_dev; /* Only for NETDEV_REGISTER... */
};

#define ECM_WORK_DC_INIT 2
struct ecm_work_dc_init {
        struct RlnhLinkObj *co;
        void *lo;
        struct RlnhLinkUCIF *uc;
};

#define ECM_WORK_DC_FINI 3
struct ecm_work_dc_fini {
        struct RlnhLinkObj *co;
};

#define ECM_WORK_DC_CONN 4
struct ecm_work_dc_conn {
        struct RlnhLinkObj *co;
};

#define ECM_WORK_DC_DISC 5
/* use struct ecm_work_disc */

#define ECM_WORK_CREATE 6
struct ecm_work_create {
        struct ethcm_ioctl_create *arg;
        struct RlnhLinkObj *co;
};

#define ECM_WORK_DESTROY 7
struct ecm_work_destroy {
        struct RlnhLinkObj *co;
        int status;
};

#define ECM_WORK_CONN_TMO 8
struct ecm_work_conn_tmo {
        struct RlnhLinkObj *co;
};

#define ECM_WORK_CONN_PKT 11
struct ecm_work_conn_pkt {
        struct RlnhLinkObj *co;
        struct net_device *dev;
        struct sk_buff *skb;
};

#define ECM_WORK_DISC 12
struct ecm_work_disc {
        struct RlnhLinkObj *co;
};

#define ECM_WORK_CLEANUP 13
/* use struct ecm_work_destroy */

struct ecm_work {
        int opcode;
        struct work_struct work;
        void *data;
};

#define tmo_ms(ms) (jiffies + msecs_to_jiffies(ms))

static unsigned long tmo_ms_rand(unsigned int ms)
{
        signed char c;

        get_random_bytes(&c, sizeof(c)); /* [-128, 127] */
        return ((int)ms + c > 1) ? tmo_ms(ms + c) : tmo_ms(1);
}

static void setup_ecm_work(struct ecm_work *w, void *p, int opcode)
{
        w->opcode = opcode;
        w->data = p;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20))
        INIT_WORK(&w->work, ecm_workq_func);
#else
        INIT_WORK(&w->work, (void (*)(void *))ecm_workq_func, w);
#endif
}

static struct ecm_work *alloc_ecm_work(size_t size, int opcode, gfp_t flags)
{
        struct ecm_work *w;
        void *p;

        w = kmalloc(sizeof(*w), flags);
        if (w == NULL)
                return NULL;
        p = kmalloc(size, flags);
        if (p == NULL) {
                kfree(w);
                return NULL;
        }
        setup_ecm_work(w, p, opcode);
        return w;
}

static void free_ecm_work(struct ecm_work *w)
{
        if (w != NULL) {
                if (w->data != NULL)
                        kfree(w->data);
                kfree(w);
        }
}

static struct ecm_work *seize_ecm_work_disc(struct RlnhLinkObj *co, int opcode)
{
        struct ecm_work *w;
        int k;

        k = atomic_xchg(&co->disc_count, 0);
        if (k == 0)
                return NULL; /* Disconnect in progess... */

        w = co->w_disc;
        co->w_disc = NULL; /* Re-install it when the work is done. */
        w->opcode = opcode;

        return w;
}

static struct ecm_device *lookup_ecm_device_by_net(struct net_device *dev)
{
        struct ecm_device *p;
        struct list_head *item;

        list_for_each(item, &ecm_device_list) {
                p = list_entry(item, struct ecm_device, node);
                if (p->dev == dev)
                        return p;
        }
        return NULL;
}

static struct ecm_device *lookup_ecm_device_by_name(const char *name)
{
        struct ecm_device *p;
        struct list_head *item;

        list_for_each(item, &ecm_device_list) {
                p = list_entry(item, struct ecm_device, node);
                if (strcmp(name, p->dev->name) == 0)
                        return p;
        }
        return NULL;
}

static struct ecm_device *alloc_ecm_device(struct net_device *dev)
{
        struct ecm_device *p;

        p = kmalloc(sizeof(*p), GFP_KERNEL);
        if (p == NULL)
                return NULL;

        INIT_LIST_HEAD(&p->node);
        INIT_LIST_HEAD(&p->conn_list);
        p->dev = dev;
        p->pt.type = __constant_htons(ECM_PROTOCOL);
        p->pt.dev = dev;
        p->pt.func = ecm_rx;
        p->pt.af_packet_priv = p;
        INIT_LIST_HEAD(&p->pt.list);

        dev_hold(dev); /* dev_put() is done in free_ecm_device(). */
        return p;
}

static void free_ecm_device(struct ecm_device *p)
{
        /*
         * Release struct net_device object, make sure that stop_ecm_device()
         * has been called first!
         */
        dev_put(p->dev);

        memset(p, 0, sizeof(*p));
        kfree(p);
}

static void start_ecm_device(struct ecm_device *p)
{
        struct list_head *item;
        struct RlnhLinkObj *co;

        list_add(&p->node, &ecm_device_list);

        /*
         * Reset transmit lock, i.e. allow TX to use the struct net_device
         * object. RX won't get any LINX packets and destroy-work makes
         * the connection in-visible, i.e. no lock is needed.
         */
        list_for_each(item, &p->conn_list) {
                co = list_entry(item, struct RlnhLinkObj, node);
                reset_ecm_lock(&co->tx_lock, 1);
        }

        /* RX callback will get LINX packets... */
        dev_add_pack(&p->pt);
}

static void stop_ecm_device(struct ecm_device *p)
{
        struct list_head *item;
        struct RlnhLinkObj *co;

        /*
         * After dev_remove_pack() returns no CPU is looking at the LINX packet
         * type, i.e. RX callback is not running and will not run on any CPU.
         */
        dev_remove_pack(&p->pt);

        /*
         * Shut-out TX and wait until all users inside the transmit region are
         * done, i.e. no TX will use struct net_dev object.
         */
        list_for_each(item, &p->conn_list) {
                co = list_entry(item, struct RlnhLinkObj, node);
                synchronize_ecm_lock(&co->tx_lock);
        }

        list_del(&p->node);
}

static void handle_netdev_register(struct net_device *dev,
                                   struct ecm_device *ecm_dev)
{
        struct list_head *item, *tmp;
        struct RlnhLinkObj *co;

        /*
         * Any orphan connections? Move them to device's conn list before
         * starting the device. No conn_list lock is needed since RX won't
         * get any Linx packet, i.e. dev_add_pack hasn't been called.
         */
        list_for_each_safe(item, tmp, &ecm_orphan_list) {
                co = list_entry(item, struct RlnhLinkObj, node);
                if (strcmp(co->dev_name, ecm_dev->dev->name) == 0) {
                        co->ecm_dev = ecm_dev;
                        list_move_tail(&co->node, &ecm_dev->conn_list);
                }
        }

        /* Enable RX and TX... */
        start_ecm_device(ecm_dev);
}

static void handle_netdev_unregister(struct net_device *dev)
{
        struct ecm_device *p;
        struct list_head *item, *tmp;
        struct RlnhLinkObj *co;

        p = lookup_ecm_device_by_net(dev);
        if (p == NULL)
                return; /* No such device! */

        /* Disable RX and TX... */
        stop_ecm_device(p);

        /*
         * Move connections to orphan list. RX has been shut-down,
         * i.e. dev_remove_pack has been called, and destroy-work makes
         * it in-visible, i.e. no lock is needed.
         */
        list_for_each_safe(item, tmp, &p->conn_list) {
                co = list_entry(item, struct RlnhLinkObj, node);
                co->ecm_dev = NULL; /* A must or terrible things may happen. */
                list_move_tail(&co->node, &ecm_orphan_list);
        }

        free_ecm_device(p);
}

static void handle_netdev_down(struct net_device *dev)
{
        struct ecm_device *p;
        struct list_head *item;
        struct RlnhLinkObj *co;

        p = lookup_ecm_device_by_net(dev);
        if (p == NULL)
                return; /* No such device! */

        /*
         * Network is down, start disconnecting. RX doesn't delete any conn_list
         * items and destroy-work makes it in-visible, i.e no lock is needed.
         */
        list_for_each(item, &p->conn_list) {
                co = list_entry(item, struct RlnhLinkObj, node);
                do_the_gory_stuff(co, CONN_RESET);
        }
}

static void report_netdev_unsupported(struct net_device *dev, const char *s)
{
        struct ecm_device *p;
        struct list_head *item;
        struct RlnhLinkObj *co;

        p = lookup_ecm_device_by_net(dev);
        if (p == NULL)
                return; /* No such device! */

        /*
         * RX doesn't delete any conn_list items and destroy-work makes it
         * in-visible, i.e no lock is needed.
         */
        list_for_each(item, &p->conn_list) {
                co = list_entry(item, struct RlnhLinkObj, node);
                printk(KERN_ERR "LINX connection %s got unsupported event %s,\n"
                       "connection behaviour is undefined!\n", co->con_name, s);
        }
}

static void handle_work_net_event(struct ecm_work *w)
{
        struct ecm_work_net_event *p;

        p = w->data;

        switch (p->event) {
        case NETDEV_REGISTER:
                handle_netdev_register(p->dev, p->ecm_dev);
                break;
        case NETDEV_UNREGISTER:
                handle_netdev_unregister(p->dev);
                break;
        case NETDEV_UP:
                break; /* CONN_TMO takes care of this... */
        case NETDEV_DOWN:
                handle_netdev_down(p->dev);
                break;
        case NETDEV_CHANGEMTU:
                report_netdev_unsupported(p->dev, "NETDEV_CHANGEMTU");
                break;
        case NETDEV_CHANGEADDR:
                report_netdev_unsupported(p->dev, "NETDEV_CHANGEADDR");
                break;
        case NETDEV_CHANGENAME:
                report_netdev_unsupported(p->dev, "NETDEV_CHANGENAME");
                break;
        default:
                /*
                 * Silently ignore all other events, e.g. NETDEV_CHANGE,
                 * NETDEV_FEAT_CHANGE, NETDEV_GOING_DOWN and NETDEV_REBOOT.
                 */
                break;
        }

        free_ecm_work(w);
}

static void send_ecm_conn_pkt(struct RlnhLinkObj *co, int type)
{
        /*
         * If a driver is unloaded, the "normal" job sequence looks like this:
         *
         *    handle_netdev_down
         *    handle_dc_conn (re-connect)
         *    handle_netdev_unregister
         *
         * However, it's possible that handle_netdev_unregister is run before
         * handle_dc_conn (due to RLNH timing). If that happens, handle_dc_conn
         * will re-enable transmit, which may cause a NULL pointer access.
         *
         * Instead of adding net-states to the state-machine (x2) or changing
         * the connection timer behavior, this innocent if-statement is added.
         * Also, why bloat the state-machine to prevent something that probably
         * never will happen...
         */
        if (co->ecm_dev != NULL)
                ecm_send_conn_pkt(co, GFP_KERNEL, type);
}

static int ecm_conn_dead(struct RlnhLinkObj *co)
{
        return atomic_dec_and_test(&co->conn_alive_count);
}

static void handle_dc_conn(struct RlnhLinkObj *co)
{
        switch (co->state) {
        case STATE_DISCONNECTED:
                ecm_start_rx(co);
                ecm_start_tx(co);
                reset_ecm_lock(&co->tx_lock, 1); /* Allow transmit. */
                co->state = STATE_CONNECTING_0;
                break;
        default:
                /* STATE_CONNECTING_0, _1, _2 and STATE_CONNECTED. */
                ERROR();
                break;
        }
}

static void handle_dc_disc(struct RlnhLinkObj *co)
{
        switch (co->state) {
        case STATE_DISCONNECTED:
                break; /* Sit tight, disconnected already called... */
        case STATE_CONNECTING_0:
        case STATE_CONNECTING_1:
        case STATE_CONNECTING_2:
                co->uc->disconnected(co->lo);
                ecm_stop_rx(co);
                ecm_stop_tx(co);
                co->state = STATE_DISCONNECTED;
                break;
        case STATE_CONNECTED:
                send_ecm_conn_pkt(co, CONN_RESET);
                synchronize_ecm_lock(&co->rx_lock);
                synchronize_ecm_lock(&co->tx_lock);
                co->uc->disconnected(co->lo);
                ecm_stop_rx(co);
                ecm_stop_tx(co);
                co->state = STATE_DISCONNECTED;
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
                co->next_conn_tmo = tmo_ms_rand(co->conn_tmo);
                break; /* Sit tight, await downcall connect. */
        case STATE_CONNECTING_0:
                send_ecm_conn_pkt(co, CONN_CONNECT);
                co->next_conn_tmo = tmo_ms_rand(co->conn_tmo);
                co->state = STATE_CONNECTING_1;
                break;
        case STATE_CONNECTING_1:
        case STATE_CONNECTING_2:
                send_ecm_conn_pkt(co, CONN_RESET);
                co->next_conn_tmo = tmo_ms_rand(co->conn_tmo);
                co->state = STATE_CONNECTING_0;
                break;
        case STATE_CONNECTED:
                if (ecm_conn_dead(co)) {
                        send_ecm_conn_pkt(co, CONN_RESET);
                        synchronize_ecm_lock(&co->rx_lock);
                        synchronize_ecm_lock(&co->tx_lock);
                        co->uc->disconnected(co->lo);
                        ecm_stop_rx(co);
                        ecm_stop_tx(co);
                        co->next_conn_tmo = tmo_ms_rand(co->conn_tmo);
                        co->state = STATE_DISCONNECTED;
                } else {
                        ecm_send_ack(co, GFP_KERNEL, REQUEST_ACK);
                        co->next_conn_tmo = tmo_ms(co->conn_tmo);
                }
                break;
        default:
                ERROR();
                break;
        }

        /* Make sure that the timer isn't restarted after a del_timer_sync(). */
        if (atomic_read(&co->conn_timer_lock) != 0)
                mod_timer(&co->conn_timer, co->next_conn_tmo);
}

static void handle_conn_connect(struct RlnhLinkObj *co)
{
        switch (co->state) {
        case STATE_DISCONNECTED:
                break; /* Sit tight, await downcall connect. */
        case STATE_CONNECTING_0:
                send_ecm_conn_pkt(co, CONN_CONNECT_ACK);
                co->state = STATE_CONNECTING_2;
                break;
        case STATE_CONNECTING_1:
        case STATE_CONNECTING_2:
                send_ecm_conn_pkt(co, CONN_RESET);
                co->state = STATE_CONNECTING_0;
                break;
        case STATE_CONNECTED:
                send_ecm_conn_pkt(co, CONN_RESET);
                synchronize_ecm_lock(&co->rx_lock);
                synchronize_ecm_lock(&co->tx_lock);
                co->uc->disconnected(co->lo);
                ecm_stop_rx(co);
                ecm_stop_tx(co);
                co->state = STATE_DISCONNECTED;
                break;
        default:
                ERROR();
                break;
        }
}

static void handle_conn_connect_ack(struct RlnhLinkObj *co)
{
        switch (co->state) {
        case STATE_DISCONNECTED:
                break; /* Sit tight, await downcall connect. */
        case STATE_CONNECTING_1:
                send_ecm_conn_pkt(co, CONN_ACK);
                ecm_mark_conn_alive(co);
                co->num_connections++;
                co->uc->connected(co->lo);
                reset_ecm_lock(&co->rx_lock, 1); /* Allow upcall deliver. */
                co->state = STATE_CONNECTED;
                break;
        case STATE_CONNECTING_0:
        case STATE_CONNECTING_2:
                send_ecm_conn_pkt(co, CONN_RESET);
                co->state = STATE_CONNECTING_0;
                break;
        case STATE_CONNECTED:
                send_ecm_conn_pkt(co, CONN_RESET);
                synchronize_ecm_lock(&co->rx_lock);
                synchronize_ecm_lock(&co->tx_lock);
                co->uc->disconnected(co->lo);
                ecm_stop_rx(co);
                ecm_stop_tx(co);
                co->state = STATE_DISCONNECTED;
                break;
        default:
                ERROR();
                break;
        }
}

static void handle_conn_ack(struct RlnhLinkObj *co)
{
        switch (co->state) {
        case STATE_DISCONNECTED:
                break; /* Sit tight, await downcall connect. */
        case STATE_CONNECTING_0:
        case STATE_CONNECTING_1:
                send_ecm_conn_pkt(co, CONN_RESET);
                co->state = STATE_CONNECTING_0;
                break;
        case STATE_CONNECTING_2:
                ecm_mark_conn_alive(co);
                co->num_connections++;
                co->uc->connected(co->lo);
                reset_ecm_lock(&co->rx_lock, 1); /* Allow upcall deliver. */
                co->state = STATE_CONNECTED;
                break;
        case STATE_CONNECTED:
                send_ecm_conn_pkt(co, CONN_RESET);
                synchronize_ecm_lock(&co->rx_lock);
                synchronize_ecm_lock(&co->tx_lock);
                co->uc->disconnected(co->lo);
                ecm_stop_rx(co);
                ecm_stop_tx(co);
                co->state = STATE_DISCONNECTED;
                break;
        default:
                ERROR();
                break;
        }
}

static void handle_conn_reset(struct RlnhLinkObj *co)
{
        switch (co->state) {
        case STATE_DISCONNECTED:
                break; /* Sit tight, await downcall connect. */
        case STATE_CONNECTING_0:
        case STATE_CONNECTING_1:
        case STATE_CONNECTING_2:
                co->state = STATE_CONNECTING_0;
                break;
        case STATE_CONNECTED:
                synchronize_ecm_lock(&co->rx_lock);
                synchronize_ecm_lock(&co->tx_lock);
                co->uc->disconnected(co->lo);
                ecm_stop_rx(co);
                ecm_stop_tx(co);
                co->state = STATE_DISCONNECTED;
                break;
        default:
                ERROR();
                break;
        }
}

static void do_the_gory_stuff(struct RlnhLinkObj *co, int event)
{
        switch (event) {
        case CONN_CONNECT:
                handle_conn_connect(co);
                break;
        case CONN_CONNECT_ACK:
                handle_conn_connect_ack(co);
                break;
        case CONN_ACK:
                handle_conn_ack(co);
                break;
        case CONN_RESET:
                handle_conn_reset(co);
                break;
        case CONN_TMO:
                handle_conn_tmo(co);
                break;
        case DC_CONN:
                handle_dc_conn(co);
                break;
        case DC_DISC:
                handle_dc_disc(co);
                break;
        default:
                ERROR();
                break;
        }
}

static int extract_ecm_features(struct RlnhLinkObj *co, uint32_t *data)
{
        uint32_t main_hdr;
        uint32_t conn_hdr;
        int mtu;
        char *features;

        main_hdr = ntoh_unaligned(data, MAIN_HDR_OFFSET);
        conn_hdr = ntoh_unaligned(data, CONN_HDR_OFFSET);

        switch (get_conn_type(conn_hdr)) {
        case CONN_CONNECT_ACK:
        case CONN_ACK:
                features = (char *)get_feat_str((uint8_t *)data);
                /* MTU is the only feature, so let's keep it simple... */
                if (strncmp(features, "mtu:", 4) == 0) {
                        mtu = (int)simple_strtoul(features + 4, NULL, 0);
                        if (mtu <= MAX_HDR_SIZE)
                                return -EINVAL;
                        if (mtu <= co->data_len) {
                                co->data_len = mtu;
				co->udata_len = co->data_len - UDATA_HSIZE;
				co->frag_len = co->data_len - FRAG_HSIZE;
			}
                }
                return 0;
        default:
                return 0;
        }
}

static void update_ecm_features(struct RlnhLinkObj *co)
{
        sprintf(co->features, "mtu:%d", co->data_len);
        co->features_len = strlen(co->features);
}

static int select_ecm_mtu(struct RlnhLinkObj *co)
{
        int dev_mtu;

        /* If we can't get it from the device, use max payload. */
        dev_mtu = (co->ecm_dev != NULL) ? co->ecm_dev->dev->mtu : ETH_DATA_LEN;

        if (co->user_mtu == 0) {
                /* User's MTU is don't care, always request device MTU. */
                return dev_mtu;
        } else {
                /* Request user's MTU, if the device allows it. */
                return (co->user_mtu < dev_mtu) ? co->user_mtu : dev_mtu;
        }
}

#define ECM_PROTO_ILLEGAL 0
#define ECM_PROTO_V2 2
#define ECM_PROTO_GT_V2 3

static int check_protocol_version(int v)
{
        if (v == 2)
                return ECM_PROTO_V2;
        else if ((v > 2) && (v <= ECM_PROTOCOL_VERSION))
                return ECM_PROTO_GT_V2;
        else
                return ECM_PROTO_ILLEGAL;
}

static void handle_work_conn_pkt(struct ecm_work *w)
{
        struct ecm_work_conn_pkt *p;
        uint32_t *data;
        uint32_t main_hdr;
        uint32_t conn_hdr;
        int peer_version;
        int peer_wsize;

        p = w->data;
        data = (uint32_t *)p->skb->data;
        main_hdr = ntoh_unaligned(data, MAIN_HDR_OFFSET);
        conn_hdr = ntoh_unaligned(data, CONN_HDR_OFFSET);
        peer_version = get_ver(main_hdr);

        switch (check_protocol_version(peer_version)) {
        case ECM_PROTO_GT_V2:
                /* >2 supports features, otherwise same as V2! */
                if (extract_ecm_features(p->co, data) != 0) {
                        /* CONN_TMO takes care of the rest... */
                        kfree_skb(p->skb);
                        break;
                } /* Fall through! */
        case ECM_PROTO_V2:
                /*
                 * Hmm, this is a little ugly. It's enough to set it once,
                 * but it's hard to find the right spot...
                 */
                p->co->peer_version = peer_version;
                p->co->peer_cid = get_publish_conn_id(conn_hdr);
                peer_wsize = 1 << get_window_size(conn_hdr);
                p->co->wsize = min(peer_wsize, p->co->preferred_wsize);

                do_the_gory_stuff(p->co, get_conn_type(conn_hdr));
                kfree_skb(p->skb);
                break;
        default:
                /* CONN_TMO takes care of the rest... */
                kfree_skb(p->skb);
                break;
        }

        free_ecm_work(w);
}

static void handle_work_conn_tmo(struct ecm_work *w)
{
        struct ecm_work_conn_tmo *p;

        p = w->data;
        do_the_gory_stuff(p->co, CONN_TMO);
        free_ecm_work(w);
}

static void free_ecm_connection(struct RlnhLinkObj *co)
{
        /* Undo alloc_ecm_connection(). */
        if (co != NULL) {
                if (co->con_name != NULL)
                        kfree(co->con_name);
                if (co->dev_name != NULL)
                        kfree(co->dev_name);
                if (co->features != NULL)
                        kfree(co->features);
                if (co->w_disc != NULL)
                        free_ecm_work(co->w_disc);
                memset(co, 0, sizeof(*co));
                kfree(co);
        }
}

static struct RlnhLinkObj *alloc_ecm_connection(struct ethcm_ioctl_create *arg)
{
        struct RlnhLinkObj *co;
        size_t size;

        co = kzalloc(sizeof(*co), GFP_KERNEL);
        if (co == NULL)
                return NULL;
        atomic_set(&co->use_count, 1);

        size = strlen((char *)kptr(arg, arg->name)) + 1;
        co->con_name = kzalloc(size, GFP_KERNEL);
        if (co->con_name == NULL)
                goto out;

        size = strlen((char *)kptr(arg, arg->dev)) + 1;
        co->dev_name = kzalloc(size, GFP_KERNEL);
        if (co->dev_name == NULL)
                goto out;

        co->features = kzalloc(32, GFP_KERNEL); /* Only MTU, keep it simple! */
        if (co->features == NULL)
                goto out;

        /* Pre-allocate memory for ECM disconnect jobs. */
        size = sizeof(struct ecm_work_disc);
        co->w_disc = alloc_ecm_work(size, 0, GFP_KERNEL);
        if (co->w_disc == NULL)
                goto out;
        atomic_set(&co->disc_count, 1);

        return co;
  out:
        free_ecm_connection(co);
        return NULL;
}

static int init_ecm_connection(struct RlnhLinkObj *co, struct ethcm_ioctl_create *arg)
{
        unsigned long ul;

        co->state = STATE_DISCONNECTED;
        INIT_LIST_HEAD(&co->node);
        ul = (unsigned long)co; /* Do a cast to avoid 64/32 bit problems. */
        co->con_cookie = (uint64_t)ul;
        co->peer_version = ECM_PROTOCOL_VERSION;
        co->conn_tmo = (arg->conn_tmo == 0) ?
	   1000 / ECM_ACKR_PER_TMO : arg->conn_tmo / ECM_ACKR_PER_TMO;
        memcpy(co->peer_mac, arg->mac, sizeof(co->peer_mac));

        strcpy(co->con_name, (char *)kptr(arg, arg->name));
        strcpy(co->dev_name, (char *)kptr(arg, arg->dev));
        strcpy(co->features, "");
        co->features_len = strlen(co->features);

        co->ecm_dev = lookup_ecm_device_by_name(co->dev_name);
        if (co->ecm_dev == NULL)
                return -ENODEV;

        co->user_mtu = arg->mtu;
        co->peer_coreid = arg->coreid;
	
        if (co->peer_coreid != -1)
        {
            co->data_len = select_ecm_mtu(co) - HDR_MULTICORE_SIZE;
	    co->mhdr_len = HDR_MULTICORE_SIZE;
	}
        else
        {
            co->data_len = select_ecm_mtu(co);
	    co->mhdr_len = 0;
        }
	
        co->udata_len = co->data_len - UDATA_HSIZE;
        co->frag_len = co->data_len - FRAG_HSIZE;
        update_ecm_features(co);

        setup_timer(&co->conn_timer, conn_tmo_func, (unsigned long)co);
        co->next_conn_tmo = tmo_ms_rand(co->conn_tmo);
        atomic_set(&co->conn_alive_count, 0);

        co->preferred_wsize = (arg->window_size == 0) ?
                WINDOW_SIZE : arg->window_size;
        co->tx_def_queue_max_size = (arg->defer_queue_size == 0) ?
                DEFERRED_QUEUE_SIZE : arg->defer_queue_size;

        init_ecm_lock(&co->tx_lock, 0); /* Block transmit. */
        init_ecm_lock(&co->rx_lock, 0); /* Block deliver of user data. */
        init_ecm_lock(&co->conn_rx_lock, 1); /* Allow deliver of conn pkts. */

        return 0;
}

struct RlnhLinkObj *get_ecm_connection(unsigned int cid, uint8_t *mac,
                                       struct ecm_device *dev, int peer_coreid)
{
        struct RlnhLinkObj *co;
        struct list_head *item;

        spin_lock_bh(&ecm_lock);
        co = ecm_connection_array[cid];
        if (unlikely(co == ECM_RELEASE_CID_0 || co == ECM_RELEASE_CID_1)) {
                spin_unlock_bh(&ecm_lock);
                return NULL;
        }
        if (likely(co != NULL)) {
                atomic_inc(&co->use_count);
                spin_unlock_bh(&ecm_lock);
                return co;
        }
        list_for_each(item, &dev->conn_list) {
                co = list_entry(item, struct RlnhLinkObj, node);
                if ((memcmp(co->peer_mac, mac, ETH_ALEN) == 0) && 
                    (co->peer_coreid == peer_coreid) ) {
                        atomic_inc(&co->use_count);
                        spin_unlock_bh(&ecm_lock);
                        return co;
                }
        }
        spin_unlock_bh(&ecm_lock);
        return NULL;
}

void put_ecm_connection(struct RlnhLinkObj *co)
{
        spin_lock_bh(&ecm_lock);
        if (unlikely(0 == atomic_dec_return(&co->use_count))) {
                spin_unlock_bh(&ecm_lock);
                free_ecm_connection(co);
                return;
        }
        spin_unlock_bh(&ecm_lock);
}

/* Make connection visible... (called from create) */
static void add_ecm_connection(struct RlnhLinkObj *co)
{
        int n;

        co->cid = 0;
        spin_lock_bh(&ecm_lock);
        for (n = 1; n < 256; n++) {
                if (ecm_connection_array[n] == NULL) {
                        ecm_connection_array[n] = co;
                        co->cid = n;
                        break;
                }
        }
        list_add_tail(&co->node, &co->ecm_dev->conn_list);
        spin_unlock_bh(&ecm_lock);
}

/* Make connection in-visible... (called from destroy) */
static void del_ecm_connection(struct RlnhLinkObj *co)
{
        int n;

        spin_lock_bh(&ecm_lock);
        for (n = 1; n < 256; n++) {
                if (ecm_connection_array[n] == co) {
                        ecm_connection_array[n] = ECM_RELEASE_CID_0;
                        break;
                }
        }
        list_del(&co->node);
        spin_unlock_bh(&ecm_lock);
}

static void ecm_release_cid(unsigned long arg)
{
        int n;

        (void)arg;

        spin_lock_bh(&ecm_lock);
        for (n = 1; n < 256; n++) {
                if (ecm_connection_array[n] == ECM_RELEASE_CID_1)
                        ecm_connection_array[n] = NULL;
                else if (ecm_connection_array[n] == ECM_RELEASE_CID_0)
                        ecm_connection_array[n] = ECM_RELEASE_CID_1;
        }
        spin_unlock_bh(&ecm_lock);

        /* restart timer */
        mod_timer(&ecm_release_cid_timer, tmo_ms(5000));
}

static void handle_work_create(struct ecm_work *w)
{
        struct ecm_work_create *p;
        struct RlnhLinkObj *co;
        int status;

        p = w->data;

        co = alloc_ecm_connection(p->arg);
        if (co == NULL) {
                co = ERR_PTR(-ENOMEM);
                goto out;
        }
        status = init_ecm_connection(co, p->arg);
        if (status < 0) {
                free_ecm_connection(co);
                co = ERR_PTR((long)status);
                goto out;
        }
        add_ecm_connection(co);

        /* Kick things off... */
        atomic_set(&co->conn_timer_lock, 1);
        mod_timer(&co->conn_timer, co->next_conn_tmo);
  out:
        /* Now it's safe to wake up submitter (waitfor p->co != NULL) */
        p->co = co;
        wake_up(&ecm_waitq);
}

static void handle_work_destroy(struct ecm_work *w)
{
        struct ecm_work_destroy *p;

        p = w->data;
        /*
         * The destroy work is divided in two parts:
         *
         * Last chance stop users from submitting any more jobs for this
         * connection. The cleanup work must be the last job for this
         * connection.
         */
        atomic_set(&p->co->conn_timer_lock, 0);
        del_timer_sync(&p->co->conn_timer);
        synchronize_ecm_lock(&p->co->conn_rx_lock);
        del_ecm_connection(p->co);

        /*
         * Re-submit the destroy work, this allows any jobs already in
         * the workqueue to finish before the connection is destroyed.
         *
         * Note: must re-use struct ecm_work, ecm_destroy() waits on
         *       status variable...
         */
        setup_ecm_work(w, p, ECM_WORK_CLEANUP);
        queue_work(ecm_workq, &w->work);
}

static void handle_work_cleanup(struct ecm_work *w)
{
        struct ecm_work_destroy *p;

        p = w->data;
        put_ecm_connection(p->co);

        /* Now it's safe to wake up submitter. */
        p->status = 0;
        wake_up(&ecm_waitq);
}

static void handle_work_dc_init(struct ecm_work *w)
{
        struct ecm_work_dc_init *p;

        p = w->data;
        p->co->lo = p->lo;
        p->co->uc = p->uc;
        free_ecm_work(w);
}

static void handle_work_dc_fini(struct ecm_work *w)
{
        free_ecm_work(w);
}

static void handle_work_dc_conn(struct ecm_work *w)
{
        struct ecm_work_dc_conn *p;

        p = w->data;
        atomic_set(&p->co->disc_count, 1); /* Allow one disconnect. */
        do_the_gory_stuff(p->co, DC_CONN);
        free_ecm_work(w);
}

static void handle_work_dc_disc(struct ecm_work *w)
{
        struct ecm_work_disc *p;

        p = w->data;
        do_the_gory_stuff(p->co, DC_DISC);
        p->co->w_disc = w; /* Re-use pre-allocated memory. */
}

static void handle_work_disc(struct ecm_work *w)
{
        struct ecm_work_disc *p;

        p = w->data;
        do_the_gory_stuff(p->co, CONN_RESET); /* Internal disconnect. */
        p->co->w_disc = w; /* Re-use pre-allocated memory. */
}

#ifndef log_ecm_work
#define log_ecm_work(x) (x)
#endif

static void ecm_workq_func(struct work_struct *w)
{
        struct ecm_work *p;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20))
        log_ecm_work(p = container_of(w, struct ecm_work, work));
#else
        log_ecm_work(p = (struct ecm_work *)w);
#endif

        switch (p->opcode) {
        case ECM_WORK_CONN_TMO:
                handle_work_conn_tmo(p);
                break;
        case ECM_WORK_CONN_PKT:
                handle_work_conn_pkt(p);
                break;
        case ECM_WORK_NET_EVENT:
                handle_work_net_event(p);
                break;
        case ECM_WORK_CREATE:
                handle_work_create(p);
                break;
        case ECM_WORK_DESTROY:
                handle_work_destroy(p);
                break;
        case ECM_WORK_CLEANUP:
                handle_work_cleanup(p);
                break;
        case ECM_WORK_DC_INIT:
                handle_work_dc_init(p);
                break;
        case ECM_WORK_DC_FINI:
                handle_work_dc_fini(p);
                break;
        case ECM_WORK_DC_CONN:
                handle_work_dc_conn(p);
                break;
        case ECM_WORK_DC_DISC:
                handle_work_dc_disc(p);
                break;
        case ECM_WORK_DISC:
                handle_work_disc(p);
                break;
        default:
                ERROR(); /* FIXME: just for now... */
                free_ecm_work(p);
                break;
        }
}

static void conn_tmo_func(unsigned long data)
{
        struct ecm_work *w;
        struct ecm_work_conn_tmo *p;
        struct RlnhLinkObj *co;

        co = (struct RlnhLinkObj *)data;

        w = alloc_ecm_work(sizeof(*p), ECM_WORK_CONN_TMO, GFP_ATOMIC);
        if (w == NULL) {
                /*
                 * It's safe to access the connection object here, since
                 * del_timer_sync() is called during cleanup. However,
                 * the timer must not be restarted (see handle_work_destroy and
                 * handle_work_cleanup).
                 */
                if (atomic_read(&co->conn_timer_lock) != 0)
                        mod_timer(&co->conn_timer, co->next_conn_tmo);
                return;
        }

        p = w->data;
        p->co = co;
        queue_work(ecm_workq, &w->work);
}

static int net_event(struct notifier_block *nb, unsigned long event, void *data)
{
        struct net_device *dev;
        struct ecm_work *w;
        struct ecm_work_net_event *p;

        (void)nb;
        dev = data;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26))
        if (dev_net(dev) != &init_net)
                return NOTIFY_DONE;
#endif

        w = alloc_ecm_work(sizeof(*p), ECM_WORK_NET_EVENT, GFP_KERNEL);
        if (w == NULL)
                return NOTIFY_DONE;

        p = w->data;
        p->event = event;
        p->dev = dev;

        /*
         * We need to call dev_hold(dev) before returning from this function,
         * alloc_ecm_device() takes care of this. Note that dev_put(dev) must
         * be done from the work queue.
         */
        if (event == NETDEV_REGISTER) {
                p->ecm_dev = alloc_ecm_device(dev);
                if (p->ecm_dev == NULL) {
                        free_ecm_work(w);
                        return NOTIFY_DONE;
                }
        }
        queue_work(ecm_workq, &w->work);

        return NOTIFY_OK;
}

static struct ethcm_ioctl_create *copy_args_from_user(void __user *arg)
{
        struct ethcm_ioctl_create k, *kp;
        size_t size;

        if (copy_from_user(&k, arg, sizeof(k)) != 0)
                return ERR_PTR(-EFAULT);

        size = sizeof(*kp) + k.name_len + 1 + k.dev_len + 1 + k.feat_len + 1;
        kp = kmalloc(size, GFP_KERNEL);
        if (kp == NULL)
                return ERR_PTR(-ENOMEM);

        if (copy_from_user(kp, arg, size) != 0) {
                kfree(kp);
                return ERR_PTR(-EFAULT);
        }
        return kp;
}

static int check_args(struct ethcm_ioctl_create *p)
{
        /*
         * Only check arguments that, for some reason, cannot
         * be verified by the application, e.g. mkethcon.
         */
        if ((p->mtu > 0) && (p->mtu <= MAX_HDR_SIZE))
                return -EINVAL; /* 0 => use default. */

        /*
         * Since we sometimes add a random value [-128,127] to conn_tmo,
         * we can't let it wrap around. 250 ms sounds good...
         */
        if ((p->conn_tmo > 0) && (p->conn_tmo < 250))
                return -EINVAL; /* 0 => use default. */

        return 0;
}

static void *ecm_create(void __user *arg)
{
        struct ecm_work *w;
        struct ecm_work_create *p;
        struct ethcm_ioctl_create *karg;
        void *co;
        int status;

        if (try_module_get(THIS_MODULE) == 0)
                return ERR_PTR(-EINVAL);

        karg = copy_args_from_user(arg);
        if (IS_ERR(karg)) {
                status = (int)PTR_ERR(karg);
                goto out_30;
        }
        status = check_args(karg);
        if (status != 0)
                goto out_20;

        w = alloc_ecm_work(sizeof(*p), ECM_WORK_CREATE, GFP_KERNEL);
        if (w == NULL) {
                status = -ENOMEM;
                goto out_20;
        }

        p = w->data;
        p->arg = karg;
        p->co = NULL;
        queue_work(ecm_workq, &w->work);

        wait_event(ecm_waitq, p->co != NULL);
        if (IS_ERR(p->co)) {
                status = (int)PTR_ERR(p->co);
                goto out_10;
        }
        co = p->co;
        kfree(karg);
        free_ecm_work(w);

        return co;

  out_10:
        free_ecm_work(w);
  out_20:
        kfree(karg);
  out_30:
        module_put(THIS_MODULE);
        return ERR_PTR(status);
}

static int ecm_destroy(void *cookie, void __user *arg)
{
        struct ecm_work *w;
        struct ecm_work_destroy *p;
        int status;

        (void)arg;

        w = alloc_ecm_work(sizeof(*p), ECM_WORK_DESTROY, GFP_KERNEL);
        if (w == NULL) {
                status = -ENOMEM;
                goto out;
        }

        p = w->data;
        p->co = cookie;
        p->status = -1;
        queue_work(ecm_workq, &w->work);

        wait_event(ecm_waitq, p->status == 0);
        free_ecm_work(w);
        status = 0;
        module_put(THIS_MODULE); /* First, make sure that job is done. */
  out:
        return status;
}

static void ecm_dc_init(struct RlnhLinkObj *co, void *lo, struct RlnhLinkUCIF *uc)
{
        struct ecm_work *w;
        struct ecm_work_dc_init *p;

        w = alloc_ecm_work(sizeof(*p), ECM_WORK_DC_INIT, GFP_TRYHARD);
        if (w == NULL) {
                printk(KERN_ERR "ECM critical out-of-memory condition!\n");
                return;
        }

        p = w->data;
        p->co = co;
        p->lo = lo;
        p->uc = uc;
        queue_work(ecm_workq, &w->work);
}

static void ecm_dc_finalize(struct RlnhLinkObj *co)
{
        struct ecm_work *w;
        struct ecm_work_dc_fini *p;

        w = alloc_ecm_work(sizeof(*p), ECM_WORK_DC_FINI, GFP_TRYHARD);
        if (w == NULL) {
                printk(KERN_ERR "ECM critical out-of-memory condition!\n");
                return;
        }

        p = w->data;
        p->co = co;
        queue_work(ecm_workq, &w->work);
}

static void ecm_dc_connect(struct RlnhLinkObj *co)
{
        struct ecm_work *w;
        struct ecm_work_dc_conn *p;

        w = alloc_ecm_work(sizeof(*p), ECM_WORK_DC_CONN, GFP_TRYHARD);
        if (w == NULL) {
                printk(KERN_ERR "ECM critical out-of-memory condition!\n");
                return;
        }

        p = w->data;
        p->co = co;
        queue_work(ecm_workq, &w->work);
}

static void ecm_dc_disconnect(struct RlnhLinkObj *co)
{
        struct ecm_work *w;
        struct ecm_work_disc *p;

        /*
         * This function can be called from atomic context, use pre-allocated
         * memory since kmalloc can't sleep...
         */
        w = seize_ecm_work_disc(co, ECM_WORK_DC_DISC);
        if (w == NULL)
                return; /* Disconnect in progess, OK! */

        p = w->data;
        p->co = co;
        queue_work(ecm_workq, &w->work);
}

int ecm_submit_conn_pkt(struct RlnhLinkObj *co, struct net_device *dev,
                        struct sk_buff *skb)
{
        struct ecm_work *w;
        struct ecm_work_conn_pkt *p;

        /* Always called from Rx softirq... */
        w = alloc_ecm_work(sizeof(*p), ECM_WORK_CONN_PKT, GFP_ATOMIC);
        if (w == NULL) {
                kfree_skb(skb);
                return -ENOMEM; /* Ok to drop, CONN pkts are sent unreliable! */
        }

        p = w->data;
        p->co = co;
        p->dev = dev;
        p->skb = skb;
        queue_work(ecm_workq, &w->work);

        return 0;
}

int ecm_submit_disconnect(struct RlnhLinkObj *co)
{
        struct ecm_work *w;
        struct ecm_work_disc *p;

        /*
         * This function can be called from atomic context, use pre-allocated
         * memory since kmalloc can't sleep...
         */
        w = seize_ecm_work_disc(co, ECM_WORK_DISC);
        if (w == NULL)
                return -EALREADY; /* Disconnect in progess, OK! */

        p = w->data;
        p->co = co;
        queue_work(ecm_workq, &w->work);

        return 0;
}

static int get_dc(const void *cookie, void **dc)
{
        extern int ecm_dc_transmit(struct RlnhLinkObj *, uint32_t, uint32_t,
                                   uint32_t, uint32_t, void *);

        static struct RlnhLinkIF ecm_dc = {
                RLNH_LINK_IF_VERSION,
                ecm_dc_init,
                ecm_dc_finalize,
                ecm_dc_connect,
                ecm_dc_disconnect,
                ecm_dc_transmit
        };

        u64 *p;
        unsigned long ul;

        p = kmalloc(sizeof(*p), GFP_KERNEL); /* Note: DB calls kfree! */
        if (p == NULL)
                return -ENOMEM;

        ul = (unsigned long)&ecm_dc;
        *p = (u64)ul;
        *dc = p;

        return (DB_TMP | DB_HEX | DB_UINT64);
}

static int __init ecm_init(void)
{
        int status;

        spin_lock_init(&ecm_lock);
        memset(ecm_connection_array, 0, sizeof(ecm_connection_array));

        INIT_LIST_HEAD(&ecm_device_list);
        INIT_LIST_HEAD(&ecm_orphan_list);

        init_waitqueue_head(&ecm_waitq);

        ecm_workq = create_singlethread_workqueue("ecm");
        if (ecm_workq == NULL)
                return -ENOMEM;

        status = register_netdevice_notifier(&ecm_notifier);
        if (status < 0) {
                destroy_workqueue(ecm_workq);
                return status;
        }

        db_add_template(DB_KEY_ETHCM, &ecm_template);
        db_proc_add(DB_KEY_ETHCM);

        setup_timer(&ecm_release_cid_timer, ecm_release_cid, 0);
        mod_timer(&ecm_release_cid_timer, tmo_ms(5000));

        return 0;
}
module_init(ecm_init);

static void __exit ecm_fini(void)
{
        struct list_head *item, *tmp;
        struct ecm_device *p;

        del_timer_sync(&ecm_release_cid_timer);

        db_proc_del(DB_KEY_ETHCM);
        db_del_template(DB_KEY_ETHCM);

        unregister_netdevice_notifier(&ecm_notifier);

        /*
         * At this point, no one is submitting jobs to the workqueue. Net events
         * are stopped and all connections are destroyed (module's use count is
         * used to make sure of this). It is safe to flush and destroy the work
         * queue.
         */
        flush_workqueue(ecm_workq);
        destroy_workqueue(ecm_workq);

        /*
         * One thing left, release all net devices that are stored in the list.
         * Normally, stop_/free_ecm_device must not be used outside
         * the workqueue, but since it has been destroyed, it's ok to use them.
         */
        list_for_each_safe(item, tmp, &ecm_device_list) {
                p = list_entry(item, struct ecm_device, node);
                stop_ecm_device(p);
                free_ecm_device(p);
        }
}
module_exit(ecm_fini);
