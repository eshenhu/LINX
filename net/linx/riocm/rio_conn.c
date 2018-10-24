/*
 * Copyright (c) 2009-2010, Enea Software AB
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
#include <linux/riocm_db_ioctl.h>
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
#include <rio.h>
#include <rio_proto.h>
#include <rio_kutils.h>

MODULE_AUTHOR("ENEA");
MODULE_DESCRIPTION("LINX RapidIO Connection Manager");
MODULE_LICENSE("GPL");
MODULE_VERSION(RIO_VERSION);

#define uptr(p, n) ((u8 __user *)(p) + (n))
#define kptr(p, n) ((u8 *)(p) + (n))

#define TMO     97 /* Must not interfer with RIO_CONN_<x> in rio_proto.h! */
#define DC_CONN 98 /* Must not interfer with RIO_CONN_<x> in rio_proto.h! */
#define DC_DISC 99 /* Must not interfer with RIO_CONN_<x> in rio_proto.h! */

#define STATE_DISCONNECTED 1
#define STATE_CONNECTING   2
#define STATE_CONNECTED    3

#define GFP_TRYHARD (__GFP_REPEAT | GFP_KERNEL)/* Ask MM to really really try */

static void do_the_gory_stuff(struct RlnhLinkObj *co, int event);
static void conn_tmo_func(unsigned long data);

static struct workqueue_struct *rio_workq;
static void rio_workq_func(struct work_struct *w);

static wait_queue_head_t rio_waitq;

static int net_event(struct notifier_block *nb,unsigned long event, void *data);
static struct notifier_block rio_notifier = {
        .notifier_call = net_event,
};

static int get_dc(const void *cookie, void **dc);
static void *rio_create(void __user *arg);
static int rio_destroy(void *cookie, void __user *arg);
static const struct db_param rio_params[] = {
        DB_PARAM("con_name", DB_PTR | DB_STRING, con_name, struct RlnhLinkObj),
        DB_PARAM("con_cookie", DB_HEX|DB_UINT64,con_cookie, struct RlnhLinkObj),
        DB_META_PARAM("con_dc", DB_HEX|DB_UINT64, sizeof(u64), 1, get_dc, NULL),
        DB_PARAM("device", DB_PTR | DB_STRING, dev_name, struct RlnhLinkObj),
/* local params */
        DB_PARAM("device_id", DB_UINT16, my_id, struct RlnhLinkObj),
        DB_PARAM("port", DB_UINT16, my_port, struct RlnhLinkObj),
        DB_PARAM("cid", DB_UINT16, cid, struct RlnhLinkObj),
        DB_PARAM("generation", DB_UINT16, generation, struct RlnhLinkObj),
/* peer params */
        DB_PARAM("peer_device_id", DB_UINT16, peer_ID, struct RlnhLinkObj),
        DB_PARAM("peer_mbox", DB_UINT8, peer_mbox, struct RlnhLinkObj),
        DB_PARAM("peer_port", DB_UINT16, peer_port, struct RlnhLinkObj),
        DB_PARAM("peer_cid", DB_UINT16, peer_cid, struct RlnhLinkObj),
        DB_PARAM("peer_generation", DB_UINT16, peer_generation,
		 struct RlnhLinkObj),
/* connection entities */
        DB_PARAM("user_mtu", DB_UINT16, user_mtu, struct RlnhLinkObj),
        DB_PARAM("mtu", DB_UINT16, conn_mtu, struct RlnhLinkObj),
        DB_PARAM("conn_tmo", DB_UINT, conn_tmo, struct RlnhLinkObj),
        DB_PARAM("state", DB_UINT16, state, struct RlnhLinkObj),
/* statistics */
        DB_PARAM("sent_packets", DB_ULONG, tx_packets, struct RlnhLinkObj),
        DB_PARAM("sent_bytes", DB_ULONG, tx_bytes, struct RlnhLinkObj),
        DB_PARAM("recv_packets", DB_ULONG, rx_packets, struct RlnhLinkObj),
        DB_PARAM("recv_bytes", DB_ULONG, rx_bytes, struct RlnhLinkObj),
        DB_PARAM("num_connects", DB_ULONG, num_connections, struct RlnhLinkObj),
        DB_PARAM_END
};
static const struct db_template rio_template = {
        .owner = THIS_MODULE,
        .create = rio_create,
        .destroy = rio_destroy,
        .param = rio_params
};

static struct list_head rio_device_list; /* Registered network devices. */
static struct list_head rio_orphan_list; /* CO not assigned to a network device. */

static DEFINE_SPINLOCK(rio_lock); /* The one and only... */
static struct RlnhLinkObj *rio_connection_array[256];
static uint16_t generation;

#define RIO_WORK_NET_EVENT 1
struct rio_work_net_event {
        unsigned long event;
        struct net_device *dev;
        struct rio_device *rio_dev; /* Only for NETDEV_REGISTER... */
};

#define RIO_WORK_DC_INIT 2
struct rio_work_dc_init {
        struct RlnhLinkObj *co;
        void *lo;
        struct RlnhLinkUCIF *uc;
};

#define RIO_WORK_DC_FINI 3
struct rio_work_dc_fini {
        struct RlnhLinkObj *co;
};

#define RIO_WORK_DC_CONN 4
struct rio_work_dc_conn {
        struct RlnhLinkObj *co;
};

#define RIO_WORK_DC_DISC 5
/* use struct rio_work_disc */

#define RIO_WORK_CREATE 6
struct rio_work_create {
        struct riocm_ioctl_create *arg;
        struct RlnhLinkObj *co;
};

#define RIO_WORK_DESTROY 7
struct rio_work_destroy {
        struct RlnhLinkObj *co;
        int status;
};

#define RIO_WORK_CONN_TMO 8
struct rio_work_conn_tmo {
        struct RlnhLinkObj *co;
};

#define RIO_WORK_CONN_PKT 11
struct rio_work_conn_pkt {
        struct RlnhLinkObj *co;
        struct net_device *dev;
        struct sk_buff *skb;
};

#define RIO_WORK_DISC 12
struct rio_work_disc {
        struct RlnhLinkObj *co;
};

#define RIO_WORK_CLEANUP 13
/* use struct rio_work_destroy */

struct rio_work {
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

static void setup_rio_work(struct rio_work *w, void *p, int opcode)
{
        w->opcode = opcode;
        w->data = p;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20))
        INIT_WORK(&w->work, rio_workq_func);
#else
        INIT_WORK(&w->work, (void (*)(void *))rio_workq_func, w);
#endif
}

static struct rio_work *alloc_rio_work(size_t size, int opcode, gfp_t flags)
{
        struct rio_work *w;
        void *p;

        w = kmalloc(sizeof(*w), flags);
        if (w == NULL)
                return NULL;
        p = kmalloc(size, flags);
        if (p == NULL) {
                kfree(w);
                return NULL;
        }
        setup_rio_work(w, p, opcode);
        return w;
}

static void free_rio_work(struct rio_work *w)
{
        if (w != NULL) {
                if (w->data != NULL)
                        kfree(w->data);
                kfree(w);
        }
}

static struct rio_work *seize_rio_work_disc(struct RlnhLinkObj *co, int opcode)
{
        struct rio_work *w;
        int k;

        k = atomic_xchg(&co->disc_count, 0);
        if (k == 0)
                return NULL; /* Disconnect in progess... */

        w = co->w_disc;
        co->w_disc = NULL; /* Re-install it when the work is done. */
        w->opcode = opcode;

        return w;
}

static struct rio_device *lookup_rio_device_by_net(struct net_device *dev)
{
        struct rio_device *p;
        struct list_head *item;

        list_for_each(item, &rio_device_list) {
                p = list_entry(item, struct rio_device, node);
                if (p->dev == dev)
                        return p;
        }
        return NULL;
}

static struct rio_device *lookup_rio_device_by_name(const char *name)
{
        struct rio_device *p;
        struct list_head *item;

        list_for_each(item, &rio_device_list) {
                p = list_entry(item, struct rio_device, node);
                if (strcmp(name, p->dev->name) == 0)
                        return p;
        }
        return NULL;
}

static struct rio_device *alloc_rio_device(struct net_device *dev)
{
        struct rio_device *p;

        p = kmalloc(sizeof(*p), GFP_KERNEL);
        if (p == NULL)
                return NULL;

        INIT_LIST_HEAD(&p->node);
        INIT_LIST_HEAD(&p->conn_list);
        p->dev = dev;
        p->pt.type = __constant_htons(RIO_PROTOCOL);
        p->pt.dev = dev;
        p->pt.func = rio_rx;
        p->pt.af_packet_priv = p;
        INIT_LIST_HEAD(&p->pt.list);

        dev_hold(dev); /* dev_put() is done in free_rio_device(). */
        return p;
}

static void free_rio_device(struct rio_device *p)
{
        /*
         * Release struct net_device object, make sure that stop_rio_device()
         * has been called first!
         */
        dev_put(p->dev);

        memset(p, 0, sizeof(*p));
        kfree(p);
}

static void start_rio_device(struct rio_device *p)
{
        struct list_head *item;
        struct RlnhLinkObj *co;

        list_add(&p->node, &rio_device_list);

        /*
         * Reset transmit lock, i.e. allow TX to use the struct net_device
         * object. RX won't get any LINX packets and destroy-work makes
         * the connection in-visible, i.e. no lock is needed.
         */
        list_for_each(item, &p->conn_list) {
                co = list_entry(item, struct RlnhLinkObj, node);
                reset_rio_lock(&co->tx_lock, 1);
        }

        /* RX callback will get LINX packets... */
        dev_add_pack(&p->pt);
}

static void stop_rio_device(struct rio_device *p)
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
                synchronize_rio_lock(&co->tx_lock);
        }

        list_del(&p->node);
}

static void handle_netdev_register(struct net_device *dev,
                                   struct rio_device *rio_dev)
{
        struct list_head *item, *tmp;
        struct RlnhLinkObj *co;

        /*
         * Any orphan connections? Move them to device's conn list before
         * starting the device. No conn_list lock is needed since RX won't
         * get any Linx packet, i.e. dev_add_pack hasn't been called.
         */
        list_for_each_safe(item, tmp, &rio_orphan_list) {
                co = list_entry(item, struct RlnhLinkObj, node);
                if (strcmp(co->dev_name, rio_dev->dev->name) == 0) {
                        co->rio_dev = rio_dev;
                        list_move_tail(&co->node, &rio_dev->conn_list);
                }
        }

        /* Enable RX and TX... */
        start_rio_device(rio_dev);
}

static void handle_netdev_unregister(struct net_device *dev)
{
        struct rio_device *p;
        struct list_head *item, *tmp;
        struct RlnhLinkObj *co;

        p = lookup_rio_device_by_net(dev);
        if (p == NULL)
                return; /* No such device! */

        /* Disable RX and TX... */
        stop_rio_device(p);

        /*
         * Move connections to orphan list. RX has been shut-down,
         * i.e. dev_remove_pack has been called, and destroy-work makes
         * it in-visible, i.e. no lock is needed.
         */
        list_for_each_safe(item, tmp, &p->conn_list) {
                co = list_entry(item, struct RlnhLinkObj, node);
                co->rio_dev = NULL; /* A must or terrible things may happen. */
                list_move_tail(&co->node, &rio_orphan_list);
        }

        free_rio_device(p);
}

static void handle_netdev_down(struct net_device *dev)
{
        struct rio_device *p;
        struct list_head *item;
        struct RlnhLinkObj *co;

        p = lookup_rio_device_by_net(dev);
        if (p == NULL)
                return; /* No such device! */

        /*
         * Network is down, start disconnecting. RX doesn't delete any conn_list
         * items and destroy-work makes it in-visible, i.e no lock is needed.
         */
        list_for_each(item, &p->conn_list) {
                co = list_entry(item, struct RlnhLinkObj, node);
                do_the_gory_stuff(co, RIO_CONN_RESET);
        }
}

static void report_netdev_unsupported(struct net_device *dev, const char *s)
{
        struct rio_device *p;
        struct list_head *item;
        struct RlnhLinkObj *co;

        p = lookup_rio_device_by_net(dev);
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

static void report_ignored_netdev_event(struct net_device *dev, int event)
{
        struct rio_device *p;
        struct list_head *item;
        struct RlnhLinkObj *co;

        p = lookup_rio_device_by_net(dev);
        if (p == NULL)
                return; /* No such device! */

        /*
         * RX doesn't delete any conn_list items and destroy-work makes it
         * in-visible, i.e no lock is needed.
         */
        list_for_each(item, &p->conn_list) {
                co = list_entry(item, struct RlnhLinkObj, node);
                printk(KERN_ERR "LINX connection %s ignored driver event %d,\n",
                       co->con_name, event);
        }
}

static void handle_work_net_event(struct rio_work *w)
{
        struct rio_work_net_event *p;

        p = w->data;

        switch (p->event) {
        case NETDEV_REGISTER:
                handle_netdev_register(p->dev, p->rio_dev);
                break;
        case NETDEV_UNREGISTER:
                handle_netdev_unregister(p->dev);
                break;
        case NETDEV_UP:
                break; /*TMO takes care of this... */
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
		report_ignored_netdev_event(p->dev, p->event);
                break;
        }

        free_rio_work(w);
}

static void send_rio_conn_pkt(struct RlnhLinkObj *co, int type)
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
        if (co->rio_dev != NULL)
                rio_send_conn_pkt(co, GFP_KERNEL, type);
}

static int rio_conn_dead(struct RlnhLinkObj *co)
{
        return atomic_dec_and_test(&co->conn_alive_count);
}

static void handle_dc_conn(struct RlnhLinkObj *co)
{
        switch (co->state) {
        case STATE_DISCONNECTED:
                rio_start_rx(co);
                rio_start_tx(co);
                reset_rio_lock(&co->tx_lock, 1); /* Allow transmit. */
                co->state = STATE_CONNECTING;
                break;
        default:
                /* STATE_CONNECTING and STATE_CONNECTED. */
                BUG();
                break;
        }
}

static void handle_dc_disc(struct RlnhLinkObj *co)
{
        switch (co->state) {
        case STATE_DISCONNECTED:
                break; /* Sit tight, disconnected already called... */
        case STATE_CONNECTING:
                co->uc->disconnected(co->lo);
                rio_stop_rx(co);
                rio_stop_tx(co);
                co->state = STATE_DISCONNECTED;
                break;
        case STATE_CONNECTED:
                send_rio_conn_pkt(co, RIO_CONN_RESET);
                synchronize_rio_lock(&co->rx_lock);
                synchronize_rio_lock(&co->tx_lock);
                co->uc->disconnected(co->lo);
                rio_stop_rx(co);
                rio_stop_tx(co);
                co->state = STATE_DISCONNECTED;
                break;
        default:
                BUG();
                break;
        }
}

static void handle_conn_tmo(struct RlnhLinkObj *co)
{
        switch (co->state) {
        case STATE_DISCONNECTED:
                co->next_conn_tmo = tmo_ms_rand(co->connect_tmo);
                break; /* Sit tight, await downcall connect. */
        case STATE_CONNECTING:
                send_rio_conn_pkt(co, RIO_CONN_REQ);
                co->next_conn_tmo = tmo_ms_rand(co->connect_tmo);
                break;
        case STATE_CONNECTED:
                if (rio_conn_dead(co)) {
                        send_rio_conn_pkt(co, RIO_CONN_RESET);
                        synchronize_rio_lock(&co->rx_lock);
                        synchronize_rio_lock(&co->tx_lock);
                        co->uc->disconnected(co->lo);
                        rio_stop_rx(co);
                        rio_stop_tx(co);
                        co->next_conn_tmo = tmo_ms_rand(co->conn_tmo);
                        co->state = STATE_DISCONNECTED;
                } else {
			rio_send_hb(co, GFP_KERNEL);
                        co->next_conn_tmo = tmo_ms(co->conn_tmo);
                }
                break;
        default:
                BUG();
                break;
        }

        /* Make sure that the timer isn't restarted after a del_timer_sync(). */
        if (atomic_read(&co->conn_timer_lock) != 0)
                mod_timer(&co->conn_timer, co->next_conn_tmo);
}

static void handle_conn_req(struct RlnhLinkObj *co)
{
        switch (co->state) {
        case STATE_DISCONNECTED:
                break; /* Sit tight, await downcall connect. */
        case STATE_CONNECTING:
                send_rio_conn_pkt(co, RIO_CONN_ACK);
                break;
        case STATE_CONNECTED: /* cancel the connection */
                synchronize_rio_lock(&co->rx_lock);
                synchronize_rio_lock(&co->tx_lock);
                co->uc->disconnected(co->lo);
                rio_stop_rx(co);
                rio_stop_tx(co);
                co->state = STATE_DISCONNECTED;
		break;
        default:
                BUG();
                break;
        }
}

static void handle_conn_ack(struct RlnhLinkObj *co)
{
        switch (co->state) {
        case STATE_DISCONNECTED:
                break; /* Sit tight, await downcall connect. */
        case STATE_CONNECTING:
		/* check if conn ack is ok, mtu... */
		send_rio_conn_pkt(co, RIO_CONN_ACK);
                rio_mark_conn_alive(co);
                co->num_connections++;
                co->uc->connected(co->lo);
                reset_rio_lock(&co->rx_lock, 1); /* Allow upcall deliver. */
		rio_deliver_queued_pkts(co);
                co->state = STATE_CONNECTED;
                break;
        case STATE_CONNECTED:
		break;
        default:
                BUG();
                break;
        }
}

static void handle_conn_reset(struct RlnhLinkObj *co)
{
        switch (co->state) {
        case STATE_DISCONNECTED:
                break; /* Sit tight, await downcall connect. */
        case STATE_CONNECTING:
                break;
        case STATE_CONNECTED:
                synchronize_rio_lock(&co->rx_lock);
                synchronize_rio_lock(&co->tx_lock);
                co->uc->disconnected(co->lo);
                rio_stop_rx(co);
                rio_stop_tx(co);
                co->state = STATE_DISCONNECTED;
                break;
        default:
                BUG();
                break;
        }
}

static void do_the_gory_stuff(struct RlnhLinkObj *co, int event)
{
        switch (event) {
        case RIO_CONN_REQ:
                handle_conn_req(co);
                break;
        case RIO_CONN_ACK:
                handle_conn_ack(co);
                break;
        case RIO_CONN_RESET:
                handle_conn_reset(co);
                break;
        case TMO:
                handle_conn_tmo(co);
                break;
        case DC_CONN:
                handle_dc_conn(co);
                break;
        case DC_DISC:
                handle_dc_disc(co);
                break;
        default:
                BUG();
                break;
        }
}

static void set_rio_data_lens(struct RlnhLinkObj *co)
{
	co->single_len =      co->conn_mtu - SINGLE_HSIZE -      RIO_HLEN;
	co->frag_start_len =  co->conn_mtu - FRAG_START_HSIZE -  RIO_HLEN;
	co->frag_len =        co->conn_mtu - FRAG_HSIZE -        RIO_HLEN;
	co->patch_start_len = co->conn_mtu - PATCH_START_HSIZE - RIO_HLEN;
}

static int handle_rio_features(struct RlnhLinkObj *co, struct sk_buff *skb)
{
	struct rio_conn_req *req;
	struct rio_conn_ack *ack;
	unsigned int hb_tmo;
        uint16_t mtu;

/*
 * connection establishment algorithm postulates that if an ack is
 * received with wrong parameters, treat the ack as a req
 */
        switch (rio_header_type(skb)) {
        case RIO_CONN_ACK:
		/* check if the peer set the correct values */
		ack = rio_header(skb, ack);
		mtu = htons(ack->mtu_ack);
		hb_tmo = 100 * ack->hb_tmo_ack;
		
		if ((co->generation != ack->generation_ack) ||
		    (mtu != co->conn_mtu) || (hb_tmo != co->conn_tmo)) {
                /* peer sent wrong params. treat it as a REQ */
			rio_header_type(skb) = RIO_CONN_REQ;
		} else {
			co->peer_cid = htons(ack->my_cid); /* important! */
			return 0;
		}
		/* fall through! */
	case RIO_CONN_REQ:
		req = rio_header(skb, req);
		co->peer_generation = req->generation;
		hb_tmo = 100 * req->hb_tmo;
		mtu = htons(req->mtu);

                /* Use lowest MTU */
		if (mtu <= RIOCM_MIN_MTU)
			return -EINVAL;
		co->conn_mtu = mtu < co->wanted_mtu ? mtu : co->wanted_mtu;
		set_rio_data_lens(co);

		/* Use highest heartbeat timeout */
		if(hb_tmo > co->user_tmo)
			co->conn_tmo = hb_tmo;
		else
			co->conn_tmo = co->user_tmo;
                return 0;
	case RIO_CONN_RESET:
		return 0; /* do nothing, it will be taken care of later */
        default:
		BUG();
                return 0;
        }
}

static void handle_work_conn_pkt(struct rio_work *w)
{
        struct rio_work_conn_pkt *p = w->data;

	if (handle_rio_features(p->co, p->skb) != 0) {
		/* TMO takes care of the rest... */
		kfree_skb(p->skb);
		goto out;
	}

	do_the_gory_stuff(p->co, rio_header_type(p->skb));
	kfree_skb(p->skb);
out:
        free_rio_work(w);
}

static void handle_work_conn_tmo(struct rio_work *w)
{
        struct rio_work_conn_tmo *p;

        p = w->data;
        do_the_gory_stuff(p->co, TMO);
        free_rio_work(w);
}

static int select_rio_mtu(struct RlnhLinkObj *co)
{
        int dev_mtu;

        /* If we can't get it from the device, use max payload. */
        dev_mtu = co->rio_dev != NULL ?	co->rio_dev->dev->mtu : RIO_DEFAULT_MTU;

        if (co->user_mtu == 0)
                /* User's MTU is don't care, always request device MTU. */
                return dev_mtu;
        else
                /* Request user's MTU, if the device allows it. */
                return (co->user_mtu < dev_mtu) ? co->user_mtu : dev_mtu;
}

static void free_rio_connection(struct RlnhLinkObj *co)
{
        /* Undo alloc_rio_connection(). */
        if (co != NULL) {
                if (co->con_name != NULL)
                        kfree(co->con_name);
                if (co->dev_name != NULL)
                        kfree(co->dev_name);
                if (co->w_disc != NULL)
                        free_rio_work(co->w_disc);
                memset(co, 0, sizeof(*co));
                kfree(co);
        }
}

static struct RlnhLinkObj *alloc_rio_connection(struct riocm_ioctl_create *arg)
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

        /* Pre-allocate memory for RIO disconnect jobs. */
        size = sizeof(struct rio_work_disc);
        co->w_disc = alloc_rio_work(size, 0, GFP_KERNEL);
        if (co->w_disc == NULL)
                goto out;
        atomic_set(&co->disc_count, 1);

        return co;
  out:
        free_rio_connection(co);
        return NULL;
}

/* is this really correct - the driver should have or has a func for this */
static uint16_t get_rio_device_id(struct net_device *dev)
{
	uint16_t id;

	id = (dev->dev_addr[0] << 8) | dev->dev_addr[1];
	return id;
}

static int init_rio_connection(struct RlnhLinkObj *co,
			       struct riocm_ioctl_create *arg)
{
        unsigned long ul;

        co->state = STATE_DISCONNECTED;
        INIT_LIST_HEAD(&co->node);
        ul = (unsigned long)co; /* Do a cast to avoid 64/32 bit problems. */
        co->con_cookie = (uint64_t)ul;
 	co->user_mtu = arg->mtu;
 	co->peer_port = arg->port;
 	co->peer_mbox = arg->mbox;
 	co->peer_ID = arg->id;
	co->user_tmo = arg->hb != 0 ? arg->hb*100 : RIO_CONN_DEFAULT_HEARTBEAT;
	co->conn_tmo = co->user_tmo; /* initially set to user_tmo */
        strcpy(co->con_name, (char *)kptr(arg, arg->name));
        strcpy(co->dev_name, (char *)kptr(arg, arg->dev));

	co->connect_tmo = 200; /* hardcoded to 200ms */

        co->rio_dev = lookup_rio_device_by_name(co->dev_name);
        if (co->rio_dev == NULL)
                return -ENODEV;
	co->my_port = arg->my_port;
	co->my_id = get_rio_device_id(co->rio_dev->dev);

	co->wanted_mtu = select_rio_mtu(co);

        setup_timer(&co->conn_timer, conn_tmo_func, (unsigned long)co);
        co->next_conn_tmo = tmo_ms_rand(co->connect_tmo);
        atomic_set(&co->conn_alive_count, 0);

        init_rio_lock(&co->tx_lock, 0); /* Block transmit. */
        init_rio_lock(&co->rx_lock, 0); /* Block deliver of user data. */
        init_rio_lock(&co->conn_rx_lock, 1); /* Allow deliver of conn pkts. */

        return 0;
}

struct RlnhLinkObj *get_rio_conn(struct sk_buff *skb, struct rio_device *dev)
{
	uint8_t type;
        struct RlnhLinkObj *co;
        struct list_head *item;
	struct rio_gen_conn *ch;
	struct rio_gen_udata *uh;

	type = rio_header_type(skb);
	if ((type & 0x80) != 0) { /* conn header, search for co */
		ch = rio_header(skb, ch);
		
		spin_lock_bh(&rio_lock);
		list_for_each(item, &dev->conn_list) {
			co = list_entry(item, struct RlnhLinkObj, node);
			if (co->peer_ID == ntohs(ch->sender) &&
			    co->peer_port == ntohs(ch->src_port) &&
			    co->my_port == ntohs(ch->dst_port)) {
				atomic_inc(&co->use_count);
				spin_unlock_bh(&rio_lock);
				return co;
			}
		}
		spin_unlock_bh(&rio_lock);
	} else { /* data or heartbeat header */
		uh = rio_header(skb, uh);
		
		spin_lock_bh(&rio_lock);
		co = rio_connection_array[ntohs(uh->dst_cid)];
		spin_unlock_bh(&rio_lock);
		if(co != NULL)
			atomic_inc(&co->use_count);
		return co; /* may be null if not present in array */
	}

        return NULL;
}

void put_rio_connection(struct RlnhLinkObj *co)
{
        spin_lock_bh(&rio_lock);
        if (unlikely(0 == atomic_dec_return(&co->use_count))) {
                spin_unlock_bh(&rio_lock);
                free_rio_connection(co);
                return;
        }
        spin_unlock_bh(&rio_lock);
}

static uint16_t __get_generation(void)
{
	uint16_t gen;

	gen = generation;
	/* increment generation. */
	generation = (gen + 1) & 0xffff;

	return gen;
}

/* Make connection visible... (called from create) */
static void add_rio_connection(struct RlnhLinkObj *co)
{
        int n;

        co->cid = 0;
        spin_lock_bh(&rio_lock);
        for (n = 0; n < 256; n++) {
                if (rio_connection_array[n] == NULL) {
                        rio_connection_array[n] = co;
                        co->cid = n;
			co->generation = __get_generation();
                        break;
                }
        }
        list_add_tail(&co->node, &co->rio_dev->conn_list);
        spin_unlock_bh(&rio_lock);
}

/* Make connection invisible... (called from destroy) */
static void del_rio_connection(struct RlnhLinkObj *co)
{
        int n;

        spin_lock_bh(&rio_lock);
        for (n = 0; n < 256; n++) {
                if (rio_connection_array[n] == co) {
                        rio_connection_array[n] = NULL;
                        break;
                }
        }
        list_del(&co->node);
        spin_unlock_bh(&rio_lock);
}

static void handle_work_create(struct rio_work *w)
{
        struct rio_work_create *p;
        struct RlnhLinkObj *co;
        int status;

        p = w->data;

        co = alloc_rio_connection(p->arg);
        if (co == NULL) {
                co = ERR_PTR(-ENOMEM);
                goto out;
        }
        status = init_rio_connection(co, p->arg);
        if (status < 0) {
                free_rio_connection(co);
                co = ERR_PTR((long)status);
                goto out;
        }
        add_rio_connection(co);

        /* Kick things off... */
        atomic_set(&co->conn_timer_lock, 1);
        mod_timer(&co->conn_timer, co->next_conn_tmo);
  out:
        /* Now it's safe to wake up submitter (waitfor p->co != NULL) */
        p->co = co;
        wake_up(&rio_waitq);
}

static void handle_work_destroy(struct rio_work *w)
{
        struct rio_work_destroy *p;

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
        synchronize_rio_lock(&p->co->conn_rx_lock);
        del_rio_connection(p->co);

        /*
         * Re-submit the destroy work, this allows any jobs already in
         * the workqueue to finish before the connection is destroyed.
         *
         * Note: must re-use struct rio_work, rio_destroy() waits on
         *       status variable...
         */
        setup_rio_work(w, p, RIO_WORK_CLEANUP);
        queue_work(rio_workq, &w->work);
}

static void handle_work_cleanup(struct rio_work *w)
{
        struct rio_work_destroy *p;

        p = w->data;
        put_rio_connection(p->co);

        /* Now it's safe to wake up submitter. */
        p->status = 0;
        wake_up(&rio_waitq);
}

static void handle_work_dc_init(struct rio_work *w)
{
        struct rio_work_dc_init *p;

        p = w->data;
        p->co->lo = p->lo;
        p->co->uc = p->uc;
        free_rio_work(w);
}

static void handle_work_dc_fini(struct rio_work *w)
{
        free_rio_work(w);
}

static void handle_work_dc_conn(struct rio_work *w)
{
        struct rio_work_dc_conn *p;

        p = w->data;
        atomic_set(&p->co->disc_count, 1); /* Allow one disconnect. */
        do_the_gory_stuff(p->co, DC_CONN);
        free_rio_work(w);
}

static void handle_work_dc_disc(struct rio_work *w)
{
        struct rio_work_disc *p;

        p = w->data;
        do_the_gory_stuff(p->co, DC_DISC);
        p->co->w_disc = w; /* Re-use pre-allocated memory. */
}

static void handle_work_disc(struct rio_work *w)
{
        struct rio_work_disc *p;

        p = w->data;
        do_the_gory_stuff(p->co, RIO_CONN_RESET); /* Internal disconnect. */
        p->co->w_disc = w; /* Re-use pre-allocated memory. */
}

#ifndef log_rio_work
#define log_rio_work(x) (x)
#endif

static void rio_workq_func(struct work_struct *w)
{
        struct rio_work *p;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20))
        log_rio_work(p = container_of(w, struct rio_work, work));
#else
        log_rio_work(p = (struct rio_work *)w);
#endif

        switch (p->opcode) {
        case RIO_WORK_CONN_TMO:
                handle_work_conn_tmo(p);
                break;
        case RIO_WORK_CONN_PKT:
                handle_work_conn_pkt(p);
                break;
        case RIO_WORK_NET_EVENT:
                handle_work_net_event(p);
                break;
        case RIO_WORK_CREATE:
                handle_work_create(p);
                break;
        case RIO_WORK_DESTROY:
                handle_work_destroy(p);
                break;
        case RIO_WORK_CLEANUP:
                handle_work_cleanup(p);
                break;
        case RIO_WORK_DC_INIT:
                handle_work_dc_init(p);
                break;
        case RIO_WORK_DC_FINI:
                handle_work_dc_fini(p);
                break;
        case RIO_WORK_DC_CONN:
                handle_work_dc_conn(p);
                break;
        case RIO_WORK_DC_DISC:
                handle_work_dc_disc(p);
                break;
        case RIO_WORK_DISC:
                handle_work_disc(p);
                break;
        default:
                BUG(); /* FIXME: just for now... */
                free_rio_work(p);
                break;
        }
}

static void conn_tmo_func(unsigned long data)
{
        struct rio_work *w;
        struct rio_work_conn_tmo *p;
        struct RlnhLinkObj *co;

        co = (struct RlnhLinkObj *)data;

        w = alloc_rio_work(sizeof(*p), RIO_WORK_CONN_TMO, GFP_ATOMIC);
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
        queue_work(rio_workq, &w->work);
}

static int net_event(struct notifier_block *nb, unsigned long event, void *data)
{
        struct net_device *dev;
        struct rio_work *w;
        struct rio_work_net_event *p;

        (void)nb;
        dev = data;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26))
        if (dev_net(dev) != &init_net)
                return NOTIFY_DONE;
#endif

        w = alloc_rio_work(sizeof(*p), RIO_WORK_NET_EVENT, GFP_KERNEL);
        if (w == NULL)
                return NOTIFY_DONE;

        p = w->data;
        p->event = event;
        p->dev = dev;

        /*
         * We need to call dev_hold(dev) before returning from this function,
         * alloc_rio_device() takes care of this. Note that dev_put(dev) must
         * be done from the work queue.
         */
        if (event == NETDEV_REGISTER) {
                p->rio_dev = alloc_rio_device(dev);
                if (p->rio_dev == NULL) {
                        free_rio_work(w);
                        return NOTIFY_DONE;
                }
        }
        queue_work(rio_workq, &w->work);

        return NOTIFY_OK;
}

static struct riocm_ioctl_create *copy_args_from_user(void __user *arg)
{
        struct riocm_ioctl_create k, *kp;
        size_t size;

        if (copy_from_user(&k, arg, sizeof(k)) != 0)
                return ERR_PTR(-EFAULT);

        size = sizeof(*kp) + k.name_len + 1 + k.dev_len + 1;
        kp = kmalloc(size, GFP_KERNEL);
        if (kp == NULL)
                return ERR_PTR(-ENOMEM);

        if (copy_from_user(kp, arg, size) != 0) {
                kfree(kp);
                return ERR_PTR(-EFAULT);
        }
        return kp;
}

static void *rio_create(void __user *arg)
{
        struct rio_work *w;
        struct rio_work_create *p;
        struct riocm_ioctl_create *karg;
        void *co;
        int status;

        if (try_module_get(THIS_MODULE) == 0)
                return ERR_PTR(-EINVAL);

        karg = copy_args_from_user(arg);
        if (IS_ERR(karg)) {
                status = (int)PTR_ERR(karg);
                goto out_30;
        }

        w = alloc_rio_work(sizeof(*p), RIO_WORK_CREATE, GFP_KERNEL);
        if (w == NULL) {
                status = -ENOMEM;
                goto out_20;
        }

        p = w->data;
        p->arg = karg;
        p->co = NULL;
        queue_work(rio_workq, &w->work);

        wait_event(rio_waitq, p->co != NULL);
        if (IS_ERR(p->co)) {
                status = (int)PTR_ERR(p->co);
                goto out_10;
        }
        co = p->co;
        kfree(karg);
        free_rio_work(w);

        return co;

  out_10:
        free_rio_work(w);
  out_20:
        kfree(karg);
  out_30:
        module_put(THIS_MODULE);
        return ERR_PTR(status);
}

static int rio_destroy(void *cookie, void __user *arg)
{
        struct rio_work *w;
        struct rio_work_destroy *p;
        int status;

        (void)arg;

        w = alloc_rio_work(sizeof(*p), RIO_WORK_DESTROY, GFP_KERNEL);
        if (w == NULL) {
                status = -ENOMEM;
                goto out;
        }

        p = w->data;
        p->co = cookie;
        p->status = -1;
        queue_work(rio_workq, &w->work);

        wait_event(rio_waitq, p->status == 0);
        free_rio_work(w);
        status = 0;
        module_put(THIS_MODULE); /* First, make sure that job is done. */
  out:
        return status;
}

static void rio_dc_init(struct RlnhLinkObj *co, void *lo, struct RlnhLinkUCIF *uc)
{
        struct rio_work *w;
        struct rio_work_dc_init *p;

        w = alloc_rio_work(sizeof(*p), RIO_WORK_DC_INIT, GFP_TRYHARD);
        if (w == NULL) {
                printk(KERN_ERR "RIO critical out-of-memory condition!\n");
                return;
        }

        p = w->data;
        p->co = co;
        p->lo = lo;
        p->uc = uc;
        queue_work(rio_workq, &w->work);
}

static void rio_dc_finalize(struct RlnhLinkObj *co)
{
        struct rio_work *w;
        struct rio_work_dc_fini *p;

        w = alloc_rio_work(sizeof(*p), RIO_WORK_DC_FINI, GFP_TRYHARD);
        if (w == NULL) {
                printk(KERN_ERR "RIO critical out-of-memory condition!\n");
                return;
        }

        p = w->data;
        p->co = co;
        queue_work(rio_workq, &w->work);
}

static void rio_dc_connect(struct RlnhLinkObj *co)
{
        struct rio_work *w;
        struct rio_work_dc_conn *p;

        w = alloc_rio_work(sizeof(*p), RIO_WORK_DC_CONN, GFP_TRYHARD);
        if (w == NULL) {
                printk(KERN_ERR "RIO critical out-of-memory condition!\n");
                return;
        }

        p = w->data;
        p->co = co;
        queue_work(rio_workq, &w->work);
}

static void rio_dc_disconnect(struct RlnhLinkObj *co)
{
        struct rio_work *w;
        struct rio_work_disc *p;

        /*
         * This function can be called from atomic context, use pre-allocated
         * memory since kmalloc can't sleep...
         */
        w = seize_rio_work_disc(co, RIO_WORK_DC_DISC);
        if (w == NULL)
                return; /* Disconnect in progess, OK! */

        p = w->data;
        p->co = co;
        queue_work(rio_workq, &w->work);
}

int rio_submit_conn_pkt(struct RlnhLinkObj *co, struct net_device *dev,
                        struct sk_buff *skb)
{
        struct rio_work *w;
        struct rio_work_conn_pkt *p;

        /* Always called from Rx softirq... */
        w = alloc_rio_work(sizeof(*p), RIO_WORK_CONN_PKT, GFP_ATOMIC);
        if (w == NULL) {
                kfree_skb(skb);
                return -ENOMEM; /* Ok to drop, CONN pkts are sent unreliable! */
        }

        p = w->data;
        p->co = co;
        p->dev = dev;
        p->skb = skb;
        queue_work(rio_workq, &w->work);

        return 0;
}

int rio_submit_disconnect(struct RlnhLinkObj *co)
{
        struct rio_work *w;
        struct rio_work_disc *p;

        /*
         * This function can be called from atomic context, use pre-allocated
         * memory since kmalloc can't sleep...
         */
        w = seize_rio_work_disc(co, RIO_WORK_DISC);
        if (w == NULL)
                return -EALREADY; /* Disconnect in progess, OK! */

        p = w->data;
        p->co = co;
        queue_work(rio_workq, &w->work);

        return 0;
}

static int get_dc(const void *cookie, void **dc)
{
        extern int rio_dc_transmit(struct RlnhLinkObj *, uint32_t, uint32_t,
                                   uint32_t, uint32_t, void *);

        static struct RlnhLinkIF rio_dc = {
                RLNH_LINK_IF_VERSION,
                rio_dc_init,
                rio_dc_finalize,
                rio_dc_connect,
                rio_dc_disconnect,
                rio_dc_transmit
        };

        u64 *p;
        unsigned long ul;

        p = kmalloc(sizeof(*p), GFP_KERNEL); /* Note: DB calls kfree! */
        if (p == NULL)
                return -ENOMEM;

        ul = (unsigned long)&rio_dc;
        *p = (u64)ul;
        *dc = p;

        return (DB_TMP | DB_HEX | DB_UINT64);
}

static int __init rio_init(void)
{
        int status;

        spin_lock_init(&rio_lock);
        memset(rio_connection_array, 0, sizeof(rio_connection_array));
	generation = 1;

        INIT_LIST_HEAD(&rio_device_list);
        INIT_LIST_HEAD(&rio_orphan_list);

        init_waitqueue_head(&rio_waitq);

        rio_workq = create_singlethread_workqueue("rio");
        if (rio_workq == NULL)
                return -ENOMEM;

        status = register_netdevice_notifier(&rio_notifier);
        if (status < 0) {
                destroy_workqueue(rio_workq);
                return status;
        }

        db_add_template(DB_KEY_RIOCM, &rio_template);
        db_proc_add(DB_KEY_RIOCM);

        return 0;
}
module_init(rio_init);

static void __exit rio_fini(void)
{
        struct list_head *item, *tmp;
        struct rio_device *p;

        db_proc_del(DB_KEY_RIOCM);
        db_del_template(DB_KEY_RIOCM);

        unregister_netdevice_notifier(&rio_notifier);

        /*
         * At this point, no one is submitting jobs to the workqueue. Net events
         * are stopped and all connections are destroyed (module's use count is
         * used to make sure of this). It is safe to flush and destroy the work
         * queue.
         */
        flush_workqueue(rio_workq);
        destroy_workqueue(rio_workq);

        /*
         * One thing left, release all net devices that are stored in the list.
         * Normally, stop_/free_rio_device must not be used outside
         * the workqueue, but since it has been destroyed, it's ok to use them.
         */
        list_for_each_safe(item, tmp, &rio_device_list) {
                p = list_entry(item, struct rio_device, node);
                stop_rio_device(p);
                free_rio_device(p);
        }
}
module_exit(rio_fini);
