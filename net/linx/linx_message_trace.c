/*
 *  Copyright (c) 2006-2007, Enea Software AB .
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <af_linx.h>
#include <linux/compiler.h>
#include <linux/ctype.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linx_assert.h>
#include <linx_trace.h>
#include <linx_message_trace.h>
#include <linx_mem.h>
#include <linux/version.h>
#include <buf_types.h>

#define ETH_UP	 1
#define ETH_DOWN 2

struct linxhdr {
	uint32_t h_src;
	uint32_t h_dst;
	uint32_t h_len;
	uint32_t h_pad;
};

#define LINXTRACE_HLEN sizeof(struct linxhdr)
#define ARPHRD_LINX	0x8911	/* the linxtrace driver */

LIST_HEAD(linx_device);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22))
#define LINX_SKB_RESET_NETWORK_HEADER(skb) (skb_reset_network_header(skb))
#else
#define LINX_SKB_RESET_NETWORK_HEADER(skb) ((skb)->nh.raw = (skb)->data)
#endif

struct linx_trace_dev {
	struct list_head node;
	int state;
	struct net_device *dev;
	uint32_t dev_clients;
	struct packet_type pt;
};

static struct linx_trace_dev *linxdev;

static int
dev_notification(struct notifier_block *nb, unsigned long evt, void *dv);

static int disconnect_device(struct net_device *dev);

static int unregister_device(struct net_device *dev);

void
linx_message_trace(void *buf, LINX_OSBUFSIZE size, struct sock *to,
		   LINX_SPID to_spid, LINX_SPID from_spid,
		   uint32_t buffer_type)
{
	int err;
	struct sk_buff *skb;
        void *skb_data_buffer;
        unsigned int flags;

	LINX_ASSERT(buf);
	LINX_ASSERT(to);
	LINX_ASSERT(to_spid != LINX_ILLEGAL_SPID);
	LINX_ASSERT(from_spid != LINX_ILLEGAL_SPID);

	linx_debug(LINX_TRACEGROUP_TRACE_MSG,
		   "LINXTRACE enter linx_message_trace "
		   "%p, %d, %p, %x, %x, %d",
		   buf, size, to, from_spid, to_spid, buffer_type);

        if ((linxdev == NULL) || (linxdev->state != ETH_UP))
                goto out;

        linx_debug(LINX_TRACEGROUP_TRACE_MSG, "linx trace device is up "
                   "... continue.\n");

        flags = in_atomic() ? GFP_ATOMIC : 0;

        if (!BUF_TYPE_SKB(buffer_type)) {
                linx_debug(LINX_TRACEGROUP_TRACE_MSG, "LINXTRACE alloc %lu "
                           "bytes.\n", (unsigned long)LINXTRACE_HLEN + size);

                skb = alloc_skb(LINXTRACE_HLEN + size, flags);
                if (unlikely(skb == NULL)) {
                        linx_err("linx_message_trace: out of memory");
                        goto out;
                }
        } else {
                linx_debug(LINX_TRACEGROUP_TRACE_MSG, "LINXTRACE copy skb for "
                           "trace dev.\n");

                if (skb_shinfo((struct sk_buff *)buf)->frag_list == NULL) {
                        skb = skb_copy_expand(buf, LINXTRACE_HLEN, 0, flags);
                        if (unlikely(skb == NULL)) {
                                linx_err("linx_message_trace: out of memory");
                                goto out;
                        }
                } else {
                        skb = pskb_copy(buf, flags);
                        if (unlikely(skb == NULL)) {
                                linx_err("linx_message_trace: out of memory");
                                goto out;
                        }
                        skb->data_len = size - skb->len;
                        skb->len = size;
                        if (pskb_expand_head(skb, LINXTRACE_HLEN, 0, flags) != 0)
                        {
                                kfree_skb(skb);
                                linx_err("linx_message_trace: expand failed");
                                goto out;
                        }
                }
                *((LINX_SIGSELECT *) (skb->data)) =
                        ((struct linx_skb_cb *)skb->cb)->signo;
        }

        skb->dev = linxdev->dev;

        if (BUF_TYPE_SKB(buffer_type)) {
                LINX_SKB_RESET_NETWORK_HEADER(skb);
        } else {
                skb_reserve(skb, LINXTRACE_HLEN);
                LINX_SKB_RESET_NETWORK_HEADER(skb);

                /* Make room for the header and payload data. */
                skb_data_buffer = skb_put(skb, size);

                /* First try to copy the signal from user space. */
                if (BUF_TYPE_KERN(buffer_type)) {
                        memcpy(skb_data_buffer, buf, size);
                } else {
                        struct iovec iov;

                        iov.iov_base = buf;
                        iov.iov_len = size;
                        LINX_ASSERT(BUF_TYPE_USER(buffer_type));
                        err = memcpy_fromiovec(skb_data_buffer, &iov, size);
                        if (unlikely(err != 0)) {
                                kfree_skb(skb);
                                linx_err("linx_message_trace: failed to copy "
                                         "iovec to kernel, err=%d", err);
                                goto out;
                        }
                }
        }

#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
        linxdev->dev->hard_header(skb, linxdev->dev, 0x8911, &to_spid,
                                  &from_spid, skb->len);
#else
        dev_hard_header(skb, linxdev->dev, 0x8911, &to_spid, &from_spid,
                        skb->len);
#endif
        dev_queue_xmit(skb);
  out:
	linx_debug(LINX_TRACEGROUP_TRACE_MSG, "LINXTRACE leave "
                   "linx_message_trace()\n");
}

/* Notifier callback for LINX message trace device. */
static struct notifier_block linx_message_trace_dev_notifier = { 0, 0, 0, };

int linx_message_trace_init(void)
{
	linxdev = NULL;

	/* Add the notification interface, it is needed to handle
	 * state changes of the device and to detect new device. */
	linx_message_trace_dev_notifier.notifier_call = &dev_notification;
	return register_netdevice_notifier(&linx_message_trace_dev_notifier);
}

int linx_message_trace_exit(void)
{
	struct list_head *node, *tmp;
	int ret;

	/* Traverse the list to make sure the device is not already
	 * registered. */
	list_for_each_safe(node, tmp, &linx_device) {
		disconnect_device(((struct linx_trace_dev *)node)->dev);
		unregister_device(((struct linx_trace_dev *)node)->dev);
	}

	ret = unregister_netdevice_notifier(&linx_message_trace_dev_notifier);

	return ret;
}

static struct linx_trace_dev *find_device_object(struct net_device *dev)
{
	struct list_head *tr_dev;

	linx_debug(LINX_TRACEGROUP_TRACE_MSG, "%p", dev);

	/* Traverse the list to make sure the device is not already
	   registered. */
	list_for_each(tr_dev, &linx_device) {
		if (dev == ((struct linx_trace_dev *)tr_dev)->dev)
			return (struct linx_trace_dev *)tr_dev;
	}

	return NULL;
}

static int register_device(struct net_device *dev)
{
	struct linx_trace_dev *tr_tmp;
	struct linx_trace_dev *tr_dev = linx_kmalloc(sizeof(*tr_dev));

	linx_debug(LINX_TRACEGROUP_TRACE_MSG, "dev name %s", dev->name);

	if (tr_dev == NULL) {
		linx_err("Failed to allocate trace device object.");
		return NOTIFY_OK;
	}

	INIT_LIST_HEAD(&tr_dev->node);
	tr_dev->state = ETH_DOWN;
	tr_dev->dev = dev;
	tr_dev->dev_clients = 0;

	/* Traverse the list to make sure the device is not already
	 * registered. */
	tr_tmp = find_device_object(dev);
	if (tr_tmp == NULL) {
		list_add(&(tr_dev->node), &linx_device);

		/* This hold is neuturalized by a unregister_device
		 * call. */
		dev_hold(dev);
	} else {
		linx_kfree(tr_dev);
	}

	return NOTIFY_OK;
}

static int connect_device(struct net_device *dev)
{
	struct linx_trace_dev *tr_dev;

	linx_debug(LINX_TRACEGROUP_TRACE_MSG, "dev name %s", dev->name);

	tr_dev = find_device_object(dev);
	if (tr_dev == NULL) {
		linx_err("find_device_object() failed.");
		return NOTIFY_OK;
	}
	if (tr_dev->state != ETH_UP) {
		tr_dev->state = ETH_UP;
		linxdev = tr_dev;
	}

	return NOTIFY_OK;
}

static int disconnect_device(struct net_device *dev)
{
	struct linx_trace_dev *tr_dev;

	linx_debug(LINX_TRACEGROUP_TRACE_MSG, "dev name %s", dev->name);

	/* Find the device object. */
	tr_dev = find_device_object(dev);
	if (tr_dev == NULL)
		goto disconnect_device_done;

	if (tr_dev->state == ETH_DOWN)
		goto disconnect_device_done;

	tr_dev->state = ETH_DOWN;
	linxdev = NULL;

      disconnect_device_done:
	return NOTIFY_OK;
}

static int unregister_device(struct net_device *dev)
{
	struct linx_trace_dev *tr_dev;

	linx_debug(LINX_TRACEGROUP_TRACE_MSG, "dev name %s", dev->name);

	/* Traverse the list to find the device. */
	tr_dev = find_device_object(dev);
	LINX_ASSERT(tr_dev != NULL);

	/* Remove the device object from the deive list. */
	list_del(&tr_dev->node);

	dev_put(tr_dev->dev);
	linx_kfree(tr_dev);

	return NOTIFY_OK;
}

static int
dev_notification(struct notifier_block *nb, unsigned long evt, void *dv)
{
	struct net_device *dev = (struct net_device *)dv;

	linx_debug(LINX_TRACEGROUP_TRACE_MSG,
		   "evt %lu dv:0x%p device_name:%s flags:0x%x",
		   evt, dev, dev->name, dev->flags);

	if (dev->type != ARPHRD_LINX)	/* only care about linxtrace */
		return NOTIFY_OK;

	switch (evt) {
	case NETDEV_UP:
		register_device(dev);
		return connect_device(dev);

	case NETDEV_DOWN:
		unregister_device(dev);
		return disconnect_device(dev);
	}
	return NOTIFY_DONE;
}
