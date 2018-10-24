/*
 *  Copyright (c) 2006-2007, Enea Software AB .
 *
 *  This driver was evolved from the dummy network driver in linux written
 *  by Nick Holloway, 27th May 1994.
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

#include <linux/ctype.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/if_arp.h>
#include <linux/version.h>

#define ARPHRD_LINX	0x8911

#ifdef LINXTRACE_DBG
#define DBGPRINTK(f, ...) printk(f, ## __VA_ARGS__)
#define DUMP_HEX_AND_ASCII(b, l) dump_hex_and_ascii(b, l)

static void dump_hex_and_ascii(const uint8_t * buf, int size)
{
	int i;

	for (i = 0; i < size; i += 16) {
		int j;

		for (j = 0; j < 16 && j + i < size; j++)
			printk("%02x ", buf[j + i]);

		for (j *= 3; j < 52; j++)
			printk(" ");

		printk("\"");
		for (j = 0; j < 16 && j + i < size; j++)
			if (isprint(buf[i + j]))
				printk("%c", buf[i + j]);
			else
				printk(".");
		printk("\"\n");
	}
}

#else
#define DBGPRINTK(f, ...) do {} while (0)
#define DUMP_HEX_AND_ASCII(b, l) do {} while (0)
#endif

struct linxhdr {
	uint32_t h_src;
	uint32_t h_dst;
	uint32_t h_len;
	uint32_t h_pad;
};

#define LINXTRACE_HLEN	sizeof(struct linxhdr)
#define LINXTRACE_ALEN	4

static int numlinxifs = 1;

static int linxtrace_xmit(struct sk_buff *skb, struct net_device *dev);
static struct net_device_stats *linxtrace_get_stats(struct net_device *dev);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
int linxtrace_header(struct sk_buff *skb, struct net_device *dev,
		     unsigned short type, const void *daddr,
		     const void *saddr, uint32_t len)
#else
int linxtrace_header(struct sk_buff *skb, struct net_device *dev,
		     unsigned short type, void *daddr,
		     void *saddr, uint32_t len)
#endif
{
	struct linxhdr *lh = (struct linxhdr *)skb_push(skb, LINXTRACE_HLEN);

	DBGPRINTK("TRACEIF enter linxtrace_header(%p, %p, %hu, %x, %x, %d)\n",
		  skb, dev, type, *(unsigned *)daddr, *(unsigned *)saddr, len);

	DBGPRINTK("TRACEIF len:%d head:%p data:%p tail:%p end:%p\n",
		  skb->len, skb->head, skb->data, skb->tail, skb->end);

	lh->h_src = *(uint32_t *) saddr;
	lh->h_dst = *(uint32_t *) daddr;
	lh->h_len = len;

	DUMP_HEX_AND_ASCII(skb->data, skb->len);
	DBGPRINTK("TRACEIF leave linxtrace_header\n");

	return LINXTRACE_HLEN;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
int linxtrace_header_cache(const struct neighbour *neigh, struct hh_cache *hh)
#else
int linxtrace_header_cache(struct neighbour *neigh, struct hh_cache *hh)
#endif
{
	DBGPRINTK("TRACEIF enter linxtrace_header_cache\n");
	DBGPRINTK("TRACEIF leave linxtrace_header_cache\n");
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
void linxtrace_header_cache_update(struct hh_cache *hh,
				   const struct net_device *dev,
				   const unsigned char *haddr)
#else
void linxtrace_header_cache_update(struct hh_cache *hh,
				   struct net_device *dev, unsigned char *haddr)
#endif
{
	DBGPRINTK("TRACEIF enter linxtrace_header_cache_update\n");
	DBGPRINTK("TRACEIF leave linxtrace_header_cache_update\n");
}

static int linxtrace_set_address(struct net_device *dev, void *p)
{
	struct sockaddr *sa = p;

	DBGPRINTK("TRACEIF enter linxtrace_set_address\n");
	if (!is_valid_ether_addr(sa->sa_data))
		return -EADDRNOTAVAIL;

	memcpy(dev->dev_addr, sa->sa_data, ETH_ALEN);

	DBGPRINTK("TRACEIF leave linxtrace_set_address\n");
	return 0;
}

/* fake multicast ability */
static void linxtrace_set_multicast_list(struct net_device *dev)
{
	DBGPRINTK("TRACEIF enter linxtrace_set_multicast_list\n");
	DBGPRINTK("TRACEIF enter linxtrace_set_multicast_list\n");
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)

static const struct header_ops linxtrace_hard_header_ops = {
	.create = linxtrace_header,
	.parse = NULL,		/* ..or eth_header_parse? */
	.rebuild = NULL,
	.cache = linxtrace_header_cache,
	.cache_update = linxtrace_header_cache_update,
};

/* SET_MODULE_OWNER is a no-op in 2.6.23 already */
#define SET_MODULE_OWNER(dev) do { } while (0)

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
static const struct net_device_ops linxtrace_net_device_ops = {
	.ndo_get_stats = linxtrace_get_stats,
	.ndo_start_xmit = linxtrace_xmit,
	.ndo_set_multicast_list = linxtrace_set_multicast_list,
	.ndo_set_mac_address = linxtrace_set_address,
	.ndo_change_mtu = NULL,
};
#endif

static void __init linxtrace_setup(struct net_device *dev)
{
	DBGPRINTK("TRACEIF enter linxtrace_setup\n");

	/* Initialize the device structure. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
	dev->netdev_ops = &linxtrace_net_device_ops;
#else
	dev->get_stats = linxtrace_get_stats;
	dev->hard_start_xmit = linxtrace_xmit;
	dev->set_multicast_list = linxtrace_set_multicast_list;
	dev->set_mac_address = linxtrace_set_address;
	dev->change_mtu = NULL;
#endif
	/* Fill in device structure with ethernet-generic values. */
	/* We don't want our trace device to have ethernet properties
	 * since we don't want to mess with ethernet headers for
	 * internal messages. */
	dev->mtu = (64 * 1024) + 20 + LINXTRACE_HLEN;	/* LINX constraints */
	dev->tx_queue_len = 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	dev->hard_header = linxtrace_header;
	dev->hard_header_cache = linxtrace_header_cache;
	dev->header_cache_update = linxtrace_header_cache_update;
	dev->rebuild_header = NULL;
#else
	dev->header_ops = &linxtrace_hard_header_ops;
#endif
	dev->hard_header_len = LINXTRACE_HLEN;
	dev->addr_len = LINXTRACE_ALEN;
	dev->features = NETIF_F_NO_CSUM | NETIF_F_HIGHDMA | NETIF_F_LLTX;
	dev->type = ARPHRD_LINX;
	dev->tx_queue_len = 0;
	dev->flags |= IFF_NOARP;
	dev->flags &= ~IFF_MULTICAST;
	SET_MODULE_OWNER(dev);
	random_ether_addr(dev->dev_addr);

	DBGPRINTK("TRACEIF leave linxtrace_setup\n");
}

static int linxtrace_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct net_device_stats *stats = netdev_priv(dev);

	DBGPRINTK("TRACEIF enter linxtrace_xmit\n");
	DUMP_HEX_AND_ASCII(skb->data, skb->len);
	stats->tx_packets++;
	stats->tx_bytes += skb->len;
	DBGPRINTK("TRACEIF, free temp trace skb.\n");
	dev_kfree_skb(skb);
	DBGPRINTK("TRACEIF leave linxtrace_xmit\n");
	return 0;
}

static struct net_device_stats *linxtrace_get_stats(struct net_device *dev)
{
	DBGPRINTK("TRACEIF enter linxtrace_get_stats\n");
	DBGPRINTK("TRACEIF leave linxtrace_get_stats\n");
	return netdev_priv(dev);
}

static struct net_device **linxifs;

/* Number of linxtrace devices to be set up by this module. */
module_param(numlinxifs, int, 0);
MODULE_PARM_DESC(numlinxifs, "Number of linxtrace pseudo devices");

static int __init linxtrace_init_one(int index)
{
	struct net_device *dev_linxtrace;
	int err;

	DBGPRINTK("TRACEIF enter linxtrace_init_one\n");

	dev_linxtrace = alloc_netdev(sizeof(struct net_device_stats),
				     "linx%d", linxtrace_setup);
	if (!dev_linxtrace)
		return -ENOMEM;

	if ((err = register_netdev(dev_linxtrace))) {
		DBGPRINTK("TRACEIF after register_netdev error\n");
		free_netdev(dev_linxtrace);
		dev_linxtrace = NULL;
	} else {
		DBGPRINTK("TRACEIF after register_netdev ok\n");
		linxifs[index] = dev_linxtrace;
	}

	DBGPRINTK("TRACEIF leave linxtrace_init_one\n");

	return err;
}

static void linxtrace_free_one(int index)
{
	DBGPRINTK("TRACEIF enter linxtrace_free_one\n");

	unregister_netdev(linxifs[index]);
	free_netdev(linxifs[index]);

	DBGPRINTK("TRACEIF leave linxtrace_free_one\n");
}

static int __init linxtrace_init_module(void)
{
	int i, err = 0;
	linxifs = kmalloc(numlinxifs * sizeof(void *), GFP_KERNEL);
	if (!linxifs)
		return -ENOMEM;
	for (i = 0; i < numlinxifs && !err; i++)
		err = linxtrace_init_one(i);
	if (err) {
		while (--i >= 0)
			linxtrace_free_one(i);
	}
	return err;
}

static void __exit linxtrace_cleanup_module(void)
{
	int i;
	for (i = 0; i < numlinxifs; i++)
		linxtrace_free_one(i);
	kfree(linxifs);
}

module_init(linxtrace_init_module);
module_exit(linxtrace_cleanup_module);
MODULE_LICENSE("GPL");
