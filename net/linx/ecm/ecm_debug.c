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

#include <linux/ethcm_db_ioctl.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <ecm.h>
#include <ecm_proto.h>
#include <ecm_debug.h>

/*
 * =============================================================================
 * Some print functions...
 * =============================================================================
 */

void ecm_init_vbuf(struct ecm_vbuf *vbuf)
{
        vbuf->buf = (char *)__get_free_page(GFP_KERNEL);
        vbuf->writep = vbuf->buf;
        vbuf->count = PAGE_SIZE;
        *vbuf->writep = '\0';
}

void ecm_fini_vbuf(struct ecm_vbuf *vbuf)
{
        free_page((unsigned long)vbuf->buf);
        vbuf->count = 0;
}

void ecm_flush_vbuf(struct ecm_vbuf *vbuf)
{
        if (vbuf->count == PAGE_SIZE)
                return; /* Nothing to flush... */

        printk("%s", vbuf->buf);

        vbuf->writep = vbuf->buf;
        vbuf->count = PAGE_SIZE;
        *vbuf->writep = '\0';
}

int ecm_vbufprintf(struct ecm_vbuf *vbuf, const char *fmt, ...)
{
        va_list args;
        int n;

        if (vbuf->count == 0)
                ecm_flush_vbuf(vbuf); /* No space left, do a flush... */

        va_start(args, fmt);
        n = vsnprintf(vbuf->writep, vbuf->count, fmt, args);
        va_end(args);

        if (n < 0)
                return n;

        if (n >= vbuf->count) {
                *vbuf->writep = '\0'; /* Undo vsnprintf! */
                vbuf->count = 0;
                return -EAGAIN; /* Try again... */
        }

        vbuf->writep += n;
        vbuf->count -= n;
        return n;
}

/*
 * =============================================================================
 * Look for memory leaks...
 * =============================================================================
 */

struct ecm_kmalloc {
        struct list_head node;
        void *data;
        size_t size;
        int line;
        const char *file;
};

struct ecm_kmalloc_list {
        struct list_head list;
        spinlock_t list_lock;        
};

static struct ecm_kmalloc_list __ecm_kmalloc;

void ecm_kmalloc_init(void)
{
        INIT_LIST_HEAD(&__ecm_kmalloc.list);
        spin_lock_init(&__ecm_kmalloc.list_lock);
}

#define dump_list_entry(vbufp, p)                                          \
do {                                                                       \
        int n = ecm_vbufprintf(vbufp, "kmalloc(%u) at line %d, file %s\n", \
                               (unsigned)p->size, p->line, p->file);       \
        if (n == -EAGAIN)                                                  \
                ecm_vbufprintf(vbufp, "kmalloc(%u) at line %d, file %s\n", \
                               (unsigned)p->size, p->line, p->file);       \
} while (0)

void ecm_kmalloc_fini(void)
{
        struct ecm_vbuf vbuf;
        struct ecm_kmalloc *p;
        struct list_head *item, *tmp;

        ecm_init_vbuf(&vbuf);

        /*
         * Note: no need to lock, no more tracing when this function is
         *       called (module unloading).
         */
        list_for_each_safe(item, tmp, &__ecm_kmalloc.list) {
                p = list_entry(item, struct ecm_kmalloc, node);
                list_del(item);

                dump_list_entry(&vbuf, p);
                
                kfree(p->data);
                kfree(p);
        }

        ecm_flush_vbuf(&vbuf);
        ecm_fini_vbuf(&vbuf);
}

void *ecm_kmalloc(size_t size, gfp_t flags, const char *file, int line)
{
        struct ecm_kmalloc *p;
        void *q;

        p = kmalloc(sizeof(*p), flags);
        if (p == NULL)
                return NULL;

        q = kmalloc(size, flags);
        if (q == NULL) {
                kfree(p);
                return NULL;
        }        
        p->data = q;
        p->size = size;
        p->line = line;
        p->file = file;
        INIT_LIST_HEAD(&p->node);

        spin_lock_bh(&__ecm_kmalloc.list_lock);
        list_add(&p->node, &__ecm_kmalloc.list);
        spin_unlock_bh(&__ecm_kmalloc.list_lock);

        return p->data;
}

char *ecm_kstrdup(const char *s, gfp_t gfp, const char *file, int line)
{
        struct ecm_kmalloc *p;

        p = kmalloc(sizeof(*p), gfp);
        if (p == NULL)
                return NULL;

        p->data = kstrdup(s, gfp);
        if (p->data == NULL) {
                kfree(p);
                return NULL;
        }
        p->size = strlen(p->data) + 1;
        p->line = line;
        p->file = file;
        INIT_LIST_HEAD(&p->node);

        spin_lock_bh(&__ecm_kmalloc.list_lock);
        list_add(&p->node, &__ecm_kmalloc.list);
        spin_unlock_bh(&__ecm_kmalloc.list_lock);

        return p->data;
}

void *ecm_kzalloc(size_t size, gfp_t flags, const char *file, int line)
{
        struct ecm_kmalloc *p;
        void *q;

        p = kmalloc(sizeof(*p), flags);
        if (p == NULL)
                return NULL;

        q = kzalloc(size, flags);
        if (q == NULL) {
                kfree(p);
                return NULL;
        }        
        p->data = q;
        p->size = size;
        p->line = line;
        p->file = file;
        INIT_LIST_HEAD(&p->node);

        spin_lock_bh(&__ecm_kmalloc.list_lock);
        list_add(&p->node, &__ecm_kmalloc.list);
        spin_unlock_bh(&__ecm_kmalloc.list_lock);

        return p->data;
}

void ecm_kfree(void *obj)
{
        struct ecm_kmalloc *p;
        struct list_head *item, *tmp;

        spin_lock_bh(&__ecm_kmalloc.list_lock);
        list_for_each_safe(item, tmp, &__ecm_kmalloc.list) {
                p = list_entry(item, struct ecm_kmalloc, node);
                if (p->data == obj) {
                        list_del(item);
                        spin_unlock_bh(&__ecm_kmalloc.list_lock);
                        kfree(p->data);
                        kfree(p);
                        return;
                }
                spin_unlock_bh(&__ecm_kmalloc.list_lock);
                spin_lock_bh(&__ecm_kmalloc.list_lock);
        }
        spin_unlock_bh(&__ecm_kmalloc.list_lock);
}

/*
 * =============================================================================
 * Trace connection management
 * =============================================================================
 */

/*
 * Note: these macros and types are cut from ecm_conn.c, make sure that they
 *       correspond with the real ones in ecm_conn.c... We don't want to
 *       publish these definitions just for some debug functions...
 */
#define kptr(p, n) ((u8 *)(p) + (n))

#define STATE_DISCONNECTED 1
#define STATE_CONNECTING_0 2
#define STATE_CONNECTING_1 3
#define STATE_CONNECTING_2 4
#define STATE_CONNECTED    5

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
struct ecm_work_dc_disc {
        struct RlnhLinkObj *co;
};

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

#define ECM_WORK_INSMOD 9
struct ecm_work_insmod {
        int status;
};

#define ECM_WORK_RMMOD 10
struct ecm_work_rmmod {
        int status;
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
/* uses struct ecm_work_destroy */

struct ecm_work {
        int opcode;
        struct work_struct work;
        void *data;
};

static const char *netevent_tostr(unsigned long event)
{
        switch (event) {
        case NETDEV_REGISTER:    return "NETDEV_REGISTER";
        case NETDEV_UNREGISTER:  return "NETDEV_UNREGISTER";
	case NETDEV_UP:          return "NETDEV_UP";
        case NETDEV_DOWN:        return "NETDEV_DOWN";
	case NETDEV_REBOOT:      return "NETDEV_REBOOT";
	case NETDEV_CHANGE:      return "NETDEV_CHANGE";
	case NETDEV_CHANGEMTU:   return "NETDEV_CHANGEMTU";
	case NETDEV_CHANGEADDR:  return "NETDEV_CHANGEADDR";
	case NETDEV_CHANGENAME:  return "NETDEV_CHANGENAME";
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12))
	case NETDEV_FEAT_CHANGE: return "NETDEV_FEAT_CHANGE";
#endif
	case NETDEV_GOING_DOWN:  return "NETDEV_GOING_DOWN";
        default:                 return "UNKNOWN EVENT!!!";
        }
}

static const char *connpkt_tostr(struct sk_buff *skb)
{
        uint32_t conn_hdr;

	conn_hdr = ntoh_unaligned((uint32_t *)skb->data, CONN_HDR_OFFSET);
        switch (get_conn_type(conn_hdr)) {
        case CONN_CONNECT:     return "CONN_CONNECT";
	case CONN_CONNECT_ACK: return "CONN_CONNECT_ACK";
	case CONN_ACK:         return "CONN_ACK";
	case CONN_RESET:       return "CONN_RESET";
	default:               return "UNKNOWN CONN PKT!!!";
        }
}

static const char *state_tostr(int state)
{
        switch (state) {
        case STATE_DISCONNECTED: return "STATE_DISCONNECTED";
        case STATE_CONNECTING_0: return "STATE_CONNECTING_0";
        case STATE_CONNECTING_1: return "STATE_CONNECTING_1";
        case STATE_CONNECTING_2: return "STATE_CONNECTING_2";
        case STATE_CONNECTED:    return "STATE_CONNECTED";
        default:                 return "UNKNOWN STATE!!!";
        }
}

static void log_ecm_work_conn_pkt(struct ecm_vbuf *vbuf,
                                  struct ecm_work_conn_pkt *p)
{
        ecm_vbufprintf(vbuf, "Connection %s got %s on %s in state [%s]\n",
                       p->co->con_name, connpkt_tostr(p->skb), p->dev->name,
                       state_tostr(p->co->state));
}

static void log_ecm_work_net_event(struct ecm_vbuf *vbuf,
                                   struct ecm_work_net_event *p)
{
        ecm_vbufprintf(vbuf, "Got network event %s from %s\n",
                       netevent_tostr(p->event), p->dev->name);
}

static void log_ecm_work_create(struct ecm_vbuf *vbuf,
                                struct ecm_work_create *p)
{
        ecm_vbufprintf(vbuf, "Create connection %s\n",
                       kptr(p->arg, p->arg->name));
}

static void log_ecm_work_destroy(struct ecm_vbuf *vbuf,
                                 struct ecm_work_destroy *p)
{
        ecm_vbufprintf(vbuf, "Destroy connection %s in state [%s]\n",
                       p->co->con_name, state_tostr(p->co->state));
}

static void log_ecm_work_cleanup(struct ecm_vbuf *vbuf,
                                 struct ecm_work_destroy *p)
{
        ecm_vbufprintf(vbuf, "Cleanup connection %s in state [%s]\n",
                       p->co->con_name, state_tostr(p->co->state));
}

static void log_ecm_work_conn_tmo(struct ecm_vbuf *vbuf,
                                  struct ecm_work_conn_tmo *p)
{
        ecm_vbufprintf(vbuf, "Connection %s timed out in state [%s]\n",
                       p->co->con_name, state_tostr(p->co->state));
}

static void log_ecm_work_rmmod(struct ecm_vbuf *vbuf, struct ecm_work_rmmod *p)
{
        (void)p;
        ecm_vbufprintf(vbuf, "Remove ecm.ko\n");
}

static void log_ecm_work_dc_init(struct ecm_vbuf *vbuf,
                                 struct ecm_work_dc_init *p)
{
        ecm_vbufprintf(vbuf, "Connection %s got dc_init() in state [%s]\n",
                       p->co->con_name, state_tostr(p->co->state));
}

static void log_ecm_work_dc_conn(struct ecm_vbuf *vbuf,
                                 struct ecm_work_dc_conn *p)
{
        ecm_vbufprintf(vbuf, "Connection %s got dc_connect() in state [%s]\n",
                       p->co->con_name, state_tostr(p->co->state));
}

static void log_ecm_work_dc_disc(struct ecm_vbuf *vbuf,
                                 struct ecm_work_dc_disc *p)
{
        ecm_vbufprintf(vbuf, "Connection %s got dc_disconnect in state [%s]\n",
                       p->co->con_name, state_tostr(p->co->state));
}

static void log_ecm_work_dc_fini(struct ecm_vbuf *vbuf,
                                 struct ecm_work_dc_fini *p)
{
        ecm_vbufprintf(vbuf, "Connection %s got dc_finialize() in state [%s]\n",
                       p->co->con_name, state_tostr(p->co->state));
}

static void log_ecm_work_disc(struct ecm_vbuf *vbuf,
                              struct ecm_work_disc *p)
{
        ecm_vbufprintf(vbuf, "Connection %s got disc in state [%s]\n",
                       p->co->con_name, state_tostr(p->co->state));
}

static void log_unknown_ecm_work(struct ecm_vbuf *vbuf)
{
        ecm_vbufprintf(vbuf, "UNKNOWN ECM WORK!!!\n");
}

void log_ecm_work__(struct ecm_work *w)
{
        struct ecm_vbuf vbuf;

        ecm_init_vbuf(&vbuf);

        switch (w->opcode) {
        case ECM_WORK_CONN_PKT:  log_ecm_work_conn_pkt(&vbuf, w->data);  break;
        case ECM_WORK_NET_EVENT: log_ecm_work_net_event(&vbuf, w->data); break;
        case ECM_WORK_CREATE:    log_ecm_work_create(&vbuf, w->data);    break;
        case ECM_WORK_DESTROY:   log_ecm_work_destroy(&vbuf, w->data);   break;
        case ECM_WORK_CLEANUP:   log_ecm_work_cleanup(&vbuf, w->data);   break;
        case ECM_WORK_CONN_TMO:  log_ecm_work_conn_tmo(&vbuf, w->data);  break;
        case ECM_WORK_RMMOD:     log_ecm_work_rmmod(&vbuf, w->data);     break;
        case ECM_WORK_DC_INIT:   log_ecm_work_dc_init(&vbuf, w->data);   break;
        case ECM_WORK_DC_CONN:   log_ecm_work_dc_conn(&vbuf, w->data);   break;
        case ECM_WORK_DC_DISC:   log_ecm_work_dc_disc(&vbuf, w->data);   break;
        case ECM_WORK_DC_FINI:   log_ecm_work_dc_fini(&vbuf, w->data);   break;
        case ECM_WORK_DISC:      log_ecm_work_disc(&vbuf, w->data);      break;
        default:                 log_unknown_ecm_work(&vbuf);            break;
        }

        ecm_flush_vbuf(&vbuf);
        ecm_fini_vbuf(&vbuf);
}

/*
 * =============================================================================
 * Dissect Ethernet packets
 * =============================================================================
 */

void debug_print_pkt(struct sk_buff *skb)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22))
	struct ethhdr *eth_hdr = (struct ethhdr *)skb_mac_header(skb);
#else
	struct ethhdr *eth_hdr = (struct ethhdr *)skb->mac.raw;
#endif
	uint32_t main_hdr, hdr = 0;
	int next_hdr;
	void *x = (uint32_t *)skb->data;
	uint8_t *mac; 
	
	printk("Ethernet frame :\n");
	printk(" dst mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
	       eth_hdr->h_dest[0], eth_hdr->h_dest[1], eth_hdr->h_dest[2],
	       eth_hdr->h_dest[3], eth_hdr->h_dest[4], eth_hdr->h_dest[5]);
	printk(" src mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
	       eth_hdr->h_source[0], eth_hdr->h_source[1], eth_hdr->h_source[2],
	       eth_hdr->h_source[3], eth_hdr->h_source[4],
	       eth_hdr->h_source[5]);
	printk(" type : 0x%04x\n", ntohs(eth_hdr->h_proto));

	main_hdr = ntoh_unaligned(x, MAIN_HDR_OFFSET);
	
	printk(" ECM main hdr :\n");
	printk("  next : 0x%02x\n", get_next(main_hdr));
	printk("  ver : 0x%02x\n", get_ver(main_hdr));
	printk("  conn_id : 0x%02x\n", get_cid(main_hdr));

	next_hdr = get_next(main_hdr);
	while(next_hdr != HDR_NONE) {
		switch(next_hdr) {
		case HDR_CONN:
			hdr = ntoh_unaligned(x, CONN_HDR_OFFSET);
			printk("  ECM conn hdr :\n");
			printk("   type : 0x%x\n", get_conn_type(hdr));
			printk("   size : 0x%x\n", get_connect_size(hdr));
			printk("   winsize : 0x%x\n", get_window_size(hdr));
			printk("   conn id : 0x%x\n", get_publish_conn_id(hdr));
			mac = get_dst_hw_addr(x);
			printk("   dst mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
			       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
			mac = get_src_hw_addr(x);
			printk("   src mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
			       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
			printk("   feat str : \"%s\"\n", get_feat_str(x));
			break;
		case HDR_UDATA:
			hdr = ntoh_unaligned(x, UDATA_HDR_OFFSET);
			printk("  ECM udata hdr :\n");
                        printk("   ...\n");
			break;
		case HDR_FRAG:
			hdr = ntoh_unaligned(x, FRAG_HDR_OFFSET);
			printk("  ECM frag hdr :\n");
			printk("   ...\n");
			break;
		case HDR_ACK:
			hdr = ntoh_unaligned(x, ACK_HDR_OFFSET);
			printk("  ECM ack hdr :\n");
			printk("   request : %d\n", get_request(hdr));
			printk("   ackno : %d\n", get_ackno(hdr));
			printk("   seqno : %d\n", get_seqno(hdr));
			break;
		case HDR_NACK:
			hdr = ntoh_unaligned(x, NACK_HDR_OFFSET);
			printk("  ECM nack hdr :\n");
			printk("   ...\n");
			break;
		default:
			printk("   msg type not recognized (%d)\n", next_hdr);
		}
		next_hdr = get_next(hdr);
	}
}
