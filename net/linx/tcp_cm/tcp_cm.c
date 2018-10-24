/*
 * Copyright (c) 2006-2011, Enea Software AB
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

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/linx_ioctl.h>
#include <linux/list.h>
#include <linux/version.h>
#include <linux/random.h>
#include <linux/err.h>

#include <asm/ioctls.h>

#include <linux/in6.h>
#include <net/ipv6.h>

#include <net/ip.h>
#include <net/sock.h>
#include <net/tcp.h>

#include <rlnh.h>
#include <linx_trace.h>
#include <buf_types.h>
#include <cfg/db.h>
#include <cfg/db_proc.h>
#include <linux/tcpcm_db_ioctl.h>
#include <rlnh/rlnh_link.h>

static int __init tcp_cm_module_init(void);
static void __exit tcp_cm_module_fini(void);

module_init(tcp_cm_module_init);
module_exit(tcp_cm_module_fini);

MODULE_AUTHOR("ENEA");
MODULE_DESCRIPTION("LINX TCP CM: TCP Connection Manager for Linx");
MODULE_LICENSE("GPL");
MODULE_VERSION(LINX_VERSION);

/* default values for module parameters */
#define MAX_WQ_LEN 0xffff
#define MAX_SEND_QUEUE 0xffffffff
#define CONN_PORT 19790
#define CONN_PORT6 19791

int linx_tcp_cm_max_wq_len = MAX_WQ_LEN;
module_param(linx_tcp_cm_max_wq_len, int, S_IRUGO);
MODULE_PARM_DESC(linx_tcp_cm_max_wq_len, "Max length of tcp cm workqueue");

int linx_tcp_cm_max_send_queue = MAX_SEND_QUEUE;
module_param(linx_tcp_cm_max_send_queue, int, S_IRUGO);
MODULE_PARM_DESC(linx_tcp_cm_max_send_queue, "Max length of send queue");

int linx_tcp_cm_port = CONN_PORT;
module_param(linx_tcp_cm_port, int, S_IRUGO);
MODULE_PARM_DESC(linx_tcp_cm_port, "Connect port of the LINX TCP CM");

int linx_tcp_cm_port6 = CONN_PORT6;
module_param(linx_tcp_cm_port6, int, S_IRUGO);
MODULE_PARM_DESC(linx_tcp_cm_port6, "Connect port of the LINX TCP CM IPv6");

int linx_tcp_cm_ipv6_support = 0;
module_param(linx_tcp_cm_ipv6_support, int, S_IRUGO);
MODULE_PARM_DESC(linx_tcp_cm_ipv6_support, "LINX TCP CM IPv6 support");

/* defines */
#define PROTO_V 3
#define OOB_BIT 0x00008000
#define DEF_LIVE_TMO      1000
#define LINX_SKB_MAX_SIZE 65536
#define CO_VECTOR_INC 8

/* connection object states */
#define STATE_READY 0
#define STATE_ACTIVE_CONNECT 1
#define STATE_PASSIVE_CONNECT 2
#define STATE_CONNECTED 3
#define STATE_DISCONNECTED 4  /* disconnected, uc done, but may connect again */
#define STATE_FINALIZED 5      /* ready for finalize, will not reconnect */

/* header types, 0x0 is reserved for errors! */
#define TCP_CONN  0x43
#define TCP_UDATA 0x55
#define TCP_PING  0x50
#define TCP_PONG  0x51

#define IPV6CONN(arg) ((arg)->remote_ip == 0xffffffff)
#define IPV4CONN(arg) ((arg)->remote_ip != 0xffffffff)
#define KMALLOC(arg) kmalloc(arg, GFP_KERNEL)
#define KMALLOC_ATOMIC(arg) kmalloc(arg, GFP_ATOMIC)
#define KFREE(arg) kfree(arg)
#define SOCK_ACCEPT(s, new, flags) (s->ops->accept(s, new, flags))
#define SOCK_BIND(s, a, alen) (s->ops->bind(s, a, alen))
#define SOCK_CONNECT(s, a, alen, flags) (s->ops->connect(s, a, alen, flags))
#define SOCK_LISTEN(s, backlog) (s->ops->listen(s, backlog))
#define SOCK_OPEN(s) (sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, s))
#define SOCK_OPEN6(s) (sock_create_kern(PF_INET6, SOCK_STREAM, IPPROTO_TCP, s))
#define SOCK_CLOSE(s) (sock_release(s))
#define SOCK_IS_CONNECTED(s) (s->sk->sk_state & TCP_ESTABLISHED)
#define SOCK_IS_CONNECTING(s) (s->sk->sk_state & TCP_SYN_SENT)
#define CONNECTED(co) (co)->rlnh_upcalls->connected((co)->rlnh_obj_p)
#define DISCONNECTED(co) (co)->rlnh_upcalls->disconnected((co)->rlnh_obj_p)
#define DELIVER(co, d) \
        (co)->rlnh_upcalls->deliver((co)->rlnh_obj_p, (d)->buf_type, (d)->src, \
                                                (d)->dst, (d)->size, (d)->skb)

/* one global needed here */
static atomic_t wq_len = ATOMIC_INIT(0);

#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20))
#define WQ_TYPE void
#define WQ_GETARG(arg, type) (arg)
#define TCM_INIT_WORK(work,func,arg) INIT_WORK(work,func,arg)
#else
#define WQ_TYPE struct work_struct
#define WQ_GETARG(arg, type) container_of(arg, type, work)
#define TCM_INIT_WORK(work,func,arg) INIT_WORK(work,func)
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22))
#define IN6ADDR_ANY_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
#define sk_sleep(sk) (sk)->sk_sleep
#endif

struct header {
	uint32_t type_version;
	uint32_t src;
	uint32_t dst;
	uint32_t size;
};
#define HLEN (sizeof (struct header))

struct RlnhLinkObjStats {
	unsigned long recv_udata_bytes;
	unsigned long sent_udata_bytes;
	unsigned long send_qlen;
	unsigned long sent_msgs;
	unsigned long received_msgs;
};

struct RlnhLinkObj {
	struct RlnhLinkUCIF *rlnh_upcalls;
	LINX_RLNH rlnh_obj;
	void *rlnh_obj_p;
	uint32_t state;
	unsigned long port;
	unsigned long peer_port;
	unsigned long peer_version;
	uint32_t index;
	uint32_t remote_ip;
	uint32_t ipv6_scope;
	struct in6_addr remote_ipv6;
	struct socket *sock;
	pid_t rx_pid;
	struct completion rx_up;
	struct completion rx_run;
	struct completion rx_done;
	struct completion ready_for_destroy;
	int alive;
	int use_nagle;
	struct RlnhLinkObjStats stats;
	struct list_head transfer_queue;
	struct list_head timer_tasks;
	uint32_t transfer_qlen;
	unsigned long live_tmo;
        char *con_name;
        uint64_t con_cookie;
};

/* transfer data */
struct t_data {
	char *pos;
	char *data;		/* used for submission */
	uint8_t peer_version;   /* used in rx_read for traffic_connect_task */
	uint32_t src;
	uint32_t dst;
	uint32_t size;
	uint32_t remaining;
	uint32_t buf_type;
	struct sk_buff *skb;	/* used for retrieval */
	struct list_head head;
};

struct wq_task_object {
	struct work_struct work;
	uint32_t index;
	void (*func) (struct wq_task_object *w, struct RlnhLinkObj *co);
	struct t_data *trans_data;
};

struct wq_timer_data {
	struct wq_task_object *w;
	struct timer_list timer;
	struct list_head head;
};

/*
 * this object is only used for submission of the socket to the co and
 * the rx-thread of the co
 */
struct sock_object {
	struct socket *s;
	uint32_t peer_ip;
	struct in6_addr peer_ipv6;
	struct list_head head;
};

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
struct pid *find_pid(int nr)
{
        extern struct pid_namespace init_pid_ns;
        struct pid *pid;
        rcu_read_lock();
        pid = find_pid_ns(nr, &init_pid_ns);
        rcu_read_unlock();
        return pid;
}

int kill_proc(pid_t pid, int sig, int priv)
{
	return kill_pid(find_pid(pid), SIGINT, 0);
}
#endif

#define uptr(p, n) ((u8 __user *)(p) + (n))
#define kptr(p, n) ((u8 *)(p) + (n))

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 13))
static char *linx_kstrdup(const char *s, unsigned int gfp)
{
        size_t len;
        char *p;

        if (s == NULL)
                return NULL;

        len = strlen(s) + 1;
        p = kmalloc(len, gfp);
        if (p == NULL)
                return NULL;

        return memcpy(p, s, len);
}
#else
#define linx_kstrdup kstrdup
#endif

static int get_dc(const void *cookie, void **dc);

static const struct db_param tcp_cm_params[] = {
	DB_PARAM("con_name", DB_PTR | DB_STRING, con_name,
		 struct RlnhLinkObj),
        DB_PARAM("con_cookie", DB_HEX | DB_UINT64, con_cookie,
		 struct RlnhLinkObj),
        DB_META_PARAM("con_dc", DB_HEX | DB_UINT64,
		      sizeof(u64), 1, get_dc, NULL),
	DB_PARAM("peer_ip", DB_UINT32, remote_ip, struct RlnhLinkObj),
	DB_PARAM("peer_ipv6", DB_UINT64, remote_ipv6, struct RlnhLinkObj),
	DB_PARAM("port", DB_ULONG, port, struct RlnhLinkObj),
	DB_PARAM("peer_port", DB_ULONG, peer_port, struct RlnhLinkObj),
	DB_PARAM("peer_version", DB_ULONG, peer_version, struct RlnhLinkObj),
	DB_PARAM("live_tmo", DB_ULONG, live_tmo, struct RlnhLinkObj),
	DB_PARAM("bytes_recv", DB_ULONG, stats.recv_udata_bytes,
		 struct RlnhLinkObj),
	DB_PARAM("bytes_sent", DB_ULONG, stats.sent_udata_bytes,
		 struct RlnhLinkObj),
	DB_PARAM("bytes_in_send_queue", DB_ULONG, stats.send_qlen,
		 struct RlnhLinkObj),
	DB_PARAM("sent_messages", DB_ULONG, stats.sent_msgs,
		 struct RlnhLinkObj),
	DB_PARAM("received_messages", DB_ULONG, stats.received_msgs,
		 struct RlnhLinkObj),
	DB_PARAM("state", DB_UINT32, state, struct RlnhLinkObj),
        DB_PARAM_END
};

static void *tcp_cm_create(void __user *arg);
static int tcp_cm_delete(void *cookie, void __user *arg);

static const struct db_template tcp_cm_template = {
        .owner = THIS_MODULE,
        .create = tcp_cm_create,
        .destroy = tcp_cm_delete,
        .param = tcp_cm_params
};

/* globals */
static pid_t listen_pid;
static struct completion listen_done;
static pid_t listen_v6_pid;
static struct completion listen_v6_done;

static struct workqueue_struct *tcp_cm_wq;
static spinlock_t tcp_cm_rx_list_lock;
static spinlock_t timer_tasks_lock;
static struct list_head linx_tcp_socks;
static spinlock_t co_vector_lock;
static struct RlnhLinkObj **co_vector;
static int co_vector_len;

/* Macros */
#define GET_STATE(co) ((co)->state & 0x7)
#define INCONSISTENT(arg) do { \
        linx_err("Inconsistent state: %o for %d,(%p)", \
                 (arg)->state & 0x3FFFFFFF, (arg)->index, (arg)); \
        } while (0)

#if 0
#define ERROR_ON(arg) BUG_ON(arg)
#define ERROR() BUG()
#else
#define ERROR_ON(arg) do { if (arg) dump_stack(); } while (0)
#define ERROR() dump_stack()
#endif

#if 0
#define TCPCMDBG(fmt, args...) \
        printk("tcp_cm:%s:%d " fmt "\n", __FUNCTION__,__LINE__, ##args)
#else
#define TCPCMDBG(fmt, args...)
#endif
/* previous states are saved for debug reasons */
#define SET_STATE(co, s) do { \
        TCPCMDBG("STATE CHANGE %d,(%p), %o: %d", \
        (co)->index, (co), (co)->state & 0x3FFFFFFF, (s)); \
        (co)->state <<= 3; \
        (co)->state |= ((s) & 0x7);} while(0);

/* some forward declarations */
static void linx_transmit_task(struct wq_task_object *w,struct RlnhLinkObj *co);
static void retry_connect_task(struct wq_task_object *w,struct RlnhLinkObj *co);
static void traffic_data_task(struct wq_task_object *w, struct RlnhLinkObj *co);
static int rx(void *p);
static void wqo_free(struct wq_task_object *w);
static void wq_cancel_delayed_tasks(struct RlnhLinkObj *co);

/* helper functions */
static void
set_sockaddr(struct sockaddr_in *s, unsigned long ip, uint16_t p)
{
	memset(s, 0, sizeof(*s));
	s->sin_family = AF_INET;
	s->sin_addr.s_addr = ip;
	s->sin_port = p;
}

static void
set_sockaddr6(struct sockaddr_in6 *s, struct in6_addr *ip6,
	      uint32_t scope, uint16_t p)
{
	memset(s, 0, sizeof(*s));
	s->sin6_family = AF_INET6;
	s->sin6_port = p;
	s->sin6_flowinfo = 0;
	memcpy(&s->sin6_addr, ip6, sizeof(*ip6));
	s->sin6_scope_id = scope;
}

static uint32_t get_ip(struct socket *s)
{
	int len, err;
	struct sockaddr_in a;
	memset(&a, 0, sizeof(a));
	len = sizeof(a);

	err = s->ops->getname(s, (struct sockaddr *)&a, &len, 1);
	if (err < 0)
		return 0;
	else
		return a.sin_addr.s_addr;
}

static void get_ip6(struct socket *s, struct in6_addr *ip)
{
	int len, err;
	struct sockaddr_in6 a;
	memset(&a, 0, sizeof(a));
	len = sizeof(a);

	err = s->ops->getname(s, (struct sockaddr *)&a, &len, 1);
	if (err < 0)
		memset(ip, 0xff, sizeof(a));
	else
		memcpy(ip, &a.sin6_addr, sizeof(a));
}

static int get_port_he(struct socket *s, int for_peer)
{
	int len, err;
	struct sockaddr_in a;
	memset(&a, 0, sizeof(a));
	len = sizeof(a);

	err = s->ops->getname(s, (struct sockaddr *)&a, &len, for_peer);
	if (err < 0)
		return 0;
	else
		return ntohs(a.sin_port);
}

static int get_port_he6(struct socket *s, int for_peer)
{
	int len, err;
	struct sockaddr_in6 a;
	memset(&a, 0, sizeof(a));
	len = sizeof(a);

	err = s->ops->getname(s, (struct sockaddr *)&a, &len, for_peer);
	if (err < 0)
		return 0;
	else
		return ntohs(a.sin6_port);
}

static void set_co_ports(struct RlnhLinkObj *co)
{
	if (IPV6CONN(co)) {
		co->port = (unsigned long)get_port_he6(co->sock, 0);
		co->peer_port = (unsigned long)get_port_he6(co->sock, 1);
	} else {
		co->port = (unsigned long)get_port_he(co->sock, 0);
		co->peer_port = (unsigned long)get_port_he(co->sock, 1);
	}		
}

static int sock_closed(struct socket *s)
{
	if (s == NULL)
		return 1;

	switch (s->sk->sk_state) {
	case TCP_CLOSE_WAIT:
	case TCP_FIN_WAIT1:
	case TCP_FIN_WAIT2:
	case TCP_CLOSE:
	case TCP_TIME_WAIT:
	case TCP_LAST_ACK:
	case TCP_CLOSING:
		TCPCMDBG("sock state %d", s->sk->sk_state);
		break;
	case TCP_ESTABLISHED:
	default:
		TCPCMDBG("good socket");
		return 0;
	}
	return -1;
}

/*
 * transfer item queue handling.
 * OOB items could be prioritized here, but this will require that this side
 * knows whether the peer supports OOB or not.
 */
static void add_transfer_item(struct t_data *item, struct RlnhLinkObj *co)
{
	list_add_tail(&item->head, &co->transfer_queue);
	co->transfer_qlen += item->size + HLEN;
	co->stats.send_qlen = co->transfer_qlen;
}

static struct t_data *get_first_transfer_item(struct list_head *l)
{
	if (!list_empty(l))
		return container_of(l->next, struct t_data, head);
	else
		return NULL;
}

static void remove_first_transfer_item(struct RlnhLinkObj *co)
{
	struct t_data *item = get_first_transfer_item(&co->transfer_queue);
	if (item == NULL)
		ERROR();
	co->transfer_qlen -= (item->size + HLEN);
	co->stats.send_qlen = co->transfer_qlen;
	list_del(&item->head);
	KFREE(item);
}

static void cancel_transfer_items(struct RlnhLinkObj *co)
{
	while (!list_empty(&co->transfer_queue))
		remove_first_transfer_item(co);
	co->transfer_qlen = 0;
	co->stats.send_qlen = 0;
}

/* socket handling */
static void close_zombie_sockets(void)
{
	struct list_head *head;
	struct list_head *tmp;
	struct list_head zombies;
	struct sock_object *t = NULL;

	INIT_LIST_HEAD(&zombies); /* temporary list, close might sleep! */

	spin_lock_bh(&tcp_cm_rx_list_lock);
	list_for_each_safe(head, tmp, &linx_tcp_socks) {
		t = container_of(head, struct sock_object, head);
		if (sock_closed(t->s)) {
			list_del(&t->head);
			list_add(&t->head, &zombies);
		}
	}
	spin_unlock_bh(&tcp_cm_rx_list_lock);

	list_for_each_safe(head, tmp, &zombies) {
		t = container_of(head, struct sock_object, head);
		list_del(&t->head);
		SOCK_CLOSE(t->s);
		KFREE(t);
	}
}

static struct socket *get_socket(struct RlnhLinkObj *co)
{
	struct list_head *head, *tmp;
	struct sock_object *t = NULL;
	struct socket *ret = NULL;
	
	close_zombie_sockets();

	if(IPV6CONN(co))
		goto ipv6;

	spin_lock_bh(&tcp_cm_rx_list_lock);
	list_for_each_safe(head, tmp, &linx_tcp_socks) {
		t = container_of(head, struct sock_object, head);
		if (t->peer_ip == co->remote_ip) {
			list_del(&t->head);
			spin_unlock_bh(&tcp_cm_rx_list_lock);
			ret = t->s;
			KFREE(t);
			return ret;
		}
	}
	spin_unlock_bh(&tcp_cm_rx_list_lock);
	return ret;
ipv6:
	spin_lock_bh(&tcp_cm_rx_list_lock);
	list_for_each_safe(head, tmp, &linx_tcp_socks) {
		t = container_of(head, struct sock_object, head);
		if (memcmp(&t->peer_ipv6, &co->remote_ipv6, 16) == 0) {
			list_del(&t->head);
			spin_unlock_bh(&tcp_cm_rx_list_lock);
			ret = t->s;
			KFREE(t);
			TCPCMDBG("Found an ipv6 socket");
			return ret;
		}
		else
			TCPCMDBG("No ipv6 match");
	}
	spin_unlock_bh(&tcp_cm_rx_list_lock);
	return ret;
}

static int add_socket(struct socket *s, int type)
{
	struct sock_object *t = NULL;

	close_zombie_sockets();

	t = KMALLOC(sizeof(*t));
	if (t == NULL)
		return -ENOMEM;

	t->s = s;
/* get ip need to get the correct ip-adress... */
	if (type == AF_INET) {
		t->peer_ip = get_ip(s);
		memset(&t->peer_ipv6, 0xff, sizeof(struct in6_addr));;
	} else {
		t->peer_ip = 0xffffffff;
		get_ip6(s, &t->peer_ipv6);
	}
		
	spin_lock_bh(&tcp_cm_rx_list_lock);
	list_add_tail(&t->head, &linx_tcp_socks);
	spin_unlock_bh(&tcp_cm_rx_list_lock);
	return 0;
}

static void remove_sockets(void)
{
	struct list_head *head, *tmp;
	struct sock_object *t = NULL;

	spin_lock_bh(&tcp_cm_rx_list_lock);
	list_for_each_safe(head, tmp, &linx_tcp_socks) {
		t = container_of(head, struct sock_object, head);
		list_del(&t->head);
		spin_unlock_bh(&tcp_cm_rx_list_lock);
		SOCK_CLOSE(t->s);
		KFREE(t);
		spin_lock_bh(&tcp_cm_rx_list_lock);
	}
	spin_unlock_bh(&tcp_cm_rx_list_lock);
}

static unsigned long random_ms(void)
{
	uint8_t byte;
	unsigned long ret;
	get_random_bytes(&byte, 1);
	ret = 2 + (byte / 31);
	return ret * 1000;
}

static pid_t rx_init(struct RlnhLinkObj *co)
{
	pid_t pid;
	init_completion(&co->rx_up);
	pid = kernel_thread((int (*)(void *))&rx, (void *)co, 0);
	if (pid >= 0) {
		init_completion(&co->rx_done);
		wait_for_completion(&co->rx_up);
	}
	return pid;
}

static void rx_run(struct RlnhLinkObj *co)
{
	complete(&co->rx_run);
}

static void remove_rx(struct RlnhLinkObj *co)
{
	if (co->rx_pid == -1) {
		TCPCMDBG("rx_proc not started");
		return;
	}
	kill_proc(co->rx_pid, SIGINT, 0);
	wait_for_completion(&co->rx_done);
	co->rx_pid = -1;
}

static void remove_socket(struct RlnhLinkObj *co)
{
	if (co->sock == NULL)
		return;
	SOCK_CLOSE(co->sock);
	co->sock = NULL;
}

/* Send TCP packets on socket */
static int send_msg(struct socket *sock, char *data, int len)
{
	struct msghdr msg;
	struct kvec iov;
	msg.msg_flags = MSG_NOSIGNAL | MSG_DONTWAIT;
	iov.iov_base = data;
	iov.iov_len = len;
	return kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
}

static int recv_msg(struct socket *sock, char *data, int len)
{
	struct msghdr msg;
	struct kvec iov;
	iov.iov_base = data;
	iov.iov_len = len;
	return kernel_recvmsg(sock, &msg, &iov, 1, len, MSG_WAITALL);
}

/* header functions */
static void set_header(char *data, uint8_t type,
		       uint32_t src, uint32_t dst, uint32_t size)
{
	struct header *h = (struct header *)data;
        /* reserved bits will be zero */
	h->type_version = htonl((type << 24) | (PROTO_V << 16));
	h->src = htonl(src);
	h->dst = htonl(dst);
	h->size = htonl(size);
}

static void set_oob_ne(char *data)
{
	struct header *h = (struct header *)data;
	h->type_version |= htonl(OOB_BIT); /* Set OOB bit */
}

static int is_oob_he(char *data)
{
	struct header *h = (struct header *)data;
	return h->type_version & OOB_BIT; /* Get OOB bit */
}

static int recv_header(struct socket *sock, struct header *h)
{
	int err = recv_msg(sock, (char *)h, HLEN);
	if (HLEN != err)
		return err;
	h->type_version = ntohl(h->type_version);
	h->src = ntohl(h->src);
	h->dst = ntohl(h->dst);
	h->size = ntohl(h->size);
	return 0;
}

static int send_conn_message(struct socket *sock)
{
	int err = 0;
	struct header h;
        /* reserved bits will be zero */
	h.type_version = htonl((TCP_CONN << 24) | (PROTO_V << 16));
	h.src = 0;
	h.dst = 0;
	h.size = 0;
	err = send_msg(sock, (char *)&h, HLEN);
	if (err != HLEN) {
		TCPCMDBG("send_msg failed with error %d", err);	   
		return -1;
	}
	
	return 0;
}

static void stop_listen(void)
{
	if (linx_tcp_cm_ipv6_support) {
		kill_proc(listen_v6_pid, SIGINT, 0);
		wait_for_completion(&listen_v6_done);
	}

	kill_proc(listen_pid, SIGINT, 0);
	wait_for_completion(&listen_done);
}

/* connection objects are in a vector */
static int init_vector(void)
{
	co_vector_len = 0;
	co_vector = KMALLOC(sizeof(*co_vector) * CO_VECTOR_INC);
	if(co_vector == NULL)
		return -ENOMEM;
	memset(co_vector, 0, sizeof(*co_vector) * CO_VECTOR_INC);
	co_vector_len = CO_VECTOR_INC;
	return 0;
}

static void fini_vector(void)
{
	co_vector_len = 0;
	KFREE(co_vector);
}

static int __extend_vector(void)
{
	struct RlnhLinkObj **temp;
	int old_len = co_vector_len;

	temp = KMALLOC_ATOMIC(sizeof(*temp) * (co_vector_len + CO_VECTOR_INC));
	if(temp == NULL)
		return -ENOMEM;
	co_vector_len = old_len + CO_VECTOR_INC;
	memset(temp, 0, sizeof(*temp) * co_vector_len);
	memcpy(temp, co_vector, old_len * sizeof(*temp));
	KFREE(co_vector);
	co_vector = temp;
	return old_len; /* return the first free index */
}

static int add_to_vector(struct RlnhLinkObj *co)
{
	int i;
	spin_lock_bh(&co_vector_lock);
	for(i = 0; i < co_vector_len; i++) {
		if(co_vector[i] == NULL) {
			co_vector[i] = co;
			co->index = i + 1;
			spin_unlock_bh(&co_vector_lock);
			return 0;
		}
	}
	i = __extend_vector();
	if(i > 0) {
		co_vector[i] = co;
		co->index = i + 1;
		spin_unlock_bh(&co_vector_lock);
		return 0;
	}
	spin_unlock_bh(&co_vector_lock);
	return -ENOMEM;
}

static void remove_from_vector(struct RlnhLinkObj *co)
{
	ERROR_ON(co->index == 0);
	spin_lock_bh(&co_vector_lock);
	co_vector[co->index - 1] = NULL;
	co->index = 0;
	spin_unlock_bh(&co_vector_lock);
}

static struct RlnhLinkObj *get_from_vector(uint32_t index)
{
	struct RlnhLinkObj *co;
	ERROR_ON(index == 0);
	spin_lock_bh(&co_vector_lock);
	co = co_vector[index - 1];
	spin_unlock_bh(&co_vector_lock);
	return co;
}

static uint32_t vector_index_by_ip(uint32_t ip)
{
	int i = 0;
	struct RlnhLinkObj *co;
	spin_lock_bh(&co_vector_lock);
	for(i = 1; i < co_vector_len; i++) {
		if(co_vector[i] != NULL) {
			co = co_vector[i];
			if(co->remote_ip == ip) {
				spin_unlock_bh(&co_vector_lock);
				return i + 1;
			}
		}
	}
	spin_unlock_bh(&co_vector_lock);
	return 0;
}

static uint32_t vector_index_by_ipv6(__u16 *ipv6)
{
	int i = 0;
	struct RlnhLinkObj *co;
	spin_lock_bh(&co_vector_lock);
	for(i = 1; i < co_vector_len; i++) {
		if(co_vector[i] != NULL) {
			co = co_vector[i];
			if(co->remote_ip != 0 &&
			   memcmp(&co->remote_ipv6, ipv6, 16) == 0) {
				spin_unlock_bh(&co_vector_lock);
				return i + 1;
			}
		}
	}
	spin_unlock_bh(&co_vector_lock);
	return 0;
}

static struct RlnhLinkObj *co_create(void)
{
	struct RlnhLinkObj *co = KMALLOC(sizeof(*co));
	if (unlikely(co == NULL))
		return NULL;

	memset(co, 0, sizeof(*co));

	INIT_LIST_HEAD(&co->transfer_queue);
	INIT_LIST_HEAD(&co->timer_tasks);
	co->alive = 1;
	co->use_nagle = 0;	/* default off */
	co->rx_pid = -1;
	co->state = 0;

	if(add_to_vector(co)) {
		KFREE(co);
		return NULL;
	}
	return co;
}

static void co_free(struct RlnhLinkObj *co)
{
	ERROR_ON(co->sock != NULL);
	remove_from_vector(co);
	wq_cancel_delayed_tasks(co);
	cancel_transfer_items(co);
        if (co->con_name != NULL)
                kfree(co->con_name); /* Allocated with kstrdup() */
	KFREE(co);
}

static struct wq_task_object *wqo_create(uint32_t index)
{
	struct wq_task_object *w;

	if (atomic_read(&wq_len) >= linx_tcp_cm_max_wq_len)
		linx_warn("Long workqueue");

	w = KMALLOC(sizeof(*w));
	if (unlikely(w == NULL)) {
		linx_err("Could not create task object - ENOMEM");
		ERROR();
		return NULL;
	}
	w->index = index;
	w->trans_data = NULL;
	atomic_inc(&wq_len);
	return w;
}

static struct wq_task_object *wqo_create_w_buf(uint32_t index, uint32_t size)
{
	struct wq_task_object *w = NULL;
	struct t_data *item = 0;

	if (atomic_read(&wq_len) >= linx_tcp_cm_max_wq_len)
		linx_warn("Max wq len overridden!");
        /*
	 * NOTE: only one allocation here. so do NOT do a wqo_free
	 * at the beginning of the linx_transmit_task
	 */

	w = KMALLOC(sizeof(*w));
	if (unlikely(w == NULL))
		goto error;
	item = KMALLOC(sizeof(*item) + size);
	if (unlikely(item == NULL))
		goto error;

	w->index = index;
	w->trans_data = item;
	item->data = (char *)item + sizeof(*item);
	item->pos = item->data;
	item->remaining = size;
	item->skb = NULL;	/* not used in submission */
	item->peer_version = 0;
	atomic_inc(&wq_len);
	if (size == 0) /* minor bloat avoid interpretion of erroneous pointer */
		item->data = NULL;
	return w;
 error:
	if(w != NULL)
		KFREE(w);
	linx_err("Could not create task object with buffer - ENOMEM");
	ERROR();
	return NULL;
}

static struct wq_task_object *wqo_create_w_skb(uint32_t index, uint32_t size)
{
	struct wq_task_object *w;

	if (atomic_read(&wq_len) >= linx_tcp_cm_max_wq_len)
		linx_warn("Max wq len overridden!");

        /* NOTE: deliver on the data element. use skb to avoid memcpy */
	w = KMALLOC(sizeof(*w) + sizeof(*(w->trans_data)));
	if (unlikely(w == NULL))
		goto error;

	w->index = index;
	w->trans_data = (struct t_data *)((char *)w + sizeof(*w));
	w->trans_data->data = NULL;	/* not used in retrieval */
	w->trans_data->skb = alloc_skb(size, GFP_KERNEL);
	if (w->trans_data->skb == NULL)
		goto free_w;
	skb_put(w->trans_data->skb, size);

        /* these are not used in deliver. set them to zero. */
	w->trans_data->pos = NULL;
	w->trans_data->remaining = 0;
	atomic_inc(&wq_len);
	return w;
 free_w:
	KFREE(w);
 error:
	linx_err("Could not create task object with skb - ENOMEM");
	ERROR();
	return NULL;
}

static void wqo_free(struct wq_task_object *w)
{
	atomic_dec(&wq_len);
	KFREE(w);
}

static void wq_init(void)
{
	tcp_cm_wq = create_singlethread_workqueue("tcp_cm_wq");
}

static void wq_function(WQ_TYPE *arg)
{
	struct wq_task_object *w = WQ_GETARG(arg, struct wq_task_object);
	struct RlnhLinkObj *co = get_from_vector(w->index);
	if (co == NULL) {
		/* free extra data if present */
		if (w->func == traffic_data_task)
			kfree_skb(w->trans_data->skb);
		else if (w->func == linx_transmit_task && w->trans_data != NULL)
			KFREE(w->trans_data);
		wqo_free(w);
		return;
	}
	w->func(w, co);
	wqo_free(w);
}

static void wq_put(struct wq_task_object *w,
		   void (*func) (struct wq_task_object *w,
				 struct RlnhLinkObj *co))
{
	if(w == NULL)
		return;
	w->func = func;
	TCM_INIT_WORK(&w->work, wq_function, w);
	queue_work(tcp_cm_wq, &w->work);
}

static void wq_cancel_delayed_tasks(struct RlnhLinkObj *co)
{
	struct list_head *head, *tmp;
	struct wq_timer_data *t = NULL;

	spin_lock_bh(&timer_tasks_lock);
	list_for_each_safe(head, tmp, &co->timer_tasks) {
		t = container_of(head, struct wq_timer_data, head);
		list_del(&t->head);
		spin_unlock_bh(&timer_tasks_lock);
		del_timer_sync(&t->timer);
		wqo_free(t->w);
		KFREE(t);
		spin_lock_bh(&timer_tasks_lock);
	}
	spin_unlock_bh(&timer_tasks_lock);
}

/* the wq_timer_fn will add the delayed task to the wq */
static void wq_timer_function(unsigned long d)
{
	struct wq_timer_data *data = (struct wq_timer_data *)d;

	spin_lock_bh(&timer_tasks_lock);
	list_del(&data->head);
	spin_unlock_bh(&timer_tasks_lock);

	wq_put(data->w, data->w->func);
	KFREE(data);
}

static void wq_delayed_put(struct RlnhLinkObj *co,
			   void (*func) (struct wq_task_object *w,
					 struct RlnhLinkObj *co),
			   unsigned long ms)
{
	struct wq_timer_data *data;
	struct wq_task_object *w = wqo_create(co->index);
	if(w == NULL)
		return;
	w->func = func;
	data = KMALLOC(sizeof(*data));
	if (data == NULL) {
		linx_err("Out of memory.");
		wqo_free(w);
		return;
	}
	data->w = w;
	init_timer(&data->timer);
	data->timer.data = (unsigned long)data;
	data->timer.function = wq_timer_function;
	data->timer.expires = msecs_to_jiffies(ms) + jiffies;

	spin_lock_bh(&timer_tasks_lock);
	list_add(&data->head, &co->timer_tasks);
	add_timer(&data->timer);
	spin_unlock_bh(&timer_tasks_lock);
}

static void wq_fini(void)
{
	flush_workqueue(tcp_cm_wq);
	destroy_workqueue(tcp_cm_wq);
	tcp_cm_wq = NULL;
}

static void timer_connect_watchdog_task(struct wq_task_object *w,
					struct RlnhLinkObj *co)
{
	if (co->rx_pid < 0) /* this watchdog belongs to old connect attempt */
		return;
	TCPCMDBG("index: %d, state: %d", co->index, GET_STATE(co));
	switch (GET_STATE(co)) {
	case STATE_ACTIVE_CONNECT:
	case STATE_PASSIVE_CONNECT:
		remove_rx(co);
		remove_socket(co);
		SET_STATE(co, STATE_READY);
		wq_put(wqo_create(co->index), retry_connect_task);
		break;
	case STATE_READY:
	case STATE_DISCONNECTED:
	case STATE_FINALIZED:
	case STATE_CONNECTED:
		break;
	default:
		INCONSISTENT(co);
		break;
	}
}

static void retry_connect(struct RlnhLinkObj *co)
{
	remove_socket(co);
	co->sock = get_socket(co);
	if (co->sock == NULL) /* try later to avoid collision */
		wq_delayed_put(co, retry_connect_task, random_ms());
	else
		wq_put(wqo_create(co->index), retry_connect_task);
}

static int passive_connect(struct RlnhLinkObj *co)
{
	/*
  	 * start rx proc to retrieve conn message
	 * schedule a watchdog
	 * set state passive connect
	 * let traffic_connect_task send reply and call connected()
	 */
	if (likely(!co->use_nagle))	/* turn off nagle */
		tcp_sk(co->sock->sk)->nonagle |= TCP_NAGLE_OFF | TCP_NAGLE_PUSH;

	co->rx_pid = rx_init(co);
	if (co->rx_pid < 0) {
		linx_err("FATAL Error starting thread");
		wq_delayed_put(co, retry_connect_task, random_ms());
		return 0;
	}
	set_co_ports(co);
	complete(&co->rx_run);
	wq_delayed_put(co, timer_connect_watchdog_task, random_ms());
	return 1;
}

static int continue_connect(struct RlnhLinkObj *co)
{
	TCPCMDBG("connect continues");
	if (send_conn_message(co->sock)) {
		TCPCMDBG("Failed to send conn message");
		remove_socket(co);
		wq_delayed_put(co, retry_connect_task, random_ms());
		return 0;
	}
	co->rx_pid = rx_init(co);
	if (co->rx_pid < 0) {
		linx_err("FATAL Error starting thread");
		return 0;
	}
	rx_run(co);
	wq_delayed_put(co, timer_connect_watchdog_task, random_ms());
	return 1;
}

static void linx_active_connect_task(struct wq_task_object *w,
				     struct RlnhLinkObj *co)
{
	TCPCMDBG("index: %d, state: %d", co->index, GET_STATE(co));
	switch (GET_STATE(co)) {
	case STATE_ACTIVE_CONNECT:
		if (SOCK_IS_CONNECTED(co->sock)) {
			if(continue_connect(co) == 0)
				SET_STATE(co, STATE_READY);
		} else if (SOCK_IS_CONNECTING(co->sock)) {
			/* still connecting. check again later */
			wq_delayed_put(co, linx_active_connect_task,
				       co->live_tmo);
		} else { /* connect failed, try again later */
			SET_STATE(co, STATE_READY);
			remove_socket(co);
			wq_delayed_put(co, retry_connect_task, random_ms());
		}
		break;
	case STATE_PASSIVE_CONNECT:
	case STATE_FINALIZED:
	case STATE_DISCONNECTED:
		break;
	case STATE_CONNECTED:
	case STATE_READY:
	default:
		INCONSISTENT(co);
		break;
	}
}

static int active_connect(struct RlnhLinkObj *co)
{
	int err = 0;

	TCPCMDBG("Active connect");
	if (IPV4CONN(co)) {
		struct sockaddr_in tx_send;
		err = SOCK_OPEN(&co->sock);
		if (err < 0) {
			linx_err("FATAL error opening co socket");
			wq_delayed_put(co, retry_connect_task, random_ms());
			return 0;
		}
		set_sockaddr(&tx_send, co->remote_ip, htons(linx_tcp_cm_port));
		if (likely(!co->use_nagle)) /* turn off nagle */
			tcp_sk(co->sock->sk)->nonagle |=
				TCP_NAGLE_OFF | TCP_NAGLE_PUSH;
		err = SOCK_CONNECT(co->sock, (struct sockaddr *)&tx_send,
				   sizeof(tx_send), O_NONBLOCK);
	} else { /* ipv6 */
		struct sockaddr_in6 tx_send6;
		err = SOCK_OPEN6(&co->sock);
		if (err < 0) {
			linx_err("FATAL error opening co ipv6 socket");
			wq_delayed_put(co, retry_connect_task, random_ms());
			return 0;
		}
		set_sockaddr6(&tx_send6, &co->remote_ipv6,
			      co->ipv6_scope, htons(linx_tcp_cm_port6));
		if (likely(!co->use_nagle)) /* turn off nagle */
			tcp_sk(co->sock->sk)->nonagle |=
				TCP_NAGLE_OFF | TCP_NAGLE_PUSH;
		err = SOCK_CONNECT(co->sock, (struct sockaddr *)&tx_send6,
				   sizeof(tx_send6), O_NONBLOCK);
	}

	if (err == -EINPROGRESS || err == 0) {
		wq_delayed_put(co, linx_active_connect_task, 100); /* 100 ms */
		return 1;
	}
	remove_socket(co);
	wq_delayed_put(co, retry_connect_task, random_ms());
	return 0;
}

static void retry_connect_task(struct wq_task_object *w, struct RlnhLinkObj *co)
{
	TCPCMDBG("index: %d, state: %d", co->index, GET_STATE(co));
	switch (GET_STATE(co)) {
	case STATE_READY:
		if (co->sock == NULL) /* lookup? */
			co->sock = get_socket(co);
		if (co->sock != NULL) {
			if(passive_connect(co))
				SET_STATE(co, STATE_PASSIVE_CONNECT);
		} else {
			if(active_connect(co))
				SET_STATE(co, STATE_ACTIVE_CONNECT);
		}
		break;
	case STATE_FINALIZED:
	case STATE_DISCONNECTED:
	case STATE_ACTIVE_CONNECT:
	case STATE_PASSIVE_CONNECT:
	case STATE_CONNECTED:
		break; /* any state possible since postponed earlier */
	default:
		INCONSISTENT(co);
		break;
	}
}


static void linx_connect_task(struct wq_task_object *w, struct RlnhLinkObj *co)
{
	TCPCMDBG("index: %d, state: %d", co->index, GET_STATE(co));
	switch (GET_STATE(co)) {
	case STATE_DISCONNECTED:
		SET_STATE(co, STATE_READY); /* reconnect, no break */
	case STATE_READY:
		if (co->sock == NULL) /* lookup? */
			co->sock = get_socket(co);
		if (co->sock != NULL) {
			if(passive_connect(co))
				SET_STATE(co, STATE_PASSIVE_CONNECT);
		} else {
			if(active_connect(co))
				SET_STATE(co, STATE_ACTIVE_CONNECT);
		}
		break;
	case STATE_ACTIVE_CONNECT:
	case STATE_PASSIVE_CONNECT:
	case STATE_CONNECTED:
	case STATE_FINALIZED:
	default:
		INCONSISTENT(co);
		break;
	}
}

static void disconnect_connection(struct RlnhLinkObj *co)
{
	cancel_transfer_items(co);
	remove_rx(co);
	remove_socket(co);
	DISCONNECTED(co);
}

static void timer_keepalive_task(struct wq_task_object *w,
				 struct RlnhLinkObj *co)
{
	TCPCMDBG("index: %d, state: %d", co->index, GET_STATE(co));
	switch (GET_STATE(co)) {
	case STATE_ACTIVE_CONNECT:
	case STATE_PASSIVE_CONNECT:
	case STATE_READY:
	case STATE_DISCONNECTED:
	case STATE_FINALIZED:	/* when reconnecting co, we could be here */
		TCPCMDBG("Connection lost normally");
		co->alive = 0;
		break;
	case STATE_CONNECTED:
		if (co->alive == 0) {	/* no ping has been received */
			linx_info("Connection timed out.");
			disconnect_connection(co);
			SET_STATE(co, STATE_DISCONNECTED);
			break;
		}
		co->alive = 0;	/* reset value */
                /* send ping */
		w = wqo_create_w_buf(co->index, HLEN);	/* reuse w */
		if (w == NULL)
			break;
		set_header(w->trans_data->data, TCP_PING, 0, 0, 0);
		wq_put(w, linx_transmit_task);
		wq_delayed_put(co, timer_keepalive_task, co->live_tmo);
		break;
	default:
		INCONSISTENT(co);
		break;
	}
}

static void linx_delete_task(struct wq_task_object *w, struct RlnhLinkObj *co)
{
	TCPCMDBG("index: %d, state: %d", co->index, GET_STATE(co));
	switch (GET_STATE(co)) {
	case STATE_READY: /* can happen if init/connect never called */
	case STATE_FINALIZED:
		complete(&co->ready_for_destroy);
		break;
	case STATE_DISCONNECTED:
	case STATE_ACTIVE_CONNECT:
	case STATE_PASSIVE_CONNECT:
	case STATE_CONNECTED:
	default:
		INCONSISTENT(co);
		break;
	}
}

static void linx_finalize_task(struct wq_task_object *w, struct RlnhLinkObj *co)
{
	TCPCMDBG("index: %d, state: %d", co->index, GET_STATE(co));
	switch (GET_STATE(co)) {
	case STATE_READY:
	case STATE_ACTIVE_CONNECT:
	case STATE_PASSIVE_CONNECT:
	case STATE_CONNECTED:
		INCONSISTENT(co);
	case STATE_DISCONNECTED:
		SET_STATE(co, STATE_FINALIZED);
		break;
	case STATE_FINALIZED:
	default:
		INCONSISTENT(co);
		break;
	}
}

static void linx_disconnect_task(struct wq_task_object *w,
				 struct RlnhLinkObj *co)
{
	TCPCMDBG("index: %d, state: %d", co->index, GET_STATE(co));
	switch (GET_STATE(co)) {
	case STATE_READY:
	case STATE_ACTIVE_CONNECT:
	case STATE_PASSIVE_CONNECT:
	case STATE_CONNECTED:
		SET_STATE(co, STATE_DISCONNECTED);
		cancel_transfer_items(co);
		remove_rx(co);
		remove_socket(co);
		DISCONNECTED(co);
		break;
	case STATE_DISCONNECTED:
	case STATE_FINALIZED:
		break;
	default:
		INCONSISTENT(co);
		break;
	}
}

static void traffic_connect_task(struct wq_task_object *w,
				 struct RlnhLinkObj *co)
{
	uint8_t peer_version = w->trans_data->peer_version;

        /* this version does not use trailing data on TCP_CONN headers */

	TCPCMDBG("index: %d, state: %d", co->index, GET_STATE(co));
	switch (GET_STATE(co)) {
	case STATE_ACTIVE_CONNECT:
		co->peer_version = peer_version;
		co->alive = 1; /* for first issued keepalive */
		set_co_ports(co);
		CONNECTED(co);
		wq_put(wqo_create(co->index), timer_keepalive_task);
		SET_STATE(co, STATE_CONNECTED);
		break;
	case STATE_PASSIVE_CONNECT:
		if (send_conn_message(co->sock)) {
			TCPCMDBG("Failed to send conn message");
			remove_socket(co);
			remove_rx(co);
			retry_connect(co);
			SET_STATE(co, STATE_READY);
		} else {
			co->peer_version = peer_version;
			co->alive = 1; /* for first issued keepalive */
			set_co_ports(co);
			CONNECTED(co);
			wq_put(wqo_create(co->index), timer_keepalive_task);
			SET_STATE(co, STATE_CONNECTED);
		}
		break;
	case STATE_READY:
	case STATE_DISCONNECTED:
		break;
	case STATE_CONNECTED:
		/* read two conn messages. dont know why yet */
		disconnect_connection(co);
		SET_STATE(co, STATE_DISCONNECTED);
		break;
	case STATE_FINALIZED:
	default:
		INCONSISTENT(co);
		break;
	}
}

static int send_item(struct RlnhLinkObj *co)
{
	int sent_data = 0;
	struct t_data *item;

	item = get_first_transfer_item(&co->transfer_queue);
	if (item == NULL)
		return 0;

	sent_data = send_msg(co->sock, item->pos, item->remaining);
	if (sent_data == item->remaining) {
		remove_first_transfer_item(co);
		co->stats.sent_udata_bytes += sent_data;
		co->stats.sent_msgs++;
	} else if (sent_data == -EAGAIN) {
		wq_put(wqo_create(co->index), linx_transmit_task);
	} else if (sent_data < 0) {
		return -1; /* error */
	} else if (sent_data < item->remaining) {
		item->pos += sent_data;
		item->remaining -= sent_data;
		co->stats.sent_udata_bytes += sent_data;
		wq_put(wqo_create(co->index), linx_transmit_task);
	}
	return 0;
}

static void linx_transmit_task(struct wq_task_object *w, struct RlnhLinkObj *co)
{
	/*
	 * use a queue of transmission items. always fetch first item. new data
	 * is tailed. upon error/disconnect, flush queue.
	 */
	struct t_data *item = w->trans_data;
	if (item != NULL)
		add_transfer_item(item, co);
	if (co->transfer_qlen >= linx_tcp_cm_max_send_queue) {
		linx_err("send queue overridden");
		disconnect_connection(co);
		SET_STATE(co, STATE_DISCONNECTED);
		return;
	}

	switch (GET_STATE(co)) {
	case STATE_CONNECTED:
		if (-1 == send_item(co)) {
			disconnect_connection(co);
			SET_STATE(co, STATE_DISCONNECTED);
		}
		break;
	case STATE_READY:
	case STATE_DISCONNECTED:
	case STATE_FINALIZED:
	case STATE_ACTIVE_CONNECT:
	case STATE_PASSIVE_CONNECT:
		cancel_transfer_items(co);
		break;
	default:
		INCONSISTENT(co);
		break;
	}
}

static void traffic_data_task(struct wq_task_object *w, struct RlnhLinkObj *co)
{
	int err = 0;
	struct t_data *d = w->trans_data;

	switch (GET_STATE(co)) {
	case STATE_CONNECTED:
		err = DELIVER(co, d);
		if (err < 0) {
			TCPCMDBG("Deliver error");
			kfree_skb(d->skb);
		}
		co->alive = 1;
		co->stats.recv_udata_bytes += d->size;
		co->stats.received_msgs++;
		break;
	case STATE_READY:
	case STATE_DISCONNECTED:
	case STATE_FINALIZED:
	case STATE_ACTIVE_CONNECT:
	case STATE_PASSIVE_CONNECT:
		if (d->skb != NULL)
			kfree_skb(d->skb);
		break;
	default:
		if (d->skb != NULL)
			kfree_skb(d->skb);
		INCONSISTENT(co);
		break;
	}
}

static void traffic_ping_task(struct wq_task_object *w, struct RlnhLinkObj *co)
{
	switch (GET_STATE(co)) {
	case STATE_READY:
	case STATE_DISCONNECTED:
	case STATE_ACTIVE_CONNECT:
	case STATE_PASSIVE_CONNECT:
	case STATE_CONNECTED:
		co->alive = 1;
                /* send ping reply, pong */
		w = wqo_create_w_buf(co->index, HLEN);	/* reuse w */
		if (w == NULL)
			break;
		set_header(w->trans_data->data, TCP_PONG, 0, 0, 0);
		wq_put(w, linx_transmit_task);
		break;
	case STATE_FINALIZED: /* may be run when finalized, avoid timeout */
		co->alive = 1;
		break;
	default:
		INCONSISTENT(co);
		break;
	}
}

static void traffic_pong_task(struct wq_task_object *w, struct RlnhLinkObj *co)
{
	switch (GET_STATE(co)) {
	case STATE_READY:
	case STATE_DISCONNECTED:
	case STATE_FINALIZED:
	case STATE_ACTIVE_CONNECT:
	case STATE_PASSIVE_CONNECT:
	case STATE_CONNECTED:
		co->alive = 1;
		break;
	default:
		INCONSISTENT(co);
		break;
	}
}

/* the rx threads */
static int handle_udata_packet(struct socket *s, struct header *h, int index)
{
	int ret = 0;
	struct wq_task_object *w = wqo_create_w_skb(index, h->size);
	if (w == NULL)
		return -ENOMEM;

	w->trans_data->src = h->src;
	w->trans_data->dst = h->dst;
	w->trans_data->size = h->size;
	w->trans_data->buf_type = BUFFER_TYPE_SKB;
	if (is_oob_he((char *)h))
		w->trans_data->buf_type |= BUFFER_TYPE_OOB;

	ret = recv_msg(s, (char *)w->trans_data->skb->data, h->size);
	if (unlikely(h->size != ret)) {
		kfree_skb(w->trans_data->skb);
		wqo_free(w);
		TCPCMDBG("Index %d receive error: %d", index, ret);
		return ret;
	} else {
		wq_put(w, traffic_data_task);
		ret = 0;
	}
	return 0;
}

static int handle_conn_packet(struct socket *s, struct header *h, int index)
{
	struct wq_task_object *w = wqo_create_w_buf(index, h->size);

	TCPCMDBG("Index %d recevied CONN", index);

	if (w == NULL)
		return -ENOMEM;

        /* Check protocol version of the incoming packet */	
	if (((h->type_version >> 16) & 0xff) != PROTO_V){
		KFREE(w->trans_data);
		wqo_free(w);
		TCPCMDBG("Index %d protocol version %d\n", index, 
		                     (h->type_version >> 16) & 0xff);
		
		return 0;
	}

	w->trans_data->peer_version = (h->type_version >> 16) & 0xff;

	if (h->size != 0) { /* read trailing conn message (feat xchg) */
		int ret = recv_msg(s, (char *)w->trans_data->data, h->size);
		if (unlikely(h->size != ret)) {
			KFREE(w->trans_data);
			wqo_free(w);
			TCPCMDBG("Index %d receive error: %d", index, ret);
			return ret; /* conn est will restart */
		}
	} 
	wq_put(w, traffic_connect_task);

	return 0;
}

static int read_packet(struct socket *s, uint32_t index)
{
	struct header h;

	if (s == NULL)
		return -1;
	if (0 != recv_header(s, &h))
		return -1;
	
	switch (h.type_version >> 24) {
	case TCP_UDATA:
		return handle_udata_packet(s, &h, index);
	case TCP_PING:
		wq_put(wqo_create(index), traffic_ping_task);
		return 0;
	case TCP_PONG:
		wq_put(wqo_create(index), traffic_pong_task);
		return 0;
	case TCP_CONN:
		return handle_conn_packet(s, &h, index);
	default:
		TCPCMDBG("Index %d: unknown 0x%x", index, h.type_version >> 24);
		return 0;
	}
	return 0;
}

static int await_data(struct socket *sock)
{
	int ret = 0;
	struct sock *sk = sock->sk;
	wait_event_interruptible(*sk_sleep(sk),
				 (ret = skb_queue_len(&sk->sk_receive_queue)));
	return ret;
}

static void rx_process(struct socket *s, int index)
{
	while (await_data(s)) {
		if (signal_pending(current))
			break;
		if (read_packet(s, index) < 0) {
			msleep(15); /* let connection time out */
			break;
		}
	}
}

static int rx(void *p)
{
	char thread_name[22];
	struct RlnhLinkObj *co = p;
	struct socket *s = co->sock;
	uint32_t index = co->index;

	sprintf(thread_name, "tcp_cm_rx_%x", index);
	daemonize(thread_name);
	allow_signal(SIGINT);
	/* synchronised startup */
	init_completion(&co->rx_run);
	complete(&co->rx_up);
	wait_for_completion(&co->rx_run);
	rx_process(s, index);
	complete(&co->rx_done);
	return 0;
}

static void listen_process(struct socket *s)
{
	while (1) {
		int err = 0;
		struct socket *new_conn;

		if (signal_pending(current))
			return;

		err = SOCK_OPEN(&new_conn);
		if (err < 0) {
			linx_err("Error %d when creating a socket", err);
			continue;
		}

		err = SOCK_ACCEPT(s, new_conn, 0);
		if (err < 0) {
			SOCK_CLOSE(new_conn);
			continue;
		}

		add_socket(new_conn, AF_INET);
	}
}

static int listen(void *p)
{
	struct socket *s;
	struct sockaddr_in s_addr;
	int err = 0;

	daemonize("tcp_cm_listen");
	allow_signal(SIGINT);

	if ((err = SOCK_OPEN(&s)) < 0) {
		linx_warn("Failed to create input socket, error: %d", err);
		complete(&listen_done);
		return err;
	}
	/* so_reuseaddr */
	s->sk->sk_reuse = 1;

        /* right now, we are listening on all interfaces */
	set_sockaddr(&s_addr, htonl(INADDR_ANY), htons(linx_tcp_cm_port));

	err = SOCK_BIND(s, (struct sockaddr *)&s_addr, sizeof(s_addr));
	if (err < 0) {
		linx_warn("Failed binding local socket, error: %d", err);
		goto out;
	}
	err = SOCK_LISTEN(s, 0);
	if (err < 0) {
		linx_warn("Failed to listen on tcp_cm socket, error: %d", err);
		goto out;
	}

	listen_process(s);
 out:
	remove_sockets();
	SOCK_CLOSE(s);
	TCPCMDBG("listen sock closed");
	complete(&listen_done);
	return 0;
}

static void listen_process6(struct socket *s)
{
	while (1) {
		int err = 0;
		struct socket *new_conn;

		if (signal_pending(current))
			return;

		err = SOCK_OPEN6(&new_conn);
		if (err < 0) {
			linx_err("Error %d when creating an ipv6 socket", err);
			continue;
		}

		err = SOCK_ACCEPT(s, new_conn, 0);
		if (err < 0) {
			if(err != -512)
				linx_err("Error %d when accepting an ipv6 "
					 "socket", err);
			SOCK_CLOSE(new_conn);
			continue;
		}
		add_socket(new_conn, AF_INET6);
	}
}

static int listen6(void *p)
{
	struct socket *s;
	struct sockaddr_in6 s_addr;
	struct in6_addr any = IN6ADDR_ANY_INIT;
	int err = 0;

	daemonize("tcp_cm_listen_v6");
	allow_signal(SIGINT);

	if ((err = SOCK_OPEN6(&s)) < 0) {
		linx_warn("Failed to create input ipv6 socket, error: %d", err);
		complete(&listen_v6_done);
		return err;
	}
	/* so_reuseaddr */
	s->sk->sk_reuse = 1;

        /* right now, we are listening on all interfaces
	   as any is used, the scope is set to 0 */
	set_sockaddr6(&s_addr, &any, 0, htons(linx_tcp_cm_port6));

	err = SOCK_BIND(s, (struct sockaddr *)&s_addr, sizeof(s_addr));
	if (err < 0) {
		linx_warn("Failed binding local ipv6 socket, error: %d", err);
		goto out;
	}
	err = SOCK_LISTEN(s, 0);
	if (err < 0) {
		linx_warn("Failed to listen on ipv6 socket, error: %d", err);
		goto out;
	}

	listen_process6(s);
 out:
	remove_sockets();
	SOCK_CLOSE(s);
	TCPCMDBG("listen sock closed");
	complete(&listen_v6_done);
	return 0;
}

/* Downcalls from the RLNH */
static int transmit(struct RlnhLinkObj *index, uint32_t buf_type, uint32_t src,
		    uint32_t dst, uint32_t size, void *data)
{
	struct wq_task_object *w;

	if (unlikely(size > LINX_SKB_MAX_SIZE))
		return -EMSGSIZE;

	w = wqo_create_w_buf((uint32_t) (unsigned long)index, size + HLEN);
	if (w == NULL)
		return -ENOMEM;

	set_header(w->trans_data->data, TCP_UDATA, src, dst, size);

	if (BUF_TYPE_OOB(buf_type))
		set_oob_ne(w->trans_data->data);

	if (BUF_TYPE_USER(buf_type)) {	/* user space data */
		char *dest = w->trans_data->data + HLEN;
		if (copy_from_user(dest, (char *)data, size)) {
			KFREE(w->trans_data);
			wqo_free(w);
			return -EFAULT;
		}
	} else { /* kernel space data, copy anyway because of wq... */
		memcpy(w->trans_data->data + HLEN, (char *)data, size);
	}

	wq_put(w, linx_transmit_task);
	return 0;
}

/* called from rlnh to couple the upcalls from rlnh, no task needed here  */
static void init(struct RlnhLinkObj *i, void *rlnh_co, struct RlnhLinkUCIF *cb)
{
	struct RlnhLinkObj *co = get_from_vector((uint32_t) (unsigned long)i);
	TCPCMDBG("Init %d", (uint32_t) (unsigned long)i);
	co->rlnh_upcalls = cb;
	co->rlnh_obj_p = rlnh_co;
	SET_STATE(co, STATE_READY);
}

static void finalize(struct RlnhLinkObj *index)
{
	TCPCMDBG("Finalize %d", (uint32_t) (unsigned long)index);
	wq_put(wqo_create((uint32_t) (unsigned long)index), linx_finalize_task);
}

static void connect(struct RlnhLinkObj *index)
{
	TCPCMDBG("Connect %d", (uint32_t) (unsigned long)index);
	wq_put(wqo_create((uint32_t) (unsigned long)index), linx_connect_task);
}

static void disconnect(struct RlnhLinkObj *index)
{
	TCPCMDBG("Disconnect %d", (uint32_t) (unsigned long)index);
	wq_put(wqo_create((uint32_t)(unsigned long)index),linx_disconnect_task);
}

static struct RlnhLinkIF tcm_downcalls = {
	RLNH_LINK_IF_VERSION,
	init,
	finalize,
	connect,
	disconnect,
	transmit,
};

/* Calls from TCP Link Configuration tool */
static int get_dc(const void *cookie, void **dc)
{
        u64 *p;
        unsigned long ul;

        p = kmalloc(sizeof(*p), GFP_KERNEL);
        if (p == NULL)
                return -ENOMEM;

        ul = (unsigned long)&tcm_downcalls;
        *p = (u64)ul;
        *dc = p;

        return (DB_TMP | DB_HEX | DB_UINT64);
}

static struct tcpcm_ioctl_create *copy_arguments_from_user(void __user *arg)
{
        struct tcpcm_ioctl_create k, *kp;
        size_t size;

        if (copy_from_user(&k, arg, sizeof(k)) != 0)
                return ERR_PTR(-EFAULT);

        size = sizeof(k) + k.name_len + 1 + k.feat_len + 1;

        kp = KMALLOC(size);
        if (kp == NULL)
                return ERR_PTR(-ENOMEM);

        if (copy_from_user(kp, arg, size) != 0) {
                KFREE(kp);
                return ERR_PTR(-EFAULT);
        }
        return kp;
}

static void *tcp_cm_create(void __user *arg)
{
        struct tcpcm_ioctl_create *p;
	struct RlnhLinkObj *co;
        int status;
        uint32_t remote_ip;

        if (try_module_get(THIS_MODULE) == 0)
                return ERR_PTR(-EINVAL);

        /* Get arguments from user-space. */
        p = copy_arguments_from_user(arg);
        if (IS_ERR(p)) {
		module_put(THIS_MODULE);
                return p;
	}

	remote_ip = p->ip_addr;
	if (remote_ip != 0) { /* ipv6? */
		if (vector_index_by_ip(remote_ip) != 0) {
			status = -EISCONN;
			goto error;
		}
	} else {
		if (vector_index_by_ipv6(p->ipv6_addr) != 0) {
			status = -EISCONN;
			goto error;
		}
	}

	co = co_create();
	if (co == NULL) {
		status = -ENOMEM;
		goto error;
	}

	if (p->live_tmo == 0)
		co->live_tmo = DEF_LIVE_TMO;
	else
		co->live_tmo = p->live_tmo;
	if (p->use_nagle == 1)
		co->use_nagle = 1;

	co->remote_ip = remote_ip;
	if(IPV6CONN(co)) {
		memcpy(&co->remote_ipv6, p->ipv6_addr, sizeof(struct in6_addr));
		co->ipv6_scope = p->ipv6_scope;
	} else {
		memset(&co->remote_ipv6, 0xff, sizeof(struct in6_addr));
	}

        co->con_name = linx_kstrdup((char *)kptr(p, p->name), GFP_KERNEL);
	if (co->con_name == NULL) {
                status = -ENOMEM;
                goto error_free_co;
        }
	/* This will be passed in downcalls. */
        co->con_cookie = (uint64_t)co->index;

	TCPCMDBG("index: %d, state: %d, %p", co->index, GET_STATE(co), co);

        KFREE(p);
	return co;

 error_free_co:
	co_free(co);
 error:
	module_put(THIS_MODULE);
        KFREE(p);
        return ERR_PTR(status);
}

static int tcp_cm_delete(void *cookie, void __user *arg)
{
	struct RlnhLinkObj *co = (struct RlnhLinkObj *)cookie;
        (void)arg;

	TCPCMDBG("index: %d, state: %d, %p", co->index, GET_STATE(co), cookie);

	/* Synchronized removal of co via workqueue */
	init_completion(&co->ready_for_destroy);
	co->remote_ip = 0;
	memset(&co->remote_ipv6, 0, sizeof(co->remote_ipv6));
	wq_put(wqo_create(co->index), linx_delete_task);
	wait_for_completion(&co->ready_for_destroy);
	co_free(co);
	module_put(THIS_MODULE);
	return 0;
}

/* Initialization and finalization of the TCP CM called from linx_module */
int tcp_cm_module_init(void)
{
	listen_pid = -1;
	listen_v6_pid = -1;

	if (linx_tcp_cm_port6 == linx_tcp_cm_port) {
		linx_err("LINX TCP CM: Same port for ipv4 and ipv6 "
			 "not supported");
		return -EINVAL;
	}

	INIT_LIST_HEAD(&linx_tcp_socks);

	wq_init();
	spin_lock_init(&tcp_cm_rx_list_lock);
	spin_lock_init(&timer_tasks_lock);
	spin_lock_init(&co_vector_lock);

	if (init_vector())
		return -ENOMEM;

	if (linx_tcp_cm_ipv6_support) {
		listen_v6_pid = kernel_thread((int (*)(void *))&listen6,
					      (void *)NULL, 0);
		if (listen_v6_pid < 0) {
			linx_err("Error starting linx_listen ipv6 thread");
			fini_vector();
			wq_fini();
			return -ECHILD;
		}
		init_completion(&listen_v6_done);
	}

	listen_pid = kernel_thread((int (*)(void *))&listen,
				   (void *)NULL, 0);
	if (listen_pid < 0) {
		linx_err("Error starting linx_listen thread");
		fini_vector();
		wq_fini();
		return -ECHILD;
	}
	init_completion(&listen_done);

        db_add_template(DB_KEY_TCPCM, &tcp_cm_template);
        db_proc_add(DB_KEY_TCPCM);

	printk("LINX TCP CM: IPv4 on port %d\n", linx_tcp_cm_port);
	printk("LINX TCP CM: IPv6 Support is %s\n",
	       linx_tcp_cm_ipv6_support ? "enabled" : "disabled");
	if (linx_tcp_cm_ipv6_support)
		printk("LINX TCP CM: IPv6 on port %d\n", linx_tcp_cm_port6);

	return 0;
}

void tcp_cm_module_fini(void)
{
        db_proc_del(DB_KEY_TCPCM);
        db_del_template(DB_KEY_TCPCM);
	stop_listen();
	fini_vector();
	wq_fini();
}
