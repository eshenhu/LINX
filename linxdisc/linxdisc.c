/*
 * Copyright (c) 2006-2010, Enea Software AB
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

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linx.h>
#include <linx_ioctl.h>
#include <linx_socket.h>
#include <linx_types.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <linxcfg.h>
#include "linxdisc.h"

#define CONFFILE		    "/etc/linxdisc.conf"
#define ETH_P_LINXDISC		    0x999A
#define ETH_BCAST		    (uint8_t *)"\xff\xff\xff\xff\xff\xff"
#define LINXDISC_ADVERTISMENT	    2
#define LINXDISC_RESOLVE_COLLISION  3
#define LINXDISC_SOLICITATION	    1
#define LOCKFILE		    "/var/run/linxdisc"
#define LOCKMODE		    (S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)
#define SA			    struct sockaddr
#define LINXDISC_RETRY_CNT          5

struct eth_hdr {
	uint8_t dst[IFHWADDRLEN];
	uint8_t src[IFHWADDRLEN];
	uint16_t type;
};

struct linxdisc_adv_msg {
	uint32_t linklen;
	uint32_t netlen;
	char strings[2];
};

struct linxdisc_res_msg {
	int pref;
};

struct linxdisc_msg {
	struct eth_hdr eh;
	uint16_t version;
	uint16_t type;
	uint32_t uptime_sec;
	uint32_t uptime_usec;
	union {
		struct linxdisc_adv_msg adv;
		struct linxdisc_res_msg res;
	} u;
};

/* Direct output: when daemon_proc != 0 output is sent to syslog otherwise
   to the terminal as usual. GLOBALS */

struct linxdisc_data linxdisc;

static int lockfile(int fd)
{
	struct flock fl;
	fl.l_type = F_WRLCK;
	fl.l_start = 0;
	fl.l_whence = SEEK_SET;
	fl.l_len = 0;
	return (fcntl(fd, F_SETLK, &fl));
}

static int already_running(int lock)
{
	int fd;

	if ((fd = open(LOCKFILE, O_RDWR | O_CREAT, LOCKMODE)) < 0) {
		err_sys("could not open %s", LOCKFILE);
	}
	if (lockfile(fd)) {
		close(fd);
		err_sys("linxdisc already running, cannot lock %s", LOCKFILE);
		return 1;
	}

	if (lock == 0)
		close(fd);

	return 0;
}

static struct peer_data *close_connection(struct peer_data *entry)
{
	struct peer_data *ret = linxdisc.peers;
        int status;

	if (!linxdisc.peers || !entry)
		return NULL;

	/* remove element from list */
	if (ret == entry) {
		linxdisc.peers = ret->next;
		ret = ret->next;
	} else {
		while (ret->next != entry) {
			if (ret->next == NULL)
				return NULL;
			else
				ret = ret->next;
		}
		ret->next = ret->next->next;
		ret = ret->next;
	}

	err_dbg("destroying %s", entry->name);
        status = linx_remove_link_and_connections(entry->name);
        if (status != 0)
                err_msg("couldn't remove %s (errno = %d)", entry->name, errno);

	memset(entry, 0, sizeof(struct peer_data));
	free(entry);

	return ret;
}

static void close_connections(void)
{
	struct peer_data *tmp = linxdisc.peers;

	while (tmp != NULL) {
		tmp = close_connection(tmp);
	}
}

void atexit_handler(void)
{
	err_msg("atexit handler called. Closing connections\n");
	close_connections();
	remove(LOCKFILE);
}

/* This function for creating a daemon process under UNIX is due to
   W.R.Stevens. */
static void daemonize(const char *cmd)
{
	int fd0, fd1, fd2;
	pid_t pid;
	struct rlimit r1;
	struct sigaction sa;

	umask(0);

	if (getrlimit(RLIMIT_NOFILE, &r1) < 0)
		err_sys("%s: getrlimit\n", cmd);

	/* Make sure output streams are empty when we daemonize */
	fflush(stdout);
	fflush(stderr);

	if ((pid = fork()) < 0)
		err_sys("%s: can't fork\n", cmd);
	else if (pid != 0)
		exit(0);
	if (setsid() < 0)
		err_sys("setsid\n");

	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGHUP, &sa, NULL) < 0)
		err_sys("SIGHUP\n");

	if ((pid = fork()) < 0)
		err_sys("%s: can't fork\n", cmd);
	else if (pid != 0)
		exit(0);

	if (chdir("/") < 0)
		err_sys("%s: can't change directory\n", cmd);

	if (r1.rlim_max == RLIM_INFINITY)
		r1.rlim_max = 1024;

	/* From now on output must go to syslog. */
	linxdisc.daemon_proc = 1;

	for (unsigned i = 0; i < r1.rlim_max; i++)
		close(i);

	fd0 = open("/dev/null", O_RDWR);
	fd1 = dup(0);
	fd2 = dup(0);

	openlog(cmd, LOG_CONS, LOG_DAEMON);
	if (fd0 != 0 || fd1 != 1 || fd2 != 2)
		err_sys("unexpected file descriptors %d %d %d\n",
			fd0, fd1, fd2);
}

static int is_name_connected(const char *name)
{
	struct peer_data *tmp = linxdisc.peers;

	while (tmp != NULL) {
		if (strcmp(tmp->name, name) == 0)
			return 1;
		tmp = tmp->next;
	}

	return 0;
}

static int get_name_connected_hwaddr(char *name, const uint8_t * addr)
{
	struct peer_data *tmp = linxdisc.peers;

	while (tmp != NULL) {
		if (memcmp(tmp->addr, addr, IFHWADDRLEN) == 0 &&
		    tmp->name[0] != '\0') {
			strcpy(name, tmp->name);
			return 1;
		}
		tmp = tmp->next;
	}

	return 0;
}

static int disallowed_interface(const char *name)
{
	uint8_t i;
	
	if (0 == linxdisc.config->no_iface)
		return 0;

	for (i = 0; i < linxdisc.config->no_iface; i++) {
		if (0 == strcmp(linxdisc.config->iface[i].name, name))
			return 0;
	}

	return -1;
}

static int llsocket(struct sockaddr *hwaddr, socklen_t len)
{
	int sd;
	int on = 1;

	sd = Socket(PF_PACKET, SOCK_RAW, htons(ETH_P_LINXDISC));
	Ioctl(sd, FIONBIO, &on);
	Bind(sd, hwaddr, len);

	return sd;
}

static struct if_data *create_if_data(void)
{
	int sd;
	int i;
	struct if_data *ifdhead, **ifdnext;

	ifdhead = NULL;
	ifdnext = &ifdhead;

	struct if_nameindex *if_ni = if_nameindex();

	sd = Socket(AF_INET, SOCK_DGRAM, 0);

	for (i = 0; if_ni[i].if_index && if_ni[i].if_name; i++) {
		struct ifreq ifr;

		/* Ignore alias interfaces, we're interested in real
		   interfaces only. */
		if (strchr(if_ni[i].if_name, ':') != NULL)
			continue;

		if (disallowed_interface(if_ni[i].if_name))
			continue;
		
		memset(&ifr, 0, sizeof ifr);
		if (strlen(if_ni[i].if_name) >= IFNAMSIZ)
			err_sys("Interface %s longer than %d\n",
				if_ni[i].if_name, IFNAMSIZ - 1);
		strcpy(ifr.ifr_name, if_ni[i].if_name);
		Ioctl(sd, SIOCGIFFLAGS, &ifr);
		if ((ifr.ifr_flags & IFF_UP) == 0)
			continue;
		if ((ifr.ifr_flags & IFF_BROADCAST) == 0)
			continue;
		if (ifr.ifr_flags & IFF_LOOPBACK)
			continue;
		err_dbg("%s %s\n", ifr.ifr_name, ifftostr(ifr.ifr_flags));

		struct if_data *ifd = Malloc(sizeof(struct if_data));
		memset(ifd, 0, sizeof(struct if_data));
		*ifdnext = ifd;
		ifdnext = &ifd->ifd_next;
		ifd->ifd_flags = ifr.ifr_flags;

		memcpy(ifd->ifd_name, ifr.ifr_name, IFNAMSIZ);

		ifd->ifd_index = if_nametoindex(if_ni[i].if_name);
		err_dbg("%s %d\n", ifr.ifr_name, ifr.ifr_ifindex);

		Ioctl(sd, SIOCGIFMTU, &ifr);
		ifd->ifd_mtu = ifr.ifr_mtu;
		err_dbg("%s %d\n", ifr.ifr_name, ifr.ifr_mtu);

		Ioctl(sd, SIOCGIFHWADDR, &ifr);
		ifd->ifd_hwlen = IFHWADDRLEN;
		err_dbg("%s %d\n", ifr.ifr_name, IFHWADDRLEN);
		memcpy(ifd->ifd_hwaddr, &ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);
		err_dbg("%s %02x:%02x:%02x:%02x:%02x:%02x\n",
			ifr.ifr_name,
			(unsigned char)ifr.ifr_hwaddr.sa_data[0],
			(unsigned char)ifr.ifr_hwaddr.sa_data[1],
			(unsigned char)ifr.ifr_hwaddr.sa_data[2],
			(unsigned char)ifr.ifr_hwaddr.sa_data[3],
			(unsigned char)ifr.ifr_hwaddr.sa_data[4],
			(unsigned char)ifr.ifr_hwaddr.sa_data[5]);

		struct sockaddr_ll hwaddr;
		memset(&hwaddr, 0, sizeof hwaddr);
		hwaddr.sll_family = PF_PACKET;
		hwaddr.sll_protocol = htons(ETH_P_LINXDISC);
		hwaddr.sll_ifindex = ifd->ifd_index;

		ifd->ifd_sd = llsocket((SA *) & hwaddr, sizeof hwaddr);
	}
	if_freenameindex(if_ni);

	Close(sd);

	return ifdhead;
}

static void free_if_data(struct if_data *ifs)
{
	while (ifs) {
		struct if_data *next = ifs->ifd_next;
		Close(ifs->ifd_sd);
		free(ifs);
		ifs = next;
	}
}

static char *getnetworkid(void)
{
	return linxdisc.config->linx_net_name;
}

static char *getnodename(void)
{
	return linxdisc.config->node_name;
}

static void setnodename(const char *name)
{
	strcpy(linxdisc.config->node_name, name);
}

static int own_message(struct if_data *ifs, uint8_t * src)
{
	while (NULL != ifs) {
		if (memcmp(ifs->ifd_hwaddr, src, IFHWADDRLEN) == 0) {
			return -1;
		}
		ifs = ifs->ifd_next;
	}
	return 0;
}

static int connection_not_allowed(const char *name)
{
	uint8_t i;
	int namelen = strlen(name);

	for (i = 0; i < linxdisc.config->no_allow; i++) {
		if (0 == memcmp(linxdisc.config->allow[i].name, name, namelen))
			return 0;
	}

	if (linxdisc.config->no_allow > 0)
		return -1;

	for (i = 0; i < linxdisc.config->no_deny; i++) {
		if (0 == memcmp(linxdisc.config->deny[i].name, name, namelen))
			return -1;
	}

	return 0;
}

static int connection_collision(const char *name, const uint8_t * addr)
{
	int namelen = strlen(name);
	struct peer_data *tmp = linxdisc.peers;

	if (namelen == 0 || namelen > LINXNAMSIZ) {
		err_msg("Illegal name %s len %d\n", name, namelen);
		return -1;
	}

	/* Walk through known associations and check if we already have a
	 * node using this name. */
	while (tmp != NULL) {
		if (tmp->name[0] != '\0') {
			if (strcmp(tmp->name, name) == 0) {
				if (memcmp(tmp->addr, addr, IFHWADDRLEN))
					return -1;
				else
					tmp->tmocnt = 3;
			}
		}
		tmp = tmp->next;
	}

	return 0;
}

static void close_disallowed_connections(void)
{
	struct peer_data *tmp = linxdisc.peers;
	while (tmp != NULL) {
		if (tmp->name[0] != '\0' && connection_not_allowed(tmp->name)) {
			tmp = close_connection(tmp);
		} else {
			tmp = tmp->next;
		}
	}

	tmp = linxdisc.peers;
	while (tmp != NULL) {
		if (strcmp(tmp->network, linxdisc.config->linx_net_name) != 0) {
			tmp = close_connection(tmp);
		} else {
			tmp = tmp->next;
		}
	}
}

static void register_connection(struct linxdisc_msg *msg)
{
	struct peer_data *tmp = Malloc(sizeof(struct peer_data));
	tmp->network[0] = '\0';

	strcpy(tmp->name, msg->u.adv.strings);
	memcpy(tmp->addr, msg->eh.src, IFHWADDRLEN);
	strcpy(tmp->network,
	       msg->u.adv.strings + ntohl(msg->u.adv.linklen) + 1);
	tmp->tmocnt = 3;

	tmp->next = linxdisc.peers;
	linxdisc.peers = tmp;
}

static void remove_connection(const char *name)
{
	struct peer_data *tmp = linxdisc.peers;
	while (tmp != NULL) {
		if (strcmp(tmp->name, name) == 0) {
			(void)close_connection(tmp);
			return;
		}
		tmp = tmp->next;
	}
}

static void print_con_param(struct linx_con_arg_eth *p)
{
	err_dbg("create connection\n");
	err_dbg("name             : %s\n", p->name);
	err_dbg("dev              : %s\n", p->ethif);
	err_dbg("mac              : %s\n", p->mac);
	err_dbg("features         : %s\n", p->features);
        err_dbg("mtu              : %u\n", p->mtu);
        err_dbg("window_size      : %u\n", p->window_size);
        err_dbg("defer_queue_size : %u\n", p->defer_queue_size);
        err_dbg("send_tmo         : %u\n", p->send_tmo);
        err_dbg("nack_tmo         : %u\n", p->nack_tmo);
        err_dbg("conn_tmo         : %u\n", p->conn_tmo);
        err_dbg("live_tmo         : %u\n", p->live_tmo);
}

static void print_link_param(struct linx_link_arg *p)
{
        char *s;
        int n;

	err_dbg("create link\n");
	err_dbg("name         : %s\n", p->name);
	err_dbg("attributes   : %s\n", p->attributes);
	err_dbg("features     : %s\n", p->features);
        for (s = p->connections, n = 1; *s != '\0'; s += strlen(s) + 1, n++)
                err_dbg("connection%02d: %s\n", n, s);
}

static void
print_message(struct sockaddr_ll *hwaddr,
	      struct linxdisc_msg *msg, const char *str)
{
	err_dbg(str);
	err_dbg("   family : %d\n", hwaddr->sll_family);
	err_dbg(" protocol : %x\n", hwaddr->sll_protocol);
	err_dbg("  ifindex : %d\n", hwaddr->sll_ifindex);
	err_dbg("    halen : %d\n", hwaddr->sll_halen);
	err_dbg("     addr : %02x:%02x:%02x:%02x:%02x:%02x\n",
		hwaddr->sll_addr[0], hwaddr->sll_addr[1],
		hwaddr->sll_addr[2], hwaddr->sll_addr[3],
		hwaddr->sll_addr[4], hwaddr->sll_addr[5]);
	err_dbg("  version : %x\n", ntohs(msg->version));
	err_dbg("     type : %x\n", ntohs(msg->type));
	err_dbg("   uptime : %d.%d\n",
		ntohl(msg->uptime_sec), ntohl(msg->uptime_usec));
	if (ntohl(msg->type) == LINXDISC_ADVERTISMENT) {
		err_dbg("  linklen : %d\n", ntohl(msg->u.adv.linklen));
		err_dbg("   netlen : %d\n", ntohl(msg->u.adv.netlen));
		err_dbg(" linkname : %s\n", msg->u.adv.strings);
		err_dbg("networkid : %s\n",
			msg->u.adv.strings + ntohl(msg->u.adv.linklen) + 1);
	} else if (ntohl(msg->type) == LINXDISC_RESOLVE_COLLISION) {
		err_dbg("preferred : %s\n", msg->u.res.pref ? "TRUE" : "FALSE");
	}
}

static long get_integer_param(char *param)
{
	char *tmp;
	long ret = 0;

	if ((tmp = strchr(param, '=')) != NULL) {
		char *end;

		errno = 0;
		ret = strtol(tmp + 1, &end, 0);
		if (errno != 0) {
			if (*end != '\0') {
				err_msg("Bad parameter at %s", end);
			}
		}
	}

	return ret;
}

static char *find_value(const char *s)
{
        char *p;
                
        p = strchr(s, '=');
        return (p != NULL ? p + 1 : NULL);
}

static char *copy_str_value(const char *param)
{
        char *tmp;

        tmp = find_value(param);        
        return (tmp != NULL ? strdup(tmp) : NULL);
}

static void get_conn_link_params(struct linx_con_arg_eth *cp,
                                 struct linx_link_arg *lp)
{
        int i;

	for (i = 0; i < linxdisc.config->no_param; i++) {
		char *name_val = linxdisc.config->params[i].name_val;

                /* Connection parameters */
		if (strstr(name_val, "mtu") != NULL) {
			cp->mtu = (uint32_t)get_integer_param(name_val);
		} else if (strstr(name_val, "window_size") != NULL) {
			cp->window_size = (uint32_t)get_integer_param(name_val);
		} else if (strstr(name_val, "defer_queue_size") != NULL) {
			cp->defer_queue_size =
                                (uint32_t)get_integer_param(name_val);
		} else if (strstr(name_val, "send_tmo") != NULL) {
			err_msg("Warning! send_tmo is obsolete from LINX 2.2.0",
                                name_val);
		} else if (strstr(name_val, "nack_tmo") != NULL) {
			err_msg("Warning! nack_tmo is obsolete from LINX 2.2.0",
                                name_val);
		} else if (strstr(name_val, "conn_tmo") != NULL) {
			cp->conn_tmo = (uint32_t)get_integer_param(name_val);
		} else if (strstr(name_val, "live_tmo") != NULL) {
			err_msg("Warning! live_tmo is obsolete from LINX 2.2.0",
                                name_val);
		}
                /* Link parameters */
                else if (strstr(name_val, "attributes") != NULL) {
                        lp->attributes = copy_str_value(name_val);
		} else {
			err_msg("Unknown LINX parameter %s.", name_val);
		}
	}
}

static void establish_connection(char *ifname, struct linxdisc_msg *msg)
{
	union linx_con_arg con;
	struct linx_link_arg lnk;
	char namebuf[LINXNAMSIZ];
	int status;

	err_dbg("TRY TO ESTABLISH CONNECTION!\n");
	if (is_name_connected(msg->u.adv.strings)) {
		return;
	}

	if (get_name_connected_hwaddr(namebuf, msg->eh.src)) {
		err_msg("Destroying connection %s\n", namebuf);
		remove_connection(namebuf);
	}

	snprintf(namebuf, LINXNAMSIZ, "%02x:%02x:%02x:%02x:%02x:%02x",
		 (unsigned int)msg->eh.src[0], (unsigned int)msg->eh.src[1], 
		 (unsigned int)msg->eh.src[2], (unsigned int)msg->eh.src[3], 
		 (unsigned int)msg->eh.src[4], (unsigned int)msg->eh.src[5]);
                
	memset(&con.eth, 0, sizeof(con.eth));
	con.eth.name = msg->u.adv.strings;
	con.eth.ethif = ifname;
	con.eth.mac = namebuf;
	con.eth.coreid = -1;
	
	memset(&lnk, 0, sizeof(lnk));
	lnk.name = msg->u.adv.strings;

	get_conn_link_params(&con.eth, &lnk);

	print_con_param(&con.eth);
	status = linx_create_connection(LINX_CON_ETH, &con, &lnk.connections);
	if (status != 0) {
		free(con.eth.features);
		free(lnk.features);
		free(lnk.attributes);
		err_msg("Creating connection %s failed (%d)\n",
			con.eth.name, status);
		return;
	}
	free(con.eth.features);

	print_link_param(&lnk);
	status = linx_create_link(&lnk);
	if (status != 0) {
		err_msg("Creating link %s failed (%d)\n", lnk.name, status);
		free(lnk.connections);
		free(lnk.features);
		free(lnk.attributes);
		return;
	}
	free(lnk.connections);
	free(lnk.features);
	free(lnk.attributes);

	register_connection(msg);
	err_msg("Connected to %s\n", lnk.name);
}

static void timeout_connections(void)
{
	struct peer_data *tmp = linxdisc.peers;
	struct peer_data *next;

	while (tmp != NULL) {
		next = tmp->next;
		if (--tmp->tmocnt == 0) {
			err_msg("linxdisc: remove %s due to tmo\n", tmp->name);
			remove_connection(tmp->name);
		}
		tmp = next;
	}
}

static void
init_lladdr(struct sockaddr_ll *hwaddr, struct if_data *ifd, uint8_t * dst)
{
	memset(hwaddr, 0, sizeof(struct sockaddr_ll));
	hwaddr->sll_family = PF_PACKET;
	hwaddr->sll_protocol = htons(ETH_P_LINXDISC);
	hwaddr->sll_ifindex = ifd->ifd_index;
	hwaddr->sll_halen = ifd->ifd_hwlen;
	memcpy(hwaddr->sll_addr, dst, ifd->ifd_hwlen);
}

static void
init_linxdisc_msg_hdr(struct linxdisc_msg *msg,
		      struct if_data *ifd, uint8_t * dst, int type)
{
	memcpy(msg->eh.dst, dst, ifd->ifd_hwlen);
	memcpy(msg->eh.src, ifd->ifd_hwaddr, ifd->ifd_hwlen);
	msg->eh.type = htons(ETH_P_LINXDISC);
	msg->type = htons(type);
	msg->version = htons(LINXDISC_VERSION);
}

static void timestamp_linxdisc_msg(struct linxdisc_msg *msg)
{
	struct timeval now = { 0, 0 };
	struct timeval uptime = { 0, 0 };

	gettimeofday(&now, NULL);
	timersub(&now, &linxdisc.start, &uptime);

	msg->uptime_sec = htonl(uptime.tv_sec);
	msg->uptime_usec = htonl(uptime.tv_usec);
}

static void send_advertisment_msg(struct if_data *ifd)
{
	struct sockaddr_ll hwaddr;
	struct linxdisc_msg *msg;
	int msglen;
	int linklen = strlen(getnodename());
	int netlen = strlen(getnetworkid());
	uint8_t *dst = ETH_BCAST;

	init_lladdr(&hwaddr, ifd, dst);
	msglen = sizeof(struct linxdisc_msg) + linklen + netlen;
	msg = Malloc(msglen);
	memset(msg, 0, msglen);
	init_linxdisc_msg_hdr(msg, ifd, dst, LINXDISC_ADVERTISMENT);
	timestamp_linxdisc_msg(msg);
	msg->u.adv.linklen = htonl(linklen);
	msg->u.adv.netlen = htonl(netlen);
	strncpy(msg->u.adv.strings, getnodename(), linklen);
	strncpy(msg->u.adv.strings + linklen + 1, getnetworkid(), netlen);

	print_message(&hwaddr, msg, "outgoing message");

	Sendto(ifd->ifd_sd, msg, msglen, 0, (SA *) & hwaddr, sizeof hwaddr);
	free(msg);
}

static void
send_resolve_collision_msg(struct if_data *ifd, uint8_t * dst, int pref)
{
	struct sockaddr_ll hwaddr;
	struct linxdisc_msg *msg;
	int msglen;

	init_lladdr(&hwaddr, ifd, dst);
	msglen = sizeof(struct linxdisc_msg);
	msg = Malloc(msglen);
	memset(msg, 0, msglen);
	init_linxdisc_msg_hdr(msg, ifd, dst, LINXDISC_RESOLVE_COLLISION);
	timestamp_linxdisc_msg(msg);
	msg->u.res.pref = htonl(pref);

	print_message(&hwaddr, msg, "outgoing message");

	Sendto(ifd->ifd_sd, msg, msglen, 0, (SA *) & hwaddr, sizeof hwaddr);
	free(msg);
}

static void
recv_advertisment_msg(struct sockaddr_ll *from, struct linxdisc_msg *msg,
		      struct if_data *ifd)
{
	char *myname, *mynetwork;
	int mynamelen, mynetlen;
	int peernamelen, peernetlen;

	/* Discard messages from local interfaces. */
	if (own_message(ifd, from->sll_addr)) {
		err_dbg("Dropping my own message from: "
			"%02x:%02x:%02x:%02x:%02x:%02x\n",
			from->sll_addr[0], from->sll_addr[1],
			from->sll_addr[2], from->sll_addr[3],
			from->sll_addr[4], from->sll_addr[5]);
		return;
	}

	/* Network id must match */
	mynetwork = getnetworkid();
	mynetlen = strlen(mynetwork);
	peernamelen = ntohl(msg->u.adv.linklen);
	peernetlen = ntohl(msg->u.adv.netlen);
	if (peernetlen == 0 && mynetlen == 0) {
		err_dbg("No LINX network ID, accept all connections\n");
	} else if (peernetlen != mynetlen ||
		   (strncmp(mynetwork, msg->u.adv.strings + peernamelen + 1,
			    peernetlen) != 0)) {
		err_dbg("LINX network ID does not match\n");
		return;
	}

	myname = getnodename();
	mynamelen = strlen(myname);
	/* Check that incoming name is unique, first this nodes name... */
	if (strncmp(myname, msg->u.adv.strings, peernamelen) == 0 &&
	    mynamelen == peernamelen) {
		/* If peer nodename is the same as we do we have a
		 * collision, determin who's allowed to remain in the
		 * cluster. */
		struct timeval now, uptime, peer_uptime;
		gettimeofday(&now, NULL);
		timersub(&now, &linxdisc.start, &uptime);
		peer_uptime.tv_sec = ntohl(msg->uptime_sec);
		peer_uptime.tv_usec = ntohl(msg->uptime_usec);
		err_dbg("collision my uptime/peer uptime %u.%u/%u.%u\n",
			uptime.tv_sec, uptime.tv_usec,
			peer_uptime.tv_sec, peer_uptime.tv_usec);
		send_resolve_collision_msg(ifd, msg->eh.src,
					   timercmp(&uptime, &peer_uptime, >));
		err_msg("local collision %s\n", msg->u.adv.strings);
		return;
	}

	/* ...and then other names that the node is connected to. */
	if (connection_collision(msg->u.adv.strings, from->sll_addr)) {
		/* Determine which linxdisc that should exit. */
		err_msg("remote collision %s\n", msg->u.adv.strings);
		return;
	}
	/* Check if the config file allows this connection. */
	if (connection_not_allowed(msg->u.adv.strings)) {
		err_dbg("connection not allowed: %s", msg->u.adv.strings);
		return;
	}

	establish_connection(ifd->ifd_name, msg);
}

static void
recv_resolve_collision_msg(struct sockaddr_ll *from, struct linxdisc_msg *msg)
{
	struct timeval now, uptime, peer_uptime;

	gettimeofday(&now, NULL);
	timersub(&now, &linxdisc.start, &uptime);
	peer_uptime.tv_sec = ntohl(msg->uptime_sec);
	peer_uptime.tv_usec = ntohl(msg->uptime_usec);
	err_dbg("Peer challenging us %u.%u/%u.%u (uptime/peer_uptime) %s\n",
		uptime.tv_sec, uptime.tv_usec,
		peer_uptime.tv_sec, peer_uptime.tv_usec,
		ntohl(msg->u.res.pref) ? "pref" : "not pref");
	if (timercmp(&uptime, &peer_uptime, <) && ntohl(msg->u.res.pref)) {
		err_quit("Misconfigured node - local collision.\n");
	} else if (timercmp(&uptime, &peer_uptime, <) &&
		   !ntohl(msg->u.res.pref)) {
		/* Break tie based on mac address, if peer address is
		 * higher he wins an we exit from the cluster. */
		if (memcmp(msg->eh.dst, msg->eh.src, from->sll_halen) < 0) {
			err_quit("Misconfigured node - local collision.\n");
		}
	}
}

static void recv_linxdisc_msg(struct if_data *ifd)
{
	uint8_t rcvbuf[1514];
	struct sockaddr_ll from;
	socklen_t flen = sizeof(from);
	struct linxdisc_msg *msg;
	int ret;

	ret = RecvFrom(ifd->ifd_sd, rcvbuf, sizeof(rcvbuf),
		       0, (void *)&from, &flen);
	if (ret <= 0)
		return;

	msg = (struct linxdisc_msg *)rcvbuf;
	
	print_message(&from, msg, "incoming message");
	
	if (ntohs(msg->version) != LINXDISC_VERSION) {
		/* Throw away messages from linxdiscs with
		 * with mismatching version number. */
		err_dbg("Linxdisc received msg with version number %d"
			", expected %d\n", ntohs(msg->version),
			LINXDISC_VERSION);
		return;
	}
	
	if (ntohs(msg->type) == LINXDISC_ADVERTISMENT) {
		recv_advertisment_msg(&from, msg, ifd);
	} else if (ntohs(msg->type) == LINXDISC_RESOLVE_COLLISION) {
		recv_resolve_collision_msg(&from, msg);
	}
}

static void do_linx_discovery(void)
{
	int ret;
	fd_set rset;
	fd_set wset;
	struct timeval tmo = { 3, 0 };
	struct if_data *ifd;

	for (ifd = linxdisc.ifs; ifd != NULL; ifd = ifd->ifd_next) {
		send_advertisment_msg(ifd);
	}

	for(;;) {
		FD_ZERO(&rset);
		FD_ZERO(&wset);
		
		for (ifd = linxdisc.ifs; ifd != NULL; ifd = ifd->ifd_next) {
			FD_SET(ifd->ifd_sd, &rset);
		}
		
		ret = Select(linxdisc.sd_max + 1, &rset, &wset, NULL, &tmo);
		if (ret <= 0) {
			err_dbg("timeout\n");
			timeout_connections();
			return;
		}
		for (ifd = linxdisc.ifs; ifd != NULL; ifd = ifd->ifd_next) {
			if (FD_ISSET(ifd->ifd_sd, &rset)) {
				recv_linxdisc_msg(ifd);
			}
		}
	}
}

void sigterm(int signo)
{
	(void)signo;
	err_msg("Got SIGTERM, exiting\n");
	close_connections();
	exit(0);
}

void sighup(int signo)
{
	(void)signo;
	struct if_data *ifd;

	free_if_data(linxdisc.ifs);

	err_msg("Updating interface information\n");

	linxdisc.ifs = create_if_data();
	for (ifd = linxdisc.ifs; ifd != NULL; ifd = ifd->ifd_next) {
		linxdisc.sd_max = MAX(linxdisc.sd_max, ifd->ifd_sd);
	}

	err_msg("Re-reading configuration file\n");

	linxdisc.config = read_conf(linxdisc.conffile);

	if (strlen(getnodename()) == 0) {
		char hostname[LINXNAMSIZ];

		if (gethostname(hostname, sizeof hostname) == -1)
			err_sys("can't read hostname\n");
		setnodename(hostname);
	}

	/* update connections ! */
	close_disallowed_connections();
}

static void usage(void)
{
	err_msg("Usage: linxdisc [-c <config_file>] [-d]\n");
	exit(1);
}

int main(int argc, char **argv)
{
	struct sigaction sa;
	int do_daemonize = 1;
	int opt;
	LINX *linxdisc_linx;
	struct if_data *ifd;

	linxdisc.daemon_proc = 0;
	linxdisc.conffile = NULL;
	linxdisc.retry_count = LINXDISC_RETRY_CNT;
	
	while ((opt = getopt(argc, argv, "dc:")) != -1) {
		switch (opt) {
		case 'd':
			do_daemonize = 0;
			break;
		case 'c':
			/* linxdisc needs absolute path to the conf
			 * file if run as a daemon process to be able
			 * to re-parse it when receiving SIGHUP. */
			if (optarg[0] == '/')
				linxdisc.conffile = optarg;
			else {
				char *cwd = NULL;
				cwd = getcwd(cwd, 0);
				linxdisc.conffile = Malloc(strlen(cwd) +
							   strlen(optarg) + 2);
				sprintf(linxdisc.conffile, "%s/%s",
					cwd, optarg);
				free(cwd);
			}
			break;
		default:
			usage();
		}
	}

	if (linxdisc.conffile == NULL) {
		linxdisc.conffile = Malloc(strlen(CONFFILE) + 1);
		strcpy(linxdisc.conffile, CONFFILE);	/* default */
	}

	/* Read linxdisc configuration before daemonizing to
	 * make sure the file exist and is correct. */
	linxdisc.config = read_conf(linxdisc.conffile);

	already_running(0);	/* just check, dont lock */

	if (do_daemonize)
		daemonize(argv[0]);

	/* lock running process */

	already_running(1);

	err_msg("linxdisc has started\n");

	/* setup an atexit_handler so that open connections are dealt
	   with upon an exit from err_quit() and err_sys() */
	if (0 != atexit(atexit_handler))
		err_sys("cannot setup an atexit handler\n");

	/* Setup signal handlers, at the moment we only care about two
	   SIGTERM and SIGHUP. SIGTERM causes a clean exit and SIGHUP
	   forces the linxdisc daemon to close all connections and
	   reread its configuration file and apply new rules to
	   received advertisements. */
	sa.sa_handler = sigterm;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGHUP);
	sa.sa_flags = 0;
	if (sigaction(SIGTERM, &sa, NULL) < 0)
		err_sys("can't catch SIGTERM\n");

	sa.sa_handler = sighup;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGTERM);
	sa.sa_flags = 0;
	if (sigaction(SIGHUP, &sa, NULL) < 0)
		err_sys("can't catch SIGHUP\n");

	if (strlen(getnodename()) == 0) {
		/* NODE_NAME not set in conf, use hostname instead */
		char hostname[LINXNAMSIZ];

		if (gethostname(hostname, sizeof hostname) == -1)
			err_sys("can't read hostname\n");
		setnodename(hostname);
	}

	gettimeofday(&linxdisc.start, NULL);

	linxdisc.ifs = create_if_data();
	for (ifd = linxdisc.ifs; ifd != NULL; ifd = ifd->ifd_next) {
		linxdisc.sd_max = MAX(linxdisc.sd_max, ifd->ifd_sd);
	}

	/* Used to supervise linxdisc. */
	if ((linxdisc_linx = linx_open("linxdisc", 0, NULL)) == NULL) {
		remove(LOCKFILE);
		err_sys("linx.ko not loaded, could not create linx socket\n");
	}

	/*  Never return ... */
	for (;;)
		do_linx_discovery();
}
