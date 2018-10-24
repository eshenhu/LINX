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

#include <arpa/inet.h>
#include <errno.h>
#include <linx_ioctl.h>
#include <linx_socket.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "linxdisc.h"

#define INADDR_SIZE sizeof "[255.255.255.255:12345] "

extern struct linxdisc_data linxdisc;

static char *ascii_addr(const struct sockaddr *addr)
{
	static char s[INADDR_SIZE];

	if (addr->sa_family == PF_INET) {
		struct sockaddr_in *inaddr = (struct sockaddr_in *)addr;
		snprintf(s, INADDR_SIZE, "[%s:%d]",
			 inet_ntoa(inaddr->sin_addr), ntohs(inaddr->sin_port));
	} else if (addr->sa_family == PF_PACKET) {
		struct sockaddr_ll *lladdr = (struct sockaddr_ll *)addr;
		snprintf(s, INADDR_SIZE,
			 "[%02x:%02x:%02x:%02x:%02x:%02x]",
			 (uint8_t) lladdr->sll_addr[0],
			 (uint8_t) lladdr->sll_addr[1],
			 (uint8_t) lladdr->sll_addr[2],
			 (uint8_t) lladdr->sll_addr[3],
			 (uint8_t) lladdr->sll_addr[4],
			 (uint8_t) lladdr->sll_addr[5]);
	}
	return s;
}

static char *domaintostr(int domain)
{
	switch (domain) {
	case PF_INET:
		return "PF_INET";
	case PF_LINX:
		return "PF_INET";
	case PF_PACKET:
		return "PF_PACKET";
	default:
		return "ERROR";
	}
}

static char *typetostr(int type)
{
	switch (type) {
	case SOCK_STREAM:
		return "SOCK_STREAM";
	case SOCK_DGRAM:
		return "SOCK_DGRAM";
	case SOCK_RAW:
		return "SOCK_RAW";
	case SOCK_PACKET:
		return "SOCK_PACKET";
	default:
		return "ERROR";
	}
}

static char *ioctltostr(unsigned long req)
{
	char ioctlreq[80];

	memset(ioctlreq, 0, 80);

	switch (req) {
	case FIONBIO:
		return "FIONBIO";
	case SIOCGIFADDR:
		return "SIOCGIFADDR";
	case SIOCGIFBRDADDR:
		return "SIOCGIFBRDADDR";
	case SIOCGIFNETMASK:
		return "SIOCGIFNETMASK";
	case SIOCGIFMTU:
		return "SIOCGIFMTU";
	case SIOCGIFFLAGS:
		return "SIOCGIFFLAGS";
	case SIOCGARP:
		return "SIOCGARP";
	case SIOCGIFMETRIC:
		return "SIOCGIFMETRIC";
	case SIOCSIFADDR:
		return "SIOCSIFADDR";
	case SIOCSIFBRDADDR:
		return "SIOCSIFBRDADDR";
	case SIOCSIFNETMASK:
		return "SIOCSIFNETMASK";
	case SIOCSIFDSTADDR:
		return "SIOCSIFDSTADDR";
	case SIOCSIFMTU:
		return "SIOCSIFMTU";
	case SIOCSIFFLAGS:
		return "SIOCSIFFLAGS";
	case SIOCSARP:
		return "SIOCSARP";
	case SIOCDARP:
		return "SIOCDARP";
	case SIOCSIFMETRIC:
		return "SIOCSIFMETRIC";
	case SIOCGIFINDEX:
		return "SIOCGIFINDEX";
	case SIOCGIFHWADDR:
		return "SIOCGIFHWADDR";
	default:
		return "UNKNOWN IOCTL";
	}
}

char *ifftostr(int flags)
{
#define BUFLEN 100
	int len = 0;
	static char buf[BUFLEN];
	char *tmp = buf;

	memset(buf, 0, BUFLEN);
	len += snprintf(tmp, BUFLEN, "<");
	if (flags & IFF_UP)
		len += snprintf(tmp + len, BUFLEN - len, "UP ");
	if (flags & IFF_BROADCAST)
		len += snprintf(tmp + len, BUFLEN - len, "BROADCAST ");
	if (flags & IFF_DEBUG)
		len += snprintf(tmp + len, BUFLEN - len, "DEBUG ");
	if (flags & IFF_LOOPBACK)
		len += snprintf(tmp + len, BUFLEN - len, "LOOPBACK ");
	if (flags & IFF_POINTOPOINT)
		len += snprintf(tmp + len, BUFLEN - len, "POINTOPOINT ");
	if (flags & IFF_RUNNING)
		len += snprintf(tmp + len, BUFLEN - len, "RUNNING ");
	if (flags & IFF_NOARP)
		len += snprintf(tmp + len, BUFLEN - len, "NOARP ");
	if (flags & IFF_PROMISC)
		len += snprintf(tmp + len, BUFLEN - len, "PROMISC ");
	len += snprintf(tmp + len - 1, BUFLEN - len, ">");
#undef BUFLEN

	return buf;
}

int Bind(int sd, const struct sockaddr *addr, socklen_t addrlen)
{
	int ret;

	err_dbg("bind(%d, %s, %d)", sd, ascii_addr(addr), addrlen);

	if ((ret = bind(sd, addr, addrlen)) == -1)
		err_sys("bind(%d, %s, %d) -> -1\n",
			sd, ascii_addr(addr), addrlen, ret);

	err_dbg(" -> %d\n", ret);

	return ret;
}

int Close(int fd)
{
	int ret;

	err_dbg("close(%d)", fd);

	if ((ret = close(fd)) == -1)
		err_sys("close(%d) -> %d\n", fd, ret);

	err_dbg(" -> 0\n");

	return ret;
}

int Ioctl(int d, unsigned long request, void *arg)
{
	int ret;

	err_dbg("ioctl(%d, %s, %p)", d, ioctltostr(request), arg);

	if ((ret = ioctl(d, request, arg)) < 0) {
		if (errno == ENOMEM)
			err_msg("ioctl(%d, %s, %p) -> %d (%s)\n",
				d, ioctltostr(request), arg, ret,
				strerror(errno));
		else
			err_sys("ioctl(%d, %s, %p) -> %d\n",
				d, ioctltostr(request), arg, ret);
	}

	err_dbg(" -> %d\n", ret);

	return ret;
}

void *Malloc(size_t s)
{
	void *ret;

	if ((ret = malloc(s)) == NULL)
		err_quit("malloc(*d) -> NULL\n", s);

	return ret;
}

int
RecvFrom(int sd, void *buf, size_t len, int flags,
	 struct sockaddr *from, socklen_t * flen)
{
	int ret;

	err_dbg("recvfrom(%d, %p, %d, %d %p %p)",
		sd, buf, len, flags, from, flen);

	if ((ret = recvfrom(sd, buf, len, flags, from, flen)) < 0)
		if (errno != EWOULDBLOCK)
			err_sys("recvfrom(%d, %p, %d, %d %p %p) -> %d\n",
				sd, buf, len, flags, from, flen, ret);

	err_dbg(" -> %d\n", ret);

	return ret;
}

int
Select(int n, fd_set * rfds, fd_set * wfds, fd_set * efds, struct timeval *tmo)
{
	int ret;

	err_dbg("select(%d, %04lx, %04lx, %s, %s)",
		n, rfds->fds_bits[0], wfds->fds_bits[0], "efds", "tmo");

	if ((ret = select(n, rfds, wfds, efds, tmo)) < 0) {
		if (errno == EINTR)
			ret = 0;
		else
			err_sys("select(%d, %04x, %04x, %s, %s) -> %d\n",
				n, rfds->fds_bits[0], wfds->fds_bits[0],
				"efds", "tmo", ret);
	}

	err_dbg(" -> %d\n", ret);

	return ret;
}

int
Sendto(int sd, const void *buf, size_t len, int flags,
       const struct sockaddr *to, socklen_t tolen)
{
	int ret;
	int retry;

	retry = linxdisc.retry_count;

	err_dbg("sendto(%d, %p, %d, %d, %s, %d)",
		sd, buf, len, flags, ascii_addr(to), tolen);

	if ((ret = sendto(sd, buf, len, flags, to, tolen)) < 0) {
		while (ret < 0 && retry > 0 &&
		       (errno == ENOBUFS || errno == ENOMEM)) {
			err_msg("sendto() failed %d (%s)\n",
				ret, strerror(errno));
			usleep(100000);	/* wait 100ms */
			ret = sendto(sd, buf, len, flags, to, tolen);
			retry--;
		}
		/* if tried a configurable amount of times, dont
		 * exit, general code tries again later */
		if (0 == retry && (errno == ENOBUFS || errno == ENOMEM))
			goto out;
		if (ret < 0) {
			err_sys("sendto(%d, %p, %d, %d, %s, %d) -> %d\n",
				sd, buf, len, flags, ascii_addr(to), tolen,
				ret);
		}
	}
      out:
	err_dbg(" -> %d\n", ret);
	return ret;
}

int Socket(int domain, int type, int protocol)
{
	int ret;

	err_dbg("socket(%s, %s, %d)", domaintostr(domain), typetostr(type));

	if ((ret = socket(domain, type, protocol)) < 0)
		err_sys("socket(%s, %s, %d) -> %d\n",
			domaintostr(domain), typetostr(type), protocol, ret);

	err_dbg(" -> %d\n", ret);

	return ret;
}
