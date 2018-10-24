/*
 * Copyright (c) 2006-2008, Enea Software AB
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

#ifndef LINXDISC_H
#define LINXDISC_H

#include <net/if.h>
#include <stdint.h>
#include <sys/time.h>

#define LINXNAMSIZ	   256
#define MAX_CONF_PARAM	   16

#define LINXDISC_VERSION (1)

struct conf_data {
	uint8_t no_iface;
	uint8_t no_allow;
	uint8_t no_deny;
	uint8_t no_param;

	char linx_net_name[LINXNAMSIZ];

	char node_name[LINXNAMSIZ];

	struct {
		char name[IFNAMSIZ];
	} iface[MAX_CONF_PARAM];

	struct {
		char name[LINXNAMSIZ];
	} allow[MAX_CONF_PARAM];

	struct {
		char name[LINXNAMSIZ];
	} deny[MAX_CONF_PARAM];

	struct {
		char name_val[LINXNAMSIZ];
	} params[MAX_CONF_PARAM];
};

struct peer_data {
	char name[LINXNAMSIZ];
	uint8_t addr[IFHWADDRLEN];
	char network[LINXNAMSIZ];
	int tmocnt;
	struct peer_data *next;
};

struct if_data {
	char ifd_name[IFNAMSIZ];
	uint16_t ifd_index;
	uint16_t ifd_mtu;
	uint8_t ifd_hwaddr[IFHWADDRLEN];
	uint16_t ifd_hwlen;
	uint16_t ifd_flags;
	int ifd_sd;
	struct if_data *ifd_next;
};

struct linxdisc_data {
	struct conf_data *config;
	struct peer_data *peers;
	struct if_data *ifs;
	int sd_max;
	int daemon_proc;
	struct timeval start;
	int retry_count;
	char *conffile;
};

void err_dbg(const char *fmt, ...);

void err_msg(const char *fmt, ...);

void err_quit(const char *fmt, ...);

void err_sys(const char *fmt, ...);

struct conf_data *read_conf(const char *filename);

char *ifftostr(int flags);

int Bind(int sd, const struct sockaddr *addr, socklen_t addrlen);

int Close(int fd);

int Ioctl(int d, unsigned long request, void *arg);

void *Malloc(size_t s);

int
RecvFrom(int sd, void *buf, size_t len, int flags,
	 struct sockaddr *from, socklen_t * flen);

int
Select(int n, fd_set * rfds, fd_set * wfds, fd_set * efds, struct timeval *tmo);

int
Sendto(int sd, const void *buf, size_t len, int flags,
       const struct sockaddr *to, socklen_t tolen);

int Socket(int domain, int type, int protocol);

#endif
