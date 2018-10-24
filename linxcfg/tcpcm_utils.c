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

/*
 * File: tcpcm_utils.c
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <unistd.h>

#include <tcpcm_db_ioctl.h>
#include "tcpcm_utils.h"

#define ptr(p, n) ((unsigned char *)(p) + (n))

static int check_ip_arg(struct linx_con_arg_tcp *arg)
{
	if ((arg->ipaddr != NULL) && (*arg->ipaddr != '\0'))
		return AF_INET;
	else if ((arg->ipv6addr != NULL) && (*arg->ipv6addr != '\0'))
		return AF_INET6;
	else
		return 0;
}

static int check_arg(struct linx_con_arg_tcp *arg)
{
        if ((arg->name == NULL) || (*arg->name == '\0'))
                return EINVAL;
        else if(check_ip_arg(arg) == 0)
                return EINVAL;
        else
                return 0;
}

static size_t sizeof_arg(struct linx_con_arg_tcp *arg)
{
        size_t size;

        size = 0;
        if (arg->name != NULL)
                size += strlen(arg->name);
        size += 1;
        if (arg->ipaddr != NULL)
                size += sizeof(struct in_addr);
        if (arg->ipv6addr != NULL)
                size += sizeof(struct in6_addr);
        size += 1;
        return size;
}

static int get_ipv6_scope(char *ip6, uint32_t *scope)
{
	char *ifname;
	int s;
	int ret;
	struct ifreq interface;

	ifname = strchr(ip6, '%');
	if(ifname == NULL) {
		printf("No %% in ipv6 address string found\n");
		return -1;
	}
	
	*ifname = '\0';
	ifname++;
	strcpy(interface.ifr_name, ifname);
	
	s = socket(AF_INET6, SOCK_STREAM, 0);
	if (s == -1) {
		printf("Could not open ipv6 socket\n");
		return -1;
	}
	ret = ioctl(s, SIOCGIFINDEX, &interface);
	if (ret != 0) {
		printf("The interface name %s is invalid\n", ifname);
		close(s);
		return -1;
	}
	
	close(s);

	*scope = interface.ifr_ifindex;
	return 0;
}

int mk_tcpcm_ioctl_create(struct linx_con_arg_tcp *arg, void **v, size_t *sizeof_v)
{
        struct tcpcm_ioctl_create *p;
        size_t size;
        char *feat;

        if (check_arg(arg) != 0)
                return EINVAL;

        size = sizeof(*p) + sizeof_arg(arg);
        p = calloc(1, size);
        if (p == NULL)
                return ENOMEM;

        p->name = sizeof(*p);
        p->name_len = strlen(arg->name);
        memcpy(ptr(p, p->name), arg->name, p->name_len + 1);

	/* not used since linx 2.2 */
        p->remote_addr = 0;
        p->remote_addr_len = 0;

        feat = (arg->features != NULL) ? arg->features : "";
        p->feat = p->remote_addr + p->remote_addr_len + 1;
        p->feat_len = strlen(feat);
        memcpy(ptr(p, p->feat), feat, p->feat_len + 1);
        
	p->use_nagle = arg->use_nagle;
	p->live_tmo = arg->live_tmo;

	switch (check_ip_arg(arg)) {
	case AF_INET:
		/* new since linx 2.2 */
		if(inet_pton(AF_INET, arg->ipaddr, (void*)&p->ip_addr) == 0)
			goto error;
		memset((void *)p->ipv6_addr, 0, 16);
		p->ipv6_scope = 0;
		break;
	case AF_INET6:
		/* new since linx 2.5 */
		if(get_ipv6_scope(arg->ipv6addr, &p->ipv6_scope) != 0)
			goto error;
		/* arg->ipv6addr has now been altered to work with pton */
		if(inet_pton(AF_INET6, arg->ipv6addr, (void*)p->ipv6_addr) == 0)
			goto error;
		/* this signifies that ipv6 shall be used */
		p->ip_addr = 0xffffffff;
		break;
	default:
		goto error;
		break;
	}

        *v = p;
        *sizeof_v = size;
        return 0;
error:
	free(p);
	return EINVAL;
}
