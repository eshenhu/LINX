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
 * File: ethcm_utils.c
 */
#include <errno.h>
#include <netinet/ether.h>
#include <stdlib.h>
#include <string.h>

#include <ethcm_db_ioctl.h>
#include "ethcm_utils.h"

#define ptr(p, n) ((unsigned char *)(p) + (n))

static int check_arg(struct linx_con_arg_eth *arg)
{
        struct ether_addr addr;

        if ((arg->name == NULL) || (*arg->name == '\0'))
                return EINVAL;
        else if ((arg->ethif == NULL) || (*arg->ethif == '\0'))
                return EINVAL;
        else if ((arg->mac == NULL) || (*arg->mac == '\0') ||
                 (ether_aton_r(arg->mac, &addr) == NULL))
                return EINVAL;
        else if ((arg->window_size & (arg->window_size - 1)) != 0)
                return EINVAL;
        else
                return 0;
}

static size_t sizeof_arg(struct linx_con_arg_eth *arg)
{
        size_t size;
        
        size = 0;
        if (arg->name != NULL)
                size += strlen(arg->name);
        size += 1;
        if (arg->ethif != NULL)
                size += strlen(arg->ethif);
        size += 1;
        if (arg->features != NULL)
                size += strlen(arg->features);
        size += 1;
        return size;
}

int mk_ethcm_ioctl_create(struct linx_con_arg_eth *arg, void **v, size_t *sizeof_v)
{
        struct ethcm_ioctl_create *p;
        struct ether_addr addr;
        char *feat;
        size_t size;

        if (check_arg(arg) != 0)
                return EINVAL;

        size = sizeof(*p) + sizeof_arg(arg);
        p = calloc(1, size);
        if (p == NULL)
                return ENOMEM;

        p->name = sizeof(*p);
        p->name_len = strlen(arg->name);
        memcpy(ptr(p, p->name), arg->name, p->name_len + 1);

        p->dev = p->name + p->name_len + 1;
        p->dev_len = strlen(arg->ethif);
        memcpy(ptr(p, p->dev), arg->ethif, p->dev_len + 1);

        feat = (arg->features != NULL) ? arg->features : "";
        p->feat = p->dev + p->dev_len + 1;
        p->feat_len = strlen(feat);
        memcpy(ptr(p, p->feat), feat, p->feat_len + 1);
        
        ether_aton_r(arg->mac, &addr); /* MAC syntax already checked! */
        memcpy(p->mac, addr.ether_addr_octet, sizeof(p->mac));

        p->window_size = arg->window_size;
        p->defer_queue_size = arg->defer_queue_size;
        p->send_tmo = arg->send_tmo;
        p->nack_tmo = arg->nack_tmo;
        p->conn_tmo = arg->conn_tmo;
        p->live_tmo = arg->live_tmo;
        p->coreid = arg->coreid;
        p->mtu = arg->mtu;

        *v = p;
        *sizeof_v = size;
        return 0;
}
