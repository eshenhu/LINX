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
 * File: riocm_utils.c
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <riocm_db_ioctl.h>
#include "riocm_utils.h"

#define ptr(p, n) ((unsigned char *)(p) + (n))

static int check_arg(struct linx_con_arg_rio *arg)
{

        if ((arg->name == NULL) || (*arg->name == '\0'))
                return EINVAL;
        else if ((arg->rioif == NULL) || (*arg->rioif == '\0'))
                return EINVAL;
        else
                return 0;
}

static size_t sizeof_arg(struct linx_con_arg_rio *arg)
{
        size_t size;
        
        size = 0;
        if (arg->name != NULL)
                size += strlen(arg->name);
        size += 1;
        if (arg->rioif != NULL)
                size += strlen(arg->rioif);
        size += 1;
        return size;
}

int mk_riocm_ioctl_create(struct linx_con_arg_rio *arg, void **v, size_t *sizeof_v)
{
        struct riocm_ioctl_create *p;
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
        p->dev_len = strlen(arg->rioif);
        memcpy(ptr(p, p->dev), arg->rioif, p->dev_len + 1);

        p->port = arg->port;
        p->mtu = arg->mtu;
        p->id = arg->id;
        p->my_port = arg->my_port;
	p->mbox = arg->mbox;
	p->hb = arg->hb;

        *v = p;
        *sizeof_v = size;
        return 0;
}
