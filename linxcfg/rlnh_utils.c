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
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <rlnh_db_ioctl.h>
#include "db_utils.h"
#include "rlnh_utils.h"

#define ptr(p, n) ((unsigned char *)(p) + (n))

static int check_arg(struct linx_link_arg *arg)
{
        if ((arg->name == NULL) || (*arg->name == '\0'))
                return EINVAL;
        else if ((arg->connections == NULL) || (*arg->connections == '\0'))
                return EINVAL;
        else
                return 0;
}

static size_t sizeof_arg(struct linx_link_arg *arg)
{
        char *s;
        size_t size, len;
        
        size = 0;
        if (arg->name != NULL)
                size += strlen(arg->name);
        size += 1;
        if (arg->attributes != NULL)
                size += strlen(arg->attributes);
        size += 1;
        if (arg->features != NULL)
                size += strlen(arg->features);
        size += 1;
        for (s = arg->connections; *s != '\0'; s += len + 1) {                
                len = strlen(s);
                size += len + 1;
        }
        return size;
}

int mk_rlnh_ioctl_create(struct linx_link_arg *arg, void **v, size_t *sizeof_v)
{
        struct rlnh_ioctl_create *p;
        char *s, *attr, *feat;
        size_t size, len, pos;
        int n, status;

        if (check_arg(arg) != 0)
                return EINVAL;

        size = sizeof(*p) + sizeof_arg(arg);
        p = calloc(1, size);
        if (p == NULL)
                return ENOMEM;

        p->name = sizeof(*p);
        p->name_len = strlen(arg->name);
        memcpy(ptr(p, p->name), arg->name, p->name_len + 1);

        attr = (arg->attributes != NULL) ? arg->attributes : "";
        p->attr = p->name + p->name_len + 1;
        p->attr_len = strlen(attr);
        memcpy(ptr(p, p->attr), attr, p->attr_len + 1);

        feat = (arg->features != NULL) ? arg->features : "";
        p->feat = p->attr + p->attr_len + 1;
        p->feat_len = strlen(feat);
        memcpy(ptr(p, p->feat), feat, p->feat_len + 1);

        n = 0;
        s = arg->connections;
        pos = p->feat + p->feat_len + 1;
        len = strlen(s);     
        do {
                p->con_name[n] = pos;
                p->con_name_len[n] = len;
                memcpy(ptr(p, p->con_name[n]), s, p->con_name_len[n] + 1);
                p->num_cons++;
                if (p->num_cons >= NUM_CONS) {
                        status = E2BIG;
                        goto out;
                }               
                n++;
                s += len + 1;
                pos += len + 1;
                len = strlen(s);
        } while (*s != '\0');

        *v = p;
        *sizeof_v = size;
        return 0;
  out:
        free(p);
        return status;
}
