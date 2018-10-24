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
 * File: db_utils.c
 */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <linx_socket.h>
#include "db_utils.h"

#define ptr(p, n) ((unsigned char *)(p) + (n))

#define KBYTE *1024

#define foreach_db_string(s, strings) \
        for ((s) = (strings); *(s) != '\0'; (s) += strlen(s) + 1)

static int db_ioctl(int cmd, void *p)
{
        int s, status;

        s = socket(AF_LINX, SOCK_DGRAM, 0);
        if (s == -1) {
                /*
                 * ENOMEM probably means that we are out of SPIDs. Return
                 * to "too many open files" instead.
                 */
                return (errno == ENOMEM) ? EMFILE : errno;
        }
        status = ioctl(s, cmd, p);
        close(s);

        return (status == -1 ? errno : 0);
}

char *mk_db_key(const char *fmt, ...)
{
        va_list ap;
        int n;
        char c, *key;

        va_start(ap, fmt);
        n = vsnprintf(&c, 0, fmt, ap);
        va_end(ap);
        if (n < 0)
                return NULL;

        key = malloc(n + 1);
        if (key == NULL)
                return NULL;

        va_start(ap, fmt);
        n = vsnprintf(key, n + 1, fmt, ap);
        va_end(ap);
        if (n < 0) {
                free(key);
                return NULL;
        }
        return key;

}

static struct db_ioctl_create *mk_db_create(const char *key, const void *arg,
                                            size_t size)
{
        struct db_ioctl_create *p;

        p = calloc(sizeof(*p) + strlen(key) + 1 + size, 1);
        if (p == NULL)
                return NULL;

        p->arg = sizeof(*p); /* Don't change, put the opaque first! */
        p->arg_size = size;
        p->key = p->arg + p->arg_size;
        p->key_len = strlen(key);
        memcpy(ptr(p, p->key), key, p->key_len + 1);
        memcpy(ptr(p, p->arg), arg, p->arg_size);

        return p;
}

int db_create(const char *key, const void *arg, size_t size)
{
        struct db_ioctl_create *p;
        int status;

        if (key == NULL)
                return EINVAL;
        p = mk_db_create(key, arg, size);
        if (p == NULL)
                return ENOMEM;
        status = db_ioctl(DB_IOCTL_CREATE, p);
        free(p);

        return status;
}

static struct db_ioctl_delete *mk_db_delete(const char *key, const void *arg,
                                            size_t size)
{
        struct db_ioctl_delete *p;

        p = calloc(sizeof(*p) + strlen(key) + 1 + size, 1);
        if (p == NULL)
                return NULL;

        p->arg = sizeof(*p); /* Don't change, put the opaque first! */
        p->arg_size = size;
        p->key = p->arg + p->arg_size;
        p->key_len = strlen(key);
        memcpy(ptr(p, p->key), key, p->key_len + 1);
        memcpy(ptr(p, p->arg), arg, p->arg_size);

        return p;
}

int db_delete(const char *key, const void *arg, size_t size)
{
        struct db_ioctl_delete *p;
        int status;

        if (key == NULL)
                return EINVAL;
        p = mk_db_delete(key, arg, size);
        if (p == NULL)
                return ENOMEM;
        status = db_ioctl(DB_IOCTL_DELETE, p);
        free(p);

        return status;
}

static struct db_ioctl_get *mk_db_get(const char *key, size_t size)
{
        struct db_ioctl_get *p;

        p = calloc(1, sizeof(*p) + strlen(key) + 1 + size);
        if (p == NULL)
                return NULL;

        p->value = sizeof(*p); /* Don't change, put the opaque first! */
        p->value_size = size;
        p->key = p->value + p->value_size;
        p->key_len = strlen(key);
        memcpy(ptr(p, p->key), key, p->key_len + 1);

        return p;
}

static size_t db_n_strlen(const char *s, size_t nstr)
{
        size_t size, len;

        for (size = 0; nstr-- > 0;) {
                len = strlen(s) + 1;
                size += len;
                s += len;
        }
        return size;
}

int db_get(const char *key, size_t size, struct db_var **v)
{
        struct db_ioctl_get *p;
        struct db_var *q;
        void *value;
        int status;

        if (key == NULL)
                return EINVAL;
        p = mk_db_get(key, size);
        if (p == NULL)
                return ENOMEM;
        status = db_ioctl(DB_IOCTL_GET, p);
        if (status != 0) {
                free(p);
                return status;
        }

        value = ptr(p, p->value);
        if (p->type == DB_STRING)
                size = db_n_strlen(value, (size_t)p->nobj);
        else
                size = p->nobj * p->objsz;

        q = malloc(sizeof(*q) + size);
        if (q == NULL) {
                free(p);
                return ENOMEM;
        }
        q->type = (unsigned int)p->type;
        q->objsz = (size_t)p->objsz;
        q->nobj = (size_t)p->nobj;
        memcpy(&q->buf[0], value, size);

        free(p); 
        *v = q;
        return 0;
}

static size_t db_strlen(char *s)
{
        size_t len, n;

        if (s == NULL)
                return 0;

        /*
         * E.g. s = ethcm/a\0ethcm/b\0\0 should result in len = 16.
         */
        for (len = 0; *s != '\0'; len += n, s += n)
                n = strlen(s) + 1;

        return len; /* Last '\0' is not included. */
}

char *db_strcat(char *s1, const char *s2)
{
        size_t l1, l2;

        l1 = db_strlen(s1);
        l2 = strlen(s2) + 1;
        s1 = realloc(s1, l1 + l2 + 1);
        if (s1 != NULL) {
                memcpy(s1 + l1, s2, l2);
                *(s1 + l1 + l2) = '\0'; /* Extra '\0' at the end. */
        }
        return s1;
}

static struct db_ioctl_list *mk_db_list(const char *key, int flags, size_t size)
{
        struct db_ioctl_list *p;

        p = calloc(1, sizeof(*p) + strlen(key) + 1 + size);
        if (p == NULL)
                return NULL;

        p->list = sizeof(*p);
        p->list_size = size;
        p->key = p->list + p->list_size;
        p->key_len = strlen(key);
        memcpy(ptr(p, p->key), key, p->key_len + 1);
        p->flags = flags;

        return p;
}

static char *db_strdup(const char *s1)
{
        char *s0, *tmp;
        
        s0 = NULL;        
        for (s0 = NULL; ; s1 += strlen(s1) + 1) {
                tmp = db_strcat(s0, s1);
                if (tmp == NULL) {
                        free(s0);
                        return NULL;
                }
                s0 = tmp;
                if (*s1 == '\0')
                        break;
        }
        return s0;
}

/* FIXME: we need a modification number, so we know if the list is over-aged or not ... */
int db_list(const char *key, int type, char **list)
{
        struct db_ioctl_list *p;
        char *tmp;
        int status, ioctl_type;
        size_t size;

        if (key == NULL)
                return EINVAL;

        switch (type) {
        case DB_LIST_ITEMS:
                ioctl_type = DB_IOCTL_LIST_F_ITEMS;
                break;
        case DB_LIST_PARAMS:
                ioctl_type = DB_IOCTL_LIST_F_PARAMS;
                break;
        default:
                return EINVAL;
        }

        for (size = 8 KBYTE; size <= 1024 KBYTE; size <<= 1) {
                p = mk_db_list(key, ioctl_type, size);
                if (p == NULL)
                        return ENOMEM;
                status = db_ioctl(DB_IOCTL_LIST, p);
                if (status == 0) {
                        tmp = db_strdup((char *)ptr(p, p->list));
                        free(p);
                        if (tmp == NULL)
                                return ENOMEM;
                        *list = tmp;
                        return 0;
                } else {
                        free(p);
                        if (status == ENOMEM)
                                continue; /* Try a bigger user buffer */
                        else
                                return status; /* Error */
                }
        }
        return ENOMEM;
}

static size_t count_strings(const char *s, const char *delimiters)
{
        size_t k, strc;

        /*
         * E.g. /a/b, ///a//b/ or a/b should all result in 2.
         */
        strc = 0;
        while (*s != '\0') {
                k = strcspn(s, delimiters);
                if (k != 0)
                        strc++;
                s += k;
                s += strspn(s, delimiters);
        }
        return strc;
}

static int init_type_1_iterator(const char *key, struct db_iter *i)
{
        char *items, *params, *s, *s0, *s1, *tmp;
        int status;

        status = db_list(key, DB_LIST_ITEMS, &items);
        if (status != 0)
                return status;
        status = db_list(key, DB_LIST_PARAMS, &params);
        if (status != 0) {
                free(items);
                return status;
        }

        /* Not the fastest, but it'll do for now... */
        foreach_db_string(s0, items) {
                foreach_db_string(s1, params) {
                        s = mk_db_key("%s/%s/%s", key, s0, s1);
                        if (s == NULL) {
                                free(i->list);
                                status = ENOMEM;
                                goto out;
                        }
                        tmp = db_strcat(i->list, s);
                        free(s);
                        if (tmp == NULL) {
                                free(i->list);
                                status = ENOMEM;
                                goto out;
                        }
                        i->list = tmp;
                }
        }
        i->cursor = i->list;
  out:
        free(params);
        free(items);

        return status;
}

static int init_type_2_iterator(const char *key, struct db_iter *i)
{
        char *params, *s, *s0, *tmp;
        int status;

        status = db_list(key, DB_LIST_PARAMS, &params);
        if (status != 0)
                return status;

        /* Not the fastest, but it'll do for now... */
        foreach_db_string(s0, params) {
                s = mk_db_key("%s/%s", key, s0);
                if (s == NULL) {
                        free(i->list);
                        status = ENOMEM;
                        goto out;
                }
                tmp = db_strcat(i->list, s);
                free(s);
                if (tmp == NULL) {
                        free(i->list);
                        status = ENOMEM;
                        goto out;
                }
                i->list = tmp;
        }
        i->cursor = i->list;
  out:
        free(params);
        return status;
}

static int init_type_3_iterator(const char *key, struct db_iter *i)
{
        char *s, *p;
        int status;

        s = strrchr(key, '/');
        if (s == NULL)
                return EINVAL;

        p = calloc((size_t)(s - key) + 1, 1);
        if (p == NULL)
                return ENOMEM;
        memcpy(p, key, (size_t)(s - key)); /* calloc 0-terminates! */

        status = init_type_2_iterator(p, i);
        if (status != 0)
                return status;

        foreach_db_string(s, i->list) {
                if (strcmp(s, key) == 0) {
                        i->cursor = s;
                        return 0;
                }
        }
        
        return EINVAL;
}

static int init_iterator(const char *key, struct db_iter **i, int type)
{
        struct db_iter *p;
        int status;

        p = calloc(1, sizeof(*p));
        if (p == NULL)
                return ENOMEM;

        switch (type) {
        case 1: /* Eg. ethcm */
                status = init_type_1_iterator(key, p);
                break;
        case 2: /* Eg. ethcm/econ_A */
                status = init_type_2_iterator(key, p);
                break;
        case 3: /* Eg. ethcm/econ_A/mtu */
                status = init_type_3_iterator(key, p);
                break;
        default:
                free(p);
                return EINVAL;
        }
        if (status != 0) {
                free(p);
                return status;
        }
        *i = p;

        return 0;
}

int db_iterate(const char *key, struct db_var **v, struct db_iter **i)
{
        int status;

        if (*i == NULL) {
                status = init_iterator(key, i, count_strings(key, "/"));
                if (status != 0)
                        return -status;
        } else {
                (*i)->cursor += strlen((*i)->cursor) + 1;
        }
        
        if (*((*i)->cursor) == '\0') {
                free((*i)->list);
                free(*i);
                *i = NULL;
                return 0; /* No more */
        }

        status = db_get((*i)->cursor, 2048, v);
        if (status != 0) {
                free((*i)->list);
                free(*i);
                *i = NULL;
                return -status;
        }

        return 1; /* More */
}
