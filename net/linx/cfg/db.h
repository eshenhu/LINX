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
#ifndef __DB_H
#define __DB_H

/*
 * DB clients, e.g. CMs, should include this file.
 */

#include <linux/types.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/db_types.h>

#define DB_PARAM(name, type, member, object)  \
{                                             \
        name,                                 \
        type,                                 \
        (short)sizeof(((object *)0)->member), \
        1,                                    \
        (short)offsetof(object, member),      \
        NULL,                                 \
        NULL,                                 \
}

#define DB_PARAM_ARR(name, type, member, object)   \
{                                                  \
        name,                                      \
        (type | DB_ARR),                           \
        (short)sizeof((((object *)0)->member)[0]), \
        (short)ARRAY_SIZE(((object *)0)->member),  \
        (short)offsetof(object, member),           \
        NULL,                                      \
        NULL,                                      \
}

#define DB_META_PARAM(name, type, size, nelem, get, set) \
{                                                        \
        name,                                            \
        type,                                            \
        size,                                            \
        nelem,                                           \
        -1,                                              \
        get,                                             \
        set,                                             \
}

#define DB_PARAM_END {"", 0, 0, 0, 0, NULL, NULL}

#define db_param_for_each(pos, head) \
        for ((pos) = (head); (pos)->name[0] != '\0'; (pos)++)

struct db_param {
        const char *name;
        short type;
        short size;
        short nelem;
        short offset;
        int (*get)(const void *p, void **val);
        int (*set)(void *p, void *val);
};

struct db_template {
        struct module *owner;
        void *(*create)(void __user *arg);
        int (*destroy)(void *p, void __user *arg);
        const struct db_param *param;
};

extern int
db_add_template(const char *name, const struct db_template *template);

extern int
db_del_template(const char *name);

struct db_value {
        int type;
        size_t objsz;
        size_t nobj;
        char buf[0];
};

extern int
db_get_value(const char *name, struct db_value *val, void *buf, size_t bufsz);

#endif
