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
 * File: db_utils.h
 */
#ifndef __DB_UTILS_H
#define __DB_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <db_ioctl.h>

#define DB_LIST_ITEMS 1
#define DB_LIST_PARAMS 2

struct db_var {
        unsigned int type;
        size_t objsz;
        size_t nobj;
        unsigned char buf[1];
};

struct db_iter {
        char *list;
        char *cursor;
};

extern char *
mk_db_key(const char *fmt, ...);

extern int
db_create(const char *key, const void *arg, size_t size);

extern int
db_delete(const char *key, const void *arg, size_t size);

extern int
db_get(const char *key, size_t size, struct db_var **p);

extern char *
db_strcat(char *s0, const char *s1);

extern int
db_list(const char *key, int type, char **list);

extern int
db_iterate(const char *key, struct db_var **v, struct db_iter **i);

#ifdef __cplusplus
}
#endif

#endif
