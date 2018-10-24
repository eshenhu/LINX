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
#ifndef __DB_PRIVATE_H
#define __DB_PRIVATE_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/db_types.h>

#if defined(DB_TRACE)
#define LOG_ENTRY(fmt, ...) \
        printk(KERN_INFO "%s(" fmt ")\n", __func__, __VA_ARGS__)
#define LOG_EXIT(fmt, ...) \
        printk(KERN_INFO "%s return " fmt ";\n", __func__, __VA_ARGS__)
#else
#define LOG_ENTRY(fmt, ...)
#define LOG_EXIT(fmt, ...)
#endif

extern int
db_template_get(const char *name, const struct db_template **template);

extern int
db_template_put(const char *name, const struct db_template **template);

extern const struct db_param *
db_lookup_param(const char *key, const struct db_template *template);

extern int
db_try_install_module(const char *name);

/*
 * IMPORTANT!
 *
 * Before any of the functions listed below can be called, db_template_get()
 * must be called. It's important because they operates on objects in other
 * modules, calling db_template_get() prevents that module from being unloaded.
 */

extern int
db_add_item(const char *name, void *item);

extern int
db_del_item(const char *name, void **item);

extern int
db_item_get(const char *name, void **item);

extern int
db_item_put(const char *name, void **item);

extern int
db_list_get(const char *name, struct list_head **list);

extern int
db_list_put(const char *name, struct list_head **list);

extern struct list_head *
db_list_start(struct list_head *list, loff_t pos, unsigned int *modno);

extern struct list_head *
db_list_next(struct list_head *list, loff_t pos, struct list_head *cursor,
             unsigned int *modno);

extern void
db_list_stop(struct list_head *head, struct list_head *cursor);

extern const char *
db_list_name(struct list_head *cursor);

extern void *
db_list_item(struct list_head *cursor);

#endif
