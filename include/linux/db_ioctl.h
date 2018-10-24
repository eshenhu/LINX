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
 * File: db_ioctl.h
 */
#ifndef __LINUX_DB_IOCTL_H
#define __LINUX_DB_IOCTL_H

#include <linux/types.h>
#include <linux/db_types.h>

#define DB_IOCTL_MAGIC 't'
#define DB_IOCTL_CREATE _IOW(DB_IOCTL_MAGIC, 1, struct db_ioctl_create)
#define DB_IOCTL_DELETE _IOW(DB_IOCTL_MAGIC, 2, struct db_ioctl_delete)
#define DB_IOCTL_GET _IOW(DB_IOCTL_MAGIC, 3, struct db_ioctl_get)
#define DB_IOCTL_LIST _IOW(DB_IOCTL_MAGIC, 4, struct db_ioctl_list)

/*
 * Note1: sizeof(struct db_ioctl_<x>) must be a multiple of 8 bytes.
 *
 * Note2: offsets, e.g. key, must be calculated from the start of
 *        the struct.
 *
 * Note3: offsets should be calculated so that their data starts on
 *        a natural boundary.
 */

struct db_ioctl_create {
        __u32 key; /* Offset to key string. */
        __u32 key_len;
        __u32 arg; /* Offset to arg. */
        __u32 arg_size;
};

struct db_ioctl_delete {
        __u32 key; /* Offset to key string. */
        __u32 key_len;
        __u32 arg; /* Offset to arg. */
        __u32 arg_size;
};

struct db_ioctl_get {
        __u32 key; /* Offset to key string. */
        __u32 key_len;
        __u32 value; /* Offset to value. */
        __u32 value_size;
        __u16 type;
        __u16 objsz;
        __u16 nobj;
        __u16 spare;
};

struct db_ioctl_list {
        __u32 key; /* Offset to key string. */
        __u32 key_len;
        __u32 list; /* Offset to list (string table). \0\0 termiantes list. */
        __u32 list_size;
        __u32 flags;
};

/* struct db_ioctl_list flag values. */
#define DB_IOCTL_LIST_F_ITEMS 0x1
#define DB_IOCTL_LIST_F_PARAMS 0x2

#ifdef __KERNEL__
#include <linux/ioctl.h>

extern int db_ioctl_entry(unsigned int cmd, unsigned long arg);
#endif

#endif
