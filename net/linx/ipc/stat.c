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
#ifdef SOCK_STAT
#include <af_linx.h>
#include <ipc/stat.h>
#include <cfg/db.h>
#include <cfg/db_proc.h>

#include <cfg/db_private.h> /* Until we have a kernel API to create/destroy */

#define DB_KEY_SOCK_STATS "sockets"

static int get_linx_sock_name(const void *p, void **vp);
static int get_no_sent_signals(const void *p, void **vp);
static int get_no_sent_bytes(const void *p, void **vp);
static int get_no_recv_signals(const void *p, void **vp);
static int get_no_recv_bytes(const void *p, void **vp);

static const struct db_param linx_sock_stats[] = {
	/* The hunt name of the LINX socket */
	DB_META_PARAM("name", DB_PTR | DB_STRING, 0, 0, get_linx_sock_name,
                      NULL),

	/* Local send/received signals/bytes */
	DB_PARAM("no_sent_local_signals", DB_UINT64, stat.no_sent_local_signals,
                 struct linx_sock),
	DB_PARAM("no_recv_local_signals", DB_UINT64, stat.no_recv_local_signals,
                 struct linx_sock),
	DB_PARAM("no_sent_local_bytes", DB_UINT64, stat.no_sent_local_bytes,
                 struct linx_sock),
	DB_PARAM("no_recv_local_bytes", DB_UINT64, stat.no_recv_local_bytes,
                 struct linx_sock),

	/* Remote send/received signals/bytes */
	DB_PARAM("no_sent_remote_signals", DB_UINT64, stat.no_sent_remote_signals,
                 struct linx_sock),
	DB_PARAM("no_recv_remote_signals", DB_UINT64, stat.no_recv_remote_signals,
                 struct linx_sock),
	DB_PARAM("no_sent_remote_bytes", DB_UINT64, stat.no_sent_remote_bytes,
                 struct linx_sock),
	DB_PARAM("no_recv_remote_bytes", DB_UINT64, stat.no_recv_remote_bytes,
                 struct linx_sock),

	/* Total send/received signals/bytes */
	DB_META_PARAM("no_sent_signals", DB_UINT64, sizeof(uint64_t), 1,
                      get_no_sent_signals, NULL),
	DB_META_PARAM("no_recv_signals", DB_UINT64, sizeof(uint64_t), 1,
                      get_no_recv_signals, NULL),
	DB_META_PARAM("no_sent_bytes", DB_UINT64, sizeof(uint64_t), 1,
                      get_no_sent_bytes, NULL),
	DB_META_PARAM("no_recv_bytes", DB_UINT64, sizeof(uint64_t), 1,
                      get_no_recv_bytes, NULL),

	/* Queued signals/bytes (not yet forwarded to user-space) */
	DB_PARAM("no_queued_signals", DB_UINT64, stat.no_queued_signals,
                 struct linx_sock),
	DB_PARAM("no_queued_bytes", DB_UINT64, stat.no_queued_bytes,
                 struct linx_sock),

        DB_PARAM_END,
};

static void *linx_sock_stats_create(void *arg);
static int linx_sock_stats_destroy(void *cookie, void *arg);

static const struct db_template linx_sock_stats_template = {
        .owner = THIS_MODULE,
        .create = linx_sock_stats_create,
        .destroy = linx_sock_stats_destroy,
        .param = linx_sock_stats,
};

static void *linx_sock_stats_create(void *arg)
{
	return arg;
}

static int linx_sock_stats_destroy(void *p, void *arg)
{
        (void)p;
        (void)arg;
	return 0;
}

static int get_linx_sock_name(const void *p, void **vp)
{
	const struct linx_sock *sk = p;
	*vp = (void *)(sk->addr->name);
	return (DB_PTR | DB_STRING);
}

static int get_no_sent_signals(const void *p, void **vp)
{
	const struct linx_sock *sk = p;
	uint64_t *p64 = kmalloc(sizeof(uint64_t), GFP_KERNEL);
	if (p64 == NULL)
		return -ENOMEM;
	*p64 = sk->stat.no_sent_local_signals + sk->stat.no_sent_remote_signals;
	*vp = p64;
	return (DB_TMP | DB_UINT64); /* Temporary storage! */
}

static int get_no_sent_bytes(const void *p, void **vp)
{
	const struct linx_sock *sk = p;
	uint64_t *p64 = kmalloc(sizeof(uint64_t), GFP_KERNEL);
	if (p64 == NULL)
		return -ENOMEM;
	*p64 = sk->stat.no_sent_local_bytes + sk->stat.no_sent_remote_bytes;
	*vp = p64;
	return (DB_TMP | DB_UINT64); /* Temporary storage! */
}

static int get_no_recv_signals(const void *p, void **vp)
{
	const struct linx_sock *sk = p;
	uint64_t *p64 = kmalloc(sizeof(uint64_t), GFP_KERNEL);
	if (p64 == NULL)
		return -ENOMEM;
	*p64 = sk->stat.no_recv_local_signals + sk->stat.no_recv_remote_signals;
	*vp = p64;
	return (DB_TMP | DB_UINT64); /* Temporary storage! */
}

static int get_no_recv_bytes(const void *p, void **vp)
{
	const struct linx_sock *sk = p;
	uint64_t *p64 = kmalloc(sizeof(uint64_t), GFP_KERNEL);
	if (p64 == NULL)
		return -ENOMEM;
	*p64 = sk->stat.no_recv_local_bytes + sk->stat.no_recv_remote_bytes;
	*vp = p64;
	return (DB_TMP | DB_UINT64); /* Temporary storage! */
}

int linx_sock_stats_add(struct linx_sock *lsk)
{
        char key[64];

        memset(&lsk->stat, 0, sizeof(lsk->stat));
        snprintf(key, sizeof(key), DB_KEY_SOCK_STATS "/spid:%#x", lsk->spid);

        /*
         * We can take a shortcut since we know that the create function is
         * empty...
         */
        return db_add_item(key, lsk);
}

int linx_sock_stats_del(const struct linx_sock *lsk)
{
        void *p;
        char key[64];

        snprintf(key, sizeof(key), DB_KEY_SOCK_STATS "/spid:%#x", lsk->spid);

        /*
         * We can take a shortcut since we know that the delete functions is
         * empty...
         */
        return db_del_item(key, &p);
}

int linx_sock_stats_init(void)
{
        int status;

        status = db_add_template(DB_KEY_SOCK_STATS, &linx_sock_stats_template);
        if (status != 0)
                return status;

        status = db_proc_add(DB_KEY_SOCK_STATS);
        if (status != 0) {
                db_del_template(DB_KEY_SOCK_STATS);
                return status;
        }

	printk(KERN_INFO "LINX: Per-socket statistics enabled.\n");
        return 0;
}

void linx_sock_stats_cleanup(void)
{
        db_proc_del(DB_KEY_SOCK_STATS);
        db_del_template(DB_KEY_SOCK_STATS);
}

#endif
