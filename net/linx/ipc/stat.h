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

#ifndef __IPC_STAT_H__
#define __IPC_STAT_H__

#include <linux/linx_ioctl.h>

#ifdef SOCK_STAT
struct linx_sock;
extern int linx_sock_stats_add(struct linx_sock *sk);
extern int linx_sock_stats_del(const struct linx_sock *sk);
extern int linx_sock_stats_init(void);
extern void linx_sock_stats_cleanup(void);
#else
#define linx_sock_stats_add(sk) (0) /* 0 => Ok */
#define linx_sock_stats_del(sk) (0)
#define linx_sock_stats_init() (0)
#define linx_sock_stats_cleanup()
#endif

struct linx_sock_stat {

	/* Sent/Received signals/bytes from/to local LINX sockets */
	uint64_t no_sent_local_signals;
	uint64_t no_recv_local_signals;
	uint64_t no_sent_local_bytes;
	uint64_t no_recv_local_bytes;

	/* Sent/Received signals/bytes from/to remote LINX sockets */
	uint64_t no_sent_remote_signals;
	uint64_t no_recv_remote_signals;
	uint64_t no_sent_remote_bytes;
	uint64_t no_recv_remote_bytes;

	/* Total number of sent/received signals/bytes */
	uint64_t no_sent_signals;
	uint64_t no_recv_signals;
	uint64_t no_sent_bytes;
	uint64_t no_recv_bytes;

	/* Number of queued signals/bytes not yet received by user-space */
	uint64_t no_queued_bytes;
	uint64_t no_queued_signals;
};

/* Trace for debugging/verifying statistics */
#if 1
#define linx_sock_trace(fmt, args...) do {} while (0)
#else
#define linx_sock_trace(fmt, args...) \
   printk(KERN_INFO "SOCK_STAT: " fmt "\n", ##args)
#endif

/*
 * Local send/receive
 */
#ifdef SOCK_STAT
#define LINX_SOCK_STAT_SEND_LOCAL_SIGNAL(sk,bytes) do { \
   linx_sock_trace("%s - local signal sent %d bytes", \
                   linx_sk(sk)->addr->name, (bytes)); \
   linx_sk(sk)->stat.no_sent_local_signals++; \
   linx_sk(sk)->stat.no_sent_local_bytes+=(bytes); \
} while(0)
#else
#define LINX_SOCK_STAT_SEND_LOCAL_SIGNAL(sk,bytes) do {} while (0)
#endif

#ifdef SOCK_STAT
#define LINX_SOCK_STAT_RECV_LOCAL_SIGNAL(sk,bytes) do { \
   linx_sock_trace("%s - local signal received %d bytes", \
                   linx_sk(sk)->addr->name, (bytes)); \
   linx_sk(sk)->stat.no_recv_local_signals++; \
   linx_sk(sk)->stat.no_recv_local_bytes+=(bytes); \
} while(0)
#else
#define LINX_SOCK_STAT_RECV_LOCAL_SIGNAL(sk,bytes) do {} while (0)
#endif

/*
 * Remote send/receive
 */
#ifdef SOCK_STAT
#define LINX_SOCK_STAT_SEND_REMOTE_SIGNAL(sk,bytes) do { \
   linx_sock_trace("%s - remote signal sent of %d bytes", \
                   linx_sk(sk)->addr->name, (bytes)); \
   linx_sk(sk)->stat.no_sent_remote_signals++; \
   linx_sk(sk)->stat.no_sent_remote_bytes+=(bytes); \
} while(0)
#else
#define LINX_SOCK_STAT_SEND_REMOTE_SIGNAL(sk,bytes) do {} while (0)
#endif

#ifdef SOCK_STAT
#define LINX_SOCK_STAT_RECV_REMOTE_SIGNAL(sk,bytes) do { \
   linx_sock_trace("%s - remote signal received %d bytes", \
                   linx_sk(sk)->addr->name, (bytes)); \
   linx_sk(sk)->stat.no_recv_remote_signals++; \
   linx_sk(sk)->stat.no_recv_remote_bytes+=(bytes); \
} while(0)
#else
#define LINX_SOCK_STAT_RECV_REMOTE_SIGNAL(sk,bytes) do {} while (0)
#endif

/*
 * Link socket send/receive
 */
#ifdef SOCK_STAT
#define LINX_LINK_STAT_SEND_SIGNAL(sk,bytes) do { \
   struct sock *s = linx_spid_to_sock(linx_sk(sk)->link_spid); \
   linx_sock_trace("%s - signal sent %d bytes", \
                   linx_sk(s)->addr->name, (bytes)); \
   linx_sk(s)->stat.no_sent_remote_signals++; \
   linx_sk(s)->stat.no_sent_remote_bytes+=(bytes); \
   sock_put(s); \
} while(0)
#else
#define LINX_LINK_STAT_SEND_SIGNAL(sk,bytes) do {} while (0)
#endif

#ifdef SOCK_STAT
#define LINX_LINK_STAT_RECV_SIGNAL(sk,bytes) do { \
   struct sock *s = linx_spid_to_sock(linx_sk(sk)->link_spid); \
   linx_sock_trace("%s - signal received %d bytes", \
                   linx_sk(s)->addr->name, (bytes)); \
   linx_sk(s)->stat.no_recv_remote_signals++; \
   linx_sk(s)->stat.no_recv_remote_bytes+=(bytes); \
   sock_put(s); \
} while(0)
#else
#define LINX_LINK_STAT_RECV_SIGNAL(sk,bytes) do {} while (0)
#endif

/*
 * Local send/receive
 */
#ifdef SOCK_STAT
#define LINX_SOCK_STAT_QUEUE_SIGNAL(sk,bytes) do { \
   linx_sock_trace("%s - queue signal %d bytes", \
                   linx_sk(sk)->addr->name, (bytes)); \
   linx_sk(sk)->stat.no_queued_signals++; \
   linx_sk(sk)->stat.no_queued_bytes+=(bytes); \
} while(0)
#else
#define LINX_SOCK_STAT_QUEUE_SIGNAL(sk,bytes) do {} while (0)
#endif

#ifdef SOCK_STAT
#define LINX_SOCK_STAT_DEQUEUE_SIGNAL(sk,bytes) do { \
   linx_sock_trace("%s - dequeue signal %d bytes", \
                   linx_sk(sk)->addr->name, (bytes)); \
   linx_sk(sk)->stat.no_queued_signals--; \
   linx_sk(sk)->stat.no_queued_bytes-=(bytes); \
} while(0)
#else
#define LINX_SOCK_STAT_DEQUEUE_SIGNAL(sk,bytes) do {} while (0)
#endif

#endif
