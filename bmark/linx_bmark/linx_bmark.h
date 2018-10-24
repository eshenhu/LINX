/*
 * Copyright (C) 2006-2009 by Enea Software AB.
 * All rights reserved.
 *
 * This Example is furnished under a Software License Agreement and
 * may be used only in accordance with the terms of such agreement.
 * No title to and ownership of the Example is hereby transferred.
 *
 * The information in this Example is subject to change
 * without notice and should not be construed as a commitment
 * by Enea Software AB.
 *
 * DISCLAIMER
 * This Example is delivered "AS IS", consequently 
 * Enea Software AB makes no representations or warranties, 
 * expressed or implied, for the Example. 
 */

#ifndef _LINX_BMARK_H_
#define _LINX_BMARK_H_

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>

#include <linx.h>
#include <linx_types.h>
#include <pthread.h>

#define CONN_EST         0x2870
#define ATTACH_SERV_SIG  0x2871
#define HUNT_SIG         0x2872
#define ECHO_SIG         0x2873
#define TERMINATE_REQ    0x2874
#define BURST_REQ        0x2875
#define CONN_TERM        0x2876
#define ATTACH_TEST_REQ  0x2877
#define ATTACH_SLAVE_SIG 0x2878
#define ATTACH_TEST_SIG  0x2879

#define CLIENT_NAME "client"
#define SERVER_NAME "server"
#define CS_PATH
#define SC_PATH

#define LOOP_CNT    10
#define BURST_CNT   40
#define BURST_SIZE  2048
#define BURST_SIGNO 0x8765
#define THROUGHPUT_INSTANCES 32

#define START_MSG_SIZE 1000
#define END_MSG_SIZE   65536
#define ITERATIONS     10
#define ONE_ITERATION  1

#define VERBOSITY 0
#define INFO 0
#define DBG 1

#define PROC_STAT 7
#define USER    0
#define NICE    1
#define SYSTEM  2
#define IDLE    3
#define IOWAIT  4
#define IRQ     5
#define SOFTIRQ 6

#define LINX_SOCKET 0
#define LINX_API 1

#ifndef likely
#define likely(x)	__builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif


extern pid_t gettid(void);

/****************************************************/

#define PRINT(v, ...) \
if ((v) <= VERBOSITY) do { \
  printf(__VA_ARGS__); \
 } while (0)

#define TRACE(v, ...) \
if ((v) <= VERBOSITY) do { \
  printf("pid:%08x %s() %s:%d,. ", (unsigned int)pthread_self(), __func__, __FILE__, __LINE__);\
  printf(__VA_ARGS__); \
  printf("\n"); \
 } while (0)

#define WARN(...) TRACE(0, "\n    WARNING: " __VA_ARGS__)

#define ERR(...) do { \
  TRACE(0, "\n    ERROR: " __VA_ARGS__); \
  TRACE(0, "\n    Got errno: %d %s", errno, strerror(errno)); \
} while (0)

/****************************************************/

struct burstSig {
	LINX_SIGSELECT sigNo;
	union LINX_SIGNAL *next;
};

struct burstReq {
	LINX_SIGSELECT sigNo;
	uint32_t n;
	LINX_SIGSELECT reply_sigNo;
	uint32_t reply_size;
};

struct connEst {
	LINX_SIGSELECT sigNo;
	uint32_t use_linx_api;
	uint32_t use_pthreads;
};

struct slave_args {
	LINX_SPID client;
	uint32_t use_linx_api;
	uint32_t slave_no;
	uint32_t use_pthreads;
};

/****************************************************/

long get_time(struct timeval *tv);

unsigned int *get_cpu_times(void);

void print_cpu_load(unsigned int *starttimes, unsigned int *stoptimes);

LINX_SPID
create_test_slave(LINX * linx, LINX_SPID server_master, int use_linx_api,
		  int use_pthreads);

void destroy_test_slave(LINX * linx, LINX_SPID test_slave);

int
attach_test(LINX * linx, const char *path, int cnt, LINX_SPID server_master,
	    int use_linx_api, int use_pthreads);

int
linx_bmark_latency(LINX * linx,
		   const char *path,
		   int cnt,
		   size_t start_msg_size,
		   size_t end_msg_size,
		   int iterations, LINX_SPID server, int use_linx_api, int use_pthreads);

int
linx_bmark_burst(LINX * linx,
		 const char *path,
		 int cnt,
		 size_t start_msg_size,
		 size_t end_msg_size,
		 int iterations,
		 uint32_t burst_cnt, LINX_SPID server, int use_linx_api, int use_pthreads);

int
linx_bmark_throughput(const char *path,
		      int cnt,
		      size_t msg_size,
		      LINX_SPID server_master,
		      int use_linx_api, int tp_instances, int use_pthreads);
#endif
