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

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <linx.h>
#include <linx_types.h>
#include <linx_ioctl.h>
#include <linx_socket.h>

#include <arpa/inet.h>

#include "linx_bmark.h"

/****************************************/

/* burstSig and burstReq is defined in linx_bmark.h */
union LINX_SIGNAL {
	LINX_SIGSELECT sigNo;
	struct burstSig burstSig;
	struct burstReq burstReq;
};

/****************************************/

int linx_bmark_burst(LINX * linx,
		     const char *path,
		     int cnt,
		     size_t start_msg_size,
		     size_t end_msg_size,
		     int iterations,
		     uint32_t burst_cnt, LINX_SPID server,
		     int use_linx_api, int use_pthreads)
{
	LINX_SPID test_slave;
	static const LINX_SIGSELECT any_sig[] = { 0 };
	int iter = 1;
	size_t msg_size;
	int sd = linx_get_descriptor(linx);
	int i;

	printf("\n%%%% Running LINX burst bmark %s linx api %%%%\n",
	       use_linx_api ? "with" : "without");
	printf("Test parameters:\n");
	printf("  Burst count  : %u\n", (unsigned)burst_cnt);
	printf("  Hunt path    : %s\n", path);
	printf("  Loop count   : %d\n", cnt);

	test_slave = create_test_slave(linx, server, use_linx_api,
				       use_pthreads);

	msg_size = start_msg_size;

	do {
		float ack = 0;
		long max = 0, min = LONG_MAX;

		static unsigned int starttimes[PROC_STAT];
		static unsigned int stoptimes[PROC_STAT];

		printf("Running subtest %d of %d", iter++, iterations);
		printf(" with message size : %zd bytes\n", msg_size);

		if (use_linx_api) {
			for (i = 0; i < cnt; i++) {
				uint32_t j;
				union LINX_SIGNAL *sig, *list = 0;
				struct timeval tv;
				long clk;

				sig = linx_alloc(linx, msg_size, BURST_REQ);

				sig->burstReq.n = htonl(burst_cnt);
				sig->burstReq.reply_size =
				    (uint32_t) htonl(msg_size);
				sig->burstReq.reply_sigNo =
				    (LINX_SIGSELECT) htonl(BURST_SIGNO);

				linx_send(linx, &sig, test_slave);

				/* Start measuring */
				memcpy(starttimes, get_cpu_times(),
				       sizeof(starttimes));
				get_time(&tv);

				for (j = 0; j < burst_cnt; j++) {
					linx_receive(linx, &sig, any_sig);
					sig->burstSig.next = list;
					list = sig;
				}
				/* Stop measuring */

				clk = get_time(&tv);
				memcpy(stoptimes, get_cpu_times(),
				       sizeof(stoptimes));

				PRINT(DBG, "Response time: %ld us\n", clk);

				while (list) {
					sig = list;
					list = list->burstSig.next;
					if (sig->sigNo != BURST_SIGNO) {
						ERR("Unknown signal %u",
						    sig->sigNo);
					}
					linx_free_buf(linx, &sig);
				}

				if (clk > max)
					max = clk;
				if (clk < min)
					min = clk;
				ack += clk;

			}
		} else {
			union LINX_SIGNAL *sig;
			int len;
			struct sockaddr_linx sockaddr;
			socklen_t socklen;

			sig = malloc(sizeof(struct burstReq) > end_msg_size ?
				     sizeof(struct burstReq) : end_msg_size);
			if (sig == NULL) {
				ERR("Out of memory");
			}

			socklen = sizeof(struct sockaddr_linx);
			sockaddr.family = AF_LINX;
			sockaddr.spid = test_slave;

			for (i = 0; i < cnt; i++) {
				uint32_t j;
				struct timeval tv;
				long clk;

				sockaddr.spid = test_slave;

				sig->sigNo = BURST_REQ;
				sig->burstReq.n = htonl(burst_cnt);
				sig->burstReq.reply_size = htonl(msg_size);
				sig->burstReq.reply_sigNo = htonl(BURST_SIGNO);

				/* Start measuring */
				memcpy(starttimes, get_cpu_times(),
				       sizeof(starttimes));
				get_time(&tv);

				len = sendto(sd, sig, sizeof(struct burstReq),
					     0, (struct sockaddr *)(void *)
					     &sockaddr, socklen);

				if (unlikely((size_t) len !=
					     sizeof(struct burstReq) ||
					     len <= 0)) {
					ERR("Failed to send echo signal. "
					    "sendto returned: %d when asked "
					    "for: %zd", len, msg_size);
				}

				for (j = 0; j < burst_cnt; j++) {
					len = recvfrom(sd,
						       sig,
						       msg_size,
						       0, (struct sockaddr *)
						       (void *)&sockaddr,
						       &socklen);

					if (unlikely(len <= 0)) {
						ERR("Failed to receive an "
						    "echo signal(%d, %d)\n",
						    len, errno);
					}
					if (unlikely(sig->sigNo != BURST_SIGNO)) {
						ERR("Unknown signal %u",
						    sig->sigNo);
					}
				}

				clk = get_time(&tv);
				memcpy(stoptimes, get_cpu_times(),
				       sizeof(stoptimes));

				PRINT(DBG, "Response time: %ld us\n", clk);

				if (clk > max)
					max = clk;
				if (clk < min)
					min = clk;
				ack += clk;
			}
			free(sig);
		}
		printf("Result:\n");
		printf("  Average : %.1f us\n", ack / cnt);
		printf("  Min     : %ld us\n", min);
		printf("  Max     : %ld us\n", max);
		printf("  Diff    : %ld us\n", max - min);

		print_cpu_load(starttimes, stoptimes);

		if (end_msg_size != start_msg_size && iterations != 1)
			msg_size += (end_msg_size - start_msg_size) /
			    (iterations - 1);
		else
			break;

	} while (msg_size <= end_msg_size);

	destroy_test_slave(linx, test_slave);

	printf("Com test 4 completed\n");

	return 0;
}
