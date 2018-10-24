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
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <linx.h>
#include <linx_types.h>
#include <linx_socket.h>

#include "linx_bmark.h"

extern pid_t gettid(void);

/****************************************/

union LINX_SIGNAL {
	LINX_SIGSELECT sigNo;
};

/****************************************/

static long
test_once(LINX * linx, LINX_SPID server, int use_linx_api, int use_pthreads)
{

	union LINX_SIGNAL *sig, *sig2;
	struct timeval tv;
	LINX_SPID test_slave;
	static const LINX_SIGSELECT any_sig[] = { 0 };
	long clk;
	static char buf[65536];	/* buffer used when not using linx api. */

	test_slave = create_test_slave(linx, server, use_linx_api,
				       use_pthreads);

	/* We do not use default LINX_OS_ATTACH_SIG */
	sig = linx_alloc(linx, sizeof(LINX_SIGSELECT), ATTACH_TEST_SIG);
	linx_attach(linx, &sig, test_slave);

	if (use_linx_api) {
		sig = linx_alloc(linx, sizeof(LINX_SIGSELECT), ATTACH_TEST_REQ);

		/* Send attach test request to test slave, this should result
		   in two signals received. First a reply on the attach request
		   and then the attach signal itself.
		 */
		linx_send(linx, &sig, test_slave);

		/* Receive the reply */
		linx_receive(linx, &sig, any_sig);
		/*
		 * Assume we received the correct signal here for measuring
		 * purposes!
		 */
		get_time(&tv);
		/* Receive the attach signal */
		linx_receive(linx, &sig2, any_sig);

		clk = get_time(&tv);

		if (sig->sigNo != ATTACH_TEST_REQ) {
			ERR("Wrong signal received in attachtest %ud",
			    sig->sigNo);
		}

		if (sig2->sigNo != ATTACH_TEST_SIG) {
			ERR("Wrong signal received in attachtest %ud",
			    sig->sigNo);
		}

		PRINT(DBG, "Response time: %ld us\n", clk);

		linx_free_buf(linx, &sig);
		linx_free_buf(linx, &sig2);
	} else {
		int len;
		struct sockaddr_linx to;
		socklen_t socklen;
		int sd = linx_get_descriptor(linx);
		sig = (void *)buf;
		socklen = sizeof(struct sockaddr_linx);
		to.family = AF_LINX;
		to.spid = test_slave;

		sig->sigNo = ATTACH_TEST_REQ;
		len = sendto(sd, sig, sizeof(LINX_SIGSELECT), 0,
			     (const struct sockaddr *)(void *)&to, socklen);
		if (unlikely((size_t) len != sizeof(LINX_SIGSELECT))) {
			ERR("sendto returned: %d when asked for: %zd",
			    len, sizeof(LINX_SIGSELECT));
		}
		if (unlikely(len <= 0)) {
			ERR("Failed to send the ATTACH_SEND_REQ signal "
			    "(%d, %s)\n", len, strerror(errno));
		}
		len = recvfrom(sd,
			       sig,
			       sizeof(LINX_SIGSELECT),
			       0, (struct sockaddr *)(void *)&to, &socklen);

		if (unlikely(len <= 0)) {
			ERR("Failed to receive a ATTACH_TEST_REQ signal "
			    "(%d, %d)\n", len, errno);
		}
		get_time(&tv);
		/* Receive the attach signal */
		len = recvfrom(sd,
			       sig,
			       sizeof(LINX_SIGSELECT),
			       0, (struct sockaddr *)(void *)&to, &socklen);

		if (unlikely(len <= 0)) {
			ERR("Failed to receive a attach signal(%d, %d)\n",
			    len, errno);
		}
		clk = get_time(&tv);

		PRINT(DBG, "Response time: %ld us\n", clk);
	}

	return clk;
}

/****************************************/

int
attach_test(LINX * linx, const char *path,
	    int cnt, LINX_SPID server, int use_linx_api, int use_pthreads)
{

	float ack = 0;
	int i;
	long max = 0, min = LONG_MAX;

	printf("\n%%%% Running attach test %s linx api %%%%\n",
	       use_linx_api ? "with" : "without");
	printf("Test parameters:\n");
	printf("  Hunt path    : %s\n", path);
	printf("  Loop count   : %d\n", cnt);

	for (i = 0; i < cnt; i++) {
		int t = test_once(linx, server, use_linx_api, use_pthreads);
		if (t > max)
			max = t;
		if (t < min)
			min = t;
		ack += t;
	}

	printf("Attach test completed.\n");
	printf("Result:\n");
	printf("  Average : %.1f us\n", ack / cnt);
	printf("  Min     : %ld us\n", min);
	printf("  Max     : %ld us\n", max);
	printf("  Diff    : %ld us\n", max - min);

	return 0;
}
