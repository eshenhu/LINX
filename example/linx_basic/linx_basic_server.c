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
#include <errno.h>
#include <linx.h>
#include "linx_basic.sig"
#include "linx_basic.h"

/*
 *    LINX example server.
 */

void server_main()
{
	LINX_SIGSELECT sigsel_any[] = { 0 };
	LINX *linx;
	LINX_SPID client;
	union LINX_SIGNAL *sig;

	printf("Server started.\n");

	/* Open LINX socket */
	linx = linx_open(SERVER_NAME, 0, NULL);
	if (linx == NULL) {
		ERR("linx_open() failed");
	}

	for (;;) {
		/* Wait until a signal arrives */
		if (linx_receive_w_tmo(linx, &sig, IDLE_TIMEOUT,
				       sigsel_any) == -1) {
			ERR("linx_receive() failed");
		}
		if (sig == LINX_NIL) {
			printf("Server: Idle too long, terminating.\n");
			if (linx_close(linx) == -1) {
				ERR("linx_close() failed");
			}
			break;
		}

		switch (sig->sig_no) {
		case REQUEST_SIG:
			{
				printf("Server: REQUEST_SIG received.\n");
				client = linx_sender(linx, &sig);
				if (client == LINX_ILLEGAL_SPID) {
					ERR("linx_sender() failed");
				}

				/* Use same signal for REPLY, just change the 
				 * signal number */
				printf("Server: Sending REPLY_SIG.\n");
				sig->sig_no = REPLY_SIG;
				if (linx_send(linx, &sig, client) == -1) {
					ERR("linx_send() failed.");
					exit(1);
				}
				break;
			}

		default:
			{
				printf("Server: Unexpected signal received "
				       "(sig_no = %d) - ignored\n",
				       sig->sig_no);
				if (linx_free_buf(linx, &sig) == -1) {
					ERR("linx_free_buf() failed");
				}
				break;
			}
		}
	}
}

static void usage(void)
{
	printf("Usage:   linx_basic_server\n\n");
	printf("LINX basic_client/server application. "
	       "Client(s) send request\n");
	printf("messages to the server. "
	       "The server answers each request with\n");
	printf("a reply message after 2 seconds.\n\n");
}

int main(int argc, char *argv[])
{
	TOUCH(argv);
	if (argc == 1) {
		server_main();
		return 0;
	}
	usage();
	exit(1);
}
