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
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <linx.h>
#include "linx_basic.sig"
#include "linx_basic.h"

/*
 *    LINX example client.
 */

static LINX_SPID find_server(LINX * linx, const char *huntpath)
{
	LINX_SIGSELECT sigsel_hunt[] = { 1, LINX_OS_HUNT_SIG };
	LINX_SPID server;
	union LINX_SIGNAL *sig;

	/* Hunt for server.
	   Since NULL is given as hunt_sigLINX_OS_HUNT_SIG is returned */
	printf("Client: Hunting for server \"%s\".\n", huntpath);
	if (linx_hunt(linx, huntpath, NULL) == -1) {
		ERR("linx_hunt() failed");
		exit(1);
	}

	/* Wait for the hunt to be resolved */
	if (linx_receive_w_tmo(linx, &sig, IDLE_TIMEOUT, sigsel_hunt) == -1) {
		ERR("linx_receive_w_tmo() failed");
		exit(1);
	}
	if (sig == LINX_NIL) {
		printf("Hunting for server on %s timed out.\n"
		       "Check that server is started "
		       "(and optional, that a link is created).\n", huntpath);
		if (linx_close(linx) == -1) {
			ERR("linx_close() failed");
		}
		exit(0);
	}

	printf("Client: Found server \"%s\".\n", huntpath);
	server = linx_sender(linx, &sig);
	if (server == LINX_ILLEGAL_SPID) {
		ERR("linx_sender() failed");
		exit(1);
	}

	/* Free hunt sig */
	if (linx_free_buf(linx, &sig) == -1) {
		ERR("linx_free_buf() failed");
		exit(1);
	}

	return server;
}

static void send_request(LINX * linx, LINX_SPID server, int seqno)
{
	union LINX_SIGNAL *sig;

	sig = linx_alloc(linx, sizeof(struct request_sig), REQUEST_SIG);
	if (sig == NULL) {
		ERR("linx_alloc() failed");
		exit(1);
	}

	sig->request.seqno = seqno;

	if (linx_send(linx, &sig, server) == -1) {
		ERR("linx_send() failed");
	}
}

void client_main(char *linkname, int num_req)
{
	LINX_SIGSELECT sigsel_any[] = { 0 };
	LINX *linx;
	LINX_SPID server;
	LINX_OSATTREF att_ref;
	union LINX_SIGNAL *sig;
	char *server_huntpath;
	int seqno = 0;
	int reply_received = 0;

	printf("Client started.\n");

	if (linkname != NULL) {
		server_huntpath =
		    malloc(strlen(linkname) + strlen(SERVER_NAME) + 2);
		sprintf(server_huntpath, "%s/%s", linkname, SERVER_NAME);
	} else {
		server_huntpath = malloc(strlen(SERVER_NAME) + 1);
		sprintf(server_huntpath, "%s", SERVER_NAME);
	}

	/* Open LINX socket */
	linx = linx_open(CLIENT_NAME, 0, NULL);
	if (linx == NULL) {
		ERR("linx_open() failed");
	}

	/* Find the server */
	server = find_server(linx, server_huntpath);

	/* Attach to the server */
	att_ref = linx_attach(linx, NULL, server);
	if (att_ref == LINX_ILLEGAL_ATTREF) {
		ERR("linx_attach() failed");
	}

	/* Loop until num_req REQUEST/REPLY exchanges have been performed,
	 * or forever if the user did not provide a value */
	while ((num_req == 0) || (num_req > seqno)) {

		/* Send REQUEST signal to server */
		seqno++;

		printf("Client: Sending REQUEST_SIG, seqno: %d", seqno);
		if (num_req)
			printf(" (of %d)", num_req);
		printf(".\n");

		send_request(linx, server, seqno);

		reply_received = 0;

		while (!reply_received) {
			/* Wait until a signal arrives */
			if (linx_receive_w_tmo(linx, &sig, IDLE_TIMEOUT,
					       sigsel_any) == -1) {
				ERR("linx_receive() failed");
			}
			if (sig == LINX_NIL) {
				printf("Client: Idle too long,"
				       " terminating.\n");
				goto quit;
			}

			switch (sig->sig_no) {
			case REPLY_SIG:
				printf("Client: REPLY_SIG received,"
				       " seqno: %d.\n",
				       sig->request.seqno);
				if (seqno == sig->request.seqno) {
					reply_received = 1;
				} else {
					printf("Client: Unexpected seqno %d "
					       "(waiting for %d) - ignored\n",
					       sig->request.seqno, seqno);
				}
				break;
			case LINX_OS_ATTACH_SIG:
				printf("Client: Contact with server lost.\n");
				/* Reestablish connection with the server
				 * (Note: the huntpath to a backup server could
				 * be used here) */
				server = find_server(linx, server_huntpath);
				att_ref = linx_attach(linx, NULL, server);
				if (att_ref == LINX_ILLEGAL_ATTREF) {
					ERR("linx_attach() failed");
				}

				/* Resend last REQUEST (since we did not
				 * get a REPLY) */
				printf("Client: Resending REQUEST_SIG,"
				       " seqno: %d.\n", seqno);
				send_request(linx, server, seqno);
				break;
			default:
				printf("Client: Unexpected signal received "
				       "(sig_no = %d) - ignored\n",
				       sig->sig_no);
				break;
			}

			/* Free received sig */
			if (linx_free_buf(linx, &sig) == -1) {
				ERR("linx_free_buf() failed");
			}
		}
		/* Let client sleep for CLIENT_TIMEOUT ms to slow things down
		 * and wait for attach meanwhile.
		 * This way the user has time to interact, for example 
		 * terminate and restart the server while a client is 
		 * running. */
		if (linx_receive_w_tmo(linx, &sig, CLIENT_TIMEOUT, sigsel_any)
		    == -1)
			ERR("linx_receive_w_tmo() failed.");

		/* Check if timeout is received (sig_attach == 0).
		 * If so move on, else check for attach sig and exit server */
		if (sig != 0) {
			switch (sig->sig_no) {
			case LINX_OS_ATTACH_SIG:
				{
					printf
					    ("Client: Exit. Discovered that client "
					     "died.\n");
					exit(0);
					break;
				}
			default:
				{
					ERR("Wrong signal received");
					exit(1);
					break;
				}
			}
		}
	}
	printf("Client: Finished, terminating.\n");

      quit:
	free(server_huntpath);
	if (linx_close(linx) == -1) {
		ERR("linx_close() failed");
	}
}

static void usage(void)
{
	printf("Usage: linx_example_client [-n <count>] [<linkname>]\n\n");
	printf("LINX client/server example application. Client(s) send "
	       "requests\n");
	printf("to the server, and the server answers each request with"
	       " a reply\n");
	printf("after 2 seconds.\n\n");
	printf("  -n    Number of requests to send before terminating.\n\n");
	printf("If no link name is provided, the client looks for the "
	       "server on\n");
	printf("the local machine.\n\n");
}

int main(int argc, char *argv[])
{
	int opt, optmsk;
	int num_req = 0;

	for (optmsk = opterr = 0; (opt = getopt(argc, argv, "n:")) != -1;) {
		switch (opt) {
		case 'n':
			num_req = atoi(optarg);
			break;
		default:
			usage();
			exit(1);
		}
	}
	client_main(argv[optind], num_req);
	return 0;
}
