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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>

#include <linx.h>
#include <linx_types.h>
#include <linx_ioctl.h>
#include <linx_socket.h>

#include <arpa/inet.h>

#include "linx_bmark.h"

/****************************************/

union LINX_SIGNAL {
	LINX_SIGSELECT sigNo;
	long time;
	struct burstReq burstReq;
	struct burstSig burstSig;
	struct connEst connEst;
};

/****************************************/

long get_time(struct timeval *tv)
{
	/* NOTE: This code does not handle wrapping of the timer. */

	long sDiff = -tv->tv_sec;
	long uDiff = -tv->tv_usec;

	if (gettimeofday(tv, 0))
		ERR("gettimeofday() failed.");

	sDiff += tv->tv_sec;
	uDiff += tv->tv_usec;

	return sDiff * 1000000 + uDiff;
}

unsigned int *get_cpu_times(void)
{
	static unsigned int times[PROC_STAT];
	char tmp[5];
	char string[80];
	char *ret;
	FILE *file;

	file = fopen("/proc/stat", "r");
	ret = fgets(string, 80, file);
	sscanf(string, "%s %u %u %u %u %u %u %u", tmp, &times[0], &times[1],
	       &times[2], &times[3], &times[4], &times[5], &times[6]);
	fclose(file);
	return times;
}

/* print_cpu_load(). The information is retreived from /proc/stat and here
   follows a short explanation of what the differens values are. Taken from
   PROC(5) man page:

   The amount of time, measured in units of USER_HZ (1/100ths of a second on
   most architectures), that the system spent in user mode, user mode with
   low  priority  (nice),  system  mode,  and  the idle task, respectively.
   The last value should be USER_HZ times the second entry in the uptime
   pseudo-file. In Linux 2.6 this line includes three additional columns:
   iowait - time  waiting for I/O to complete (since 2.5.41); irq - time
   servicing interrupts (since 2.6.0-test4); softirq - time servicing softirqs
   (since 2.6.0-test4).
*/

void print_cpu_load(unsigned int *starttimes, unsigned int *stoptimes)
{
	unsigned int total;
	double load;
	int i;
	static unsigned int resulttimes[PROC_STAT];
	for (i = 0; i < PROC_STAT; i++)
		resulttimes[i] = stoptimes[i] - starttimes[i];
	total = 0;
	for (i = 0; i < PROC_STAT; i++)
		total += resulttimes[i];
	if (total != 0) {
		load = (double)resulttimes[IDLE] * 100.0 / (double)total;
		printf("  CPU load  : %2.2f%%\n", 100.0 - load);
		printf("    user    : %u%%\n"
		       "    system  : %u%%\n"
		       "    nice    : %u%%\n"
		       "    idle    : %u%%\n"
		       "    iowait  : %u%%\n"
		       "    irq     : %u%%\n"
		       "    softirq : %u%%\n",
		       (resulttimes[USER] * 100 / total),
		       (resulttimes[SYSTEM] * 100 / total),
		       (resulttimes[NICE] * 100 / total),
		       (resulttimes[IDLE] * 100 / total),
		       (resulttimes[IOWAIT] * 100 / total),
		       (resulttimes[IRQ] * 100 / total),
		       (resulttimes[SOFTIRQ] * 100 / total));
	} else {
		printf("  CPU load  : 0.0\n");
	}
}

/****************************************/

LINX_SPID create_test_slave(LINX * linx, LINX_SPID server, int use_linx_api,
			    int use_pthreads)
{
	LINX_SPID test_slave_spid;
	union LINX_SIGNAL *sig;
	LINX_SIGSELECT any_sig[] = { 0 };

	sig = linx_alloc(linx, sizeof(struct connEst), CONN_EST);
	sig->connEst.use_linx_api = htonl(use_linx_api);
	sig->connEst.use_pthreads = htonl(use_pthreads);

	linx_send(linx, &sig, server);

	linx_receive(linx, &sig, any_sig);

	if (sig->sigNo != CONN_EST) {
		ERR("Unknown signal %ud", sig->sigNo);
	}

	test_slave_spid = linx_sender(linx, &sig);

	linx_free_buf(linx, &sig);

	return test_slave_spid;
}

/****************************************/

void destroy_test_slave(LINX * linx, LINX_SPID ts)
{
	union LINX_SIGNAL *sig;
	LINX_SIGSELECT any_sig[] = { 0 };

	sig = linx_alloc(linx, sizeof(LINX_SIGSELECT), ATTACH_SLAVE_SIG);
	linx_attach(linx, &sig, ts);

	sig = linx_alloc(linx, sizeof(LINX_SIGSELECT), TERMINATE_REQ);
	TRACE(1, "Terminate request");
	linx_send(linx, &sig, ts);

	linx_receive(linx, &sig, any_sig);

	if (sig->sigNo != ATTACH_SLAVE_SIG) {
		ERR("Wrong signal received while waiting for attach signal"
		    " from test slave. %d", sig->sigNo);
	}
	linx_free_buf(linx, &sig);
}

/****************************************/

static void test_with_linxlib(LINX_SPID client, LINX * linx)
{
	LINX_SPID sender;
	union LINX_SIGNAL *sig;
	LINX_SIGSELECT any_sig[] = { 0 };

	for (;;) {
		linx_receive(linx, &sig, any_sig);

		sender = linx_sender(linx, &sig);
		if (sender != client) {
			WARN("Ignoring signal from spid %ud", sender);
			linx_free_buf(linx, &sig);
			continue;
		}

		switch (sig->sigNo) {
		case ECHO_SIG:
			TRACE(1, "Sending echo");
			linx_send(linx, &sig, client);
			break;

		case TERMINATE_REQ:
			TRACE(1, "Terminating");
			linx_free_buf(linx, &sig);
			linx_close(linx);
			return;

		case ATTACH_TEST_REQ:
			linx_send(linx, &sig, client);
			linx_close(linx);
			return;

		case BURST_REQ:
			{
				int sigCnt = ntohl(sig->burstReq.n);
				int reply_size =
				    ntohl(sig->burstReq.reply_size);
				LINX_SIGSELECT reply_sigNo =
				    ntohl(sig->burstReq.reply_sigNo);
				union LINX_SIGNAL *list = 0;

				linx_free_buf(linx, &sig);

				/* Allocate all signals before sending then to
				 * make the send loop as tight as possible */
				while (sigCnt--) {
					sig = linx_alloc(linx, reply_size,
							 reply_sigNo);
					sig->burstSig.sigNo = reply_sigNo;
					sig->burstSig.next = list;
					list = sig;
				}

				while (list) {
					sig = list;
					list = list->burstSig.next;
					sig->burstSig.next = NULL;
					linx_send(linx, &sig, client);
				}
				break;
			}

		default:
			WARN("Ignoring unknown signal %ud", sig->sigNo);
			linx_free_buf(linx, &sig);
		}
	}
}

static void test_without_linxlib(LINX_SPID client, LINX * linx)
{
	int len, sig_len;
	struct sockaddr_linx to;
	socklen_t socklen;
	int sd = linx_get_descriptor(linx);
	size_t msg_size = 65536;
	union LINX_SIGNAL *sig = malloc(msg_size);

	if (sig == NULL) {
		ERR("Failed to allocate memory");
		exit(1);
	}
	socklen = sizeof(struct sockaddr_linx);
	to.family = AF_LINX;
	to.spid = LINX_ILLEGAL_SPID;

	for (;;) {
		len = sig_len = recvfrom(sd,
					 sig,
					 msg_size,
					 0, (struct sockaddr *)(void *)&to,
					 &socklen);

		if (unlikely(len <= 0)) {
			ERR("Failed to receive a signal(%d, %d)\n", len, errno);
			continue;
		}

		if (unlikely(to.spid != client)) {
			WARN("Ignoring signal from spid %#x since it is"
			     " not %#x", to.spid, client);
			continue;
		}

		switch (sig->sigNo) {
		case ECHO_SIG:
			TRACE(1, "Sending echo");

			len = sendto(sd, sig, len,
				     0, (struct sockaddr *)(void *)&to,
				     socklen);
			if (unlikely(sig_len != len)) {
				ERR("sendto returned: %d when asked "
				    "for: %d", len, sig_len);
			}
			if (unlikely(len <= 0)) {
				ERR("Failed to send the echo signal "
				    "(%d, %s)\n", len, strerror(errno));
			}
			break;

		case TERMINATE_REQ:
			TRACE(1, "Terminating");
			free(sig);
			linx_close(linx);
			return;

		case ATTACH_TEST_REQ:
			len = sendto(sd, sig, len,
				     0, (struct sockaddr *)(void *)&to,
				     socklen);
			if (unlikely(sig_len != len)) {
				ERR("sendto returned: %d when asked "
				    "for: %d", len, sig_len);
			}
			if (unlikely(len <= 0)) {
				ERR("Failed to send the echo signal "
				    "(%d, %s)\n", len, strerror(errno));
			}
			linx_close(linx);
			return;

		case BURST_REQ:
			{
				uint32_t sigCnt = ntohl(sig->burstReq.n);
				uint32_t reply_size =
				    ntohl(sig->burstReq.reply_size);

				LINX_SIGSELECT reply_sigNo =
				    ntohl(sig->burstReq.reply_sigNo);

				/* Allocate all signals before sending then to
				 * make the send loop as tight as possible */
				sig->burstSig.sigNo = reply_sigNo;
				while (sigCnt--) {
					len = sendto(sd, sig, reply_size,
						     0,
						     (struct sockaddr *)(void *)&to,
						     socklen);
					if (unlikely
					    (reply_size != (uint32_t) len)) {
						ERR("sendto returned: %d when "
						    "asked for: %d", len,
						    reply_size);
					}
					if (unlikely(len <= 0)) {
						ERR("Failed to send the echo "
						    "signal (%d, %s)\n",
						    len, strerror(errno));
					}
				}
				break;
			}

		default:
			WARN("Ignoring unknown signal %ud", sig->sigNo);
		}
	}
	free(sig);
}

static void *test_slave_proc(void *input)
{
	char proc_name[24];
	LINX *linx;
	union LINX_SIGNAL *sig;
	struct slave_args *arg_ = (struct slave_args *)input;

	sprintf(proc_name, "linx_bmark_%08u", arg_->slave_no);
	TRACE(1, "Server instance \"%s\" start.", proc_name);
	linx = linx_open(proc_name, 0, NULL);

	sig = linx_alloc(linx, sizeof(struct connEst), CONN_EST);
	sig->connEst.use_linx_api = htonl(arg_->use_linx_api);
	linx_send(linx, &sig, arg_->client);

	if (arg_->use_linx_api)
		test_with_linxlib(arg_->client, linx);
	else
		test_without_linxlib(arg_->client, linx);
	if(arg_->use_pthreads) {
		free(input);
		pthread_exit(NULL);
	}
	return NULL;
}

/****************************************/

void *server(void *server_name)
{
	LINX *linx;
	union LINX_SIGNAL *sig;
	LINX_SPID client;
	pid_t pid;
	LINX_SIGSELECT any_sig[] = { 0 };
	unsigned slave_no = 0;
	char *name = (char *)server_name;
	if (!(name && *name))
		name = SERVER_NAME;
	PRINT(INFO, "Server master start. Using service name \"%s\"\n", name);

	linx = linx_open(name, 0, NULL);
	if (linx == NULL) {
		ERR("server linx_open failed. (insmod linx.ko done?)");
	}

	for (;;) {
		linx_receive(linx, &sig, any_sig);

		if (sig->sigNo == CONN_EST) {
			uint32_t use_linx_api =
			    ntohl(sig->connEst.use_linx_api);
			uint32_t use_pthreads = 
				ntohl(sig->connEst.use_pthreads);
			client = linx_sender(linx, &sig);
			linx_free_buf(linx, &sig);
			slave_no++;


			/* Spawn a test slave handling the
			 * requests from the client */
			if (use_pthreads) {
				pthread_t server_slave_th;
				struct slave_args *input =
					malloc(sizeof(*input));
				if(input == NULL) {
					ERR("Failed to allocate memory");
					exit(1);
				}
	input->client = client;
				input->slave_no = slave_no;
				input->use_linx_api = use_linx_api;
				input->use_pthreads = use_pthreads;
				if (pthread_create(&server_slave_th,
						   NULL, test_slave_proc,
						   (void *)input)) {
					fprintf(stderr, "pthread_create(): %d\n", errno);
					exit(errno);
				}
				/* thread frees arguments */
			} else {
				pid = fork();
				if (pid < 0) {
					ERR("server failed to fork. pid %d", pid);
					exit(1);
				}
				if (!pid) {
					pid = fork();
					if (pid < 0) {
						ERR("server failed to perform second "
						    "fork. pid %d", pid);
						exit(1);
					}
					if (!pid) {
						struct slave_args arg_;
						arg_.client = client;
						arg_.slave_no = slave_no;
						arg_.use_linx_api = use_linx_api;
						arg_.use_pthreads = use_pthreads;
						(void)test_slave_proc((void *)&arg_);
						exit(0);
					}
					exit(0);
				}
				wait(NULL);
			}
		} else if (sig->sigNo == CONN_TERM) {
			printf("server_master received conn_term\n");
			linx_free_buf(linx, &sig);
			printf("closing...\n");
			linx_close(linx);
			return NULL;
		} else {
			WARN("Ignoring unknown signal %ud", sig->sigNo);
			linx_free_buf(linx, &sig);
		}
	}
	return NULL;
}

/****************************************/

static void print_usage(const char *cmd_name)
{
	printf("Usage:\n  %s -S<name> [ -l ]\n", cmd_name);
	printf("    Start server master using <name> as the hunt name.\n\n");

	printf("  %s -a [ -p<path> ] [ -n<loop_cnt> ]\n\n", cmd_name);
	printf("    Run attach test:\n"
	       "    1) A connection is established to a slave process.\n"
	       "    2) The slave is terminated, which triggers an attach\n"
	       "       signal.\n"
	       "    The time between the termination and the reception of\n"
	       "    the attach signal is measured.\n"
	       "    The server master must be started.\n\n");

	printf("  %s -c1 [ -p<path> ]\n"
	       "         [ -n<loop_cnt> ]\n"
	       "         [ -m<msgSize> ]\n" "         [ -l ]\n\n", cmd_name);

	printf("    Run com test 1 (latency):\n"
	       "    The time for sending a signal to a slave and back is\n"
	       "    measured\n"
	       "    The server master must be started.\n\n"
	       "  %s -c2 [ -p<path> ]\n"
	       "         [ -n<loop_cnt> ]\n"
	       "         [ -m<msgSize> ]\n"
	       "         [ -b<burstCnt> ]\n" "         [ -l ]\n\n", cmd_name);

	printf("    Run com test 2:\n"
	       "    1) A connection is established to a slave process\n"
	       "    2) The slave sends <burstCnt> signal\n"
	       "    The time until all signals have been received is\n"
	       "    measured.\n");
	printf("    The server master must be started.\n\n");

	printf("  %s -c3 [ -p<path> ]\n"
	       "         [ -n<loop_cnt> ]\n"
	       "         [ -s<start message size> ]\n"
	       "         [ -e<end message size> ]\n"
	       "         [ -i<number of iterations> ]\n"
	       "         [ -l ]\n\n", cmd_name);

	printf("    Run com test 3:\n"
	       "    The time total time for sending <loop_cnt> number of\n"
	       "    signals to a slave is measured. The message size starts\n"
	       "    at <start message size> and is increased\n"
	       "    <number of iterations> times until it reaches\n"
	       "    <end_message_size>.\n"
	       "    The latency plus CPU load is presented for each\n"
	       "    iteration. The server master must be started.\n\n");

	printf("  %s -c4 [ -p<path> ]\n"
	       "         [ -n<loop_cnt> ]\n"
	       "         [ -s<start message size> ]\n"
	       "         [ -e<end message size> ]\n"
	       "         [ -i<number of iterations> ]\n"
	       "         [ -b<burstCnt> ]\n" "         [ -l ]\n\n", cmd_name);

	printf("    Run com test 4:\n"
	       "    The time total time for receiving burstCnt number of\n"
	       "    signals is measured. For each iteration the size of the\n"
	       "    signals is increased, starting from start message size\n"
	       "    for the first iteration and then growing until it\n"
	       "    reaches end message size. The average time plus CPU load\n"
	       "    is presented for each iteration.\n"
	       "    The server master must be started.\n\n");

	printf("  %s -c5 [ -p<path> ]\n"
	       "         [ -n<loop_cnt> ]\n"
	       "         [ -m<message size> ]\n"
	       "         [ -i<number of iterations> ]\n"
	       "         [ -t<number of process pairs> ]\n"
	       "         [ -l ]\n\n", cmd_name);

	printf("    Run com test 5:\n"
	       "    Measure the throughput of <number of process pairs>\n"
	       "    parallel clients and servers sending <message size>\n"
	       "    large signals back and forth (ping pong) <loop_cnt>\n"
	       "    number of times.\n\n");

	printf("  The tests are repeated <loop_cnt> times and some\n"
	       "  statistics are calculated, <path> is the hunt path to\n"
	       "  master server. If it located on the machine where the\n"
	       "  test is initiated, it can be omitted. <msgSize> is the\n"
	       "  size of the message(s). If -l is used, the test will use\n"
	       "  the LINX API during the measurement. Otherwise the LINX\n"
	       "  socket API will be accessed directly. To kill the server\n"
	       "  master process, run %s with -q and the -p<path> to server\n"
	       "\n", cmd_name);

}

/****************************************/

int main(int argc, char *argv[])
{
	LINX *linx;
	LINX_SPID server_spid;
	union LINX_SIGNAL *sig;
	pthread_t server_th;
	int c;
	int loop_cnt = LOOP_CNT;
	int use_linx_api = LINX_SOCKET;
	size_t msg_size = BURST_SIZE;
	unsigned long burst_cnt = BURST_CNT;
	size_t start_msg_size = START_MSG_SIZE;
	size_t end_msg_size = END_MSG_SIZE;
	unsigned long throughput_instances = THROUGHPUT_INSTANCES;
	int iterations = ITERATIONS;
	LINX_SIGSELECT any_sig[] = { 0 };

	char *path = NULL;
	char *server_name = NULL;
	int run_attach_test = 0;
	int run_com_test = 0;
	int kill_server = 0;
	int all = 0;
	int use_pthreads = 0;

	if (argc < 2) {
		print_usage(argv[0]);
		return 0;
	}

	while ((c = getopt(argc, argv, "S?p:ac:n:m:b:i:s:e:Alt:qP")) != -1) {
		switch (c) {
		case 'S':
			/* Start server */
			server_name = (optarg == NULL ? SERVER_NAME : optarg);
			break;

		case 'P':
			/* Start server as posix thread */
			server_name = SERVER_NAME;
			use_pthreads = 1;
			break;

		case 'p':
			/* Hunt path */
			path = optarg;
			break;

		case 'a':
			/* Run attach test */
			run_attach_test = 1;
			break;

		case 'c':
			/* Connection test */
			run_com_test = atoi(optarg);
			break;

		case 'n':
			/* Loop count */
			loop_cnt = atoi(optarg);
			break;

		case 'm':
			/* Message size */
			msg_size = atol(optarg);
			break;

		case 'b':
			/* Burst count */
			burst_cnt = atol(optarg);
			break;

		case 'i':
			/* Iterations */
			iterations = atoi(optarg);
			break;

		case 's':
			/* Start message size */
			start_msg_size = atol(optarg);
			break;

		case 'e':
			/* End message size */
			end_msg_size = atol(optarg);
			break;

		case 'A':
			/* Run all tests */
			all = 1;
			break;

		case 'l':
			/* Use linx api in tests */
			use_linx_api = LINX_API;
			break;

		case 't':
			/* Number of instances in throughput */
			throughput_instances = atoi(optarg);
			break;

		case 'q':
			/* Quit the server */
			kill_server = 1;
			break;
		default:
			print_usage(argv[0]);
			return 0;
		}
	}

	if(use_pthreads) {
		kill_server = 1;
		if (pthread_create(&server_th, NULL, server,
				   (void *)server_name)) {
			fprintf(stderr, "pthread_create(): %d\n", errno);
			exit(errno);
		}
	} else if (server_name != NULL) {
		(void)server(server_name);
		return 0;
	}

	/* Path to server */
	path = path && *path ? path : CS_PATH SERVER_NAME;

	/* Hunt for server */
	linx = linx_open(CLIENT_NAME, 0, NULL);
	linx_hunt(linx, path, NULL);
	linx_receive_w_tmo(linx, &sig, 1000, any_sig);
	if (sig == NULL) {
		printf("Hunt failed. No server found at path '%s'.\n"
		       "Is the server started and path ok? "
		       "(Server started with -S option)\n", path);
		linx_close(linx);
		return 1;
	}
	if (sig->sigNo != LINX_OS_HUNT_SIG) {
		ERR("Failed to hunt for '%s'", path);
		linx_free_buf(linx, &sig);
		linx_close(linx);
		return 1;
	}
	server_spid = linx_sender(linx, &sig);
	linx_free_buf(linx, &sig);

	/* Attach to server */
	sig = linx_alloc(linx, sizeof(LINX_SIGSELECT), ATTACH_SERV_SIG);
	linx_attach(linx, &sig, server_spid);

	if (run_attach_test) {
		attach_test(linx, path, loop_cnt, server_spid, use_linx_api,
			    use_pthreads);
	}

	switch (run_com_test) {
	case 1:
		/* Start com test 1 */
		linx_bmark_latency(linx, path, loop_cnt, msg_size, msg_size,
				   ONE_ITERATION, server_spid, use_linx_api,
				   use_pthreads);
		break;
	case 2:
		/* Start com test 2 */
		linx_bmark_burst(linx, path, loop_cnt, msg_size,
				 msg_size, ONE_ITERATION,
				 burst_cnt, server_spid, use_linx_api,
				 use_pthreads);
		break;
	case 3:
		/* Start com test 3 */
		linx_bmark_latency(linx, path, loop_cnt, start_msg_size,
				   end_msg_size, iterations, server_spid,
				   use_linx_api, use_pthreads);
		break;
	case 4:
		/* Start com test 4 */
		linx_bmark_burst(linx, path, loop_cnt, start_msg_size,
				 end_msg_size, iterations, burst_cnt,
				 server_spid, use_linx_api, use_pthreads);
		break;
	case 5:
		/* Start com test 5 */
		linx_bmark_throughput(path, loop_cnt, msg_size,
				      server_spid, use_linx_api,
				      throughput_instances, use_pthreads);
		break;
	default:
		break;
	}

	if (all) {
		/* All tests  */
		attach_test(linx, path, loop_cnt, server_spid, use_linx_api,
			    use_pthreads);
		linx_bmark_latency(linx, path, loop_cnt, msg_size, msg_size,
				   ONE_ITERATION, server_spid, use_linx_api,
				   use_pthreads);
		linx_bmark_burst(linx, path, loop_cnt, msg_size, msg_size,
				 ONE_ITERATION, burst_cnt,
				 server_spid, use_linx_api, use_pthreads);
		linx_bmark_latency(linx, path, loop_cnt, start_msg_size,
				   end_msg_size, iterations,
				   server_spid, use_linx_api, use_pthreads);
		linx_bmark_burst(linx, path, loop_cnt, start_msg_size,
				 end_msg_size, iterations, burst_cnt,
				 server_spid, use_linx_api, use_pthreads);
		linx_bmark_throughput(path, loop_cnt, msg_size,
				      server_spid, use_linx_api,
				      throughput_instances, use_pthreads);
	}

	if (kill_server) {
		/* If no test argument specified, let server close */
		sig = linx_alloc(linx, sizeof(LINX_SIGSELECT), CONN_TERM);
		linx_send(linx, &sig, server_spid);
		printf("Waiting for attach from server.\n");
		linx_receive(linx, &sig, any_sig);
		if (sig == LINX_NIL) {
			ERR("No attach signal was received from the server.");
		}
		if (sig->sigNo != ATTACH_SERV_SIG) {
			ERR("Wrong signal received while waiting for "
			    "attach signal from server.");
		}
		linx_free_buf(linx, &sig);

		/* Close client spid */
		linx_close(linx);
	}

	if(use_pthreads)
		pthread_join(server_th, NULL);
	
	return 0;
}
