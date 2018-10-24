/*
 * Copyright (c) 2006-2010, Enea Software AB
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>

#include <linx.h>
#include <linx_types.h>
#include "linx_info.h"

#define ATTACH_STR_MAX 11

#define DEFAULT_NAME_LENGTH 18
#define MINIMUM_NAME_LENGTH 5
int maxNameLength = DEFAULT_NAME_LENGTH;


char *hunt_name = NULL;


static void usage(void)
{
	printf("Usage: linxstat [-b] [-h] [-aHqSs] [-l <length>] "
		"[-n <hunt_name>] [-t <type>]\n");
	printf("Description: Print LINX information specific socket "
	       "information\n");
	printf("\t-a print verbose pending attach information\n");
	printf("\t-b batch mode, print # of linx end points\n");
	printf("\t-f print receive filters\n");
	printf("\t-H print verbose pending hunt information\n");
	printf("\t-h print this help\n");
	printf("\t-l specify length of name to be printed, default %d, minimum %d\n",
		DEFAULT_NAME_LENGTH, MINIMUM_NAME_LENGTH);
	printf("\t-n <hunt_name> print info only for <hunt_name>\n");
	printf("\t-q print verbose receive queue information\n");
	printf("\t-S print per socket statistics (NOT)\n");
	printf("\t-s print socket individual information only\n");
	printf("\t-t print sockets of specified type only\n");
	printf("\t-T print pending timeouts\n");
	exit(0);
}

static int get_terminal_width(void)
{
	struct winsize win = {0,0,0,0};
	int terminal_width = 0;
	
	ioctl(fileno(stdout), TIOCGWINSZ, &win);
	if (win.ws_col > 0)
		terminal_width = win.ws_col;
	else
		terminal_width = 80;

	return terminal_width;
}

static const char *state_to_str(int state)
{
	switch (state) {
	case LINX_STATE_UNKNOWN:
		return "-";
	case LINX_STATE_RUNNING:
		return "run";
	case LINX_STATE_RECV:
		return "recv";
	case LINX_STATE_POLL:
		return "poll";
	default:
		break;
	}

	return "";
}

static char *strtolower(const char *str)
{
	int i;
	/* 8 characters is enough - we'll only use strtolower to convert
	 * socket types. */
	static char s[8] = { 0, };

	for (i = 0; str[i]; i++)
		s[i] = tolower(str[i]);

	return s;
}

static int get_proc_type(char *str)
{
	char *tmp = strtolower(str);

	if (strcmp("unknown", tmp) == 0) {
		return LINX_TYPE_UNKNOWN;
	} else if (strcmp("local", tmp) == 0) {
		return LINX_TYPE_LOCAL;
	} else if (strcmp("remote", tmp) == 0) {
		return LINX_TYPE_REMOTE;
	} else if (strcmp("link", tmp) == 0) {
		return LINX_TYPE_LINK;
	} else if (strcmp("illegal", tmp) == 0) {
		return LINX_TYPE_ILLEGAL;
	} else if (strcmp("zombie", tmp) == 0) {
		return LINX_TYPE_ZOMBIE;
	} else {
		return LINX_TYPE_UNKNOWN;
	}
}

static const char *type_to_str(int type)
{
	switch (type) {
	case LINX_TYPE_LOCAL:
		return "local";
	case LINX_TYPE_REMOTE:
		return "remote";
	case LINX_TYPE_LINK:
		return "link";
	case LINX_TYPE_ILLEGAL:
		return "illegal";
	case LINX_TYPE_ZOMBIE:
		return "zombie";
	default:
		/* includes LINX_TYPE_UNKNOWN */
		break;
	}

	return "unknown";
}

static void print_attach(int count, struct linx_info_attach *att, int from)
{
	int i;

	printf("\tAttach info (%s):\n",
	       from == LINX_ATTACH_FROM ? "from" : "to");

	for (i = 0; i < count; i++) {
		printf("\t [attref:0x%08x   %s:0x%08x "
		       "signo:%-10d size:%6d]\n",
		       att[i].attref,
		       from == LINX_ATTACH_FROM ? "from" : "to",
		       from == LINX_ATTACH_FROM ?
		       att[i].spid : att[i].attach_signal.from,
		       att[i].attach_signal.signo,
		       att[i].attach_signal.size);
	}
}

static void print_hunt(int count, struct linx_info_hunt *hunt)
{
	int i;

	printf("\tPending hunts (%d, %p):\n", count, (void *)hunt);

	for (i = 0; i < count; i++) {
		printf("\t [signo:%-10d size:%-6d owner:0x%08x"
		       " hunt_name:%s]\n",
		       hunt[i].hunt_signal.signo,
		       hunt[i].hunt_signal.size,
		       hunt[i].owner,
		       hunt[i].hunt_name);
	}
}

static void print_tmo(int count, struct linx_info_tmo *tmo)
{
	int i;

	printf("\tTimeouts:\n");
	for (i = 0; i < count; i++) {
		printf("\t [tmoref:%#08x   %u signo:%-10d size:%6d]\n",
		       tmo[i].tmoref,
		       tmo[i].tmo,
		       tmo[i].tmo_signal.signo,
		       tmo[i].tmo_signal.size);
	}
}

static void print_filter(LINX_SIGSELECT *filter)
{
	int i;
	int count = abs(filter[0]) + 1;

	printf("\tFilters:\n");
	if (count == 1) {
		printf("\t recv[any]\n");
		return;
	}

	if ((int)(filter[0]) < 0)
		printf("\t recv but[ ");
	else
		printf("\t recv[ (%d) ", filter[0]);
	for (i = 1; i < count; i++) {
		printf("%x ", filter[i]);
	}
	printf("]\n");
}

static void print_signals(int count, struct linx_info_signal_2 *signals)
{
	int i;

	if (count > 0)
		printf("\tSignal queue:\n");
	else
		return;

	for (i = 0; i < count; i++) {
		printf("\t [position:%03d signo:%-10d "
		       "size:%-10d from:0x%08x oob:%s]\n",
		       i,
		       signals[i].signo,
		       signals[i].size,
		       signals[i].from,
		       signals[i].flags & MSG_OOB ? "yes" : "no");
	}
}

static void print_sock_stat(struct linx_info_stat *info_stat)
{
	printf("\tsent bytes:%llu recv bytes:%llu\n",
	       (long long unsigned int)info_stat->no_sent_bytes,
	       (long long unsigned int)info_stat->no_recv_bytes);

	printf("\tsent signals:%llu recv signals:%llu\n",
	       (long long unsigned int)info_stat->no_sent_signals,
	       (long long unsigned int)info_stat->no_recv_signals);

	printf("\tsent local signals:%llu recv local bytes:%llu\n",
	       (long long unsigned int)info_stat->no_sent_local_bytes,
	       (long long unsigned int)info_stat->no_recv_local_bytes);

	printf("\tsent local signals:%llu recv local signals:%llu\n",
	       (long long unsigned int)info_stat->no_sent_local_signals,
	       (long long unsigned int)info_stat->no_recv_local_signals);

	printf("\tsent remote bytes:%llu recv remote bytes:%llu\n",
	       (long long unsigned int)info_stat->no_sent_remote_bytes,
	       (long long unsigned int)info_stat->no_recv_remote_bytes);

	printf("\tsent remote signals:%llu recv remote signals:%llu\n",
	       (long long unsigned int)info_stat->no_sent_remote_signals,
	       (long long unsigned int)info_stat->no_recv_remote_signals);
	
	printf("\tqueued bytes:%llu queued signals:%llu\n",
	       (long long unsigned int)info_stat->no_queued_bytes,
	       (long long unsigned int)info_stat->no_queued_signals);
}

/* prints the date of one LINX process */
static void print_proc_info(struct linx_proc_info *proc_info,
			    struct linx_proc_details *pd)
{
	char *ptr;
	char tmp[ATTACH_STR_MAX + 1];
	int i, other_width, name_width, terminal_width, contents_width;

	printf("%6d ", proc_info->pid);
	printf("0x%-8x ", proc_info->spid);

	printf("%-7s ", type_to_str(proc_info->type));

	printf("%-6s ", state_to_str(proc_info->state));

	printf("%-5d ", proc_info->msg_queued);

	if (proc_info->attach_from > 99999)
		i = sprintf(tmp, "XXXXX/");
	else
		i = sprintf(tmp, "%d/", proc_info->attach_from);
	ptr = tmp + i;

	if (proc_info->attach_to > 99999)
		sprintf(ptr, "XXXXX");
	else
		sprintf(ptr, "%d", proc_info->attach_to);
	printf("%-11s ", tmp);

	printf("%-5d ", proc_info->hunts);

	printf("%-5d ", proc_info->timeouts);

	other_width = 60; /* Other fields take 60 characters */
	/* TOC takes by default 78 characters */
	contents_width = other_width + maxNameLength;
	terminal_width = get_terminal_width();
	if (terminal_width < contents_width) /* TOC wraps anyway, let it wrap*/
		name_width = proc_info->hunt_name_len;
	else
		name_width = terminal_width - other_width;
	if (name_width > maxNameLength)
		name_width = maxNameLength;
	ptr = malloc(name_width + 1);
	strncpy(ptr, proc_info->hunt_name, name_width + 1);
	ptr[name_width] = '\0';
	printf("%-*s", name_width, ptr);

	free(ptr);

	printf("\n");

	if (pd == NULL)
		return;

	if (pd->attach_from != NULL) {
		print_attach(pd->no_attach_from, pd->attach_from,
			     LINX_ATTACH_FROM);
	}
	if (pd->attach_to != NULL) {
		print_attach(pd->no_attach_to, pd->attach_to,
			     LINX_ATTACH_TO);
	}
	if (pd->hunt != NULL) {
		print_hunt(pd->no_hunt, pd->hunt);
	}
	if (pd->tmo != NULL) {
		print_tmo(pd->no_tmo, pd->tmo);
	}
	if (pd->filter != NULL) {
		print_filter(pd->filter);
	}
	if (pd->signals != NULL) {
		print_signals(pd->no_of_signals, pd->signals);
	}
	if(pd->socket_stats != NULL) {
		print_sock_stat(pd->socket_stats);
	}
}

int main(int argc, char *argv[])
{
	LINX *linx;
	struct linx_pid_list *pid_list = NULL;
	struct linx_proc_info *info;
	unsigned int i;
	int atts, hunts, tmos, sigs, local, remote, links, opt;
	int proc_type = 0, do_proc_type = 0;
	int batch = 0, simple = 0;
	int flags = 0;

	/* Check arguments. */
	while ((opt = getopt(argc, argv, "abfHhl:qsSt:Tn:") ) != -1)
	{
		switch (opt) {
		case 'a':
			flags |= LINX_DETAILS_ATTACH_ALL;
			break;
		case 'b':
			batch = 1;
			break;
		case 'f':
			flags |= LINX_DETAILS_FILTER;
			break;
		case 'l':
			maxNameLength = atol(optarg);
			if (maxNameLength < MINIMUM_NAME_LENGTH)
			    maxNameLength = MINIMUM_NAME_LENGTH;
			break;
		case 'h':
			usage();
			break;
		case 'H':
			flags |= LINX_DETAILS_HUNT;
			break;
		case 'q':
			flags |= LINX_DETAILS_QUEUE;
			break;
		case 't':
			proc_type = get_proc_type(optarg);
			do_proc_type = 1;
			break;
		case 's':
			simple = 1;
			break;
		case 'S':
			flags |= LINX_DETAILS_SOCKET_STATS;
			break;
		case 'T':
			flags |= LINX_DETAILS_TMO;
			break;
		case 'n':
			hunt_name = optarg;
			break;
		default:
			usage();
			exit(EXIT_FAILURE);
			break;
		}
	}

	linx = linx_open("linxstat", 0, NULL);
	if (linx == NULL) {
		printf("Could not open linx: %d\n", errno);
		exit(EXIT_FAILURE);
	}

	if (linx_get_pid_list(linx, &pid_list) == -1) {
		fprintf(stderr, "Could not get process list\n");
		linx_close(linx);
		exit(EXIT_FAILURE);
	}
	if (batch) {
		printf("%lu\n", pid_list->count);
		goto do_exit;
	}
	if ((!simple) && (hunt_name == NULL))
        {
		atts = hunts = tmos = sigs = local = remote = links = 0;
		for (i = 0; i < pid_list->count; i++) {
			info = &(pid_list->proc[i]);
			if (info->spid == LINX_ILLEGAL_SPID)
				continue;
			
			/* statistics */
			atts  += info->attach_from;
			hunts += info->hunts;
			tmos  += info->timeouts;
			sigs  += info->msg_queued;
			switch (info->type) {
			case LINX_TYPE_LOCAL:
				local++;
				break;
			case LINX_TYPE_LINK:
				links++;
				break;
			case LINX_TYPE_REMOTE:
				remote++;
				break;
			default:
				break;
			}
		}
		printf(" local:%d remote:%d, link:%d\n", local, remote, links);
		printf(" pending attach:%d\n", atts);
		printf(" pending hunt:%d\n", hunts);
		printf(" pending timeout:%d\n", tmos);
		printf(" queued signals:%d\n", sigs);

	/* new code that allows user to use -l maxNameLength to alter the
	// length of name field to be printed
	// use the * in the printf format to get the width of field size from
	// parameter list
	*/
                printf("\n   PID spid\t  type"
                       "    state  queue attach(f/t) hunt  tmo   %-*s\n", maxNameLength, "name");
	}

	for (i = 0; i < pid_list->count; i++) {
		struct linx_proc_details *pd = NULL;
		info = &(pid_list->proc[i]);
		if (info->spid == LINX_ILLEGAL_SPID)
			continue;
		if (do_proc_type && (info->type != proc_type))
			continue;

		if (flags) {
			linx_get_proc_details(linx, info->spid, flags, &pd);
		}
		if ((hunt_name != NULL) && (strcmp(hunt_name, info->hunt_name) != 0))
		{
			/* not the one we are looking for */
			continue;
		}
		print_proc_info(info, pd);

		if (pd != NULL)
			linx_free_proc_details(linx, &pd);
	}

do_exit:
	linx_free_pid_list(linx, &pid_list);
	linx_close(linx);

	exit(EXIT_SUCCESS);
}
