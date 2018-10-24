/*
 * Copyright (c) 2009, Enea Software AB
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

#include <ctype.h>
#include <errno.h>
#include <linx.h>
#include <linx_ioctl.h>
#include <linx_socket.h>
#include <linx_types.h>

#include "linx_info.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#define HUNT_NAME_MAX_LEN 1024
#define MAX_SIGNALS 10
#define MAX_SPIDS 2048

#define LINX_STAT_FLAG_OOB 0x0001

static int get_owner(int sd, struct linx_proc_info *proc_info)
{
	struct linx_info info;
	struct linx_info_owner o;

	o.spid = proc_info->spid;
	info.type = LINX_INFO_OWNER;
	info.type_spec = &o;

	if (ioctl(sd, LINX_IOCTL_INFO, &info) == -1) {
		return -1;
	}

	proc_info->pid = o.owner;
	return 0;
}

static int get_name(int sd, struct linx_proc_info *proc_info)
{
	struct linx_info info;
	struct linx_info_name info_name;
	int len;
	char buf[HUNT_NAME_MAX_LEN];

	info_name.spid = proc_info->spid;
	info_name.namelen = HUNT_NAME_MAX_LEN;
	info_name.name = buf;

	info.type = LINX_INFO_NAME;
	info.type_spec = &info_name;
	if (ioctl(sd, LINX_IOCTL_INFO, &info) == -1) {
		return -1;
	}

	if (info_name.namelen == 0) {
		proc_info->hunt_name_len = 0;
		proc_info->hunt_name = NULL;
		return 0;
	}

	len = proc_info->hunt_name_len = strlen(info_name.name);

	proc_info->hunt_name = malloc(len + 1);
	if (proc_info->hunt_name == NULL) {
		return -1;
	}
	strncpy(proc_info->hunt_name, info_name.name, len + 1);
	/* make really sure it's really null-terminated */
	proc_info->hunt_name[len] = '\0';

	return 0;
}

static int get_queues(int sd, struct linx_proc_info *proc_info)
{
	struct linx_info info;
	struct linx_info_recv_queue_2 recv_queue;

	recv_queue.spid = proc_info->spid;
	recv_queue.buffer_size = 0;
	recv_queue.buffer = NULL;

	info.type = LINX_INFO_RECV_QUEUE_2;
	info.type_spec = &recv_queue;

	if (ioctl(sd, LINX_IOCTL_INFO, &info) == -1) {
		proc_info->msg_queued = 0;
		return -1;
	}

	proc_info->msg_queued = recv_queue.no_of_signals;

	return 0;
}

static int get_attach(int sd, struct linx_proc_info *proc_info)
{
	struct linx_info info;
	struct linx_info_pend_attach pend_attach;

	pend_attach.spid = proc_info->spid;
	pend_attach.from_or_to = LINX_ATTACH_FROM;
	pend_attach.buffer_size = 0;
	pend_attach.buffer = NULL;

	info.type = LINX_INFO_PEND_ATTACH;
	info.type_spec = &pend_attach;

	if (ioctl(sd, LINX_IOCTL_INFO, &info) == -1) {
		proc_info->attach_from = 0;
		return -1;
	}

	proc_info->attach_from = pend_attach.no_of_attaches;

	pend_attach.from_or_to = LINX_ATTACH_TO;
	if (ioctl(sd, LINX_IOCTL_INFO, &info) == -1) {
		proc_info->attach_to = 0;
		return -1;
	}

	proc_info->attach_to = pend_attach.no_of_attaches;

	return 0;
}

static int get_hunt(int sd, struct linx_proc_info *proc_info)
{
	struct linx_info info;
	struct linx_info_pend_hunt pend_hunt;

	pend_hunt.spid = proc_info->spid;
	pend_hunt.buffer_size = 0;
	pend_hunt.buffer = NULL;

	info.type = LINX_INFO_PEND_HUNT;
	info.type_spec = &pend_hunt;

	if (ioctl(sd, LINX_IOCTL_INFO, &info) == -1) {
		return -1;
	}

	proc_info->hunts = pend_hunt.no_of_hunts;

	return 0;
}

static int get_timeouts(int sd, struct linx_proc_info *proc_info)
{
	struct linx_info info;
	struct linx_info_pend_tmo pend_tmo;

	pend_tmo.spid = proc_info->spid;
	pend_tmo.buffer_size = 0;
	pend_tmo.buffer = NULL;

	info.type = LINX_INFO_PEND_TMO;
	info.type_spec = &pend_tmo;

	if (ioctl(sd, LINX_IOCTL_INFO, &info) == -1) {
		return -1;
	}

	proc_info->timeouts = pend_tmo.no_of_timeouts;

	return 0;
}

static int get_type_and_state(int sd, struct linx_proc_info *proc_info)
{
	struct linx_info info;
	struct linx_info_type type;
	struct linx_info_state state;

	type.spid = proc_info->spid;

	info.type = LINX_INFO_TYPE;
	info.type_spec = &type;

	if (ioctl(sd, LINX_IOCTL_INFO, &info) == -1) {
		return -1;
	}

	proc_info->type = type.type;

	info.type = LINX_INFO_STATE;
	info.type_spec = &state;
	state.spid = proc_info->spid;

	if (ioctl(sd, LINX_IOCTL_INFO, &info) == -1) {
		return -1;
	}

	proc_info->state = state.state;

	return 0;
}

/*
 * returns -1 on error
 */
int linx_get_pid_list(LINX *linx, struct linx_pid_list **pid_list)
{
	struct linx_info info;
	struct linx_info_sockets sockets;
	struct linx_proc_info *proc_info;
	LINX_SPID spid_list[MAX_SPIDS];
	int sd, i;
	int no_of_spids = 0;
	int size;

	sd = linx_get_descriptor(linx);
	/* check sd type? */

	sockets.local  = LINX_TRUE;
	sockets.remote = LINX_TRUE;
	sockets.link   = LINX_TRUE;
	sockets.buffer =  spid_list;
	sockets.buffer_size = sizeof(spid_list);
	info.type = LINX_INFO_SOCKETS;
	info.type_spec = &sockets;

	if (ioctl(sd, LINX_IOCTL_INFO, &info) == -1) {
		*pid_list = NULL;
		return -1;
	}

	no_of_spids = sockets.no_of_sockets;
	if (sockets.buffer_size < no_of_spids * (int)sizeof(LINX_SPID)) {
		printf("Failed to retrieve information on all sockets\n");
		no_of_spids = sockets.buffer_size / sizeof(LINX_SPID);
	}

	size = sizeof(struct linx_pid_list) +
		(no_of_spids - 1) * sizeof(struct linx_proc_info);

	*pid_list = malloc(size);
	
	if (*pid_list == NULL) {
		/* FIXME: set errno */
		return -1;
	}
	
	memset (*pid_list, 0x0, size);
	
	proc_info = (*pid_list)->proc;
	(*pid_list)->count = no_of_spids;

	for (i = 0; i < no_of_spids; i++) {
		proc_info[i].spid = spid_list[i];
		(void)linx_attach(linx, NULL, spid_list[i]);

		if (get_owner(sd, &proc_info[i]) == -1) {
			proc_info[i].spid = LINX_ILLEGAL_SPID;
			continue;
		}

		if (get_queues(sd, &proc_info[i]) == -1) {
			proc_info[i].spid = LINX_ILLEGAL_SPID;
			continue;
		}

		if (get_name(sd, &proc_info[i]) == -1) {
			proc_info[i].spid = LINX_ILLEGAL_SPID;
			continue;
		}

		if (get_attach(sd, &proc_info[i]) == -1) {
			proc_info[i].spid = LINX_ILLEGAL_SPID;
			continue;
		}

		if (get_hunt(sd, &proc_info[i]) == -1) {
			proc_info[i].spid = LINX_ILLEGAL_SPID;
			continue;
		}

		if (get_timeouts(sd, &proc_info[i]) == -1) {
			proc_info[i].spid = LINX_ILLEGAL_SPID;
			continue;
		}

		if (get_type_and_state(sd, &proc_info[i]) == -1) {
			proc_info[i].spid = LINX_ILLEGAL_SPID;
			continue;
		}

	}

	return 0;
}

int linx_free_pid_list(LINX *linx, struct linx_pid_list **pid_list)
{
	(void)linx;
	struct linx_proc_info *proc_info;
	uint32_t i;

	if (pid_list == NULL || *pid_list == NULL) {
		return -1;
	}

	i = (*pid_list)->count;
	/* iterate over all proc_info structures to free the process name */
	for (proc_info = (*pid_list)->proc; i--; proc_info++) {
		if (proc_info->hunt_name != NULL)
			free(proc_info->hunt_name);
	}

	free(*pid_list);
	*pid_list = NULL;
	return 0;
}

static int get_attach_details(int sd, struct linx_proc_details *pd, int flags)
{
	struct linx_info info;
	struct linx_info_pend_attach pend_attach;
	size_t size;

	info.type = LINX_INFO_PEND_ATTACH;
	info.type_spec = &pend_attach;

	pend_attach.spid = pd->spid;

	if (!(flags & LINX_DETAILS_ATTACH_FROM))
		goto attach_to;

	pend_attach.from_or_to = LINX_ATTACH_FROM;
	pend_attach.buffer_size = 0;
	pend_attach.buffer = NULL;

	if (ioctl(sd, LINX_IOCTL_INFO, &info) == -1) {
		pd->no_attach_from = 0;
		return -1;
	}

	pd->no_attach_from = pend_attach.no_of_attaches;

	size = sizeof(struct linx_info_attach) * pend_attach.no_of_attaches;

	pend_attach.buffer = malloc(size);

	if (pend_attach.buffer == NULL)
		return -1;

	pend_attach.buffer_size = size;

	if (ioctl(sd, LINX_IOCTL_INFO, &info) == -1) {
		pd->no_attach_from = 0;
		free(pend_attach.buffer);
		return -1;
	}

	pd->attach_from = pend_attach.buffer;

	if (!(flags & LINX_DETAILS_ATTACH_TO))
		return 0;

attach_to:
	pend_attach.buffer_size = 0;
	pend_attach.buffer = NULL;
	pend_attach.from_or_to = LINX_ATTACH_TO;

	if (ioctl(sd, LINX_IOCTL_INFO, &info) == -1) {
		pd->no_attach_to = 0;
		return -1;
	}

	pd->no_attach_to = pend_attach.no_of_attaches;

	size = sizeof(struct linx_info_attach) * pend_attach.no_of_attaches;
	pend_attach.buffer = malloc(size);

	if (pend_attach.buffer == NULL)
		return -1;

	pend_attach.buffer_size = size;

	if (ioctl(sd, LINX_IOCTL_INFO, &info) == -1) {
		pd->no_attach_to = 0;
		free(pend_attach.buffer);
		return -1;
	}

	pd->attach_to = pend_attach.buffer;

	return 0;
}

static int get_hunt_details(int sd, struct linx_proc_details *details)
{
	struct linx_info info;
	struct linx_info_pend_hunt pend_hunt;
	size_t size;

	pend_hunt.spid = details->spid;
	pend_hunt.buffer_size = 0;
	pend_hunt.buffer = NULL;

	info.type = LINX_INFO_PEND_HUNT;
	info.type_spec = &pend_hunt;

	details->hunt = NULL;
	details->no_hunt = 0;
	if (ioctl(sd, LINX_IOCTL_INFO, &info) == -1) {
		return -1;
	}
	if (pend_hunt.no_of_hunts == 0) {
		return 0;
	}

	details->no_hunt = pend_hunt.no_of_hunts;

	pend_hunt.strings_offset =
		sizeof(struct linx_info_hunt) * pend_hunt.no_of_hunts;
#define CHARS_PER_HUNT 16
	size = pend_hunt.strings_offset +
		CHARS_PER_HUNT * pend_hunt.no_of_hunts;
#undef CHARS_PER_HUNT

	pend_hunt.buffer = malloc(size);
	if (pend_hunt.buffer == NULL) {
		return -1;
	}
	pend_hunt.buffer_size = size;

	if (ioctl(sd, LINX_IOCTL_INFO, &info) == -1) {
		free(pend_hunt.buffer);
		return -1;
	}

	details->hunt = pend_hunt.buffer;

	return 0;
}

static int get_tmo_details(int sd, struct linx_proc_details *details)
{
	struct linx_info info;
	struct linx_info_pend_tmo pend_tmo;
	size_t size;

	pend_tmo.spid = details->spid;
	pend_tmo.buffer_size = 0;
	pend_tmo.buffer = NULL;

	info.type = LINX_INFO_PEND_TMO;
	info.type_spec = &pend_tmo;

	details->tmo = NULL;
	details->no_tmo = 0;
	if (ioctl(sd, LINX_IOCTL_INFO, &info) == -1) {
		return -1;
	}
	if (pend_tmo.no_of_timeouts == 0) {
		return 0;
	}

	size = sizeof(struct linx_info_tmo) * pend_tmo.no_of_timeouts;
	pend_tmo.buffer = malloc(size);
	if (pend_tmo.buffer == NULL) {
		return -1;
	}
	pend_tmo.buffer_size = size;

	if (ioctl(sd, LINX_IOCTL_INFO, &info) == -1) {
		free(pend_tmo.buffer);
		return -1;
	}

	details->tmo = pend_tmo.buffer;
	details->no_tmo = pend_tmo.no_of_timeouts;

	return 0;
}

static int get_filter_details(int sd, struct linx_proc_details *details)
{
	struct linx_info info;
	struct linx_info_filters filters;
	struct linx_info_state state;
	LINX_SIGSELECT count;
	size_t size;

	details->from_filter = LINX_ILLEGAL_SPID;

	state.spid = details->spid;

	info.type = LINX_INFO_STATE;
	info.type_spec = &state;

	if (ioctl(sd, LINX_IOCTL_INFO, &info) == -1) {
		return -1;
	}

	details->state = state.state;
	if (state.state != LINX_STATE_RECV && state.state != LINX_STATE_POLL) {
		return 0;
	}

	filters.spid = details->spid;
	filters.from_filter = LINX_ILLEGAL_SPID;
	filters.buffer = &count;
	filters.buffer_size = sizeof(count);
	info.type = LINX_INFO_FILTERS;
	info.type_spec = &filters;

	if (ioctl(sd, LINX_IOCTL_INFO, &info) == -1) {
		return -1;
	}

	count = (LINX_SIGSELECT)abs((int32_t)count) + 1;

	size = sizeof(LINX_SIGSELECT) * count;
	filters.buffer = malloc(size);
	if (filters.buffer == NULL) {
		return -1;
	}
	filters.buffer_size = size;
	filters.from_filter = LINX_ILLEGAL_SPID;

	if (ioctl(sd, LINX_IOCTL_INFO, &info) == -1) {
		free(filters.buffer);
		return -1;
	}

	details->from_filter = filters.from_filter;
	details->filter = filters.buffer;

	return 0;
}

static int get_queue_details(int sd, struct linx_proc_details *details)
{
	struct linx_info info;
	struct linx_info_recv_queue_2 recv_queue;

	details->signals = NULL;
	details->no_of_signals = 0;

	recv_queue.spid = details->spid;
	recv_queue.buffer_size = 0;
	recv_queue.buffer = NULL;

	info.type = LINX_INFO_RECV_QUEUE_2;
	info.type_spec = &recv_queue;

	if (ioctl(sd, LINX_IOCTL_INFO, &info) == -1) {
		return -1;
	}

	recv_queue.buffer_size = sizeof(struct linx_info_signal_2) *
		recv_queue.no_of_signals;
	recv_queue.buffer = malloc(recv_queue.buffer_size);
	if (recv_queue.buffer == NULL) {
		return -1 ;
	}

	if (ioctl(sd, LINX_IOCTL_INFO, &info) == -1) {
		free(recv_queue.buffer);
		return -1;
	}

	details->no_of_signals = recv_queue.no_of_signals;
	details->signals = (struct linx_info_signal_2 *)recv_queue.buffer;

	return 0;
}

static int get_socket_stats(int sd, struct linx_proc_details *details)
{
	int rv;
	struct linx_info info;
	struct linx_info_stat *info_stat;

	info_stat = malloc(sizeof(struct linx_info_stat));
	if (info_stat == NULL)
		return -1;

	info_stat->spid = details->spid;

	info.type = LINX_INFO_STAT;
	info.type_spec = info_stat;

	rv = ioctl(sd, LINX_IOCTL_INFO, &info);
	if (rv < 0) {
		if (errno == ENOSYS) {
			printf("\tSocket statistics not supported "
			       "by the LINX kernel module.\n");
		}
		return -1;
	}

	details->socket_stats = info_stat;
	return 0;
}

/* returns 0 on success, a negative value on error */
int linx_get_proc_details(LINX *linx, LINX_SPID spid, int flags,
			  struct linx_proc_details **proc_details)
{
	int sd;
	int rv = 0;

	sd = linx_get_descriptor(linx);

	*proc_details = malloc(sizeof(struct linx_proc_details));
	if (*proc_details == NULL)
		return -1;

	memset(*proc_details, 0, sizeof(struct linx_proc_details));

	(*proc_details)->spid = spid;

	if (flags & (LINX_DETAILS_ATTACH_FROM | LINX_DETAILS_ATTACH_TO)) {
		rv += get_attach_details(sd, *proc_details, flags);
	}

	if (flags & LINX_DETAILS_HUNT) {
		rv += get_hunt_details(sd, *proc_details);
	}

	if (flags & LINX_DETAILS_TMO) {
		rv += get_tmo_details(sd, *proc_details);
	}

	if (flags & LINX_DETAILS_FILTER) {
		rv += get_filter_details(sd, *proc_details);
	}

	if (flags & LINX_DETAILS_QUEUE) {
		rv += get_queue_details(sd, *proc_details);
	}

	if (flags & LINX_DETAILS_SOCKET_STATS) {
		rv += get_socket_stats(sd, *proc_details);
	}

	return rv;
}

#define _free_this(var, field) do {		\
		if ((var)->field != NULL)	\
			free((var)->field);	\
	} while (0)

int linx_free_proc_details(LINX *linx, struct linx_proc_details **details)
{
	(void)linx;
	
	_free_this(*details, attach_from);
	_free_this(*details, attach_to);
	_free_this(*details, hunt);
	_free_this(*details, tmo);
	_free_this(*details, filter);

	free(*details);
	*details = NULL;
	return 0;
}
