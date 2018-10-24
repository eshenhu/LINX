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

#ifndef _LINX_INFO_h
#define _LINX_INFO_h

/* *INDENT-OFF* */
#ifdef __cplusplus
extern "C" {
#endif
/* *INDENT-ON* */

#include <sys/types.h>
#include <linx.h>
#include <linx_types.h>
#include <linx_socket.h>

struct linx_proc_info {
	LINX_SPID spid;
	char      *hunt_name;
	size_t    hunt_name_len;
	pid_t     pid;
	int       type;
	int       state;
	int       msg_queued;
	int       attach_from;
	int       attach_to;
	int       hunts;
	int       timeouts;
};

#define LINX_DETAILS_ATTACH_FROM  0x01
#define LINX_DETAILS_ATTACH_TO    0x02
#define LINX_DETAILS_ATTACH_ALL   (LINX_DETAILS_ATTACH_FROM | LINX_DETAILS_ATTACH_TO)
#define LINX_DETAILS_HUNT         0x04
#define LINX_DETAILS_TMO          0x08
#define LINX_DETAILS_FILTER       0x10
#define LINX_DETAILS_QUEUE        0x20
#define LINX_DETAILS_SOCKET_STATS 0x40

struct linx_proc_details {
	LINX_SPID spid;
	/* set by LINX_DETAILS_ATTACH_FROM */
	int no_attach_from;
	struct linx_info_attach *attach_from;
	/* set by LINX_DETAILS_ATTACH_TO */
	int no_attach_to;
	struct linx_info_attach *attach_to;
	/* set by LINX_DETAILS_HUNT */
	int no_hunt;
	struct linx_info_hunt *hunt;
	/* set by LINX_DETAILS_TMO */
	int no_tmo;
	struct linx_info_tmo *tmo;
	/* set by LINX_DETAILS_FILTER */
	int state;
	LINX_SPID from_filter;
	LINX_SIGSELECT *filter;
	/* set by LINX_DETAILS_QUEUE */
	int no_of_signals;
	struct linx_info_signal_2 *signals;
	/* set by LINX_DETAILS_SOCKET_STATS */
	struct linx_info_stat *socket_stats;
};

struct linx_pid_list {
	unsigned long count;
	struct linx_proc_info proc[1];
};

int linx_get_pid_list(LINX *linx, struct linx_pid_list **pid_list);
int linx_free_pid_list(LINX *linx, struct linx_pid_list **pid_list);

int linx_get_proc_details(LINX *linx, LINX_SPID spid, int details,
			  struct linx_proc_details **proc_details);
int linx_free_proc_details(LINX *linx,
			   struct linx_proc_details **proc_details);

#endif
/* *INDENT-OFF* */
#ifdef __cplusplus
} 				/* extern "C" */
/* *INDENT-ON* */
#endif
