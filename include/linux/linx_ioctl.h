/*
 * Copyright (c) 2006-2008, Enea Software AB
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

/* *INDENT-OFF* */
#ifdef __cplusplus
extern "C" {
#endif
/* *INDENT-ON* */

#ifndef _LINUX_LINX_IOCTL_H
#define _LINUX_LINX_IOCTL_H

#if defined __KERNEL__
#include <linux/linx_types.h>
#endif
	
#include <linux/types.h>

#define LINX_VERSION	    "2.5.1"

/* The hunt ioctl parameter structure. */
struct linx_hunt_param {
	LINX_OSBUFSIZE sigsize;	/* The payload size of the hunt signal in
				 * bytes. */
	union LINX_SIGNAL *sig;	/* The hunt signal pointer (payload). */
	LINX_SPID from;		/* The owner of the hunt. */
	size_t namelen;		/* The strlen of the hunt name. */
	char *name;		/* The hunt name pointer (null
				 * terminated string */
};

/* The attach ioctl parameter structure. */
struct linx_attach_param {
	LINX_SPID spid;		/* The spid to attach to. */
	LINX_OSBUFSIZE sigsize;	/* The payload size of the attach signal in
				 * bytes */
	union LINX_SIGNAL *sig;	/* The attach signal pointer (payload) */

	/* OUTPUT */
	LINX_OSATTREF attref;	/* The attach reference output parameter */
};

/* The detach ioctl parameter structure. */
struct linx_detach_param {
	LINX_OSATTREF attref;	/* The attach reference input parameter. */
};

/* The receive_filter ioctl parameter structure. */
struct linx_receive_filter_param {
	LINX_SPID from;		/* The spid to receive from */
	LINX_OSBUFSIZE sigselect_size;	/* Size of sigselect buffer */
	const LINX_SIGSELECT *sigselect;	/* Array of sigselect numbers */
};

/* The send with sender cmessage structure. */
struct linx_sender_param {
	/* OUTPUT */
	LINX_SPID from;		/* The spid to send from */
};

/* Timeout parameter structure */
struct linx_tmo_param {
	LINX_OSTIME tmo;	/* Remaining time left */
	LINX_OSBUFSIZE sigsize;	/* The payload length of the signal */
	union LINX_SIGNAL *sig;	/* The timeout signal pointer (payload) */
	LINX_OSTMOREF tmoref;	/* Timeout reference */
};

/* New link paramter structure */
struct linx_new_link_param {
	uint32_t token;         /* Token to be used in the next request call */
	uint32_t new_link_ref;  /* Reference used when removing the request */
};
	
/* Information about a signal*/
struct linx_info_signal {
	LINX_SIGSELECT signo;	/* Signal number */
	int size;		/* The size of signal */
	LINX_SPID from;		/* The sending spid of the signal */
};

/* Information about a signal*/
struct linx_info_signal_2 {
	LINX_SIGSELECT signo;	/* Signal number */
	int size;		/* The size of signal */
	LINX_SPID from;		/* The sending spid of the signal */
	uint32_t flags;         /* Flags of signal */
};

/* Information about an attach */
struct linx_info_attach {
	LINX_SPID spid;		/* To or from attach SPID */
	LINX_OSATTREF attref;	/* Attach reference */
	struct linx_info_signal attach_signal;	/* Attach signal information */
};

/* Information about a hunt */
struct linx_info_hunt {
	struct linx_info_signal hunt_signal;	/* Provided hunt signal */
	LINX_SPID owner;	/* Spid of the hunter */
	char *hunt_name;	/* Huntpath */
};

/* Information about a timeout */
struct linx_info_tmo {
	LINX_OSTIME tmo;	/* Remaining time */
	LINX_OSTMOREF tmoref;	/* Timeout reference */
	struct linx_info_signal tmo_signal;	/* Timeout signal information */
};

#define LINX_INFO_SUMMARY  0
/* Information about LINX sockets */
struct linx_info_summary {
	/* OUTPUT */
	int no_of_local_sockets;	/* Locally opened LINX sockets */
	int no_of_remote_sockets;	/* Phantom LINX sockets */
	int no_of_link_sockets;	/* LINX sockets representing a link */
	int no_of_pend_attach;	/* Pending attaches */
	int no_of_pend_hunt;	/* Pending hunts */
	int no_of_pend_tmo;	/* Pending timeouts */
	int no_of_queued_signals;	/* Queued signals */
};

#define LINX_INFO_SOCKETS  1

/* Request number of LINX sockets on the node */
struct linx_info_sockets {
	LINX_OSBOOLEAN local;	/* Boolean, set if local sockets shall
				 * be included in the output. */
	LINX_OSBOOLEAN remote;	/* Boolean, set if remote sockets
				 * shall be included in the output. */
	LINX_OSBOOLEAN link;	/* Boolean, set if link sockets shall
				 * be included in the output. */
	int buffer_size;	/* size of provided buffer */

	/* OUTPUT */
	int no_of_sockets;	/* Number of sockets in buffer */
	LINX_SPID *buffer;	/* Information of LINX sockets */
};

#define LINX_INFO_NAME	   2

/* Request name of LINX socket */
struct linx_info_name {
	LINX_SPID spid;		/* Spid of the LINX socket to request name on */
	int namelen;		/* Length of the provided buffer */
	/* OUTPUT */
	char *name;		/* Huntname of the spid */
};

#define LINX_INFO_TYPE	   3

/* Spid types. */
#define LINX_TYPE_UNKNOWN  0
#define LINX_TYPE_LOCAL	   1
#define LINX_TYPE_REMOTE   2
#define LINX_TYPE_LINK	   3
#define LINX_TYPE_ILLEGAL  4
#define LINX_TYPE_ZOMBIE   5

/* Request type of LINX socket */
struct linx_info_type {
	LINX_SPID spid;		/* Spid to request type of */
	/* OUTPUT */
	int type;		/* Type of the LINX socket */
};

#define LINX_INFO_STATE	   4

/* Spid states. */
#define LINX_STATE_UNKNOWN 0
#define LINX_STATE_RUNNING 1
#define LINX_STATE_RECV	   2
#define LINX_STATE_POLL	   3

/* Request state of LINX socket */
struct linx_info_state {
	LINX_SPID spid;		/* Spid to request type of */
	/* OUTPUT */
	int state;		/* State of the LINX socket */
};

#define LINX_INFO_FILTERS  5

/* Request check receive filter on a LINX socket */
struct linx_info_filters {
	LINX_SPID spid;		/* Target spid of request */
	LINX_SPID from_filter;	/* From spid */
	int buffer_size;	/* Size of provided buffer */
	/* OUTPUT */
	int no_of_sigselect;	/* No of sigselects returned */
	LINX_SIGSELECT *buffer;	/* Buffer of sigselects */
};

#define LINX_INFO_RECV_QUEUE 6

/* Request receive queue of a LINX socket */
struct linx_info_recv_queue {
	LINX_SPID spid;		/* Spid of LINX socket */
	int buffer_size;	/* Size of buffer provided */
	/* OUTPUT */
	int no_of_signals;	/* Total no of signals returned */
	struct linx_info_signal *buffer;	/* Info of the owned signals */
};

#define LINX_INFO_PEND_ATTACH 7

#define LINX_ATTACH_FROM      0
#define LINX_ATTACH_TO	      1

/* Request the ataches to or from a LINX socket */
struct linx_info_pend_attach {
	LINX_SPID spid;		/* Spid of attacher/attachee */
	int from_or_to;		/* If LINX_ATTACH_FROM, the call will
				 * return information about attaches
				 * from spid. If LINX_ATTACH_TO, the
				 * call will return information about
				 * attaches to spid */
	int buffer_size;	/* The size of provided buffer */
	/* OUTPUT */
	int no_of_attaches;	/* No of attaches in buffer */
	struct linx_info_attach *buffer;	/* Info of attaches */
};

#define LINX_INFO_PEND_HUNT 8

/* Request the pending hunts from a LINX socket */
struct linx_info_pend_hunt {
	LINX_SPID spid;		/* Spid of the hunter */
	int buffer_size;	/* Size of provided buffer */
	/* OUTPUT */
	int strings_offset;	/* Offset into the buffer where hunt name
				 * strings are stored. */
	int no_of_hunts;	/* No of hunts in buffer */
	struct linx_info_hunt *buffer;	/* Info of hunts */
};

#define LINX_INFO_SIGNAL_PAYLOAD 9

/* Request the payload of a signal */
struct linx_info_signal_payload {
	LINX_SPID spid;		/* Spid of signal owner. */
	int buffer_size;	/* Size of provided buffer */
	/* OUTPUT */
	struct linx_info_signal signal;	/* A signal structure returned by a
					 * previous LINX_INFO call. */
	int payload_size;	/* Size of payload returned */
	char *buffer;		/* The payload. */
};

#define LINX_INFO_OWNER	10

/* Request the owning pid of a LINX socket */
struct linx_info_owner {
	LINX_SPID spid;		/* Spid of the LINX socket */
	/* OUTPUT */
	pid_t owner;		/* Owner of the LINX socket */
};

#define LINX_INFO_STAT 11

/* Request statistics of a LINX socket */
struct linx_info_stat {
	LINX_SPID spid;		/* Spid of the LINX socket */

	/* OUTPUT */

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

#define LINX_INFO_PEND_TMO 12

/* Request the timeouts for a LINX socket */
struct linx_info_pend_tmo {
	LINX_SPID spid;		/* Owner of the timeouts */
	int buffer_size;	/* Size of provided buffer */
	/* OUTPUT */
	int no_of_timeouts;	/* No of timeouts in buffer */
	struct linx_info_tmo *buffer;	/* Info of timeouts */
};

#define LINX_INFO_RECV_QUEUE_2 13

/* Request receive queue of a LINX socket */
struct linx_info_recv_queue_2 {
	LINX_SPID spid;		/* Spid of LINX socket */
	int buffer_size;	/* Size of buffer provided */
	/* OUTPUT */
	int no_of_signals;	/* Total no of signals returned */
	char *buffer;           /* Info of the owned signals */
};

/* The linx_info struct is passed with the LINX_IOCTL_INFO ioctl() call */
struct linx_info {
	int type;		/* Type of info requested */
	void *type_spec;	/* Type specific parameter */
};

/* This struct is passed with LINX_IOCTL_HUNTNAME ioctl() call */
struct linx_huntname {
	LINX_SPID spid;		/* Spid of the LINX socket */
	size_t namelen;		/* The length of the name. */
	char *name;		/* Pointer to the name of the linx. */
};

/* This struct is used with LINX_IOCTL_RECEIVE and  LINX_IOCTL_SEND */
struct linx_sndrcv_param {
	__u32 from;           /* From spid */
	__u32 to;             /* To spid */
	__u32 size;           /* Size of the signal */
	__u32 sig_attr;       /* Signal attributes */
	__u32 sigselect_size; /* Size of sigselect buffer */
	__u32 tmo;            /* Timeout value */
	__u64 sigselect;      /* Pointer to array of sigselect numbers */
	__u64 buffer;         /* Pointer to the payload */
	__u64 real_buf;       /* Pointer to real payload, used in threads */
};

/* This is for legacy since real_buf was added */
struct linx_sndrcv_legacy_param {
	__u32 from;           /* From spid */
	__u32 to;             /* To spid */
	__u32 size;           /* Size of the signal */
	__u32 sig_attr;       /* Signal attributes */
	__u32 sigselect_size; /* Size of sigselect buffer */
	__u32 tmo;            /* Timeout value */
	__u64 sigselect;      /* Pointer to array of sigselect numbers */
	__u64 buffer;         /* Pointer to the payload */
};	
	
/* Ioctl switches. */
#define LINX_IOCTL_MAGIC 0xF4

#define LINX_IOCTL_SET_RECEIVE_FILTER \
_IOW(LINX_IOCTL_MAGIC, 1, struct linx_receive_filter_param)
#define LINX_IOCTL_HUNT \
_IOWR(LINX_IOCTL_MAGIC, 2, struct linx_hunt_param)
#define LINX_IOCTL_ATTACH \
_IOWR(LINX_IOCTL_MAGIC, 3, struct linx_attach_param)
#define LINX_IOCTL_DETACH \
_IOW(LINX_IOCTL_MAGIC, 4, LINX_OSATTREF)
#define LINX_IOCTL_REGISTER_LINK_SUPERVISOR \
_IO(LINX_IOCTL_MAGIC, 5)
#define LINX_IOCTL_UNREGISTER_LINK_SUPERVISOR \
_IO(LINX_IOCTL_MAGIC, 6)
#define LINX_IOCTL_INFO \
_IOWR(LINX_IOCTL_MAGIC, 7, struct linx_info)
#define LINX_IOCTL_HUNTNAME \
_IOWR(LINX_IOCTL_MAGIC, 8, struct linx_huntname)
#define LINX_IOCTL_VERSION \
_IOR(LINX_IOCTL_MAGIC, 14, unsigned int)
#define LINX_IOCTL_REQUEST_TMO \
_IOR(LINX_IOCTL_MAGIC, 15, struct linx_tmo_param)
#define LINX_IOCTL_CANCEL_TMO \
_IOR(LINX_IOCTL_MAGIC, 16, struct linx_tmo_param)
#define LINX_IOCTL_MODIFY_TMO \
_IOR(LINX_IOCTL_MAGIC, 17, struct linx_tmo_param)
#define LINX_IOCTL_REQUEST_NEW_LINK \
_IOR(LINX_IOCTL_MAGIC, 18, struct linx_new_link_param)
#define LINX_IOCTL_CANCEL_NEW_LINK \
_IOR(LINX_IOCTL_MAGIC, 19, struct linx_new_link_param)
#define LINX_IOCTL_LEGACY_SEND \
_IOW(LINX_IOCTL_MAGIC, 20, struct linx_sndrcv_legacy_param)	
#define LINX_IOCTL_LEGACY_RECEIVE \
_IOWR(LINX_IOCTL_MAGIC, 21, struct linx_sndrcv_legacy_param)
#define LINX_IOCTL_SEND \
_IOW(LINX_IOCTL_MAGIC, 22, struct linx_sndrcv_param)	
#define LINX_IOCTL_RECEIVE \
_IOWR(LINX_IOCTL_MAGIC, 23, struct linx_sndrcv_param)


#endif

/* *INDENT-OFF* */	
#ifdef __cplusplus
}				/* extern "C" */
#endif
/* *INDENT-ON* */
