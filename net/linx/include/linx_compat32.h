/*
 * Copyright (c) 2006-2007, Enea Software AB
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

#ifndef __LINX_COMPAT32_H__
#define __LINX_COMPAT32_H__

#ifdef CONFIG_64BIT
#ifdef CONFIG_COMPAT

#include <linux/linx_ioctl.h>
#include <linux/compat.h>

/* Returns offset of member in 32 bit version of struct s. */
#define linx_compat_offsetof(s,memb) offsetof(struct s##_32, memb)

/* Returns size of the 32 bit version of struct s. */
#define linx_compat_size(s) sizeof(struct s##_32)

/* The hunt ioctl parameter structure. */
struct linx_hunt_param_32 {
	/* INPUT */
	compat_ssize_t sigsize;	/* The payload size of the hunt signal
				 * in bytes. */
	compat_uptr_t sig;	/* The hunt signal pointer (payload). */
	LINX_SPID from;		/* The owner of the hunt. */
	compat_size_t namelen;	/* The strlen of the hunt name. */
	compat_uptr_t name;	/* The hunt name pointer (null
				 * terminated string). */
};

/* The attach ioctl parameter structure. */
struct linx_attach_param_32 {
	/* INPUT */
	LINX_SPID spid;		/* The spid to attach to. */
	compat_ssize_t sigsize;	/* The payload size of the attach signal
				 * in bytes. */
	compat_uptr_t sig;	/* The attach signal pointer (payload). */

	/* OUTPUT */
	LINX_OSATTREF attref;	/* The attach reference output
				 * parameter. */
};

/* The receive_filter ioctl parameter structure. */
struct linx_receive_filter_param_32 {
	LINX_SPID from;
	compat_ssize_t sigselect_size;
	compat_uptr_t sigselect;
};

/* Timeout parameter structure */
struct linx_tmo_param_32 {
	LINX_OSTIME tmo;
	compat_ssize_t sigsize;
	compat_uptr_t sig;
	LINX_OSTMOREF tmoref;
};

struct linx_info_hunt_32 {
	struct linx_info_signal hunt_signal;
	LINX_SPID owner;
	compat_uptr_t hunt_name;
};

struct linx_info_sockets_32 {
	LINX_OSBOOLEAN local;	/* Boolean, set if local sockets shall
				 * be included in the output. */
	LINX_OSBOOLEAN remote;	/* Boolean, set if remote sockets
				 * shall be included in the output. */
	LINX_OSBOOLEAN link;	/* Boolean, set if link sockets shall
				 * be included in the output. */
	int buffer_size;	/* bytes */
	int no_of_sockets;	/* Output */
	compat_uptr_t buffer;
};

struct linx_info_name_32 {
	LINX_SPID spid;
	int namelen;
	compat_uptr_t name;
};

struct linx_info_filters_32 {
	LINX_SPID spid;
	LINX_SPID from_filter;
	int buffer_size;	/* bytes */
	int no_of_sigselect;	/* output */
	compat_uptr_t buffer;
};

struct linx_info_recv_queue_32 {
	LINX_SPID spid;
	int buffer_size;	/* bytes */
	int no_of_signals;	/* output */
	compat_uptr_t buffer;
};

struct linx_info_pend_attach_32 {
	LINX_SPID spid;
	int from_or_to;		/* If LINX_ATTACH_FROM, the
				 * call will return
				 * information about
				 * attaches from spid. If
				 * LINX_ATTACH_TO, the call
				 * will return information
				 * about attaches to
				 * spid. */
	int buffer_size;	/* bytes */
	int no_of_attaches;	/* Output. */
	compat_uptr_t buffer;
};

struct linx_info_pend_hunt_32 {
	LINX_SPID spid;
	int buffer_size;	/* bytes */
	int strings_offset;	/* offset into the
				 * buffer where hunt
				 * name strings are
				 * stored. */
	int no_of_hunts;	/* output. */
	compat_uptr_t buffer;	/* The buffer will
				 * contain variable size
				 * linx_info_hunt
				 * structures. */
};

struct linx_info_signal_payload_32 {
	LINX_SPID spid;		/* The signal owner. */
	int buffer_size;	/* bytes */
	struct linx_info_signal signal;	/* A signal structure
					 * returned by a previous
					 * LINX_INFO call. */
	int payload_size;	/* Size of payload returned
				 * in bytes. */
	compat_uptr_t buffer;	/* The buffer will
				 * contain the payload. */
};

struct linx_info_pend_tmo_32 {
	LINX_SPID spid;		/* Owner of the timeouts */
	int buffer_size;	/* Size of provided buffer */
	int no_of_timeouts;	/* No of timeouts in buffer */
	compat_uptr_t buffer;	/* Info of timeouts */
};

struct linx_info_32 {
	int type;
	compat_uptr_t type_spec;
};

struct linx_huntname_32 {
	LINX_SPID spid;
	compat_size_t namelen;	/* The length of the name. */
	compat_uptr_t name;	/* Pointer to the name of the linx. */

};


/* Ioctl switches. */
#define LINX_IOCTL_MAGIC 0xF4

#define LINX_IOCTL_SET_RECEIVE_FILTER_32 \
_IOW(LINX_IOCTL_MAGIC, 1, struct linx_receive_filter_param_32)
#define LINX_IOCTL_HUNT_32 \
_IOWR(LINX_IOCTL_MAGIC, 2, struct linx_hunt_param_32)
#define LINX_IOCTL_ATTACH_32 \
_IOWR(LINX_IOCTL_MAGIC, 3, struct linx_attach_param_32)
#define LINX_IOCTL_INFO_32 \
_IOWR(LINX_IOCTL_MAGIC, 7, struct linx_info_32)
#define LINX_IOCTL_HUNTNAME_32 \
_IOWR(LINX_IOCTL_MAGIC, 8, struct linx_huntname_32)

#define LINX_IOCTL_REQUEST_TMO_32 \
_IOR(LINX_IOCTL_MAGIC, 15, struct linx_tmo_param_32)
#define LINX_IOCTL_CANCEL_TMO_32 \
_IOR(LINX_IOCTL_MAGIC, 16, struct linx_tmo_param_32)
#define LINX_IOCTL_MODIFY_TMO_32 \
_IOR(LINX_IOCTL_MAGIC, 17, struct linx_tmo_param_32)

static inline void linx_compat_linx_hunt_param(void *hp_raw)
{
	struct linx_hunt_param_32 *hp32 = hp_raw;
	struct linx_hunt_param hp;
	hp.sigsize = hp32->sigsize;
	hp.sig = compat_ptr(hp32->sig);
	hp.from = hp32->from;
	hp.namelen = hp32->namelen;
	hp.name = compat_ptr(hp32->name);
	memcpy(hp_raw, &hp, sizeof(struct linx_hunt_param));
}

static inline void linx_compat_linx_attach_param(void *ap_raw)
{
	struct linx_attach_param_32 *ap32 = ap_raw;
	struct linx_attach_param ap;
	ap.spid = ap32->spid;
	ap.sigsize = ap32->sigsize;
	ap.sig = compat_ptr(ap32->sig);
	ap.attref = ap32->attref;
	memcpy(ap_raw, &ap, sizeof(struct linx_attach_param));
}

static inline void linx_compat_linx_receive_filter_param(void *rfp_raw)
{
	struct linx_receive_filter_param_32 *rfp32 = rfp_raw;
	struct linx_receive_filter_param rfp;
	rfp.from = rfp32->from;
	rfp.sigselect = compat_ptr(rfp32->sigselect);
	rfp.sigselect_size = rfp32->sigselect_size;
	memcpy(rfp_raw, &rfp, sizeof(struct linx_receive_filter_param));
}

static inline void linx_compat_linx_tmo_param(void *ap_raw)
{
	struct linx_tmo_param_32 *ap32 = ap_raw;
	struct linx_tmo_param ap;
	ap.tmo = ap32->tmo;
	ap.sigsize = ap32->sigsize;
	ap.sig = compat_ptr(ap32->sig);
	ap.tmoref = ap32->tmoref;
	memcpy(ap_raw, &ap, sizeof(struct linx_tmo_param));
}

static inline void linx_compat_linx_info_hunt(void *ih_raw)
{
	struct linx_info_hunt_32 *ih32 = ih_raw;
	struct linx_info_hunt ih;
	ih.hunt_signal = ih32->hunt_signal;
	ih.owner = ih32->owner;
	ih.hunt_name = compat_ptr(ih32->hunt_name);
	memcpy(ih_raw, &ih, sizeof(struct linx_info_hunt));
}

static inline void linx_compat_linx_info_sockets(void *is_raw)
{
	struct linx_info_sockets_32 *is32 = is_raw;
	struct linx_info_sockets is;
	is.local = is32->local;
	is.remote = is32->remote;
	is.link = is32->link;
	is.no_of_sockets = is32->no_of_sockets;
	is.buffer_size = is32->buffer_size;
	is.buffer = compat_ptr(is32->buffer);
	memcpy(is_raw, &is, sizeof(struct linx_info_sockets));
}

static inline void linx_compat_linx_info_name(void *in_raw)
{
	struct linx_info_name_32 *in32 = in_raw;
	struct linx_info_name in;
	in.spid = in32->spid;
	in.namelen = in32->namelen;
	in.name = compat_ptr(in32->name);
	memcpy(in_raw, &in, sizeof(struct linx_info_name));
}

static inline void linx_compat_linx_info_filters(void *ifi_raw)
{
	struct linx_info_filters_32 *ifi32 = ifi_raw;
	struct linx_info_filters ifi;
	ifi.spid = ifi32->spid;
	ifi.from_filter = ifi32->from_filter;
	ifi.buffer_size = ifi32->buffer_size;
	ifi.no_of_sigselect = ifi32->no_of_sigselect;
	ifi.buffer = compat_ptr(ifi32->buffer);
	memcpy(ifi_raw, &ifi, sizeof(struct linx_info_filters));
}

static inline void linx_compat_linx_info_signal_payload(void *isp_raw)
{
	struct linx_info_signal_payload_32 *isp32 = isp_raw;
	struct linx_info_signal_payload isp;
	isp.spid = isp32->spid;
	isp.signal = isp32->signal;
	isp.buffer_size = isp32->buffer_size;
	isp.buffer = compat_ptr(isp32->buffer);
	memcpy(isp_raw, &isp, sizeof(struct linx_info_signal_payload));
}

static inline void linx_compat_linx_info_recv_queue(void *irq_raw)
{
	struct linx_info_recv_queue_32 *irq32 = irq_raw;
	struct linx_info_recv_queue irq;
	irq.spid = irq32->spid;
	irq.no_of_signals = irq32->no_of_signals;
	irq.buffer_size = irq32->buffer_size;
	irq.buffer = compat_ptr(irq32->buffer);
	memcpy(irq_raw, &irq, sizeof(struct linx_info_recv_queue));
}

static inline void linx_compat_linx_info_pend_attach(void *ipa_raw)
{
	struct linx_info_pend_attach_32 *ipa32 = ipa_raw;
	struct linx_info_pend_attach ipa;
	ipa.spid = ipa32->spid;
	ipa.from_or_to = ipa32->from_or_to;
	ipa.no_of_attaches = ipa32->no_of_attaches;
	ipa.buffer_size = ipa32->buffer_size;
	ipa.buffer = compat_ptr(ipa32->buffer);
	memcpy(ipa_raw, &ipa, sizeof(struct linx_info_pend_attach));
}

static inline void linx_compat_linx_info_pend_hunt(void *iph_raw)
{
	struct linx_info_pend_hunt_32 *iph32 = iph_raw;
	struct linx_info_pend_hunt iph;
	iph.spid = iph32->spid;
	iph.no_of_hunts = iph32->no_of_hunts;
	iph.buffer_size = iph32->buffer_size;
	iph.strings_offset = iph32->strings_offset;
	iph.buffer = compat_ptr(iph32->buffer);
	memcpy(iph_raw, &iph, sizeof(struct linx_info_pend_hunt));
}

static inline void linx_compat_linx_info_pend_tmo(void *ipt_raw)
{
	struct linx_info_pend_tmo_32 *ipt32 = ipt_raw;
	struct linx_info_pend_tmo ipt;
	ipt.spid = ipt32->spid;
	ipt.no_of_timeouts = ipt32->no_of_timeouts;
	ipt.buffer_size = ipt32->buffer_size;
	ipt.buffer = compat_ptr(ipt32->buffer);
	memcpy(ipt_raw, &ipt, sizeof(struct linx_info_pend_tmo));
}

static inline void linx_compat_linx_info(void *i_raw)
{
	struct linx_info_32 *i32 = i_raw;
	struct linx_info i;
	i.type = i32->type;
	i.type_spec = compat_ptr(i32->type_spec);
	memcpy(i_raw, &i, sizeof(struct linx_info));
}

static inline void linx_compat_linx_huntname(void *hn_raw)
{
	struct linx_huntname_32 *hn32 = hn_raw;
	struct linx_huntname hn;
	hn.namelen = hn32->namelen;
	hn.spid = hn32->spid;
	hn.name = compat_ptr(hn32->name);
	memcpy(hn_raw, &hn, sizeof(struct linx_huntname));
}

#endif
#endif
#endif
