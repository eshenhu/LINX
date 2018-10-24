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

/*
 * Handle attach and detach.
 */

#ifndef __IPC_ATTACH_DETACH_H__
#define __IPC_ATTACH_DETACH_H__

#include <af_linx.h>
#include <linux/linx_types.h>
#include <linux/linx_ioctl.h>

/* This function is called as part of release,
 * it trigger attachments to the specific sk.
 * attaches made from the socket are canceled and
 * victim made to the socket are resolved.
 */
void linx_trigger_attach(struct sock *sk);

/* The attach function.
 * The attach function run in the context of the caller socket.
 * The victim spid may be an open or closed socket.
 * The signal sig can be zero of no signal is provided or the
 * RLNH makes the call.
 * The signal size sigsize can be 0 if rlnh makes the call or no
 * signal is provided.
 * Attref is an output parameter that shall contain the attach reference.
 * rlnh specify if the caller is RLNH or not.
 *
 * The attach function is called to supervise a socket. When the socket is
 * closed the provided attach signal, the default attach signal or the rlnh
 * callback shall be sent/called to the caller.
 *
 * If the victim socket is already closed, the attach signal / callback
 * shall be sent imediatelly.
 *
 * The attach signal is always sent from (from address) the closed socket,
 * even if the socket is already closed.
 */
int
linx_attach(struct sock *caller_sk,
	    LINX_SPID victim_spid,
	    void *sig,
	    LINX_OSBUFSIZE sigsize,
	    LINX_OSATTREF * attref, LINX_OSBOOLEAN rlnh);

int linx_detach(struct sock *sk, LINX_OSATTREF attref);

/* Initialize the socket specific attach data structures. */
void linx_init_attach(struct sock *sk);

int
linx_info_pend_attach_payload(struct sock *sk,
			      struct linx_info_signal_payload *isig_payload);

int
linx_info_pend_attach(struct linx_info_pend_attach *ipend_attach,
		      struct linx_info_attach __user * attaches);

int linx_init_attref_array(void);

void linx_exit_attref_array(void);

void linx_free_pend_attach(uint32_t ref);

int
linx_attref_register_signal(LINX_OSATTREF attref,
			    struct sk_buff *skb, struct sock *to);

#endif
