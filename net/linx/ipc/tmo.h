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

#ifndef __IPC_TMO_H__
#define __IPC_TMO_H__

#include <af_linx.h>
#include <linux/linx_types.h>
#include <linux/linx_ioctl.h>

int
linx_request_tmo(struct sock *sk,
		 LINX_OSTIME tmo,
		 void *sig, LINX_OSBUFSIZE sigsize, LINX_OSTMOREF * tmoref);

int linx_cancel_tmo(struct sock *sk, LINX_OSTMOREF tmoref);

int linx_modify_tmo(struct sock *sk, LINX_OSTIME tmo, LINX_OSTMOREF tmoref);

void linx_remove_timeouts(struct sock *sk);

void linx_init_tmo(struct sock *sk);

int
linx_info_pend_tmo_payload(struct sock *sk,
			   struct linx_info_signal_payload *isig_payload);

int
linx_info_pend_tmo(struct linx_info_pend_tmo *ipend_tmo,
		   struct linx_info_tmo __user * timeouts);

int linx_init_tmoref_array(void);

void linx_exit_tmoref_array(void);

void linx_free_pend_tmo(uint32_t tmoref);

int
linx_tmoref_register_signal(LINX_OSTMOREF tmoref,
			    struct sk_buff *skb, struct sock *to);

#endif
