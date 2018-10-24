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

/* *INDENT-OFF* */
#ifdef __cplusplus
extern "C" {
#endif
/* *INDENT-ON* */

#ifndef _LINX_H
#define _LINX_H

#include <stdint.h>
#include <sys/types.h>
#include <linx_types.h>
#include <linx_ioctl.h>

union LINX_SIGNAL;		/* Forward declaration. */

/*
***********************************************************************
* LINX System calls.
***********************************************************************
*/

LINX *linx_open(const char *name, uint32_t options, void *arg);

int linx_close(LINX * linx);

int linx_get_descriptor(LINX * linx);

union LINX_SIGNAL *linx_alloc(LINX * linx, LINX_OSBUFSIZE size,
			      LINX_SIGSELECT sig_no);

int linx_free_buf(LINX * linx, union LINX_SIGNAL **sig);

int linx_send(LINX * linx, union LINX_SIGNAL **sig, LINX_SPID to);

int
linx_send_w_s(LINX * linx, union LINX_SIGNAL **sig, LINX_SPID from,
	      LINX_SPID to);

int
linx_send_w_opt(LINX * linx, union LINX_SIGNAL **sig, LINX_SPID from,
		LINX_SPID to, int32_t *taglist);

int
linx_sigattr(const LINX *linx, const union LINX_SIGNAL **sig,
	     uint32_t attr, void **value);

int
linx_receive(LINX * linx, union LINX_SIGNAL **sig,
	     const LINX_SIGSELECT * sig_sel);

int
linx_receive_w_tmo(LINX * linx, union LINX_SIGNAL **sig,
		   LINX_OSTIME tmo, const LINX_SIGSELECT * sig_sel);

int
linx_receive_from(LINX * linx, union LINX_SIGNAL **sig,
		  LINX_OSTIME tmo, const LINX_SIGSELECT * sig_sel,
		  LINX_SPID from);

LINX_SPID linx_sender(LINX * linx, union LINX_SIGNAL **sig);

LINX_OSBUFSIZE linx_sigsize(LINX * linx, union LINX_SIGNAL **sig);

int
linx_set_sigsize(LINX * linx, union LINX_SIGNAL **sig, LINX_OSBUFSIZE sigsize);

int linx_hunt(LINX * linx, const char *name, union LINX_SIGNAL **hunt_sig);

int
linx_hunt_from(LINX * linx, const char *name,
	       union LINX_SIGNAL **hunt_sig, LINX_SPID from);

LINX_OSATTREF linx_attach(LINX * linx, union LINX_SIGNAL **sig, LINX_SPID spid);

int linx_detach(LINX * linx, LINX_OSATTREF * attref);

LINX_SPID linx_get_spid(LINX * linx);

int linx_get_name(LINX * linx, LINX_SPID spid, char **name);

int linx_free_name(LINX * linx, char **name);

pid_t linx_get_owner(LINX *linx, LINX_SPID spid);

int linx_get_stat(LINX * linx, LINX_SPID spid, struct linx_info_stat **stat);

int linx_free_stat(LINX * linx, struct linx_info_stat **stat);

LINX_OSTMOREF
linx_request_tmo(LINX * linx, LINX_OSTIME tmo, union LINX_SIGNAL **sig);

int linx_cancel_tmo(LINX * linx, LINX_OSTMOREF * tmoref);

int linx_modify_tmo(LINX * linx, LINX_OSTMOREF * tmoref, LINX_OSTIME tmo);

LINX_NLREF linx_request_new_link(LINX * linx, LINX_NLTOKEN token);

int linx_cancel_new_link(LINX * linx, LINX_NLREF *nlref);

int linx_get_version(char *buf); /* Note: buf must contain at least 14 bytes. */
	
#endif				/* _LINX_H */

/* *INDENT-OFF* */
#ifdef __cplusplus
}				/* extern "C" */
#endif
/* *INDENT-ON* */
