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

#ifndef _LINUX_LINX_TYPES_H
#define _LINUX_LINX_TYPES_H

#if defined __KERNEL__
#include <linux/types.h>
#endif

typedef int LINX_OSBUFSIZE;
typedef uint32_t LINX_SPID;
typedef int LINX_OSBOOLEAN;
typedef uint32_t LINX_SIGSELECT;
typedef uint32_t LINX_OSTIME;
typedef uint32_t LINX_OSATTREF;
typedef uint32_t LINX_RLNH;
typedef uint32_t LINX_OSTMOREF;
typedef uint32_t LINX_NLREF;
typedef uint32_t LINX_NLTOKEN;
	
typedef struct LINX_IPC LINX;

#define LINX_NIL ((union LINX_SIGNAL *) 0)

#define LINX_FALSE 0
#define LINX_TRUE  1

#define LINX_ILLEGAL_SPID    ((LINX_SPID)0)
#define LINX_ILLEGAL_ATTREF  ((LINX_OSATTREF)0)
#define LINX_ILLEGAL_TMOREF  ((LINX_OSTMOREF)0)
#define LINX_ILLEGAL_RLNH    ((LINX_RLNH)0)
#define LINX_ILLEGAL_NLREF   ((LINX_NLREF)0)
#define LINX_OS_ATTACH_SIG   ((LINX_SIGSELECT)252)
#define LINX_OS_HUNT_SIG     ((LINX_SIGSELECT)251)
#define LINX_OS_LINK_SIG     ((LINX_SIGSELECT)250)
#define LINX_OS_TMO_SIG      ((LINX_SIGSELECT)249)
#define LINX_OS_NEW_LINK_SIG ((LINX_SIGSELECT)248)
	
#define LINX_SIG_OPT_END 0
#define LINX_SIG_OPT_OOB 1

#define LINX_SIG_ATTR_OOB 1
	
struct linx_new_link {
	LINX_SIGSELECT signo; /* Signal number */
	LINX_NLTOKEN token;   /* Token to be used in the next request. */
	int name;	      /* Name offset into buf */
	int attr;	      /* Attribute offset into buf */
	char buf[1];	      /* String table. */
};
	
#endif

/* *INDENT-OFF* */	
#ifdef __cplusplus
}				/* extern "C" */
#endif
/* *INDENT-ON* */
