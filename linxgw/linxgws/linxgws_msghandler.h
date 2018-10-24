/*
 * Copyright (c) 2008-2009, Enea Software AB
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

#include <stdint.h> /* Because ose_gwp dos not include it... */
#include <ose_gwp.h>
#include <linx.h>
#define PROCESS    LINX_SPID
#define SIGSELECT  LINX_SIGSELECT
typedef uint32_t   OSTIME;

struct ClientInfo
{
        int              sd;
        int              commit_suicide;
        PROCESS          curr_pid;
        OseGW_UL         status;
        char             *gw_name;
        SIGSELECT        *sig_sel;
        OSTIME           rec_tmo;
        OseGW_UL         client_version;
        OseGW_UL         client_flags;
        char             *user_name;
        PROCESS          helper;
        LINX *linx;
};

/* Callback functions for packet handling */

int OseGW_PLT_GenericErrorReply_cbk(int skt, int len, char *payload,
					   struct ClientInfo *cinfo);
int OseGW_PLT_InterfaceRequest_cbk(int skt, int len, char *payload,
					  struct ClientInfo *cinfo);
int OseGW_PLT_InterfaceReply_cbk(int skt, int len, char *payload,
					struct ClientInfo *cinfo);
int OseGW_PLT_LoginRequest_cbk(int skt, int len, char *payload,
				      struct ClientInfo *cinfo);
int OseGW_PLT_ChallengeResponse_cbk(int skt, int len, char *payload,
					   struct ClientInfo *cinfo);
int OseGW_PLT_ChallengeReply_cbk(int skt, int len, char *payload,
					struct ClientInfo *cinfo);
int OseGW_PLT_LoginReply_cbk(int skt, int len, char *payload,
				    struct ClientInfo *cinfo);
int OseGW_PLT_CreateRequest_cbk(int skt, int len, char *payload,
				       struct ClientInfo *cinfo);
int OseGW_PLT_CreateReply_cbk(int skt, int len, char *payload,
				     struct ClientInfo *cinfo);
int OseGW_PLT_DestroyRequest_cbk(int skt, int len, char *payload,
					struct ClientInfo *cinfo);
int OseGW_PLT_DestroyReply_cbk(int skt, int len, char *payload,
				      struct ClientInfo *cinfo);
int OseGW_PLT_SendRequest_cbk(int skt, int len, char *payload,
				     struct ClientInfo *cinfo);
int OseGW_PLT_SendReply_cbk(int skt, int len, char *payload,
				   struct ClientInfo *cinfo);
int OseGW_PLT_ReceiveRequest_cbk(int skt, int len, char *payload,
					struct ClientInfo *cinfo);
int OseGW_PLT_ReceiveReply_cbk(int skt, int len, char *payload,
				      struct ClientInfo *cinfo);
int OseGW_PLT_HuntRequest_cbk(int skt, int len, char *payload,
				     struct ClientInfo *cinfo);
int OseGW_PLT_HuntReply_cbk(int skt, int len, char *payload,
				   struct ClientInfo *cinfo);
int OseGW_PLT_AttachRequest_cbk(int skt, int len, char *payload,
				       struct ClientInfo *cinfo);
int OseGW_PLT_AttachReply_cbk(int skt, int len, char *payload,
				     struct ClientInfo *cinfo);
int OseGW_PLT_DetachRequest_cbk(int skt, int len, char *payload,
				       struct ClientInfo *cinfo);
int OseGW_PLT_DetachReply_cbk(int skt, int len, char *payload,
				     struct ClientInfo *cinfo);
int OseGW_PLT_NameRequest_cbk(int skt, int len, char *payload,
				     struct ClientInfo *cinfo);
int OseGW_PLT_NameReply_cbk(int skt, int len, char *payload,
				   struct ClientInfo *cinfo);
