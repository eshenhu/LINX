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

#ifndef LGWS_H
#define LGWS_H
#include "linx.h"
#include "ose_gwp.h"

#define DEFAULT_BROADCAST_PORT    21768
#define DEFAULT_LISTENING_PORT    16384
#define MAX_NAME_LEN              80
#define MAX_NUMBER_OF_CLIENTS     10
#define ETHERNET_PACKET_SIZE      1500

#define OseGW_ProtocolVersion     100

#define PROCESS    LINX_SPID
#define SIGSELECT  LINX_SIGSELECT
#define MAX_SIGSIZE 65536

typedef uint32_t   OSUSER;
typedef uint32_t   U32;

#if defined(GW_VERBOSE)
#define LOG(format, ...) syslog(LOG_INFO, format,  ## __VA_ARGS__)
#else
#define LOG(format, ...)
#endif

OseGW_UL gw_server_flags(void);
int recv_data(int skt, void *recv_buffer, int to_read);
struct sig_transport_header {
	SIGSELECT sig_no;	/* SIG_TRANSPORT_HEADER */
	struct OseGW_TransportHdr hdr;
};

union LINX_SIGNAL {
	SIGSELECT sig_no;
	struct sig_transport_header transport_header;
};

struct configuration_data
{
        char interface_name[MAX_NAME_LEN];
        char gateway_name[MAX_NAME_LEN];
        char configuration_file_name[MAX_NAME_LEN];
        unsigned short int  public_port;
        unsigned short int  broadcast_port;
};

int linxgws_main(int argc, char *argv[]);

#endif
