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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#undef __EXTENSIONS__
#define __EXTENSIONS__
#include <signal.h>

#ifdef _WIN32
#include <winsock.h>
#define read(fd, buf, len)     recv((fd), (buf), (len), 0)
#define write(fd, buf, len)    send((fd), (buf), (len), 0)
#define close(fd)              closesocket(fd)
#define sockerr                WSAGetLastError()

#elif defined(__INCvxANSIh) || defined(VXWORKS)
#include <hostLib.h>
#include <inetLib.h>
#include <ioLib.h>
#include <sockLib.h>
#include <unistd.h>
#define sockerr                errno
#define INVALID_SOCKET         -1
#define TCP_NODELAY            0x01

#else
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#ifndef FIONBIO
#include <sys/filio.h>
#endif
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#define sockerr                errno
#define INVALID_SOCKET         -1
#endif

#include "ose_gw.h"
#include "ose_gwp.h"

#ifndef INADDR_NONE
#define INADDR_NONE -1
#endif

#ifdef OSEGW_DEBUG
#define GWClient OSEGW
#endif

/*
 * The reply timeout in milliseconds for conceptually non-blocking
 * gateway operations, i.e. all operations except osegw_receive() and
 * osegw_receive_w_tmo(). A value of 0 means infinite timeout.
 * This additional feature was introduced to prevent operations like
 * osegw_send() to block potentially indefinitely because of communication
 * issues. Set OSEGW_REPLY_TIMEOUT to 0 to get the original behavior.
 */
#ifndef OSEGW_REPLY_TIMEOUT
#define OSEGW_REPLY_TIMEOUT 8000
#endif

#define MK_STR(x) #x
#define VAL_TO_STR(x) MK_STR(x)

static const char gw_brc_hdr[] = \
   "OSEGW? " VAL_TO_STR(OseGW_ProtocolVersion) "\n";

struct GWFoundNode
{
   struct GWFoundNode *next;
   char               *gw_addr;
   size_t              gw_addr_len;
   char               *gw_name;
};

struct GWFind
{
   int                 sd;
   struct sockaddr_in  broadcast_addr;
   OSEGW_FOUND_GW     *gw_found;
   void               *usr_hd;
   struct GWFoundNode *found_list;
};

#define MAGIC_SIGNO 0x05E05E01
#define FREED_SIGNO 0x05E05E02
#define END_MARK    0xEE

#define sig_to_adm(sig) (&((struct GWSigAdm *)(sig))[-1])
#define adm_to_sig(adm) ((union OSEGW_SIGNAL *)&(adm)[1])

struct GWSigAdm
{
   OseGW_UL         magic_signo;
   struct GWClient *owner;
   struct GWSigAdm *next_owned;
   struct GWSigAdm *prev_owned;
   OSEGW_OSBUFSIZE  size;
   OSEGW_PROCESS    dest_id;
   OSEGW_PROCESS    sender_id;
   OseGW_UL         res0;
};

struct GWClient
{
   int                 sd;
   OSEGW_PROCESS       pid;
   struct GWSigAdm    *owned_sig_head;
   struct GWSigAdm    *owned_sig_tail;
   OSEGW_ERRORHANDLER *err_hnd;
   void               *err_usr_hd;
   OseGW_UL            server_version;
   OseGW_UL            server_flags;
   OSEGW_OSBUFSIZE     max_sigsize;
   OSEGW_OSERRCODE     err_code;
   OSEGW_OSERRCODE     err_extra;
};

union OSEGW_SIGNAL
{
   OSEGW_SIGSELECT sig_no;
};

/**********************************************************************
 *  E R R O R H A N D L E R   C O D E
 **********************************************************************/

static OSEGW_BOOLEAN
call_error_handler(struct GWClient *gwc,
		   OSEGW_OSERRCODE  ecode,
		   OSEGW_OSERRCODE  extra)
{
   gwc->err_code  = ecode;
   gwc->err_extra = extra;

   if (gwc->err_hnd)
   {
      return gwc->err_hnd(gwc->err_usr_hd, (struct OSEGW *)gwc, ecode, extra);
   }
   return OSEGW_FALSE;
} /* call_error_handler */

OSEGW_OSERRCODE
osegw_get_error(struct OSEGW *ose_gw)
{
   struct GWClient *gwc = (struct GWClient *)ose_gw;

   return (gwc != NULL)
      ? gwc->err_code
      : OSEGW_EOK;
} /* osegw_get_error */

void
osegw_reset_error(struct OSEGW *ose_gw)
{
   struct GWClient *gwc = (struct GWClient *)ose_gw;

   if (gwc != NULL)
      gwc->err_code = OSEGW_EOK;
} /* osegw_reset_error */

/**********************************************************************
 *  S O C K E T   C O D E
 **********************************************************************/

#ifdef _WIN32
static void
cleanup_socks(void)
{
   WSACleanup();
} /* cleanup_socks */
#endif

static int
init_socks(void)
{
   static int done_init = 0;

   if (done_init)
      return 0;

#ifdef _WIN32
   {
      WORD    reqver = MAKEWORD (1, 1);
      WSADATA repver;


      if (WSAStartup(reqver, &repver) != 0)
      {
	 fprintf(stderr, "WSAStartup error: %lu\n", WSAGetLastError());
	 return -1;
      }

      if (LOBYTE(repver.wVersion) != 1 || HIBYTE(repver.wVersion) != 1)
      {
	 fprintf(stderr, "WSAStartup error: incompatible versions\n");
	 WSACleanup();
	 return -1;
      }
      atexit(cleanup_socks);
   }
#else
   signal(SIGPIPE, SIG_IGN);
#endif
   done_init = 1;
   return 0;
} /* init_socks */

static int
open_broadcast(struct GWFind *gwf, int port)
{
   int enable = 1;
   struct sockaddr_in addr;

   if (init_socks())
      return -1;

   /* Open socket */
   if ((gwf->sd = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
   {
      perror("Can not open socket");
      return -1;
   }

   /* Enable broadcast */
   if (setsockopt(gwf->sd, SOL_SOCKET, SO_BROADCAST,
		  (char *)&enable, sizeof(enable)))
   {
      perror("Can not enable broadcast");
      return -1;
   }

   /* Set local wildcard address. */
   memset(&addr, 0, sizeof(addr));
   addr.sin_family = AF_INET;
   addr.sin_addr.s_addr = htonl(INADDR_ANY);
   addr.sin_port = htons((unsigned short)(port & 0xFFFF));

   /* Enable address reuse. */
   if (setsockopt(gwf->sd, SOL_SOCKET, SO_REUSEADDR,
		  (char *)&enable, sizeof(enable)))
   {
      perror("Can not enable socket reuse");
   }

   /* Bind socket to port. */
   if (bind(gwf->sd, (struct sockaddr *)&addr, sizeof(addr)))
   {
      perror("Can not bind socket");
      return -1;
   }

   /* Set broadcast address. */
   memset(&gwf->broadcast_addr, 0, sizeof(gwf->broadcast_addr));
   gwf->broadcast_addr.sin_family = AF_INET;
   gwf->broadcast_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
   gwf->broadcast_addr.sin_port = htons((unsigned short)port);
   return 0;
} /* open_broadcast */

static void
close_broadcast(struct GWFind *gwf)
{
   close(gwf->sd);
} /* close_broadcast */

static int
write_broadcast(struct GWFind *gwf, const void *data, size_t len)
{
  if ((size_t)sendto(gwf->sd, data, len, 0,
		     (struct sockaddr *)&gwf->broadcast_addr,
		     sizeof(gwf->broadcast_addr)) != len)
  {
     perror("Broadcast socket write failed");
     return -1;
  }
  return 0;
} /* write_broadcast */

static int
read_broadcast(struct GWFind *gwf,
	       void          *data,
	       size_t         len,
	       unsigned long  tmo)
{
   fd_set fds;
   struct timeval timeout;
   struct sockaddr_in from;
   int fromlen = sizeof(from);
   int ret;
   int rcv_len;

   FD_ZERO(&fds);
   FD_SET(gwf->sd, &fds);
   timeout.tv_sec  = (long)tmo / 1000;
   timeout.tv_usec = (tmo % 1000u) * 1000u;

   ret = select(gwf->sd+1, &fds, NULL, NULL, &timeout);
   if (ret < 0)
   {
      perror("Socket select failed");
      return -1;
   }
   else if (ret > 0 && FD_ISSET(gwf->sd, &fds))
   {

      if ((rcv_len = recvfrom(gwf->sd, data, len, 0,
			      (struct sockaddr *)&from,
			      (void *)&fromlen)) < 0)
      {
	 perror("Socket recvfrom failed");
	 return -1;
      }
#ifdef OSEGW_DEBUG
      {
	 char *from_str;
	 /* Fill in from */
	 if ((from_str = inet_ntoa(from.sin_addr)) == NULL)
	    return -1;
	 else
	 {
	    fprintf(stderr, "%s: ", from_str);
	    fwrite(data, (size_t)rcv_len, 1u, stdout);
	 }
      }
#endif
      return rcv_len;
   }
   else
      return 0;
} /* read_broadcast */

static char *
parse_server_url(struct GWClient *gwc, const char *server_url, int *port)
{
   char *cp;
   const char *server;
   size_t server_len;

   if (strncmp(server_url, "tcp://" , 6) != 0)
   {
      call_error_handler(gwc,
			 (OSEGW_OSERRCODE)OSEGW_EBAD_PARAMETER,
			 (OSEGW_OSERRCODE)server_url);
      return NULL;
   }
   server = &server_url[6];
   cp = strchr(server, ':');
   if (cp == NULL || !isdigit((unsigned char)cp[1]))
   {
      call_error_handler(gwc,
			 (OSEGW_OSERRCODE)OSEGW_EBAD_PARAMETER,
			 (OSEGW_OSERRCODE)server_url);
      return NULL;
   }
   *port = atoi(&cp[1]);
   if (*port <= 0)
   {
      call_error_handler(gwc,
			 (OSEGW_OSERRCODE)OSEGW_EBAD_PARAMETER,
			 (OSEGW_OSERRCODE)server_url);
      return NULL;
   }
   server_len = (size_t)(cp - server);
   if (server_len > 0)
   {
      char *server_str = malloc(server_len + 1);
      if (server_str == NULL)
      {
	 call_error_handler(gwc,
			    (OSEGW_OSERRCODE)OSEGW_ENO_CLIENT_MEMORY,
			    (OSEGW_OSERRCODE)server_len + 1);
	 return NULL;
      }
      memcpy(server_str, server, server_len);
      server_str[server_len] = '\0';
      return server_str;
   }
   return NULL;
} /* parse_server_url */

static int
open_server(struct GWClient *gwc, const char *server_url)
{
   int                 enable = 1;
   int                 port;
   char               *server = parse_server_url(gwc, server_url, &port);
   struct sockaddr_in  addr;

   if (server == NULL)
   {
      return -1;
   }

   if (init_socks())
      return -1;

   memset(&addr, 0, sizeof(addr));
   if ((gwc->sd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
   {
      call_error_handler(gwc,
			 (OSEGW_OSERRCODE)OSEGW_ECAN_NOT_CONNECT,
			 (OSEGW_OSERRCODE)sockerr);
      free(server);
     return -1;
   }

   /* By disabling the nagle algorithm like this, we hope to get a
    * shorter latency...
    */
   (void)setsockopt(gwc->sd, IPPROTO_TCP, TCP_NODELAY,
		    (void *)&enable, sizeof(enable));

   addr.sin_family = AF_INET;
   addr.sin_port = htons((unsigned short)port);

   /* Check for xxx.xxx.xxx.xxx address. */
   if ((addr.sin_addr.s_addr = inet_addr(server)) != INADDR_NONE)
   {
      if (connect(gwc->sd, (struct sockaddr *)&addr, sizeof(addr)))
      {
	 call_error_handler(gwc,
			    (OSEGW_OSERRCODE)OSEGW_ECAN_NOT_CONNECT,
			    (OSEGW_OSERRCODE)sockerr);
	 free(server);
	 close(gwc->sd);
	 return -1;
      }
   }
   else
   {
      int ok = 0;

#if defined(__INCvxANSIh) || defined(VXWORKS)
      addr.sin_addr.s_addr = hostGetByName(server);
      if (((long) addr.sin_addr.s_addr) != ERROR)
      {
         ok = 1;
      }
#else
      struct hostent *he = gethostbyname(server);
      if (he != NULL)
      {
	 memcpy(&addr.sin_addr, he->h_addr, (size_t)he->h_length);
	 ok = 1;
      }
#endif
      if (ok)
      {

	 if (connect(gwc->sd, (struct sockaddr *)&addr, sizeof(addr)))
	 {
	    call_error_handler(gwc,
			       (OSEGW_OSERRCODE)OSEGW_ECAN_NOT_CONNECT,
			       (OSEGW_OSERRCODE)sockerr);
	    free(server);
	    close(gwc->sd);
	    return -1;
	 }
      }
      else
      {
	 call_error_handler(gwc,
			    (OSEGW_OSERRCODE)OSEGW_EBAD_PARAMETER,
			    (OSEGW_OSERRCODE)server_url);
      }
   }
   free(server);
   return gwc->sd;
} /* open_server */

static long
read_server_data(int sd, void *data, size_t len)
{
   char *feed = (char *)data;
   size_t left = len;

   do
   {
      long s = read(sd, feed, left);

      if ((s < 0) && (sockerr == EINTR))
      {
	 continue;
      }
      if (s <= 0)
      {
	 return (long)(len - left);
      }
      left -= (size_t)s;
      feed += (size_t)s;
   } while (left > 0);
/* fprintf(stderr, "READ: %lu\n", len); */
   return (long)len;
} /* read_server_data */

/**********************************************************************
 * H E L P E R   M A C R O S   &   F U N C T I O N S
 **********************************************************************/
static OseGW_UL gwc_client_flags(void);


#define alloc_trans_mem(gw, typ, plus, outlen) \
   ((struct OseGW_TransportData *)get_trans_mem((gw), OseGW_PLT_ ## typ, \
                                                sizeof(struct OseGW_ ## typ) \
					        + (size_t)(plus), \
						(outlen)))

static void *
get_trans_mem(struct GWClient *gwc,
	      OseGW_UL         type,
	      OseGW_UL         payload_len,
	      OseGW_UL        *outlen)
{
   OseGW_UL totsize = sizeof(struct OseGW_TransportHdr) + payload_len;
   struct OseGW_TransportData *td;

   if (totsize > gwc->max_sigsize)
   {
      call_error_handler(gwc,
			 (OSEGW_OSERRCODE)OSEGW_EBUFFER_TOO_LARGE,
			 (OSEGW_OSERRCODE)totsize);
      return NULL;
   }

   td = (struct OseGW_TransportData *)malloc((size_t)totsize);
   if (td == NULL)
   {
      call_error_handler(gwc,
			 (OSEGW_OSERRCODE)OSEGW_ENO_CLIENT_MEMORY,
			 (OSEGW_OSERRCODE)sizeof(struct OseGW_TransportHdr)
			 + payload_len);
      return NULL;
   }

   td->hdr.payload_type = htonl(type);
   td->hdr.payload_len  = htonl(payload_len);
   *outlen = payload_len;
   return td;
} /* get_trans_mem */

static int
write_request(struct GWClient            *gwc,
	      struct OseGW_TransportData *td,
	      OseGW_UL                    payload_len)
{
   if (offsetof(struct OseGW_TransportData, payload)
       == sizeof(td->hdr)) /*lint !e506 *//* Constant value Boolean */
   {
      /* We are able to write both header and payload as one chunk. */
      size_t wlen = sizeof(td->hdr) + (size_t)payload_len;

      if ((size_t)write(gwc->sd, (char *)&td->hdr, wlen) != wlen)
      {
	 return -1;
      }
   }
   else
   {
      if ((size_t)write(gwc->sd,
			(char *)&td->hdr,
			sizeof(td->hdr)) != sizeof(td->hdr))
      {
	 return -1;
      }
      if ((OseGW_UL)write(gwc->sd,
			  (char *)&td->payload.start_of_payload,
			  payload_len) != payload_len)
      {
	 return -1;
      }
   }
   return 0;
} /* write_request */

#define check_reply_hdr(gw, td, typ) \
   do_check_reply_hdr((gw), (td), \
                      OseGW_PLT_ ## typ, sizeof(struct OseGW_ ## typ))

static int
check_reply_status(struct GWClient *gwc, OseGW_UL status)
{
   if (status != OseGW_StatusOk)
   {
      switch (status)
      {
	 case OseGW_StatusErr:
	    break;
	 case OseGW_StatusAuthentErr:
	    call_error_handler(gwc, (OSEGW_OSERRCODE)OSEGW_ELOGIN_FAILED, 0);
	    break;
	 case OSEGW_EBUFFER_TOO_LARGE:
	 case OSEGW_ENO_USER_SIGSPACE:
	 case OSEGW_ETOO_MANY_ATTACHED:
	 case OSEGW_EDETACHED_TWICE:
	 case OSEGW_EDETACH_AFTER_RECEIVE:
	 case OSEGW_EUSED_NIL_POINTER:
	 case OSEGW_EILLEGAL_PROCESS_ID:
	 case OSEGW_EATTACHED_TO_CALLER:
	 case OSEGW_ENOT_SIG_OWNER:
	 case OSEGW_EBAD_PARAMETER:
	 case OSEGW_ENO_BUFFER_END_MARK:
	    call_error_handler(gwc, (OSEGW_OSERRCODE)status, 0);
	    break;
	 default:;
	    call_error_handler(gwc,
			       (OSEGW_OSERRCODE)OSEGW_EUNKNOWN_ECODE,
			       (OSEGW_OSERRCODE)status);
	    break;
      }
      return -1;
   }
   return 0;
} /* check_reply_status */

static int
do_check_reply_hdr(struct GWClient            *gwc,
		   struct OseGW_TransportData *td,
		   OseGW_UL                    type,
		   OseGW_UL                    payload_len)
{
   if (htonl(td->hdr.payload_type) != type)
   {
      call_error_handler(gwc,
	 (OSEGW_OSERRCODE)OSEGW_EPROTOCOL_ERROR,
	 (OSEGW_OSERRCODE)( ((htonl(td->hdr.payload_type) & 0xFFFF) << 16)
			   | (type & 0xFFFF)));
      return -1;
   }
   else if (htonl(td->hdr.payload_len) != payload_len)
   {
      return -1;
   }
   return check_reply_status(gwc, htonl(td->payload.status));
} /* do_check_reply_hdr */

#define read_simple_reply(gw, td, typ) \
   (do_read_simple_reply((gw), (td), \
                        sizeof(struct OseGW_TransportHdr) \
		        + sizeof(struct OseGW_ ## typ)) == 0 \
      ?  check_reply_hdr((gw), (td), typ) \
      : -1)

static int
readable_timeout(int sd, long timeout)
{
   fd_set rset;
   struct timeval tv;

   FD_ZERO(&rset);
   FD_SET(sd, &rset);

   tv.tv_sec = timeout / 1000;
   tv.tv_usec = (timeout % 1000) * 1000;

   return select(sd + 1, &rset, NULL, NULL, &tv);
}

static int
do_read_simple_reply(struct GWClient *gwc, void *data, size_t len)
{
   OSEGW_OSERRCODE retry_cnt = 0;

   for (;;)
   {
      int status = readable_timeout(gwc->sd, OSEGW_REPLY_TIMEOUT);

      if (status > 0)
      {
         break;
      }
      else if (status == 0)
      {
         if (call_error_handler(gwc,
                                (OSEGW_OSERRCODE)OSEGW_ECONNECTION_TIMEDOUT,
                                (++retry_cnt * OSEGW_REPLY_TIMEOUT)))
         {
            /*
             * The user error handler says that we should ignore the timeout
             * and continue in hope that the reply will show up eventually.
             */
            continue;
         }
      }

      call_error_handler(gwc,
                         (OSEGW_OSERRCODE)OSEGW_ECONNECTION_LOST,
                         (OSEGW_OSERRCODE)sockerr);
      return -1;
   }

   if (read_server_data(gwc->sd, data, len) != (int)len)
   {
      call_error_handler(gwc,
                         (OSEGW_OSERRCODE)OSEGW_ECONNECTION_LOST,
                         (OSEGW_OSERRCODE)sockerr);
      return -1;
   }
   else
      return 0;
} /* do_read_simple_reply */

static int
send_interface_request(struct GWClient *gwc)
{
   struct OseGW_TransportData *td;
   OseGW_UL payload_len;
   int rv;
   int offset;
   fd_set fds;
   struct timeval timeout;

   td = alloc_trans_mem(gwc, InterfaceRequest, 0, &payload_len);

   if (td == NULL)
   {
      return -1;
   }

   td->payload.interface_request.cli_version = htonl(OseGW_ProtocolVersion);
   td->payload.interface_request.cli_flags   = htonl(gwc_client_flags());

   offset = 0;
   payload_len += sizeof(td->hdr);

   for (;;)
   {

#if 0 /* Solaris doesn't support MSG_DONTWAIT */
      rv = send(gwc->sd, (char *)&td->hdr + offset, payload_len, MSG_DONTWAIT);
#else

#if defined(WIN32)
#define ioctl ioctlsocket
#endif
      {
	 int err;
	 int blocking = 0;
	 int non_blocking = 1;
	 /* set sock to non-blocking */
	 err = ioctl(gwc->sd, FIONBIO, &non_blocking);
	 if (err < 0)
	    return err;
	 rv = send(gwc->sd, (char *)&td->hdr + offset, payload_len, 0);
	 /* set sock back to blocking */
	 err = ioctl(gwc->sd, FIONBIO, &blocking);
	 if (err < 0)
	    return err;
      }
#endif

      if (rv == (int)payload_len)
         break; /* whole msg sent */

      if (rv == -1 && errno != EAGAIN)
	 return -1; /* send failed but try again if errno EAGAIN */

      payload_len -= rv;
      offset += rv;

      FD_ZERO(&fds);
      FD_SET(gwc->sd, &fds);
      timeout.tv_sec = OSEGW_REPLY_TIMEOUT; /* what timeout to use here? */
      timeout.tv_usec = 0;

      rv = select(gwc->sd + 1, NULL, &fds, NULL, &timeout);
      if (rv < 0)
	 return -1; /* select failed */

      if (rv > 0 && FD_ISSET(gwc->sd, &fds))
	 continue; /* socket is writable again */
      else
	 return -1; /* timeout */
   }
   return 0;
}

static int
do_blocking_read_simple_reply(struct GWClient *gwc, void *data, size_t len)
{
   int status;
   struct OseGW_TransportData *td;
   OSEGW_OSERRCODE retry_cnt = 0;
   OSEGW_OSERRCODE tmo;
   int received_sig = 0;
   
   for (;;)
   {
      status = readable_timeout(gwc->sd, OSEGW_PING_TIMEOUT);
      if (status > 0)
      {
	 /* check is it a interface request or receive request */
	 td = (struct OseGW_TransportData *)malloc(sizeof(struct OseGW_TransportData));
	 if (td == NULL )
	 {
	    return -1;
	 }

	 recv(gwc->sd, (void *)td, sizeof(struct OseGW_TransportData), MSG_PEEK);

	 if (ntohl(td->hdr.payload_type) == OseGW_PLT_InterfaceReply)
	 {
	    td = (struct OseGW_TransportData *)
	       realloc((void *)td, sizeof(struct OseGW_TransportHdr) + ntohl(td->hdr.payload_len));
	    /* remove the signal from the socket */
	    recv(gwc->sd, (void *)td, sizeof(struct OseGW_TransportHdr) + ntohl(td->hdr.payload_len), 0);
	    free(td);
            retry_cnt = 0;
	    if (received_sig == 1)
		    return 0;
	    continue;
	 }

	 free(td);
	 
	 if (read_server_data(gwc->sd, data, len) != (int)len)
	 {
		 call_error_handler(gwc,
				    (OSEGW_OSERRCODE)OSEGW_ECONNECTION_LOST,
				    (OSEGW_OSERRCODE)sockerr);
		 return -1;
	 }
	 
	 /* Return if we're not waiting for any ping */
	 if (retry_cnt == 0)
		 return 0;
	 
	 received_sig = 1;
      }
      else if (status == 0)
      {
         if (retry_cnt != 0)
         {
            tmo = retry_cnt*OSEGW_PING_TIMEOUT + (retry_cnt - 1)*OSEGW_REPLY_TIMEOUT;
            status = call_error_handler(gwc,
                                        (OSEGW_OSERRCODE)OSEGW_ECONNECTION_TIMEDOUT,
                                        (OSEGW_OSERRCODE)tmo);
            if (status == 0)
            {
               call_error_handler(gwc,
                                  (OSEGW_OSERRCODE)OSEGW_ECONNECTION_LOST,
                                  (OSEGW_OSERRCODE)0);
               return -1;
            }
         }
	 /* Send an interface request to check if the socket is still
	    connected */
	 status = send_interface_request(gwc);
	 if (status < 0)
	 {
	    call_error_handler(gwc,
			       (OSEGW_OSERRCODE)OSEGW_ECONNECTION_LOST,
			       (OSEGW_OSERRCODE)sockerr);
	    return -1;
	 }
         retry_cnt += 1;
      }
   }
} /* do_blocking_read_simple_reply */

static struct GWSigAdm *
check_buffer(struct GWClient     *gwc,
	     union OSEGW_SIGNAL **sigptr,
	     OSEGW_OSERRCODE      errorcode)
{
   union OSEGW_SIGNAL *sig;
   struct GWSigAdm    *sig_adm;

   if (sigptr == NULL)
   {
      call_error_handler(gwc,
			 (OSEGW_OSERRCODE)OSEGW_EBAD_PARAMETER | errorcode,
			 (OSEGW_OSERRCODE)sigptr);
      return NULL;
   }
   sig = *sigptr;
   if (sig == NULL)
   {
      call_error_handler(gwc,
			 (OSEGW_OSERRCODE)OSEGW_EUSED_NIL_POINTER | errorcode,
			 (OSEGW_OSERRCODE)sigptr);
      return NULL;
   }
   sig_adm = sig_to_adm(sig);
   if (END_MARK != *(unsigned char *)(sig_adm->size + (unsigned char *)sig))
   {
      call_error_handler(gwc,
		 (OSEGW_OSERRCODE)OSEGW_ENO_BUFFER_END_MARK | errorcode,
		 (OSEGW_OSERRCODE)sig);
      return NULL;
   }
   if (sig_adm->owner != gwc)
   {
      call_error_handler(gwc,
		 (OSEGW_OSERRCODE)OSEGW_ENOT_SIG_OWNER | errorcode,
		 (OSEGW_OSERRCODE)sig);
      return NULL;
   }
   return sig_adm;
} /* check_buffer */

static void
link_sig_owner(struct GWClient *gwc,
	       struct GWSigAdm *sig_adm)
{
   sig_adm->owner = gwc;

   /* Link signal into list of owned signals. */
   if(gwc->owned_sig_head != NULL)
   {
      sig_adm->next_owned             = NULL;
      sig_adm->prev_owned             = gwc->owned_sig_tail;
      gwc->owned_sig_tail->next_owned = sig_adm;
      gwc->owned_sig_tail             = sig_adm;
   }
   else
   {
      sig_adm->next_owned = NULL;
      sig_adm->prev_owned = NULL;
      gwc->owned_sig_head = sig_adm;
      gwc->owned_sig_tail = sig_adm;
   }
} /* link_sig_owner */

static void
unlink_sig_owner(struct GWClient *gwc,
		 struct GWSigAdm *sig_adm)
{
   if (sig_adm->prev_owned != NULL)
   {
      sig_adm->prev_owned->next_owned = sig_adm->next_owned;
   }
   else
   {
      gwc->owned_sig_head = sig_adm->next_owned;
   }

   if (sig_adm->next_owned != NULL)
   {
      sig_adm->next_owned->prev_owned = sig_adm->prev_owned;
   }
   else
   {
      gwc->owned_sig_tail = sig_adm->prev_owned;
   }
   sig_adm->owner = NULL;
} /* unlink_sig_owner */

static void
adm_free_buf(struct GWClient *gwc,
	     struct GWSigAdm *sig_adm)
{
   unlink_sig_owner(gwc, sig_adm);
   sig_adm->magic_signo = FREED_SIGNO;
   free(sig_adm);
} /* adm_free_buf */

static void
free_owned_sigs(struct GWClient *gwc)
{
   struct GWSigAdm *sig_adm = gwc->owned_sig_head;

   while (sig_adm != NULL)
   {
      struct GWSigAdm *next_sig_adm = sig_adm->next_owned;

      adm_free_buf(gwc, sig_adm);
      sig_adm = next_sig_adm;
   }
} /* free_owned_sigs */

/**********************************************************************
 *  H  A N D L E   O S E G W _ F I N D _ G W
 **********************************************************************/

static size_t
get_hdr_str(const char **found_out, const char *hdr, const char *str)
{
   const char *found = strstr(hdr, str);
   const char *cp;

   if (found == NULL)
   {
      *found_out = NULL;
      return 0;
   }
   found += strlen(str);
   while (*found == ' ')
   {
      ++found;
   }
   *found_out = found;
   cp = found;
   while (*cp != '\0' && *cp != ' ' && *cp != '\n')
   {
      ++cp;
   }
   return (size_t)(cp - found);
} /* get_hdr_str */

static char *
dup_hdr_str(const char *hdr, const char *str)
{
   char       *duped;
   const char *found;
   size_t      len = get_hdr_str(&found, hdr, str);

   if (len == 0)
   {
      return NULL;
   }
   duped = malloc(len + 1);
   if (duped == NULL)
   {
      return NULL;
   }
   memcpy(duped, found, len);
   duped[len] = '\0';
   return duped;
} /* dup_hdr_str */

static int
add_found_gw(struct GWFind *gwf, char *rcv_buf)
{
   struct GWFoundNode *node;
   char               *str;
   const char         *gw_addr;
   size_t              gw_len;

   gw_len = get_hdr_str(&gw_addr, rcv_buf, "Gateway-addr:");
   if (gw_len == 0)
   {
      return OSEGW_FALSE;
   }

   /* Find the host in list. */
   for (node = gwf->found_list ; node != NULL ; node = node->next)
   {
      if (node->gw_addr_len == gw_len
	  && memcmp(node->gw_addr, gw_addr, gw_len) == 0)
      {
	 /* Duplicate */
#ifdef OSEGW_DEBUG
	 fprintf(stderr, "Duplicate gw entry: \"%s\"\n", node->gw_addr);
#endif
	 return OSEGW_FALSE;
      }
   }

   /* Host is not in list, so add it to the list. */
   node = (struct GWFoundNode *)malloc(sizeof(struct GWFoundNode));

   if (node == NULL)
      return OSEGW_TRUE;
   str = (char *)malloc(gw_len + 1);
   if (str == NULL)
   {
      free(node);
      return OSEGW_TRUE;
   }
   memcpy(str, gw_addr, gw_len);
   str[gw_len] = '\0';
   node->gw_addr = str;
   node->gw_addr_len = gw_len;
   node->gw_name = dup_hdr_str(rcv_buf, "Gateway-name:");

   node->next = gwf->found_list;
   gwf->found_list = node;
#ifdef OSEGW_DEBUG
   fprintf(stderr, "Added \"%s\" to the gw list.\n", node->gw_addr);
#endif
   if (gwf->gw_found(gwf->usr_hd,
		     node->gw_addr,
		     node->gw_name != NULL
		     ? node->gw_name
		     : ""))
   {
      return OSEGW_TRUE;
   }
   return OSEGW_FALSE;
} /* add_found_gw */

OSEGW_BOOLEAN
osegw_find_gw(const char     *broadcast_address,
	      OSEGW_OSTIME    timeout,
	      OSEGW_FOUND_GW *gw_found,
	      void           *usr_hd)
{
   struct GWFind gwf;
   int udp_port;

   if (gw_found == NULL)
   {
      return OSEGW_FALSE;
   }
   memset(&gwf, 0, sizeof(gwf));
   gwf.gw_found = gw_found;
   gwf.usr_hd   = usr_hd;

   if (broadcast_address == NULL)
   {
      gwf.gw_found(gwf.usr_hd, "<error>", "broadcast address missing");
      return OSEGW_FALSE;
   }
   if (strncmp(broadcast_address, "udp://*:" , 8) != 0
       || !isdigit((unsigned char)broadcast_address[8]))
   {
      gwf.gw_found(gwf.usr_hd, "<error>",
		    "broadcast address not in \"udp://*:<port>\" form");
      return OSEGW_FALSE;
   }
   udp_port = atoi(&broadcast_address[8]);
   if (udp_port <= 0)
   {
      gwf.gw_found(gwf.usr_hd, "<error>", "erroneous broadcast port");
      return OSEGW_FALSE;
   }
   if (open_broadcast(&gwf, udp_port) != 0)
   {
      gwf.gw_found(gwf.usr_hd, "<error>", "open broadcast failed");
      return OSEGW_FALSE;
   }
   if (write_broadcast(&gwf, gw_brc_hdr, strlen(gw_brc_hdr) + 1) != 0)
   {
      gwf.gw_found(gwf.usr_hd, "<error>", "write broadcast failed");
      close_broadcast(&gwf);
      return OSEGW_FALSE;
   }

   {
#define RCV_BUF_SIZE 1500
      OSEGW_BOOLEAN  found = OSEGW_FALSE;
      char          *rcv_buf = malloc(RCV_BUF_SIZE);
      int            len;

      if (rcv_buf == NULL)
      {
	 close_broadcast(&gwf);
	 return OSEGW_FALSE;
      }

      while ((len = read_broadcast(&gwf,
				   &rcv_buf[0],
				   RCV_BUF_SIZE - 1,
				   timeout)) > 0)
      {
#ifdef OSEGW_DEBUG
	 fwrite(rcv_buf, (size_t)len, 1u, stdout);
#endif
	 rcv_buf[len] = '\0';
	 if (add_found_gw(&gwf, rcv_buf))
	 {
	    found = OSEGW_TRUE;
	    break;
	 }
      }
      close_broadcast(&gwf);
      free(rcv_buf);
#undef RCV_BUF_SIZE

      { /* Delete all Found Gateway nodes. */
	 struct GWFoundNode *node;

	 node = gwf.found_list;
	 while (node != NULL)
	 {
	    struct GWFoundNode *next = node->next;

	    free(node->gw_addr);
	    if (node->gw_name)
	       free(node->gw_name);
	    free(node);
	    node = next;
	 }
      }
      return found;
   }
} /* osegw_find_gw */

/**********************************************************************
 *  H  A N D L E   O S E G W _ C R E A T E
 **********************************************************************/

static OseGW_UL
gwc_client_flags(void)
{
   static const int endian_chk = 1;
   OseGW_UL         flags      = 0UL;

   /* "Constant value Boolean" warning removed from lint output. */
   if (*(char *)&endian_chk != 0) /*lint !e506 */
   {
      flags |= OseGw_CFL_LittleEndian;
   }
   return flags;
} /* gwc_client_flags */

static int
gwc_interface(struct GWClient *gwc)
{
   int                         status = 0;
   OseGW_UL                    payload_len;
   struct OseGW_TransportData *td;

   td = alloc_trans_mem(gwc, InterfaceRequest, 0, &payload_len);

   if (td == NULL)
   {
      return -1;
   }

   td->payload.interface_request.cli_version = htonl(OseGW_ProtocolVersion);
   td->payload.interface_request.cli_flags   = htonl(gwc_client_flags());

   if (write_request(gwc, td, payload_len) == 0)
   {
      if (do_read_simple_reply(gwc, td,
			    sizeof(struct OseGW_TransportHdr)) == 0)
      {
	 if (htonl(td->hdr.payload_type) == OseGW_PLT_InterfaceReply)
	 {
	    struct OseGW_InterfaceReply *ir;
	    
	    payload_len = htonl(td->hdr.payload_len);
	    ir = (struct OseGW_InterfaceReply *)malloc((size_t)payload_len);

	    if (ir == NULL)
	    {
	       call_error_handler(gwc,
				  (OSEGW_OSERRCODE)OSEGW_ENO_CLIENT_MEMORY,
				  (OSEGW_OSERRCODE)payload_len);
	       status = -1;
	    }
	    else if ((  do_read_simple_reply(gwc, ir, payload_len) == 0)
		     && check_reply_status(gwc, htonl(ir->status)) == 0)
	    {		    
	       OseGW_UL types_len = ntohl(ir->types_len);
	       OseGW_UL n;

	       gwc->server_version = ntohl(ir->srv_version);
	       gwc->server_flags   = ntohl(ir->srv_flags);

	       for (n = 0UL ; n < types_len ; ++n)
	       {
		       ir->payload_types[n] = ntohl(ir->payload_types[n]);
	       }

	       free(ir);
	    }
	    else
	    {
	       status = -1;
	    }
	 }
      }
   }
   free(td);
   return status;
} /* gwc_interface */

static struct OseGW_TransportData *
create_challenge_response(struct GWClient *gwc,
			  OseGW_UL        *payload_len,
			  OseGW_UL         auth_type,
			  const char      *user_name,
			  const char      *passwd,
			  const char      *challenge_data,
			  OseGW_UL         challenge_data_len)
{
   struct OseGW_TransportData *td;
   OseGW_UL data_len = 0;
   switch (auth_type)
   {
      case OseGW_AUT_NoPassWord:
	 break;
      case OseGW_AUT_PlainText:
	 data_len = strlen(passwd) + 1;
	 break;
      default:
	 call_error_handler(gwc,
			    (OSEGW_OSERRCODE)OSEGW_EUNSUPPORTED_AUTH,
			    (OSEGW_OSERRCODE)auth_type);
	 return NULL;
   }
   td = alloc_trans_mem(gwc,
			ChallengeResponse,
			strlen(passwd),
			payload_len);
   if (td == NULL)
   {
      return NULL;
   }

   td->payload.challenge_response.data_len  = htonl(data_len);

   if (auth_type == OseGW_AUT_PlainText)
   {
      strcpy(&td->payload.challenge_response.data[0], passwd);
   }
   else
   {
      /* Use challenge data & username/passwd to create a response. */
      (void)challenge_data;
      (void)challenge_data_len;
      (void)user_name;
   }
   return td;
} /* create_challenge_response */

static int
gwc_login(struct GWClient *gwc, const char *auth)
{
   int status = 0;
   const char *passwd;
   size_t user_name_len;
   OseGW_UL payload_len;
   struct OseGW_TransportData *td;

   if (!(gwc->server_flags & OseGw_SFL_UseAuthent))
   {
      /* No authentication needed. */
      return 0;
   }

   if (auth == NULL)
   {
      call_error_handler(gwc, (OSEGW_OSERRCODE)OSEGW_ELOGIN_FAILED, 0);
      return -1;
   }
   passwd = strchr(auth, ':');
   if (passwd == NULL)
   {
      call_error_handler(gwc,
			 (OSEGW_OSERRCODE)OSEGW_EBAD_PARAMETER,
			 (OSEGW_OSERRCODE)auth);
      return -1;
   }

   user_name_len = (size_t)(passwd - auth);

   /* Move passwd pointer past the ':' separator. */
   passwd++;

   td = alloc_trans_mem(gwc, LoginRequest, user_name_len, &payload_len);

   if (td == NULL)
   {
      return -1;
   }

   strncpy(&td->payload.login_request.user_name[0], auth, user_name_len);
   td->payload.login_request.user_name[user_name_len] = '\0';

   if (write_request(gwc, td, payload_len) == 0)
   {
      if (do_read_simple_reply(gwc, td,
			    sizeof(struct OseGW_TransportHdr)) == 0)
      {
	 if (htonl(td->hdr.payload_type) == OseGW_PLT_ChallengeReply)
	 {
	    struct OseGW_ChallengeReply *cr;

	    payload_len = htonl(td->hdr.payload_len);
	    cr = (struct OseGW_ChallengeReply *)malloc((size_t)payload_len);

	    if (cr == NULL)
	    {
	       call_error_handler(gwc,
				  (OSEGW_OSERRCODE)OSEGW_ENO_CLIENT_MEMORY,
				  (OSEGW_OSERRCODE)payload_len);
	       status = -1;
	    }
	    else if ((  do_read_simple_reply(gwc, cr, payload_len) == 0)
		     && check_reply_status(gwc, htonl(cr->status)) == 0)
	    {
	       char *user_name = malloc(user_name_len + 1);

	       if (user_name == NULL)
	       {
		  call_error_handler(gwc,
				     (OSEGW_OSERRCODE)OSEGW_ENO_CLIENT_MEMORY,
				     (OSEGW_OSERRCODE)user_name_len + 1);
		  status = -1;
	       }
	       else
	       {
		  memcpy(user_name, auth, user_name_len);
		  user_name[user_name_len] = '\0';
		  free(td);
		  td = create_challenge_response(gwc,
						 &payload_len,
						 ntohl(cr->auth_type),
						 user_name, passwd,
						 cr->data, cr->data_len);
		  free(user_name);
		  if ((  td == NULL)
		      || (write_request(gwc, td, payload_len) != 0))
		  {
		     status = -1;
		  }
	       }
	    }
	    else
	    {
	       status = -1;
	    }
	    if (cr != NULL)
	       free(cr);
	 }
      }
      if ((status != 0) || read_simple_reply(gwc, td, LoginReply) != 0)
      {
	 status = -1;
      }
   }
   else
   {
      status = -1;
   }
   if (td != NULL)
      free(td);
   return status;
} /* gwc_login */

static int
gwc_create(struct GWClient *gwc, const char *name, OSEGW_OSUSER user)
{
   int status = 0;
   OseGW_UL payload_len;
   struct OseGW_TransportData *td;

   if (name == NULL)
   {
      call_error_handler(gwc,
			 (OSEGW_OSERRCODE)OSEGW_EBAD_PARAMETER,
			 (OSEGW_OSERRCODE)name);
      return -1;

   }

   td = alloc_trans_mem(gwc,
		     CreateRequest,
		     strlen(name) + sizeof(struct OseGW_CreateReply),
		     &payload_len);
   if (td == NULL)
   {
      return -1;
   }

   payload_len -= sizeof(struct OseGW_CreateReply);
   td->hdr.payload_len  = htonl(payload_len);

   assert(sizeof(struct OseGW_CreateRequest)
	  + sizeof(struct OseGW_CreateReply)
	  >= sizeof(struct OseGW_CreateReply));

   td->payload.create_request.user = htonl(user);
   strcpy(&td->payload.create_request.my_name[0], name);

   if ((  write_request(gwc, td, payload_len) == 0)
       && read_simple_reply(gwc, td, CreateReply) == 0)
   {
      gwc->pid         = ntohl(td->payload.create_reply.pid);
      gwc->max_sigsize = ntohl(td->payload.create_reply.max_sigsize);

   }
   else
   {
      status = -1;
   }
   free(td);
   return status;
} /* gwc_create */

struct OSEGW *
osegw_create(const char         *my_name,
	     OSEGW_OSUSER        user,
	     const char         *gw_address,
	     const char         *user_auth,
	     OSEGW_ERRORHANDLER *err_hnd,
	     void               *usr_hd)
{
   struct GWClient *gwc = malloc(sizeof(struct GWClient));

   if (gwc == NULL)
   {
      if (err_hnd != NULL)
      {
	 err_hnd(usr_hd, NULL,
		 (OSEGW_OSERRCODE)OSEGW_ENO_CLIENT_MEMORY,
		 (OSEGW_OSERRCODE)sizeof(struct GWClient));
      }
      return NULL;
   }
   memset(gwc, 0, sizeof(struct GWClient));

   gwc->max_sigsize = (uint32_t)~0;
   gwc->err_hnd     = err_hnd;
   gwc->err_usr_hd  = usr_hd;

   if (open_server(gwc, gw_address) < 0)
   {
      free(gwc);
      return NULL;
   }

   if ((   gwc_interface(gwc) < 0)
       || (gwc_login(gwc, user_auth) < 0)
       || (gwc_create(gwc, my_name, user) < 0))
   {
      close(gwc->sd);
      free(gwc);
      gwc = NULL;
   }

#ifdef OSEGW_DEBUG
   if (gwc != NULL)
   {
      fprintf(stderr, "Created pid: %#010lx\n", gwc->pid);
   }
#endif

   return (struct OSEGW *)gwc;
} /* osegw_create */

/**********************************************************************
 *  H  A N D L E   O S E G W _ D E S T R O Y
 **********************************************************************/

void
osegw_destroy(struct OSEGW *ose_gw)
{
   struct GWClient *gwc = (struct GWClient *)ose_gw;
   OseGW_UL payload_len;
   struct OseGW_TransportData *td;
   
   if (ose_gw == NULL)
      return;

   td = alloc_trans_mem(gwc, DestroyRequest, 0, &payload_len);

   if (td != NULL)
   {
      assert(sizeof(struct OseGW_DestroyRequest) >=
	     sizeof(struct OseGW_DestroyReply));

#ifdef OSEGW_DEBUG
      fprintf(stderr, "Destroy pid: %#010lx\n", gwc->pid);
#endif

      td->payload.destroy_request.pid = htonl(gwc->pid);

      if (write_request(gwc, td, payload_len) == 0)
      {
	 (void)read_simple_reply(gwc, td, DestroyReply);
      }
      free(td);
   }
   close(((struct GWClient *)ose_gw)->sd);
   free_owned_sigs(gwc);
   free(ose_gw);
} /* osegw_destroy */

/**********************************************************************
 *  H  A N D L E   O S E G W _ H U N T
 **********************************************************************/

OSEGW_OSBOOLEAN
osegw_hunt(struct OSEGW        *ose_gw,
	   const char          *name,
	   OSEGW_OSUSER         user,
	   OSEGW_PROCESS       *pid_,
	   union OSEGW_SIGNAL **hunt_sig)
{
   struct GWClient *gwc      = (struct GWClient *)ose_gw;
   size_t           name_len = strlen(name);
   OSEGW_PROCESS    pid      = 0;
   struct GWSigAdm *sig_adm;
   OseGW_UL         data_len;
   OseGW_UL         payload_len;
   struct OseGW_TransportData *td;

   if (hunt_sig != NULL)
   {
      sig_adm = check_buffer(gwc, hunt_sig, 0);
      if(sig_adm == NULL)
	 return 0;
      data_len = sig_adm->size - sizeof(OSEGW_SIGSELECT);
   }
   else
   {
      sig_adm  = NULL;
      data_len = 0;
   }

   td = alloc_trans_mem(gwc, HuntRequest, name_len + data_len, &payload_len);

   if (td == NULL)
   {
      return OSEGW_FALSE;
   }

   assert(sizeof(struct OseGW_HuntRequest) >=
	  sizeof(struct OseGW_HuntReply));

#ifdef OSEGW_DEBUG
   fprintf(stderr, "Hunt: `%s' ", name);
#endif

   td->payload.hunt_request.user       = htonl(user);
   td->payload.hunt_request.name_index = 0;
   strcpy(&td->payload.hunt_request.data[0], name);

   if (sig_adm != NULL)
   {
      td->payload.hunt_request.sig_index  = htonl(name_len + 1);
      td->payload.hunt_request.sig_len    = htonl(sig_adm->size);
      td->payload.hunt_request.sig_no     = htonl((*hunt_sig)->sig_no);
      if (data_len != 0)
      {
	 memcpy(&td->payload.hunt_request.data[name_len + 1],
		&(((OSEGW_SIGSELECT *)(*hunt_sig))[1]),
		data_len);
      }
   }
   else
   {
      td->payload.hunt_request.sig_index = 0;
      td->payload.hunt_request.sig_len   = 0;
      td->payload.hunt_request.sig_no    = 0;
   }


   if ((  write_request(gwc, td, payload_len) == 0)
       && read_simple_reply(gwc, td, HuntReply) == 0)
   {
      pid = ntohl(td->payload.hunt_reply.pid);
      if (pid_ != NULL)
	 *pid_ = pid;

#ifdef OSEGW_DEBUG
      if (pid != 0)
	 fprintf(stderr, "found PID: %#010lx\n", pid);
      else
	 fprintf(stderr, "found nothing\n");
#endif
   }
   free(td);
   return pid != 0 ? OSEGW_TRUE : OSEGW_FALSE;
} /* osegw_hunt */

/**********************************************************************
 *  H A N D L E   O S E G W _ G E T _ P I D   /
 *  O S E G W _ A L L O C   /   O S E G W _ F R E E _ B U F   /
 *  O S E G W _ S I G S I Z E   /   O S E G W _ S E N D E R
 **********************************************************************/

OSEGW_PROCESS
osegw_get_pid(struct OSEGW *ose_gw)
{
   struct GWClient *gwc = (struct GWClient *)ose_gw;

   return ((gwc != NULL) ? gwc->pid : 0);
} /* osegw_get_pid */

union OSEGW_SIGNAL *
osegw_alloc(struct OSEGW    *ose_gw,
	    OSEGW_OSBUFSIZE  size,
	    OSEGW_SIGSELECT  sig_no)
{
   struct GWClient    *gwc     = (struct GWClient *)ose_gw;
   size_t              need    = sizeof(struct GWSigAdm)
				 + sizeof(OSEGW_SIGSELECT)
				 + size
				 + 1; /* For the endmark. */
   struct GWSigAdm    *sig_adm;
   union OSEGW_SIGNAL *sig;

   if (size < sizeof(OSEGW_SIGSELECT))
   {
       size = sizeof(OSEGW_SIGSELECT);
   }

   sig_adm = malloc(need);
   if (sig_adm == NULL)
   {
      call_error_handler(gwc,
			 (OSEGW_OSERRCODE)OSEGW_ENO_USER_SIGSPACE,
			 (OSEGW_OSERRCODE)need);
      return NULL;
   }
   sig_adm->magic_signo = MAGIC_SIGNO;
   sig_adm->size        = size;
   sig_adm->dest_id     = gwc->pid;
   sig_adm->sender_id   = gwc->pid;
   sig_adm->res0        = 0xCCCCCCCC;
   link_sig_owner(gwc, sig_adm);

   sig = adm_to_sig(sig_adm);
   sig->sig_no = sig_no;
   ((unsigned char *)sig)[size] = END_MARK;

   return sig;
} /* osegw_alloc */

void
osegw_free_buf(struct OSEGW        *ose_gw,
	       union OSEGW_SIGNAL **sig)
{
   struct GWClient *gwc      = (struct GWClient *)ose_gw;
   struct GWSigAdm *sig_adm  = check_buffer(gwc, sig, 0);

   if(sig_adm == NULL)
      return;

   /* Take signal pointer from user. */
   *sig = OSEGW_NIL;

   adm_free_buf(gwc, sig_adm);
} /* osegw_free_buf */

OSEGW_OSBUFSIZE
osegw_sigsize(struct OSEGW        *ose_gw,
	      union OSEGW_SIGNAL **sig)
{
   struct GWClient *gwc      = (struct GWClient *)ose_gw;
   struct GWSigAdm *sig_adm  = check_buffer(gwc, sig, 0);

   if(sig_adm == NULL)
      return 0;
   else
      return sig_adm->size;
} /* osegw_sigsize */

OSEGW_PROCESS
osegw_sender(struct OSEGW *ose_gw,
	     union OSEGW_SIGNAL **sig)
{
   struct GWClient *gwc      = (struct GWClient *)ose_gw;
   struct GWSigAdm *sig_adm  = check_buffer(gwc, sig, 0);

   if(sig_adm == NULL)
      return 0;
   else
      return sig_adm->sender_id;
} /* osegw_sender */

/**********************************************************************
 *  H A N D L E   O S E G W _ S E N D   /   O S E G W _ S E N D _ W _ S
 **********************************************************************/

void
osegw_send(struct OSEGW        *ose_gw,
	   union OSEGW_SIGNAL **sig,
	   OSEGW_PROCESS        pid)
{
   osegw_send_w_s(ose_gw, sig, 0, pid); /* From me! */
} /* osegw_send */

void
osegw_send_w_s(struct OSEGW        *ose_gw,
	       union OSEGW_SIGNAL **sig,
	       OSEGW_PROCESS        from,
	       OSEGW_PROCESS        to)
{
   struct GWClient *gwc      = (struct GWClient *)ose_gw;
   struct GWSigAdm *sig_adm  = check_buffer(gwc, sig, 0);
   OseGW_UL         data_len;
   OseGW_UL         payload_len;
   struct OseGW_TransportData *td;

   if (sig_adm == NULL)
      return;

   data_len = sig_adm->size - sizeof(OSEGW_SIGSELECT);
   td = alloc_trans_mem(gwc, SendRequest, data_len, &payload_len);

   if (td == NULL)
   {
      return;
   }

   assert(sizeof(struct OseGW_SendRequest) >=
	  sizeof(struct OseGW_SendReply));

   td->payload.send_request.dest_pid = htonl(to);
   td->payload.send_request.from_pid = htonl(from);
   td->payload.send_request.sig_len  = htonl(sig_adm->size);
   td->payload.send_request.sig_no   = htonl((*sig)->sig_no);
   if (data_len != 0)
   {
      memcpy(&td->payload.send_request.sig_data[0],
	     &(((OSEGW_SIGSELECT *)(*sig))[1]),
	     data_len);
   }

   /* Take signal pointer from user. */
   *sig = OSEGW_NIL;

   adm_free_buf(gwc, sig_adm);

   if (write_request(gwc, td, payload_len) == 0)
   {
      (void)read_simple_reply(gwc, td, SendReply);
   }

   free(td);
} /* osegw_send_w_s */

/**********************************************************************
 *  H  A N D L E   O S E G W _ R E C E I V E _ W _ T M O
 **********************************************************************/

static int
send_receive_request(struct OSEGW          *ose_gw,
		     OSEGW_OSTIME           tmo,
		     const OSEGW_SIGSELECT *sig_sel)
{
   struct GWClient    *gwc = (struct GWClient *)ose_gw;
   int                 sigsel_elems = 0;
   OseGW_UL            payload_len;
   struct OseGW_TransportData *td;
   int count;

   if (sig_sel != NULL)
   {
      count = sig_sel[0];  
      sigsel_elems = (count < 0 ? -count :  count);
   }

   td = alloc_trans_mem(gwc, ReceiveRequest,
			sizeof(OseGW_UL) * (size_t)sigsel_elems,
			&payload_len);
   if (td == NULL)
   {
      return -1;
   }

   td->payload.receive_request.timeout = htonl(tmo);

   if (sig_sel != NULL)
   {
      int i = sigsel_elems;

      td->payload.receive_request.sigsel_len = (OseGW_UL)htonl(sigsel_elems
							       + 1);

      while (i >= 0)
      {
	 td->payload.receive_request.sigsel_list[i] = htonl(sig_sel[i]);
	 --i;
      }
   }
   else
   {
      td->payload.receive_request.sigsel_len     = 0;
      td->payload.receive_request.sigsel_list[0] = 0;
   }

   (void)write_request(gwc, td, payload_len);

   free(td);
   return 0;
} /* send_receive_request */

void *
osegw_get_blocking_object(struct OSEGW    *ose_gw,
                          OSEGW_OSADDRESS *type)
{
   struct GWClient *gwc = (struct GWClient *)ose_gw;

   if (type != NULL)
   {
      *type = OSEGW_BO_SOCKET;
   }
   return (void *)&gwc->sd;
} /* osegw_get_blocking_object */

void
osegw_init_async_receive(struct OSEGW          *ose_gw,
			  const OSEGW_SIGSELECT *sig_sel)
{
   (void)send_receive_request(ose_gw, (uint32_t)~0, sig_sel);
} /* osegw_init_async_receive */

union OSEGW_SIGNAL *
osegw_async_receive(struct OSEGW *ose_gw)
{
   struct GWClient    *gwc = (struct GWClient *)ose_gw;
   union OSEGW_SIGNAL *sig = OSEGW_NIL;
   struct OseGW_TransportData td;

   if (do_blocking_read_simple_reply(gwc, &td,
			    sizeof(struct OseGW_TransportHdr)) == 0)
   {
      if (htonl(td.hdr.payload_type) == OseGW_PLT_ReceiveReply)
      {
	 OseGW_UL                   payload_len = htonl(td.hdr.payload_len);
	 struct OseGW_ReceiveReply *rr =
	    (struct OseGW_ReceiveReply *)malloc((size_t)payload_len);

	 if (rr == NULL)
	 {
	    call_error_handler(gwc,
			       (OSEGW_OSERRCODE)OSEGW_ENO_CLIENT_MEMORY,
			       (OSEGW_OSERRCODE)payload_len);
	 }
	 else if ((  do_blocking_read_simple_reply(gwc, rr, payload_len) == 0)
		  && check_reply_status(gwc, htonl(rr->status)) == 0)
	 {
	    OseGW_UL sig_len = ntohl(rr->sig_len);

	    if (sig_len != 0)
	    {
	       sig = osegw_alloc(ose_gw, sig_len, ntohl(rr->sig_no));

	       if (sig != OSEGW_NIL)
	       {
		  sig_to_adm(sig)->sender_id = ntohl(rr->sender_pid);
		  sig_to_adm(sig)->dest_id   = ntohl(rr->addressee_pid);
		  if (sig_len > sizeof(OSEGW_SIGSELECT))
		  {
			  memcpy(&(((OSEGW_SIGSELECT *)sig)[1]),
			    &rr->sig_data[0],
			    sig_len - sizeof(OSEGW_SIGSELECT));
		  }
	       }
	    }
	 }
	 if (rr != NULL)
	    free(rr);
      }
   }
   return sig;
} /* osegw_async_receive */

union OSEGW_SIGNAL *
osegw_cancel_async_receive(struct OSEGW *ose_gw)
{
   union OSEGW_SIGNAL *sig = OSEGW_NIL;

   if (send_receive_request(ose_gw, (uint32_t)~0, NULL) == 0)
   {
      sig = osegw_async_receive(ose_gw);
      if(sig != OSEGW_NIL)
      {
         /*
          * The gateway server had obviously already sent a "too late to cancel"
          * signal back to us. Which means that we need to do another
          * osegw_async_receive() call in order to stay in sync with the gateway
          * server. This osegw_async_receive() call will read out the "cancel reply"
          * which carry no signal data, thus the (void) cast.
          */
	 (void)osegw_async_receive(ose_gw);
      }
   }
   return sig;
} /* osegw_cancel_async_receive */

union OSEGW_SIGNAL *
osegw_receive(struct OSEGW          *ose_gw,
	      const OSEGW_SIGSELECT *sig_sel)
{
   return (send_receive_request(ose_gw, (uint32_t)~0, sig_sel) == 0)
      ? osegw_async_receive(ose_gw)
      : OSEGW_NIL;
} /* osegw_receive */

union OSEGW_SIGNAL *
osegw_receive_w_tmo(struct OSEGW          *ose_gw,
		    OSEGW_OSTIME           tmo,
		    const OSEGW_SIGSELECT *sig_sel)
{
   tmo &= (((uint32_t)~0) >> 1);

   return (send_receive_request(ose_gw, tmo, sig_sel) == 0)
      ? osegw_async_receive(ose_gw)
      : OSEGW_NIL;
} /* osegw_receive_w_tmo */

/**********************************************************************
 *  H  A N D L E   O S E G W _ A T T A C H   /    D E T A C H
 **********************************************************************/

OSEGW_OSATTREF
osegw_attach(struct OSEGW        *ose_gw,
	     union OSEGW_SIGNAL **sig,
	     OSEGW_PROCESS        pid)
{
   struct GWClient *gwc = (struct GWClient *)ose_gw;
   struct GWSigAdm *sig_adm;
   OseGW_UL         data_len;
   OseGW_UL         payload_len;
   struct OseGW_TransportData *td;

   if (sig != NULL)
   {
      sig_adm = check_buffer(gwc, sig, 0);
      if(sig_adm == NULL)
	 return 0;
      data_len = sig_adm->size - sizeof(OSEGW_SIGSELECT);
   }
   else
   {
      sig_adm  = NULL;
      data_len = 0;
   }

   td = alloc_trans_mem(gwc, AttachRequest, data_len, &payload_len);

   if (td == NULL)
   {
      return 0;
   }

   assert(sizeof(struct OseGW_AttachRequest) >=
	  sizeof(struct OseGW_AttachReply));

   td->payload.attach_request.pid = htonl(pid);

   if (sig_adm != NULL)
   {
      td->payload.attach_request.sig_len = htonl(sig_adm->size);
      td->payload.attach_request.sig_no  = htonl((*sig)->sig_no);
      if (data_len != 0)
      {
	 memcpy(&td->payload.attach_request.sig_data[0],
		&(((OSEGW_SIGSELECT *)(*sig))[1]),
		data_len);
      }

      /* Take signal pointer from user. */
      *sig = OSEGW_NIL;

      adm_free_buf(gwc, sig_adm);
   }
   else
   {
      td->payload.attach_request.sig_len     = 0;
      td->payload.attach_request.sig_no      = 0;
      td->payload.attach_request.sig_data[0] = 0;
   }

   if ((  write_request(gwc, td, payload_len) == 0)
       && read_simple_reply(gwc, td, AttachReply) == 0)
   {
      OSEGW_OSATTREF attref = ntohl(td->payload.attach_reply.attref);

      free(td);
      return attref;
   }
   else
   {
      free(td);
      return 0;
   }
} /* osegw_attach */

void
osegw_detach(struct OSEGW   *ose_gw,
	     OSEGW_OSATTREF *attref)
{
   struct GWClient *gwc = (struct GWClient *)ose_gw;
   OseGW_UL         payload_len;
   struct OseGW_TransportData *td;

   if (attref == NULL || *attref == 0xFFFFDEAD)
   {
      call_error_handler(gwc, (OSEGW_OSERRCODE)OSEGW_EDETACHED_TWICE, 0);
      return;
   }

   td = alloc_trans_mem(gwc, DetachRequest, 0, &payload_len);

   if (td == NULL)
   {
      return;
   }

   assert(sizeof(struct OseGW_DetachRequest) >=
	  sizeof(struct OseGW_DetachReply));

   td->payload.detach_request.attref = htonl(*attref);

   /* Set the users attref value in order to detect multiple
    * detach calls.
    */
   *attref  = 0xFFFFDEAD;

   if (write_request(gwc, td, payload_len) == 0)
   {
      (void)read_simple_reply(gwc, td, DetachReply);
   }
   free(td);
} /* osegw_detach */
