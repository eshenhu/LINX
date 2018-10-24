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

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>

#include <linx.h>

#include "linxgws_msghandler.h"
#include "linxgws.h"

static unsigned long elapsed_msec(struct timeval *from)
{
        struct timeval now;

        (void)gettimeofday(&now, 0);
        if (now.tv_usec >= from->tv_usec) {
                return (now.tv_sec - from->tv_sec) * 1000 +
                        (now.tv_usec - from->tv_usec) / 1000;
        } else {
                return (now.tv_sec - 1 - from->tv_sec) * 1000 +
                        (now.tv_usec + 1000000 - from->tv_usec) / 1000;
        }
}

static struct timeval *msec_to_timeval(unsigned long msec, struct timeval *t)
{
        t->tv_sec = msec / 1000;
        t->tv_usec = (msec % 1000) * 1000;
        return t;
}
static void recalc_tmo(unsigned long tmo, struct timeval *t0, struct timeval *t)
{
        unsigned long dt;

        dt = elapsed_msec(t0);
        dt = (dt < tmo) ? tmo - dt : 0;
        (void)msec_to_timeval(dt, t);
}

static LINX_SIGSELECT *copy_sigselect(struct OseGW_ReceiveRequest *p)
{
        LINX_SIGSELECT *sigsel;
        size_t sigsel_len;
        int n;

        sigsel_len = ntohl(p->sigsel_len);

        if (sigsel_len == 0)
                return NULL;

        if (sigsel_len == 1)
                return calloc(1, sizeof(LINX_SIGSELECT)); /* Any signal */

        sigsel = malloc(sigsel_len * sizeof(LINX_SIGSELECT));
        if (sigsel == NULL) {
                syslog(LOG_ERR, "malloc failed");
                return NULL;
        }
        for (n = 0; n < (int)sigsel_len; n++)
                *(sigsel + n) = ntohl(p->sigsel_list[n]);

        return sigsel;
}

static int set_sigselect(int s, const LINX_SIGSELECT *sigsel)
{
        struct linx_receive_filter_param rfp;

        rfp.from = LINX_ILLEGAL_SPID;
        rfp.sigselect_size = (*sigsel + 1) * sizeof(LINX_SIGSELECT);
        rfp.sigselect = sigsel;

        return ioctl(s, LINX_IOCTL_SET_RECEIVE_FILTER, &rfp);
}

static void *get_command(int s, struct OseGW_TransportHdr *hdr)
{
        void *buf;

        if (recv_data(s, hdr, sizeof(*hdr)) == -1)
                return NULL;

        hdr->payload_type = ntohl(hdr->payload_type);
        hdr->payload_len = ntohl(hdr->payload_len);

        buf = malloc(hdr->payload_len);
        if (buf == NULL)
                return NULL;

        if (recv_data(s, buf, hdr->payload_len) == -1) {
                free(buf);
                return NULL;
        }
        return buf;
}

int OseGW_PLT_GenericErrorReply_cbk(int skt, int len, char *payload,
				    struct ClientInfo *cinfo)
{
	return 0;
}

int OseGW_PLT_InterfaceRequest_cbk(int skt, int len, char *payload,
				   struct ClientInfo *cinfo)
{
	struct OseGW_InterfaceRequest *interface_request = NULL;

	interface_request = (struct OseGW_InterfaceRequest *)payload;
	cinfo->client_version = ntohl(interface_request->cli_version);
	cinfo->client_flags = ntohl(interface_request->cli_flags);
	LOG("Linux Gateway daemon client requests interface "
            "specs on socket: %d version: %d flags:%d", skt,
            (int)cinfo->client_version, (int)cinfo->client_flags);

	/* Send the reply */
	return OseGW_PLT_InterfaceReply_cbk(skt, 0, NULL, cinfo);
}

int OseGW_PLT_InterfaceReply_cbk(int skt, int len, char *payload,
				 struct ClientInfo *cinfo)
{
#define NO_OF_PLT 10UL
	OseGW_UL payload_len =
		(sizeof(struct OseGW_InterfaceReply) +
		 (sizeof(OseGW_UL) * (NO_OF_PLT - 1UL)));
	struct OseGW_TransportData *reply = NULL;
	int status = 0;
	int size = 0;

	size = sizeof(struct OseGW_TransportData) + payload_len;
	reply = (struct OseGW_TransportData *)malloc(size);
	if (reply == NULL)
		return -1;

	/* Filling the header */
	reply->hdr.payload_type = htonl(OseGW_PLT_InterfaceReply);
	reply->hdr.payload_len = htonl(payload_len);
	/* Filling the payload */
	reply->payload.interface_reply.status = htonl(OseGW_StatusOk);
	reply->payload.interface_reply.srv_version =
		htonl(OseGW_ProtocolVersion);
	reply->payload.interface_reply.srv_flags =
		htonl(gw_server_flags());
	reply->payload.interface_reply.types_len = htonl(NO_OF_PLT);
	/* Filling the interface specs */
	reply->payload.interface_reply.payload_types[0] =
		htonl(OseGW_PLT_InterfaceRequest);
	reply->payload.interface_reply.payload_types[1] =
		htonl(OseGW_PLT_NameRequest);
	reply->payload.interface_reply.payload_types[2] =
		htonl(OseGW_PLT_LoginRequest);
	reply->payload.interface_reply.payload_types[3] =
		htonl(OseGW_PLT_CreateRequest);
	reply->payload.interface_reply.payload_types[4] =
		htonl(OseGW_PLT_DestroyRequest);
	reply->payload.interface_reply.payload_types[5] =
		htonl(OseGW_PLT_SendRequest);
	reply->payload.interface_reply.payload_types[6] =
		htonl(OseGW_PLT_ReceiveRequest);
	reply->payload.interface_reply.payload_types[7] =
		htonl(OseGW_PLT_HuntRequest);
	reply->payload.interface_reply.payload_types[8] =
		htonl(OseGW_PLT_AttachRequest);
	reply->payload.interface_reply.payload_types[9] =
		htonl(OseGW_PLT_DetachRequest);
	size = sizeof(struct OseGW_TransportHdr) + payload_len;
	status = send(skt, reply, size, 0);
	if (status == size) {
		LOG("Gateway Client: replying interface "
                    "specs on socket %d",skt);
	} else {
		syslog(LOG_INFO, "Linux Gateway daemon failed replying "
		       "interface on socket %d", skt);
		status = -1;
	}

	free(reply);
	return status;
}

int OseGW_PLT_LoginRequest_cbk(int skt, int len, char *payload,
                               struct ClientInfo *cinfo)
{
	return 0;
}

int OseGW_PLT_ChallengeResponse_cbk(int skt, int len, char *payload,
                                    struct ClientInfo *cinfo)
{
	return 0;
}

int OseGW_PLT_ChallengeReply_cbk(int skt, int len, char *payload,
                                 struct ClientInfo *cinfo)
{
	return 0;
}

int OseGW_PLT_LoginReply_cbk(int skt, int len, char *payload,
                             struct ClientInfo *cinfo)
{
	return 0;
}

int OseGW_PLT_CreateRequest_cbk(int skt, int len,
				char *payload, struct ClientInfo *cinfo)
{
	struct OseGW_CreateRequest *create_request =
		(struct OseGW_CreateRequest *) payload;
	OSUSER user;

	LOG("CreateRequests  on skt: %d version: %d "
            "flags:%d from %s",skt, (int) cinfo->client_version,
            (int) cinfo->client_flags, create_request->my_name);

	user = ntohl(create_request->user);
	cinfo->status = OseGW_StatusOk;

	/* Sending reply */
	return OseGW_PLT_CreateReply_cbk(skt, len, payload, cinfo);
}

int OseGW_PLT_CreateReply_cbk(int skt, int len, char *payload,
                              struct ClientInfo *cinfo)
{

	OseGW_UL payload_len = sizeof(struct OseGW_CreateReply);
	struct OseGW_TransportData *reply = NULL;
	struct OseGW_CreateRequest *create_request =
		(struct OseGW_CreateRequest *) payload;
	PROCESS pid = 0;
	int status = 0;
	int size = 0;

	size = sizeof(struct OseGW_TransportHdr) + payload_len;
	reply = (struct OseGW_TransportData *) malloc(size);
	if (reply == NULL) {
		return -1;
	}

	/* Fill the header */
	reply->hdr.payload_type = htonl(OseGW_PLT_CreateReply);
	reply->hdr.payload_len = htonl(payload_len);
	/* Fill the payload */
	reply->payload.create_reply.status = htonl(cinfo->status);
	reply->payload.create_reply.max_sigsize = htonl(MAX_SIGSIZE);
	cinfo->sd = skt;
	cinfo->linx = NULL;
	cinfo->linx = linx_open(create_request->my_name, 0, 0);
	if (cinfo ->linx == NULL) {
		syslog(LOG_ERR, "linx_open() failed");
		free(reply);
		return -1;
	}

	pid = linx_get_spid(cinfo->linx);
	cinfo->curr_pid = pid;
	reply->payload.create_reply.pid = htonl(pid);
	/*Send */
	size = sizeof(struct OseGW_TransportHdr) + payload_len;
	status = send(skt, (void *) reply, size, 0);
	if (status == size) {
		LOG("Gateway Client: replying CreateReply "
                    "on socket %d", skt);
	} else {
		syslog(LOG_INFO, "Gateway Client: failed replying "
		       "CreateReply on socket %d", skt);
		status = -1;
	}

	free(reply);
	return status;
}

int OseGW_PLT_DestroyRequest_cbk(int skt, int len, char *payload,
				 struct ClientInfo *cinfo)
{

	return OseGW_PLT_DestroyReply_cbk(skt, len, payload, cinfo);
}

int OseGW_PLT_DestroyReply_cbk(int skt, int len, char *payload,
			       struct ClientInfo *cinfo)
{
	OseGW_UL payload_len = sizeof(struct OseGW_DestroyReply);
	struct OseGW_TransportData *reply = NULL;
	struct OseGW_DestroyRequest *destroy_request = NULL;
	int status = 0;
	int size = 0;

	destroy_request = (struct OseGW_DestroyRequest *) payload;
	size = sizeof(struct OseGW_TransportHdr) + payload_len;
	reply = (struct OseGW_TransportData *) malloc(size);
	if (reply == NULL) {
		return -1;
	}

	reply->hdr.payload_type = htonl(OseGW_PLT_DestroyReply);
	reply->hdr.payload_len = htonl(sizeof(struct OseGW_DestroyReply));
	if (ntohl(destroy_request->pid) == cinfo->curr_pid) {
		LOG("Gateway Client: Destroy: pid: %d",
                    cinfo->curr_pid);
		reply->payload.destroy_reply.status =
			htonl(OseGW_StatusOk);
	} else {
		LOG("Gateway Client: Destroy: "
                    "<unknown pid: %#lx>\n",
                    (long unsigned int) ntohl(destroy_request->pid));
		reply->payload.destroy_reply.status =
			(uint32_t)htonl((uint32_t)OseGW_StatusErr);
	}
	size = sizeof(struct OseGW_TransportHdr) + payload_len;
	status = send(skt, (void *) reply, size, 0);
	if (status == size) {
		LOG("Gateway Client: replying DestroyReply "
                    "on socket %d", skt);
	} else {
		syslog(LOG_INFO,"Gateway Client: failed replying"
		       " DestroyReply on socket %d", skt);
	}

	free(reply);
	close(cinfo->sd);
	linx_close(cinfo->linx);
	exit(EXIT_SUCCESS);
}

int OseGW_PLT_SendRequest_cbk(int skt, int len, char *payload,
			      struct ClientInfo *cinfo)
{
	struct OseGW_SendRequest *send_request = NULL;
	union LINX_SIGNAL *signal;
	int status = 0;

	send_request = (struct OseGW_SendRequest *) payload;
	send_request->dest_pid = ntohl(send_request->dest_pid);
	send_request->from_pid = ntohl(send_request->from_pid);
	send_request->sig_len = ntohl(send_request->sig_len);
	signal = linx_alloc(cinfo->linx, send_request->sig_len,
		            ntohl(send_request->sig_no));
	if (signal == LINX_NIL) {
		syslog(LOG_ERR, "Linx alloc failed at Send request");
		return -1;
	}

	memcpy(&((char *) signal)[sizeof(SIGSELECT)],
	       send_request->sig_data,
	       send_request->sig_len - sizeof(SIGSELECT));
	if (send_request->from_pid == 0) {
		status = linx_send(cinfo->linx, &signal,send_request->dest_pid);

	} else {
		status = linx_send_w_s(cinfo->linx, &signal,
			               send_request->from_pid,
			               send_request->dest_pid);

	}
	if (status == -1) {
		/* signals sent to closed endpoints are silently discarded */
		if (errno == ECONNRESET || errno == EPIPE) {
			status = 0;
		} else {
			syslog(LOG_ERR, "Error sending signal to pid %x (%s)",
			       (int) send_request->dest_pid, strerror(errno));
			return status;
		}
	}

	LOG(" Sent signal: %#x to pid: %#x\n",
            (int) ntohl(send_request->sig_no),
            (int) send_request->dest_pid);
	status = OseGW_PLT_SendReply_cbk(skt, len, payload, cinfo);
	return status;
}

int OseGW_PLT_SendReply_cbk(int skt, int len, char *payload,
                            struct ClientInfo *cinfo)
{
	OseGW_UL payload_len = sizeof(struct OseGW_SendReply);
	struct OseGW_TransportData *reply = NULL;
	int status = 0;
	int size = 0;

	size = sizeof(struct OseGW_TransportHdr) + payload_len;
	reply = (struct OseGW_TransportData *) malloc(size);
	/*Fill the header */
	reply->hdr.payload_type = htonl(OseGW_PLT_SendReply);
	reply->hdr.payload_len = htonl(sizeof(struct OseGW_SendReply));
	/*Fill the payload */
	reply->payload.send_reply.status = htonl(cinfo->status);
	/*Send */
	size = sizeof(struct OseGW_TransportHdr) + payload_len;
	status = send(skt, (void *) reply, size, 0);
	if (status == size) {
	        LOG("Linux Gateway daemon replying SendReply "
                    "on socket %d", skt);
	} else {
		syslog(LOG_INFO, "Linux Gateway daemon failed replying "
		       "SendReply on skt %d", skt);
		status = -1;
	}
	free(reply);
	return status;
}

/*
 * We end up here due to a osegw_receive, osegw_receive_w_tmo or
 * osegw_init_async_receive. While we are waiting for a signal,
 * we must be able to handle "pings" and osegw_cancel_async_receive
 * from the client.
 */
int OseGW_PLT_ReceiveRequest_cbk(int skt, int len, char *payload,
                                 struct ClientInfo *cinfo)
{
	struct OseGW_ReceiveRequest *req;
        struct OseGW_TransportHdr thdr;
        union LINX_SIGNAL *sig;
        LINX_SIGSELECT *sigsel = NULL;
        int nfds, status, size = 0, linx_skt, sigsel_len;
        fd_set rfds;
        struct timeval tv0, tv, *tvp;
        unsigned int tmo;
        void *buf;

        linx_skt = linx_get_descriptor(cinfo->linx);
	req = (struct OseGW_ReceiveRequest *)payload;
        sigsel_len = ntohl(req->sigsel_len);
        buf = NULL;

        /* 0. This may be a osegw_cancel_async_receive... */
        if (sigsel_len == 0) {
                sig = NULL;
                size = 0;
                goto out;
        }

        /* 1. Setup signal filter that should be used while polling... */
        sigsel = copy_sigselect(req);
        if (sigsel == NULL)
                goto e_exit;
        if (set_sigselect(linx_skt, sigsel) == -1)
                goto e_exit;

        /* 2. Setup time-out... */
	tmo = ntohl(req->timeout);
        if (tmo != (unsigned int)~0) {
                tvp = msec_to_timeval(tmo, &tv);
                if (gettimeofday(&tv0, NULL) == -1)
                        goto e_exit;
        } else
                tvp = NULL; /* Infinite */

  again:

        /* 3. Setup descriptors... */
        FD_ZERO(&rfds);
        FD_SET(linx_skt, &rfds); /* LINX socket */
        FD_SET(skt, &rfds);      /* TCP socket */
        nfds = linx_skt > skt ? linx_skt : skt;

        /* 4. Wait for a signal, ping or osegw_cancel_async_receive */
        status = select(nfds + 1, &rfds, NULL, NULL, tvp);
        if (status == -1)
                goto e_exit;

        if (status == 0) {
                /* osegw_receive_w_tmo has timed out */
                sig = NULL;
                size = 0;
                goto out;
        }

        if (FD_ISSET(linx_skt, &rfds)) {
                /* A signal that matches the signal filter is available */
                status = linx_receive(cinfo->linx, &sig, sigsel);
                if (status == -1)
                        goto e_exit;
                size = linx_sigsize(cinfo->linx, &sig) - sizeof(SIGSELECT);
                goto out;
        }

        if (FD_ISSET(cinfo->sd, &rfds)) {
                /* Get command */
                buf = get_command(skt, &thdr);
                if (buf == NULL)
                        goto e_exit;

                switch (thdr.payload_type) {
                case OseGW_PLT_InterfaceRequest:
                        status = OseGW_PLT_InterfaceRequest_cbk(skt, thdr.payload_len, buf, cinfo);
                        if (status == -1)
                                goto e_exit;
                        /* Compensate for the time spent in select */
                        if (tvp != NULL)
                                recalc_tmo(tmo, &tv0, &tv);
                        goto again;
                        break;
                case OseGW_PLT_ReceiveRequest:
                        req = (struct OseGW_ReceiveRequest *)buf;
                        sigsel_len = ntohl(req->sigsel_len);
                        if (sigsel_len != 0)
                                goto e_exit; /* Only cancel async receive is allowed */
                        sig = NULL;
                        size = 0;
                        goto out;
                        break;
                default:
                        syslog(LOG_INFO, "Gateway protocol violation detected, "
                               "got type %d while in a receive", thdr.payload_type);
                        goto e_exit;
                        break;
                }
        }
  out:
        free(buf);
        free(sigsel);
        return OseGW_PLT_ReceiveReply_cbk(skt, size, (char *)sig, cinfo);

  e_exit:
        free(buf);
        free(sigsel);
        return -1;
}

int OseGW_PLT_ReceiveReply_cbk(int skt, int len, char *payload,
                               struct ClientInfo *cinfo)
{
	OseGW_UL payload_len = sizeof(struct OseGW_ReceiveReply) + len;
	struct OseGW_TransportData *reply;
	union LINX_SIGNAL *signal = (union LINX_SIGNAL *)payload;
	int status = 0;
	int size;

	size = sizeof(struct OseGW_TransportHdr) + payload_len;
	reply = malloc(size);
	if (reply == NULL) {
		syslog(LOG_ERR, "Malloc failure in Receive reply");
		return -1;
	}

	reply->hdr.payload_type = htonl(OseGW_PLT_ReceiveReply);
	reply->hdr.payload_len = htonl(payload_len);

	if (signal != LINX_NIL) {
		/*Fill the payload */
		reply->payload.receive_reply.status = htonl(OseGW_StatusOk);
		reply->payload.receive_reply.sender_pid =
			htonl(linx_sender(cinfo->linx, &signal));
		reply->payload.receive_reply.addressee_pid =
			htonl(cinfo->curr_pid);
		reply->payload.receive_reply.sig_len =
			htonl(len + sizeof(SIGSELECT));
		reply->
		  payload
		  .receive_reply
		  .sig_no = htonl(
				  signal->sig_no);
		memcpy(&reply->payload.receive_reply.sig_data[0],
		       &(((SIGSELECT *) signal)[1]), len);
	} else {
		/* Fill the payload */
		syslog(LOG_ERR, " Received timeout (or was canceled)\n");
		size = sizeof(struct OseGW_ReceiveReply);
		memset(&reply->payload.start_of_payload, 0, size);
		reply->payload.receive_reply.status = htonl(OseGW_StatusOk);
	}

	/*Send */
	size = sizeof(struct OseGW_TransportHdr) + payload_len;
	status = send(skt, (void *) reply, size, 0);
	if (status == size) {
		LOG("Gateway Client: replying ReceiveReply "
                    "on socket %d", skt);
	} else {
		syslog(LOG_INFO, "Gateway Client: failed replying "
		       "ReceiveReply on socket %d",  skt);
		status = -1;
	}

	/* Clean up */
	if (signal != LINX_NIL) {
		linx_free_buf(cinfo->linx, &signal);
	}
	free(reply);
	return status;
}

int OseGW_PLT_HuntRequest_cbk(int skt, int len, char *payload,
                              struct ClientInfo  *cinfo)
{

	return OseGW_PLT_HuntReply_cbk(skt, len, payload, cinfo);
}

int OseGW_PLT_HuntReply_cbk(int skt, int len, char *payload,
                            struct ClientInfo *cinfo)
{
	OseGW_UL payload_len = sizeof(struct OseGW_HuntReply);
	struct OseGW_TransportData *reply = NULL;
	struct OseGW_HuntRequest *hunt_request =
		(struct OseGW_HuntRequest *) payload;
	union LINX_SIGNAL *hunt_sig = NULL;
	const LINX_SIGSELECT hunt_sigsel[] = { 1, LINX_OS_HUNT_SIG };
	LINX *gws_hunter;
	PROCESS pid = 0;
	int status = 0;
	int size = 0;

	/*Fill the header */
	size = sizeof(struct OseGW_TransportHdr) + payload_len;
	reply = (struct OseGW_TransportData *) malloc(size);
	if (reply == NULL) {
		syslog(LOG_ERR, "Malloc failure in Hunt reply");
		return -1;
	}
	reply->hdr.payload_type = htonl(OseGW_PLT_HuntReply);
	reply->hdr.payload_len = htonl(sizeof(struct OseGW_HuntReply));
	/* Fill the payload */
	hunt_request->user = ntohl(hunt_request->user);
	hunt_request->sig_len = ntohl(hunt_request->sig_len);
	hunt_request->name_index = ntohl(hunt_request->name_index);
	if (hunt_request->sig_len != 0) {
		hunt_sig = linx_alloc(cinfo->linx, hunt_request->sig_len,
				      ntohl(hunt_request->sig_no));
		if (hunt_sig == LINX_NIL) {
			syslog(LOG_ERR, "Linx alloc failed in Hunt reply");
			free(reply);
			return -1;
		}
		size = hunt_request->sig_len - sizeof(SIGSELECT);
		memcpy(&((char *) hunt_sig)[sizeof(SIGSELECT)],
		       &hunt_request->
		       data[ntohl(hunt_request->sig_index)], size);
		/*
		 * This hunt sig will be returned to caller or be cleaned
		 * up when caller closes the gateway socket.
		 */
		status = linx_hunt(cinfo->linx,
				   &hunt_request->data
				   [hunt_request->name_index],
				   &hunt_sig);

		if (status == -1) {
			free(reply);
			return status;
		}
	}

	/*
	 * The gateway hunt(...) returns the pid of the hunted process if the
	 * process exist when the hunt is done. The LINX hunt(...) does not so
	 * a hunt/receive_w_tmo/sender is done to get the pid. The gws_hunter
	 * socket is opened to prevent at client from flooding the gw server
	 * with hunt requests that could lead to out-of-memory in the LINX
	 * kernel module. If the hunted process does not exist the hunt is
	 * cleaned up when the gws_hunter socket is closed.
	 */

	gws_hunter = linx_open("gws_hunter", 0, NULL);
	status = linx_hunt(gws_hunter,
			   &hunt_request->data[hunt_request->name_index],
			   NULL);
	if (status == -1) {
	        free(reply);
	        return status;
	}

	status = linx_receive_w_tmo(gws_hunter, &hunt_sig, 0, hunt_sigsel);
	if (status == -1) {
		free(reply);
		return status;
	}

	if (hunt_sig != LINX_NIL) {
		pid = linx_sender(gws_hunter, &hunt_sig);
		if (pid == LINX_ILLEGAL_SPID) {
			free(reply);
			return -1;
		}
		linx_free_buf(gws_hunter, &hunt_sig);
	}
	/* free up the "hunt" */
	linx_close(gws_hunter);

	reply->payload.hunt_reply.status = htonl(cinfo->status);
	reply->payload.hunt_reply.pid = htonl(pid);
	/*Send */
	size = sizeof(struct OseGW_TransportHdr) + payload_len;
	status = send(skt, (void *) reply, size, 0);
	if (status == size) {
		LOG("Gateway Client: replying HuntReply "
                    "on socket %d", skt);
	} else {
		syslog(LOG_INFO, "Gateway Clinet: failed replying "
		       "HuntReply on socket %d", skt);
		status = -1;
	}
	free(reply);
	return status;
}

int OseGW_PLT_AttachRequest_cbk(int skt, int len, char *payload,
                                struct ClientInfo *cinfo)
{
	return OseGW_PLT_AttachReply_cbk(skt, len, payload, cinfo);
}

int OseGW_PLT_AttachReply_cbk(int skt, int len, char *payload,
                              struct ClientInfo *cinfo)
{
	OseGW_UL payload_len = sizeof(struct OseGW_AttachReply);
	struct OseGW_TransportData *reply = NULL;
	struct OseGW_AttachRequest *attach_request = NULL;
	int status = 0;
	PROCESS pid;
	union LINX_SIGNAL *signal;
	LINX_OSATTREF attref;
	int size = 0;

	size = sizeof(struct OseGW_TransportHdr) + payload_len;
	reply = (struct OseGW_TransportData *)malloc(size);
	if (reply == NULL) {
		syslog(LOG_ERR, "Malloc failure in Attach reply ");
		return -1;
	}

	attach_request = (struct OseGW_AttachRequest *)payload;
	pid = ntohl(attach_request->pid);
	attach_request->sig_len = ntohl(attach_request->sig_len);
	LOG("Gateway Client: attaching to %#x", pid);
	if (attach_request->sig_len) {
		signal = linx_alloc(cinfo->linx, attach_request->sig_len,
				    ntohl(attach_request->sig_no));
		if (signal == LINX_NIL) {
			syslog(LOG_ERR, "Linx alloc failed in Attach "
                               "reply");
			free(reply);
			return -1;
		}
		memcpy(&((char *) signal)[sizeof(SIGSELECT)],
		       attach_request->sig_data,
		       attach_request->sig_len - sizeof(SIGSELECT));
		attref = linx_attach(cinfo->linx, &signal, pid);
	} else {
		attref = linx_attach(cinfo->linx, NULL, pid);
	}

	if (attref == LINX_ILLEGAL_ATTREF) {
	        free(reply);
		return -1;
	}
	/* Fill the header */
	reply->hdr.payload_type = htonl(OseGW_PLT_AttachReply);
	reply->hdr.payload_len = htonl(sizeof(struct OseGW_AttachReply));
	/* Fill the payload */
	reply->payload.attach_reply.status = htonl(cinfo->status);
	reply->payload.attach_reply.attref = htonl(attref);
	/*Send */
	size = sizeof(struct OseGW_TransportHdr) + payload_len;
	status = send(skt, (void *) reply, size, 0);
	if (status == size) {
		LOG("Gateway Client: replying AttachReply "
                    "on socket %d", skt);
	} else {
		syslog(LOG_INFO, "Gateway Client: failed replying "
		       "AttachReply on socket %d",  skt);
		status = -1;
	}
	free(reply);
	return status;
}

int OseGW_PLT_DetachRequest_cbk(int skt, int len, char *payload,
                                struct ClientInfo *cinfo)
{
	struct OseGW_DetachRequest *detach_request = NULL;
	LINX_OSATTREF attref;
	int status;

	detach_request = (struct OseGW_DetachRequest *)payload;
	attref = ntohl(detach_request->attref);
	status = linx_detach(cinfo->linx, &attref);
	if (status == -1) {
	        return status;
	}
	status = OseGW_PLT_DetachReply_cbk(skt, len, payload, cinfo);
	return status;
}

int OseGW_PLT_DetachReply_cbk(int skt, int len, char *payload,
                              struct ClientInfo *cinfo)
{
	OseGW_UL payload_len = sizeof(struct OseGW_DetachReply);
	struct OseGW_TransportData *reply = NULL;
	int size = 0;
	int status;

	/* Fill the header */
	size = sizeof(struct OseGW_TransportHdr) + payload_len;
	reply = (struct OseGW_TransportData *) malloc(size);
	if (reply == NULL) {
		syslog(LOG_ERR, "Malloc failure in Detach reply");
		return -1;
	}
	reply->hdr.payload_type = htonl(OseGW_PLT_DetachReply);
	reply->hdr.payload_len = htonl(sizeof(struct OseGW_DetachReply));
	/* Fill the payload */
	reply->payload.detach_reply.status = htonl(cinfo->status);
	/*Send */
	size = sizeof(struct OseGW_TransportHdr) + payload_len;
	status = send(skt, (void *)reply, size, 0);
	if (status == size) {
		LOG("Gateway Client: replying DettachReply "
                    "on socket %d", skt);
	} else {
		syslog(LOG_INFO, "Linux Gateway daemon failed replying "
                       "DettachReply on socket %d", skt);
		status = -1;
	}

	free(reply);
	return status;
}

int OseGW_PLT_NameRequest_cbk(int skt, int len, char *payload,
                              struct ClientInfo *cinfo)
{
	return OseGW_PLT_NameReply_cbk(skt, len, payload, cinfo);
}

int OseGW_PLT_NameReply_cbk(int skt, int len, char *payload,
                            struct ClientInfo *cinfo)
{
  OseGW_UL payload_len = offsetof(struct OseGW_NameReply, name) +
                strlen(cinfo->gw_name) + 1;
	struct OseGW_TransportData *reply = NULL;
	int status = 0;
	int size = 0;

	size = sizeof(struct OseGW_TransportHdr) + payload_len;
	reply = (struct OseGW_TransportData *)malloc(size);
	if (reply == NULL) {
		syslog(LOG_ERR, "Malloc failure in Name reply");
		return -1;
	}
	reply->hdr.payload_type = htonl(OseGW_PLT_NameReply);
	reply->hdr.payload_len = htonl(payload_len);
	reply->payload.name_reply.status = htonl(OseGW_StatusOk);
	reply->payload.name_reply.name_len = htonl(strlen(cinfo->gw_name) + 1);
	strcpy(reply->payload.name_reply.name, cinfo->gw_name);
	/*Send */
	size = sizeof(struct OseGW_TransportHdr) + payload_len;
	status = send(skt, (void *) reply, size, 0);
	if (status == size) {
		LOG("Gateway Client: replying NameReply on "
                    "socket %d", skt);
	} else {
		syslog(LOG_INFO, "Gateway Client: failed replying "
		       "NameReply on socket %d", skt);
		status = -1;
	}

	free(reply);
	return status;
}

