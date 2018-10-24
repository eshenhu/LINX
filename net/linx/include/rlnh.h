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

#ifndef __RLNH_H__
#define __RLNH_H__

#include <linux/linx_types.h>

struct RlnhLinkObj;
struct RlnhLinkIF;

/* Description: Initialize RLNH, this function is called at
 *              startup (module init). When the initialization
 *              is done, the RLNH is expected to be up and running.
 * Parameters:  -
 * Return:      Returns 0 on success.
 *              Returns -errno on failures.
 */
int rlnh_init(void);

/* Description: Finalize RLNH, this function is called at
 *              shutdown (module exit). When the finalization
 *              is done, the RLNH is expected have released
 *              all its resources.
 * Parameters:  -
 * Return:      Returns 0 on success.
 *              Returns -errno on failures.
 */
int rlnh_finalize(void);

/*
 * Descrition: Test if the maximum number of allowed links is reached.
 *
 *             This function shall be called once for every
 *             link that shall be connected.
 *
 *             This function shall be called before linux_rlnh_create_link()
 *             is calledto verify that the maximum number of links is not
 *             reached.
 *
 * Return:     Return 0 if a new link is allowed to be created or
 *             -1 if it is not allowed.
 */

int linux_rlnh_create_link_limit_check(void);

/* Descrition: Create a link.
 *             This function shall be called once for every
 *             link that shall be connected.
 *
 *             When the linux_rlnh_create_link function is called, the
 *             connection managers @link "rlnh_link.h" "rlnh_link_dc_init"
 *             down call is called to initialize and connect the link.
 *
 *             When the link is connected, a process with the link handlers
 *             name of the link is created. The created process lifecycle
 *             match the lifecycle of the links connection. When the link is
 *             connected, the process is created and when the link is
 *             disconnected the process is killed.
 *
 *             The linux_rlnh_create_link function usually returns
 *             before the link is connected.
 *
 *             The detection of a connected link is done by
 *             using the hunt() system call. The link handlers
 *             name of the link used used with the hunt().
 *             The link handler has the following name
 *             representing the specific link:
 *             "<rlnhLinkName>/"
 *
 * Parameters: rlnhLinkName - The name of the link. When
 *                            hunting for a remote process over
 *                            the specific link, use the following
 *                            syntax: "<rlnhLinkName>/<process name>".
 *             rlnhLinkIF   - The connection manager specific downcall
 *                            interface implementation as specified by
 *                            "rlnh_link.h" "RlnhLinkIF".
 *             rlnhLinkObj  - The connection manager specific handle
 *                            to the link.
 *                            See "rlnh_link.h" "RlnhLinkObj" for a
 *                            description of RlnhLinkObj.
 *             rlnhLinkAttr - An arbitrary string that contains link
 *                            specific attributes.
 *
 * Return:     The linux_rlnh_create_link function returns a handle to a link,
 *             which shall be passed in subsequent RLNH-interface calls.
 */

LINX_RLNH
linux_rlnh_create_link(const char *rlnhLinkName,
		       const char *featString,
		       struct RlnhLinkIF *rlnhLinkIF,
		       struct RlnhLinkObj *rlnhLinkObj,
		       const char *rlnhLinkAttr);

/*
 * Descrition: Destroy a link.
 *
 *             This function shall be called once for every
 *             link that shall be released.
 *
 *             The linux_rlnh_destroy_link function blocks until
 *             the link is disconnected.
 *
 *             The linux_rnh_destroy_link call result in a down call
 *             to "rlnh_link.h" "rlnh_link_dc_finalize".
 *
 *             The detection of a disconnected link is done by
 *             using the attach() system call. See
 *             "linux_rlnh_create_link" for information
 *             about how to supervise the connected link.
 *
 * Paramters:  rlnhObj - The RLNH specific handle to the link,
 *                       which was returned in the call to
 *                       linux_rlnh_create_link.
 */

struct RlnhLinkObj *linux_rlnh_destroy_link(LINX_RLNH rlnh);

/* Description: Hunt for a peer via RLNH.
 * Parameters:  rlnh           - reference to the RLNH object (link) that
 *                               shall perform the hunt (the caller of
 *                               ipc_add_hunt_path() for the link name).
 *              name           - The hunt name, include
 *                               hunt_path.
 *              owner          - The owning socket. The owner of
 *                               the hunt path specified in name.
 *                               The owning socket is guaranied to
 *                               not be released.
 *                               During the hunt call, the owner
 *                               socket is prevented from being
 *                               released. As a consequese of
 *                               of the close prevention,
 *                               linx_remove_peer on the owner
 *                               socket may not be called during
 *                               rlnh_hunt.
 *              from           - The from socket. The original
 *                               caller socket of hunt.
 *                               The from socket is guaranied to
 *                               be bound and not released.
 *                               During the hunt call, the from
 *                               socket is prevented from being
 *                               released. As a consequese of
 *                               of the close prevention,
 *                               linx_remove_peer on the from
 *                               socket may not be called during
 *                               rlnh_hunt.
 * Return:      Returns 0 on success.
 *              Returns -errno on failures.
 */
int
rlnh_hunt(LINX_RLNH rlnh, const char *name, LINX_SPID owner, LINX_SPID from);

/* Description: Hunt resolve callback, a pending hunt
 *              previously requested from RLNH has been
 *              resolved. If the callback retun successfully,
 *              the pending hunt is removed.
 * Parameters:  rlnh     - reference to the RLNH object (link) that
 *                         shall handle the resolved hunt (caller of
 *                         ipc_hunt())
 *              name   - The hunt name of the original hunt
 *                       call.
 *              victim - The victim spid. Note that the
 *                       victim may already be dead at
 *                       this point.
 *              hunter - The owner of the hunt request.
 *                       Note that the hunter is guaranied
 *                       to be a live bound or unbound socket.
 *                       The hunter is prevented from being
 *                       closed during this call. This means
 *                       that it is illegal to call
 *                       linx_remove_peer on the hunter
 *                       socket during
 *                       rlnh_hunt_resolved.
 * Return:      Returns 0 on success.
 *              Returns -errno on failures.
 */
int
rlnh_hunt_resolved(LINX_RLNH rlnh, const char *name, LINX_SPID victim,
		   LINX_SPID hunter);

/* Description: An attach requested from RLNH is resolved due
 *              to a released socket.
 * Parameters:  rlnh - a reference to the RLNH object (link)
 *                     that shall handle
 *                        the attach notification (the caller of
 *                        ipc_attach()).
 *              spid    - The attached victim socket. This socket
 *                        is in the progress of being released.
 * Return:      Returns 0 on success.
 *              Returns -errno on failures.
 */
int rlnh_attach_notification(LINX_RLNH rlnh, LINX_SPID spid);

/* Description: Send a signal via RLNH.
 * Parameters:
 *              src_rlnh       - RLNH instance representing the
 *                               link of the sender.
 *              rlnh           - RLNH instance representing the
 *                               link of the receiver.
 *              payload        - The payload buffer pointer.
 *              payload_size   - The size, in bytes, of the
 *                               payload.
 *              payload_type   - uint32_t, payload can be situated
 *                               in user or kernel space.
 *              src            - The sending socket. The
 *                               sending socket is guaranied to
 *                               be bound and not released.
 *                               During the send call, the from
 *                               socket is prevented from being
 *                               released. As a consequese of
 *                               of the close prevention,
 *                               linx_remove_peer on the from
 *                               socket may not be called during
 *                               rlnh_send.
 *              src_hd         - The per-socket data attached
 *                               to the sending socket where
 *                               the linkaddresses are stored.
 *              dst            - The receiving socket. The
 *                               receiving socket is guaranied to
 *                               be bound and not released.
 *                               During the send call, the to
 *                               socket is prevented from being
 *                               released. As a consequese of
 *                               of the close prevention,
 *                               linx_remove_peer on the to
 *                               socket may not be called during
 *                               rlnh_send.
 *              dst_addr       - The destination link address of
 *                               the remote LINX socket.
 *              src_dst_addr   - The sending sockets destination
 *                               linkaddress if socket is a remote
 *                               LINX socket.
 *              peer_la        - The peer linkaddress of the
 *                               sending remote LINX socket.
 * Return:      Returns 0 on success.
 *              Returns -errno on failures.
 */
int
rlnh_send(LINX_RLNH src_rlnh,
	  LINX_RLNH rlnh,
	  void *payload,
	  LINX_OSBUFSIZE payload_size,
	  uint32_t payload_type,
	  LINX_SPID src,
	  uint32_t * src_hd,
	  LINX_SPID dst,
	  uint32_t dst_addr, uint32_t src_dst_addr, uint32_t peer_la);

/* Description: Access the RLNH via the ioctl general
 *              purpuse interface.
 *
 * Parameters:  spid           - The spid of the socket used
 *                               to access ioctl.
 *              cmd            - The command to execute.
 *              arg            - The ioctl arguments as a
 *                               structure of arguments.
 * Return:      Returns 0 on success.
 *              Returns -errno on failures.
 * Errors:      EINVAL - The command is not recougnized.
 */
int rlnh_ioctl(LINX_SPID spid, unsigned int cmd, unsigned long arg);

/* Description: Force disconnect of a link, typically
 *              done when message ordering or reliability can not
 *              ge garantied by the ipc layer.
 *
 * Return:      Returns 0 on success.
 *              Returns -errno on failures.
 */
int rlnh_disconnect(LINX_RLNH rlnh);

/* Description: Returns the spid of the link phantom.
 *
 * Return:      Returns the spid on success.
 *              Returns LINX_ILLEGAL_SPID on failures.
 */
LINX_SPID rlnh_get_spid(LINX_RLNH rlnh);

#endif
