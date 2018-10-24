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

#ifndef __IPC_H__
#define __IPC_H__

#include <linux/linx_types.h>

/*
 *
 * Upcalls used by RLNH
 *
 */

/* Description: Add a hunt path to the LINX.
 * Parameters:  hunt_path - The hunt path.
 *              owner     - The spid of the hunt path owner.
 *              attr      - The attribute string.
 * Return:      Returns 0 if successful.
 *              Return -errno on failures.
 * Errors:      EINVAL - Bad syntax of hunt_path (includes '/').
 *              EINVAL - Dead or illegal owner.
 *              EINVAL - The owner is not created by RLNH.
 */
int ipc_add_hunt_path(const char *hunt_path, LINX_SPID spid, const char *attr);

/* Description: Remove a hunt path from the LINX.
 * Parameters:  owner     - The spid of the hunt path owner.
 * Return:      Returns 0 if successful.
 *              Return -errno on failures.
 * Errors:      -
 *
 */
int ipc_remove_hunt_path(LINX_SPID owner);

/* Description: Send a signal from a socket to another.
 * Parameters:  payload      - The signal payload (including
 *                             signo).
 *              payload_size - The size of the payload (bytes).
 *                             The minimal size is the size of
 *                             LINX_SIGSELECT.
 *              to           - The spid of the receiving socket.
 *              from         - The spid of the sending socket.
 *              buffer_type  - Buffer flags.
 * Return:      Returns 0 if successful.
 *              Return -errno on failures.
 * Errors:      EINVAL - The sending socket is dead/illegal.
 *              EINVAL - The receiving socket is dead/illegal.
 *              EINVAL - The size of the payload is too small.
 *              EINVAL - The sending socket is not bound.
 *              EINVAL - The receiving socket is not bound.
 */
int
ipc_send_signal(void *payload, uint32_t payload_size, LINX_SPID to,
		LINX_SPID from, uint32_t buffer_type);

/* Description: Create a peer.
 * Parameters:  -
 * Return:      Returns the spid of the new peer on success.
 *              Returns LINX_ILLEGAL_SPID on failures.
 * Errors:      LINX_ILLEGAL_SPID - Out of memory resources.
 *              LINX_ILLEGAL_SPID - The maximum number of
 *                                    sockets is reached.
 */
LINX_SPID ipc_create_peer(LINX_RLNH rlnh, char *name, uint32_t rlnh_sock_id);

int ipc_get_sender_hd(LINX_SPID spid, uint32_t index, uint32_t * val);

int ipc_set_sender_hd(LINX_SPID spid, uint32_t index, uint32_t val);

int ipc_get_peer_hd(LINX_SPID spid, uint32_t * val);

int ipc_set_peer_hd(LINX_SPID spid, uint32_t val);

int ipc_local_peer(LINX_SPID spid);

/* Description: Remove(release) a peer.
 * Parameters:  spid - The spid to remove.
 * Return:      Returns 0 on success.
 *              Returns -errno on failures.
 * Errors:      EINVAL - The spid is illegal or dead.
 *              EINVAL - The spid is already released.
 *              ENOMEM - Out of memory.
 */
int ipc_remove_peer(LINX_SPID spid);

/* Description: Hunt for a socket.
 * Parameters:  name   - The name to hunt for.
 *              from   - The socket to hunt from. If from is
 *                       released its pending hunts will be
 *                       removed.
 * Return:      Returns 0 on success.
 *              Returns -errno on failures.
 * Errors:      EINVAL - From is illegal or dead.
 *              EINVAL - From is already released.
 */
int ipc_hunt(LINX_SPID owner, const char *name, LINX_SPID from);

/* Description: Attach to an existing socket.
 * Parameters:  to     - The attach victim socket.
 *              from   - The attach caller socket.
 *              attach_handle - A user defined handle that
 *                       replace the attach signal content of
 *                       the common linx_attach.
 *              attref - The attach reference output.
 * Return:      Returns 0 on success.
 *              Returns -errno on failures.
 * Errors:      EINVAL - To is illegal or dead.
 *              EINVAL - To is already released.
 *              EINVAL - From is illegal or dead.
 *              EINVAL - From is already released.
 *              ENOMEM - Out of memory.
 */
int
ipc_attach(LINX_SPID to, LINX_SPID from, void *attach_handle,
	   LINX_OSATTREF * attref);

/* Description: Detach from an existing socket.
 * Parameters:  from   - The detach caller socket
 *                       (shall be the caller of previous attach).
 *              attref - The attach reference.
 * Return:      Returns 0 on success.
 *              Returns -errno on failures.
 * Errors:      -
 */
int ipc_detach(LINX_SPID from, LINX_OSATTREF * attref);

/* Description: Retrieve the bound name of a socket.
 *              Note: The socket specified by spid will
 *              be locked when linx_spid_to_name return.
 *              When the called is finished using the name,
 *              the function linx_unlock_spid shall be
 *              called to enable close again.
 * Parameters:  spid - The spid of the bound socket.
 *              sk_unlock - This socket must be unlocked.
 * Return:      Returns a pointer to the name if successful.
 *              Return NULL on failures (sk_unlock is untouched).
 * Errors:      NULL - The socket is dead/illegal.
 *              NULL - The socket is not bound.
 */
const char *ipc_spid_to_name(LINX_SPID spid, struct sock **sk_unlock);

#endif
