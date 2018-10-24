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

#ifndef __IPC_RLNH_H__
#define __IPC_RLNH_H__

#include <linux/linx_types.h>

struct sock;

/*
 *
 * Internal LINX functions, not to be used by RLNH.
 *
 */

/* Description: Hunt resolve callback, a pending hunt
 *              has been resolved. Shall be called by LINX
 *              when a RLNH requested hunt is resolved. Do
 *              not call rlnh_hunt_resolved directly, most
 *              error checks are performad in this function.
 * Parameters:  name   - The hunt name of the original hunt
 *                       call.
 *              victim - The victim spid. Note that the
 *                       victim may already be dead at
 *                       this point.
 *              hunter - The owner of the hunt request.
 * Return:      Returns 0 on success.
 *              Returns -errno on failures.
 * Errors:      EINVAL - Hunter is illegal or dead.
 *              EINVAL - Hunter is already released.
 */
int
linx_rlnh_hunt_resolved(LINX_RLNH rlnh,
			const char *name, LINX_SPID victim, LINX_SPID hunter);

/* Description: An attach is resolved due to a released socket.
 *              Notify the RLNH. Shall be called by LINX
 *              when a RLNH requested attach is resolved. Do
 *              not call rlnh_attach_notification directly, most
 *              error checks are performad in this function.
 * Parameters:  to     - The attached victim socket. This socket
 *                       is already released or in the progress
 *                       of being released.
 * Return:      Returns 0 on success.
 *              Returns -errno on failures.
 * Errors:      EINVAL - From is illegal or dead.
 *              EINVAL - From is already released.
 */
int
linx_rlnh_attach_notification(LINX_RLNH rlnh, LINX_SPID to);

/* Description: Send a signal via RLNH.
 *              this function shall be called when sending a
 *              signal via RLNH,  the direct rlnh_send call
 *              shall not be used since most error checks are
 *              performed in linx_rlnh_send.
 * Parameters:  payload        - The payload buffer pointer.
 *              payload_size   - The size, in bytes, of the
 *                               payload.
 *              from           - The sending socket.
 *              to             - The receiving socket.
 *              kernal_payload - uint32_t, payload can be situated
 *                               in kernel and user space.
 * Return:      Returns 0 on success.
 *              Returns -errno on failures.
 * Errors:      EINVAL - To is illegal or dead.
 *              EINVAL - To is already released.
 *              EINVAL - From is illegal or dead.
 *              EINVAL - From is already released.
 */
int linx_rlnh_send(void *payload,
		   LINX_OSBUFSIZE payload_size,
		   struct sock *from_sk,
		   LINX_SPID from,
		   struct sock *to_sk,
		   LINX_SPID to, uint32_t payload_type);

/* Description: Hunt for a peer via RLNH.
 * Parameters:  name           - The hunt name, includes
 *                               the hunt path.
 *              owner          - The owning socket. The owner of
 *                               the hunt path specified in name.
 *              from           - The from socket. The original
 *                               calling socket of hunt.
 * Return:      Returns 0 on success.
 *              Returns -errno on failures.
 * Errors:      EINVAL - The owner is dead or illegal.
 *              EINVAL - The owner is released.
 *              EINVAL - The from is dead or illegal.
 *              EINVAL - The from is released.
 *              EINVAL - The from is not bound.
 */
int linx_rlnh_hunt(const char *name, LINX_SPID owner, LINX_SPID from);

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
int linx_rlnh_ioctl(LINX_SPID spid, unsigned int cmd, unsigned long arg);

#endif
