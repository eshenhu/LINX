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

#ifndef __IPC_HUNT_H__
#define __IPC_HUNT_H__

#include <net/sock.h>
#include <linux/linx_types.h>
#include <linux/linx_ioctl.h>
#include <linx_assert.h>

/* The linx_hunt function takes a name and a signal to
 * hunt for a specific socket.
 * The sigsize shall be set to 0 and sig shall be set to NULL
 * if no hunt signal is provided.
 * if the hunt is made from RLNH rlnh is set to LINX_TRUE
 * The spid parameter contain the spid of the hunter.
 * found point at the found spid or LINX_ILLEGAL_SPID if
 * no match was found.
 */
int
linx_hunt(struct sock *sk,
	  const char *name,
	  int namelen,
	  void *sig,
	  LINX_OSBUFSIZE sigsize,
	  LINX_SPID hunter_spid,
	  LINX_SPID owner_spid, LINX_SPID * hunted_spid, LINX_OSBOOLEAN rlnh);

/* Resolve a pending hunt as part of bind. */
void linx_resolve_pend_hunt(const char *name, struct sock *sk);

/* Store socket states. */

/* Store an unbound socket in unbound sockets list. */
void linx_store_unbound(struct sock *sk);

/* Publish a name (addr) for hunt requests. */
void linx_publish(struct sock *sk, struct linx_huntname *addr);

/* Unpublish a hunt name. */
void linx_unpublish(struct sock *sk);

/* Unpublish all hunt names. */
void linx_unpublish_all(void);

/* Hunt paths. */

/* Add a hunt path to the existing hunt paths */
int
linx_add_hunt_path(const char *hunt_path, LINX_SPID owner,
		   struct sock *owner_sk, const char *attr);

/* Remove a previously added hunt path. */
int linx_remove_hunt_path(struct sock *owner_sk, LINX_SPID owner);

/* Remove all hunt paths in the system, this is
 * typically called  from the kernel module exit handler. */
void linx_remove_all_hunt_paths(void);

int linx_add_link_supervisor(struct sock *sk);
int linx_remove_link_supervisor(LINX_SPID supervisor);
void linx_remove_all_link_supervisors(void);

int
linx_info_sockets(struct linx_info_sockets *isockets, LINX_SPID __user * spids);

int
linx_info_pend_hunt(struct linx_info_pend_hunt *ipend_hunt,
		    struct linx_info_hunt __user * hunts,
		    int *strings_offset, int compat);

int
linx_info_pend_hunt_payload(struct sock *sk,
			    struct linx_info_signal_payload *isig_payload);

/* Calculate a hash value for a given input value.
 * The hash value is used as the hunt name table slot
 * location for the specific hash
 */
static inline unsigned hash_fold(unsigned hash, int hash_size)
{
	hash ^= hash >> 16;
	hash ^= hash >> 8;
	return hash & (hash_size - 1);
}

/* Calculate a hash for a given hunt name */
static inline unsigned hash_name(const char *name, int namelen, int hash_size)
{
	LINX_ASSERT(strlen(name) == namelen);
	return hash_fold(csum_partial((const unsigned char *)name,
				      namelen + 1, 0), hash_size);
}

#endif
