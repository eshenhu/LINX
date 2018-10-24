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

#include <af_linx.h>
#include <ipc/attach_detach.h>
#include <ipc/hunt.h>
#include <ipc/rlnh.h>
#include <linux/version.h>
#include <linux/linx_socket.h>
#include <linux/linx_types.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <linx_mem.h>
#include <rlnh.h>
#include <net/sock.h>
#include <linx_trace.h>
#include <buf_types.h>

extern atomic_t linx_no_of_local_sockets;
extern atomic_t linx_no_of_remote_sockets;

extern struct workqueue_struct *linx_workqueue;

/* Socket statesTypes for lock/unlock socket. */

/* The socket may be in any state (except destructed). */
#define LINX_SOCK_STATE_ANY      7
/* The socket may be unbound. */
#define LINX_SOCK_STATE_UNBOUND  1
/* The socket may be bound. */
#define LINX_SOCK_STATE_BOUND    2
/* The socket may be released. */
#define LINX_SOCK_STATE_RELEASED 4

/* The socket may be of any type. */
#define LINX_SOCK_TYPE_ANY      3
/* The socket shall be of type peer. */
#define LINX_SOCK_TYPE_PEER     1
/* The socket shall be of type local (not created by rlnh). */
#define LINX_SOCK_TYPE_LOCAL    2

static inline void check_socket(struct sock *sk, uint32_t state, uint32_t type)
{
#ifdef ERRORCHECKS
	if (unlikely(!(type & LINX_SOCK_TYPE_PEER) &&
		     linx_sk(sk)->type == LINX_TYPE_REMOTE)) {
		linx_trace(LINX_TRACE_ERR, LINX_TRACEGROUP_IPC,
			   "It is illegal to use a peer "
			   "socket (0x%x)", linx_sock_to_spid(sk));
		BUG();
	}
	if (unlikely(!(state & LINX_SOCK_STATE_UNBOUND) &&
		     linx_sk(sk)->addr == NULL)) {
		linx_trace(LINX_TRACE_ERR, LINX_TRACEGROUP_IPC,
			   "It is illegal to use an unbound "
			   "socket (0x%x)", linx_sock_to_spid(sk));
		BUG();
	}
	if (unlikely(!(state & LINX_SOCK_STATE_BOUND) &&
		     linx_sk(sk)->addr != NULL)) {
		linx_trace(LINX_TRACE_ERR, LINX_TRACEGROUP_IPC,
			   "It is illegal to use a bound "
			   "socket (0x%x)", linx_sock_to_spid(sk));
		BUG();
	}
#endif
}

/* Lock a socket to a specific range of states,
 * translate its spid to a sock structure,
 * verify the sockets type and state.
 */
static inline int lock_socket(LINX_SPID spid, struct sock **sk)
{
	/* make sure the socket is alive and prevent destruction
	 * of the socket. */
	*sk = linx_spid_to_sock(spid);
	if (unlikely(*sk == NULL)) {
		if (!linx_is_zombie_spid(spid)) {
			/* Replaced the linx_err with a linx_info since
			 * sending to a socket that has been closed is not
			 * an error. */
			linx_info("Unable to lock socket, "
				 "illegal spid (%#x)", spid);
			return -EINVAL;
		}
		return -ECONNRESET;
	}

	/* From here it is safe to access the sk structure since it
	 * is prevented from being removed by linx_spid_to_sock. */
	return 0;
}

/* Unlock a socket locked with lock_socket.
 * The same state and type information shall be provided. */
static inline void unlock_socket(struct sock *sk)
{
	linx_check_sock(sk);
	sock_put(sk);
}

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
int ipc_add_hunt_path(const char *hunt_path, LINX_SPID owner, const char *attr)
{
	struct sock *sk;
	int ret;

	LINX_ASSERT(hunt_path != NULL);
	LINX_ASSERT(owner != LINX_ILLEGAL_SPID);

	linx_trace_enter(LINX_TRACEGROUP_IPC,
			 "%s, 0x%x",
			 hunt_path == NULL ? "null" : hunt_path, owner);

	/* Make sure the socket is alive and prevent destruction
	 * of the socket. Also make sure the socket is a peer. */
	ret = lock_socket(owner, &sk);
	if (ret != 0)
		return ret;

	check_socket(sk,
		     LINX_SOCK_STATE_UNBOUND | LINX_SOCK_STATE_BOUND,
		     LINX_SOCK_TYPE_PEER);
	/* Syntax and other controls are done in
	 * linx_add_hunt_path. */
	ret = linx_add_hunt_path(hunt_path, owner, sk, attr);
	/* Unlock the socket again allowing it to be released
	 * and destructed. */
	unlock_socket(sk);

	return ret;
}

/* Description: Remove a hunt path from the LINX.
 * Parameters:  owner     - The spid of the hunt path owner.
 * Return:      Returns 0 if successful.
 *              Return -errno on failures.
 * Errors:      -
 *
 */
int ipc_remove_hunt_path(LINX_SPID owner)
{
	struct sock *sk;
	int err;

	LINX_ASSERT(owner != LINX_ILLEGAL_SPID);
	linx_trace_enter(LINX_TRACEGROUP_IPC, "0x%x", owner);

	/* Make sure the socket is alive and prevent destruction
	 * of the socket. Also make sure the socket is a peer. */
	err = lock_socket(owner, &sk);
	if (err != 0)
		return err;

	check_socket(sk,
		     LINX_SOCK_STATE_UNBOUND | LINX_SOCK_STATE_BOUND,
		     LINX_SOCK_TYPE_PEER);

	/* Remove the hunt path. */
	err = linx_remove_hunt_path(sk, owner);

	/* Unlock the socket. */
	unlock_socket(sk);

	return err;
}

/* Description: Send a signal from a socket to another.
 * Parameters:  payload      - The signal payload (including
 *                             signo).
 *              payload_size - The size of the payload (bytes).
 *                             The minimal size is the size of
 *                             LINX_SIGSELECT.
 *              to           - The spid of the receiving socket.
 *              from         - The spid of the sending socket.
 *              payload_skb  - The payload is a skb buffer.
 * Return:      Returns 0 if successful.
 *              Return -errno on failures.
 * Errors:      EINVAL - The sending socket is dead/illegal.
 *              EINVAL - The receiving socket is dead/illegal.
 *              EINVAL - The size of the payload is too small.
 *              EINVAL - The sending socket is not bound.
 *              EINVAL - The receiving socket is not bound.
 *              ENOMEM - Out of memory.
 */
int
ipc_send_signal(void *payload, uint32_t payload_size, LINX_SPID to,
		LINX_SPID from, uint32_t buffer_type)
{
	struct sock *to_sk = NULL;
	struct sock *from_sk = NULL;
	int err = 0;
	LINX_OSBOOLEAN payload_skb = BUF_TYPE_SKB(buffer_type);
	uint32_t consumed = 0;
	LINX_ASSERT(payload != NULL);
	LINX_ASSERT(payload_size != 0);

	linx_trace_enter(LINX_TRACEGROUP_IPC,
			 "%p, %d, 0x%x, 0x%x", payload, payload_size, to, from);

	/* Lock the to socket. */
	err = lock_socket(to, &to_sk);
	if (unlikely(err != 0 && err != -ECONNRESET))
		return err;
	/* Both to and from shall be bound sockets. The from socket
	 * shall be a peer while the to socket may be of any type. */
	if (unlikely(to_sk == NULL)) {
		/* To socket apparently is no more, free message and return. */
		if (payload_skb)
			kfree_skb(payload);
		else
			linx_kfree(payload);
		return 0;
	}
	check_socket(to_sk, LINX_SOCK_STATE_BOUND, LINX_SOCK_TYPE_ANY);

	/* Lock the from socket. */
	err = lock_socket(from, &from_sk);
	if (unlikely(err != 0)) {
		unlock_socket(to_sk);
		/* From socket is no more, free message and return,
		 * this can be the case with send_w_s(). */
		if (payload_skb)
			kfree_skb(payload);
		else
			linx_kfree(payload);
		return 0;
	}

	check_socket(from_sk, LINX_SOCK_STATE_BOUND, LINX_SOCK_TYPE_PEER);

	/* Send the signal. */
	err = linx_do_sendmsg(from_sk, payload, payload_size, to_sk, to,
			      from_sk,from, buffer_type, &consumed);

	/* Unlock the to and from sockets. */
	unlock_socket(to_sk);
	unlock_socket(from_sk);
	if (unlikely(!payload_skb)) {
		linx_kfree(payload);
	}

	return err;
}

/* Description: Retrieve the bound name of a socket.
 *              Note: The socket specified by spid will
 *              be locked when linx_spid_to_name return.
 *              When the called is finished using the name,
 *              the function linx_unlock_spid shall be
 *              called to enable close again.
 * Parameters:  spid - The spid of the bound socket.
 * Return:      Returns a pointer to the name if successful.
 *              Return NULL on failures.
 * Errors:      NULL - The socket is dead/illegal.
 *              NULL - The socket is not bound.
 */
const char *ipc_spid_to_name(LINX_SPID spid, struct sock **sk_unlock)
{
	struct sock *sk;
	struct linx_huntname *huntname;
	const char *name = NULL;
	int err;

	LINX_ASSERT(spid != LINX_ILLEGAL_SPID);

	err = lock_socket(spid, &sk);
	if (err != 0)
		return NULL;

	check_socket(sk, LINX_SOCK_STATE_BOUND, LINX_SOCK_TYPE_ANY);

	/* Get the bound name of the socket from the address structure
	 * of the socket. If no address is present, the socket is not
	 * bound. */
	huntname = (struct linx_huntname *)linx_sk(sk)->addr;
	LINX_ASSERT(huntname != NULL && huntname->name != NULL);
	name = huntname->name;

	/* NOTE : leave the socket locked, this means that the
	 *        sock_put needs to be called as soon as
	 *        possible after ipc_spid_to_name has returned and
	 *        the name has been used. The sk_unlock contains
	 *        the pointer that must be used in sock_put. */

	*sk_unlock = sk;
	return name;
}

/* Description: Publish (bind) a peer to a hunt name.
 * Note:        Publish is really bind. The reason why create
 *              and publish are separated is because ppd may
 *              need to be set before the socket is huntable.
 * Parameters:  spid - The spid to publish.
 *              name - The hunt name of the spid.
 * Return:      Returns 0 on success.
 *              Returns -errno on failures.
 * Errors:      EINVAL - The spid is illegal or dead.
 *              EINVAL - The spid is already bound.
 *              EINVAL - The spid is already released.
 *              EINVAL - The name is of zero length.
 *              ENOMEM - Out of memory.
 */
static int ipc_publish_peer(LINX_SPID spid, const char *name)
{
	int err;
	struct sock *sk;
	struct linx_huntname *huntname;

	LINX_ASSERT(spid != LINX_ILLEGAL_SPID);
	LINX_ASSERT(name != NULL);

	linx_trace_enter(LINX_TRACEGROUP_IPC,
			 "0x%x, %s", spid, name == NULL ? "null" : name);

	if (name == NULL || *name == '\0') {
		return -EINVAL;
	}

	/* Lock the socket. */
	err = lock_socket(spid, &sk);
	if (err != 0) {
		return err;
	}

	check_socket(sk, LINX_SOCK_STATE_UNBOUND, LINX_SOCK_TYPE_PEER);

	if(strlen(name) == 0) {
		err = -EINVAL;
		goto publish_peer_done_unlock;
	}

	huntname = linx_alloc_huntname(spid, name);
	if (huntname == NULL) {
		err = -ENOMEM;
		goto publish_peer_done_unlock;
	}

	err = linx_do_ioctl_name(sk, huntname);

	linx_free_linx_name(huntname);

      publish_peer_done_unlock:
	unlock_socket(sk);

	return err;
}

/* Description: Remove(release) a peer.
 * Parameters:  spid - The spid to remove.
 * Return:      Returns 0 on success.
 *              Returns -errno on failures.
 * Errors:      EINVAL - The spid is illegal or dead.
 *              EINVAL - The spid is already released.
 *              ENOMEM - Out of memory.
 */
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20))
static void linx_do_remove_peer(void *sk_void)
{
	struct sock *sk = sk_void;
#else
static void linx_do_remove_peer(struct work_struct *work)
{
	struct linx_sock *linx_sk = (struct linx_sock *)
		container_of(work, struct linx_sock, close_work);

	struct sock *sk = &linx_sk->sk;
#endif
	linx_check_sock(sk);
	LINX_ASSERT(!in_atomic());

	linx_trace_enter(LINX_TRACEGROUP_IPC, "%p", sk);

	/* Unlock the socket to allow destruction. */
	unlock_socket(sk);

	/* Calling release equals close from user land. */
	sock_release(sk->sk_socket);
}

int ipc_remove_peer(LINX_SPID spid)
{
	struct sock *sk;
	int err;

	LINX_ASSERT(spid != LINX_ILLEGAL_SPID);
	linx_trace_enter(LINX_TRACEGROUP_IPC, "0x%x", spid);

	err = lock_socket(spid, &sk);
	if (err != 0)
		return err;
	check_socket(sk, LINX_SOCK_STATE_ANY, LINX_SOCK_TYPE_PEER);

	if (in_atomic()) {
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20))
		INIT_WORK(&linx_sk(sk)->close_work, linx_do_remove_peer, sk);
#else
		INIT_WORK(&linx_sk(sk)->close_work, linx_do_remove_peer);
#endif
		queue_work(linx_workqueue, &linx_sk(sk)->close_work);
	} else {
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20))
		linx_do_remove_peer(sk);
#else
		linx_do_remove_peer(&linx_sk(sk)->close_work);
#endif
	}
	return 0;
}

/* Description: Create a peer.
 * Parameters:  name - The hunt name.
 *              rlnh_sock_id - rlnh assigned id for this peer,
 *              to be passed down in rlnh_send()
 * Return:      Returns the spid of the new peer on success.
 *              Returns LINX_ILLEGAL_SPID on failures.
 * Errors:      LINX_ILLEGAL_SPID - Out of memory resources.
 *              LINX_ILLEGAL_SPID - The maximum number of
 *                                    sockets is reached.
 */
LINX_SPID ipc_create_peer(LINX_RLNH rlnh, char *name, uint32_t rlnh_dst_addr)
{
	struct socket *new_socket;
	LINX_SPID spid;
	struct sock *sk;
	int err;

	linx_trace_enter(LINX_TRACEGROUP_IPC, "");

	/* Create the peer by calling the net subsystem equivalence
	 * of the socket() function. */
	err = sock_create_kern(AF_LINX, SOCK_DGRAM, 0, &new_socket);
	/* SOCKNOSUPPORT and EPROTONOSUPPORT are the consquense of bad
	 * input parameters. */
	LINX_ASSERT(err != -ESOCKTNOSUPPORT);
	LINX_ASSERT(err != -EPROTONOSUPPORT);
	if (err != 0) {
		return LINX_ILLEGAL_SPID;
	}
	/* Get the sk structure. */
	sk = new_socket->sk;

	/* Make sure the new socket is correctly created. */
	linx_check_socket(new_socket);

	/* Set to socket to remote type. */
	LINX_ASSERT(linx_sk(sk)->type == LINX_TYPE_LOCAL);
	atomic_dec(&linx_no_of_local_sockets);
	atomic_inc(&linx_no_of_remote_sockets);
	linx_sk(sk)->type = LINX_TYPE_REMOTE;
	linx_sk(sk)->rlnh = rlnh;

	/* Calculate the spid. */
	spid = linx_sock_to_spid(sk);

#ifdef SOCK_STAT
	linx_sk(sk)->link_spid = rlnh_get_spid(rlnh);

	if (unlikely(linx_sk(sk)->link_spid == 0x0)) {
		/* If linx_spid is NULL this is a link phantom */
		linx_sk(sk)->link_spid = spid;
	}
#endif

	/* Make sure the socket is held twice, since the release
	 * functionality of the net subsystem requires that. */
	LINX_ASSERT(atomic_read(&sk->sk_refcnt) == 2);

	linx_sk(sk)->rlnh_dst_addr = rlnh_dst_addr;

	if (ipc_publish_peer(spid, name) < 0) {
		return LINX_ILLEGAL_SPID;
	}

	return spid;
}

int ipc_get_sender_hd(LINX_SPID spid, uint32_t index, uint32_t * val)
{
	struct sock *sk;
	int err;

	err = lock_socket(spid, &sk);
	if (err != 0)
		return err;
	*val = linx_sk(sk)->rlnh_sender_hd[index];
	unlock_socket(sk);

	return 0;
}

int ipc_set_sender_hd(LINX_SPID spid, uint32_t index, uint32_t val)
{
	struct sock *sk;
	int err;

	err = lock_socket(spid, &sk);

	if (err != 0)
		return err;

	linx_sk(sk)->rlnh_sender_hd[index] = val;
	unlock_socket(sk);

	return 0;
}

int ipc_get_peer_hd(LINX_SPID spid, uint32_t * val)
{
	struct sock *sk;
	int err;

	err = lock_socket(spid, &sk);
	if (err != 0)
		return err;
	*val = linx_sk(sk)->rlnh_peer_addr;
	unlock_socket(sk);

	return 0;
}

int ipc_set_peer_hd(LINX_SPID spid, uint32_t val)
{
	struct sock *sk;
	int err;

	err = lock_socket(spid, &sk);
	if (err != 0)
		return err;
	linx_sk(sk)->rlnh_peer_addr = val;
	unlock_socket(sk);

	return 0;
}

int ipc_local_peer(LINX_SPID spid)
{
	struct sock *sk;
	int err, rv = 0;

	err = lock_socket(spid, &sk);
	if (err != 0)
		return err;

	if (linx_sk(sk)->type == LINX_SOCK_TYPE_LOCAL) {
		rv = 1;
	}

	unlock_socket(sk);

	return rv;
}

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
int ipc_hunt(LINX_SPID owner, const char *name, LINX_SPID from)
{
	LINX_SPID found;
	int err;
	struct sock *sk;

	LINX_ASSERT(owner != LINX_ILLEGAL_SPID);
	LINX_ASSERT(name != NULL);
	LINX_ASSERT(from != LINX_ILLEGAL_SPID);
	linx_trace_enter(LINX_TRACEGROUP_IPC, "%s, 0x%x", name, from);

	err = lock_socket(owner, &sk);
	if (err != 0)
		return err;
	check_socket(sk,
		     LINX_SOCK_STATE_UNBOUND | LINX_SOCK_STATE_BOUND,
		     LINX_SOCK_TYPE_PEER);

	/* Hunt for the specified name. Note that found is just
	 * a dummy that is not used, notification of a resolved hunt
	 * is always provided by the hunt_resolved callback. */

	/* NOTE: linx_hunt will make sure from
	 *       is supervised. */
	err = linx_hunt(sk, name, strlen(name),
			NULL, 0, from, from, &found, LINX_TRUE);
	/* NOTE: A hunt_from over a link can result in linx_hunt
	 *       returning -EINVAL if the from socket has been
	 *       lost. */
	if (err == -EINVAL)
		err = 0;

	unlock_socket(sk);

	return err;
}

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
	   LINX_OSATTREF * attref)
{
	int ret;
	struct sock *from_sk = NULL;

	LINX_ASSERT(to != LINX_ILLEGAL_SPID);
	LINX_ASSERT(from != LINX_ILLEGAL_SPID);

	linx_trace_enter(LINX_TRACEGROUP_IPC, "%u, %u, %p", to, from, attref);

	/* NOTE: The to socket can be dead or destructed,
	 *       in that case the attach callback is called
	 *       at once from within linx_attach.
	 *       This means that no validation or locking of
	 *       the victim shall be done here. */

	/* Lock the from socket. */
	ret = lock_socket(from, &from_sk);
	if (ret != 0)
		return ret;
	check_socket(from_sk, LINX_SOCK_STATE_BOUND, LINX_SOCK_TYPE_PEER);

	/* Call the general attach function. */
	/* NOTE: Last argument LINX_TRUE means: called from RLNH. */
	ret = linx_attach(from_sk, to, attach_handle, 0, attref, LINX_TRUE);

	/* Unlock the socket. */
	unlock_socket(from_sk);

	return ret;
}

/* Description: Detach from an existing socket.
 * Parameters:  from   - The detach caller socket
 *                       (shall be the caller of previous attach).
 *              attref - The attach reference.
 * Return:      Returns 0 on success.
 *              Returns -errno on failures.
 * Errors:      -
 */
int ipc_detach(LINX_SPID from, LINX_OSATTREF * attref)
{
	int ret;
	struct sock *from_sk = NULL;

	LINX_ASSERT(from != LINX_ILLEGAL_SPID);
	linx_trace_enter(LINX_TRACEGROUP_IPC, "%u, %p", from, attref);

	/* Lock the from socket. */
	ret = lock_socket(from, &from_sk);
	if (ret != 0)
		return ret;
	check_socket(from_sk, LINX_SOCK_STATE_BOUND, LINX_SOCK_TYPE_PEER);

	/* Call the general attach function. */
	ret = linx_detach(from_sk, *attref);

	/* Unlock the socket. */
	unlock_socket(from_sk);

	return ret;
}

/* Description: Hunt resolve callback, a pending hunt
 *              has been resolved.
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
linx_rlnh_hunt_resolved(LINX_RLNH rlnh, const char *name,
			LINX_SPID victim, LINX_SPID hunter)
{
	int err;

	LINX_ASSERT(name != NULL);
	LINX_ASSERT(victim != LINX_ILLEGAL_SPID);
	LINX_ASSERT(hunter != LINX_ILLEGAL_SPID);

	linx_trace_enter(LINX_TRACEGROUP_IPC,
			 "%s, 0x%x, 0x%x",
			 name == NULL ? "null" : name, victim, hunter);

	LINX_ASSERT(name != NULL);
	LINX_ASSERT(strlen(name) != 0);
	LINX_ASSERT(victim != LINX_ILLEGAL_SPID);
	LINX_ASSERT(hunter != LINX_ILLEGAL_SPID);

	/* Call the downcall implemented by RLNH. */
	err = rlnh_hunt_resolved(rlnh, name, victim, hunter);

	return err;
}

/* Description: An attach is resolved due to a released socket.
 *              Notify the RLNH.
 * Parameters:  to     - The attached victim socket. This socket
 *                       is already released or in the progress
 *                       of being released.
 *              from   - The original attach caller and owner.
 * Return:      Returns 0 on success.
 *              Returns -errno on failures.
 * Errors:      EINVAL - From is illegal or dead.
 *              EINVAL - From is already released.
 */
int
linx_rlnh_attach_notification(LINX_RLNH rlnh, LINX_SPID to)
{
	int err;

	linx_trace_enter(LINX_TRACEGROUP_IPC, "0x%x", to);

	LINX_ASSERT(to != LINX_ILLEGAL_SPID);

	/* Call the downcall implemented by RLNH. */
	err = rlnh_attach_notification(rlnh, to);

	return err;
}

/* Description: Send a routed signal via RLNH.
 * Parameters:
 * Return:
 * Errors:
 */
extern struct sk_buff_head routed_skb_list;
struct linx_sendmsg_routed {
	struct work_struct work;
};

static uint8_t routed_payload[64 * 1024];

#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20))
static void linx_do_sendmsg_routed(void *data)
{
	struct linx_sendmsg_routed *lsr = data;
#else
static void linx_do_sendmsg_routed(struct work_struct *work)
{
	struct linx_sendmsg_routed *lsr = (struct linx_sendmsg_routed *)
		container_of(work, struct linx_sendmsg_routed, work);
#endif
	int err = 0;
	uint32_t buffer_type = BUFFER_TYPE_KERNEL;
	struct sock *to_sk = NULL;
	struct sock *from_sk = NULL;
	struct linx_skb_cb *cb = NULL;
	struct sk_buff *skb = skb_dequeue(&routed_skb_list);
	ERROR_ON(skb == NULL); /* more works than items in list */
	cb = (struct linx_skb_cb *)skb->cb;

	ERROR_ON(cb->payload_size > 64 * 1024);

	linx_kfree(lsr);

	/* Change data_len and len fields of the skb so normal skb_copy_bits
	 * can be used. */
	skb->data_len = cb->payload_size - skb->len;
	skb->len = cb->payload_size;
	
	if (skb_copy_bits(skb, 0, routed_payload, cb->payload_size) != 0) {
		err = -EFAULT;
		goto linx_do_sendmsg_routed_failed;
	}
	
	err = lock_socket(cb->to_spid, &to_sk);
	if (err != 0) {
		if (err == -ECONNRESET)
			goto linx_do_sendmsg_routed_done;
		goto linx_do_sendmsg_routed_failed;
	}
	check_socket(to_sk, LINX_SOCK_STATE_BOUND, LINX_SOCK_TYPE_PEER);

	err = lock_socket(cb->from_spid, &from_sk);
	if (err != 0) {
		if (err == -ECONNRESET)
			goto linx_do_sendmsg_routed_done;
		goto linx_do_sendmsg_routed_failed;
	}
	check_socket(from_sk, LINX_SOCK_STATE_BOUND, LINX_SOCK_TYPE_PEER);

	/* rlnh_send expects signo to be in HOST ENDIAN */
	((uint32_t *) routed_payload)[0] =
	    ntohl(((uint32_t *) routed_payload)[0]);

	if(cb->flags & MSG_OOB)
		buffer_type |= BUFFER_TYPE_OOB;

	err = rlnh_send(linx_sk(from_sk)->rlnh,
			linx_sk(to_sk)->rlnh,
			routed_payload,
			cb->payload_size,
			buffer_type,
			cb->from_spid,
			linx_sk(from_sk)->rlnh_sender_hd,
			cb->to_spid,
			linx_sk(to_sk)->rlnh_dst_addr,
			linx_sk(from_sk)->rlnh_dst_addr,
			linx_sk(from_sk)->rlnh_peer_addr);
	if (err < 0 && err != -ECONNRESET) {
		goto linx_do_sendmsg_routed_failed;
	}

 linx_do_sendmsg_routed_done:
	if (to_sk)
		unlock_socket(to_sk);
	if (from_sk)
		unlock_socket(from_sk);

	kfree_skb(skb);

	return;

 linx_do_sendmsg_routed_failed:
	if (skb)
		kfree_skb(skb);

	if (to_sk) {
		rlnh_disconnect(linx_sk(to_sk)->rlnh);
		unlock_socket(to_sk);
	}
	if (from_sk) {
		rlnh_disconnect(linx_sk(from_sk)->rlnh);
		unlock_socket(from_sk);
	}
}

static int
rlnh_send_routed(struct sk_buff *skb, LINX_OSBUFSIZE payload_size,
		 LINX_SPID from, LINX_SPID to, uint32_t buffer_type)
{
	int err = 0;
	struct linx_skb_cb *cb = (struct linx_skb_cb *)skb->cb;
	struct linx_sendmsg_routed *send_routed;

	send_routed = linx_kmalloc(sizeof(*send_routed));
	if (send_routed == NULL) {
		err = -ENOMEM;
		return err;
	}

	cb->payload_size = payload_size;
	cb->from_spid = from;
	cb->to_spid = to;

	if(unlikely(BUF_TYPE_OOB(buffer_type))) {
		cb->flags |= MSG_OOB;
		skb_insert_oob(skb, &routed_skb_list);
	} else {
		cb->flags &= ~MSG_OOB;
		skb_queue_tail(&routed_skb_list, skb);
	}
	
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20))
	INIT_WORK(&send_routed->work, linx_do_sendmsg_routed, send_routed);
#else
	INIT_WORK(&send_routed->work, linx_do_sendmsg_routed);
#endif
	queue_work(linx_workqueue, &send_routed->work);
	return err;
}

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
 *              buffer_type    - buffer type and properties.
 * Return:      Returns 0 on success.
 *              Returns -errno on failures.
 * Errors:      EINVAL - To is illegal or dead.
 *              EINVAL - To is already released.
 *              EINVAL - From is illegal or dead.
 *              EINVAL - From is already released.
 */
int
linx_rlnh_send(void *payload, LINX_OSBUFSIZE payload_size,
	       struct sock *from_sk, LINX_SPID from,
	       struct sock *to_sk, LINX_SPID to, uint32_t buffer_type)
{
	int err = 0;

	linx_trace_enter(LINX_TRACEGROUP_IPC,
			 "%p, %d, %p, %u, %p, %u, %d",
			 payload,
			 payload_size,
			 from_sk, from, to_sk, to, buffer_type);

	LINX_ASSERT(payload != NULL);
	LINX_ASSERT(payload_size >= sizeof(LINX_SIGSELECT));
	LINX_ASSERT(to != LINX_ILLEGAL_SPID);
	LINX_ASSERT(from != LINX_ILLEGAL_SPID);

	if (likely(!BUF_TYPE_SKB(buffer_type))) /* Send the signal. */
		err = rlnh_send(linx_sk(from_sk)->rlnh,
				linx_sk(to_sk)->rlnh,
				payload,
				payload_size,
				buffer_type,
				from,
				linx_sk(from_sk)->rlnh_sender_hd,
				to,
				linx_sk(to_sk)->rlnh_dst_addr,
				linx_sk(from_sk)->rlnh_dst_addr,
				linx_sk(from_sk)->rlnh_peer_addr);
	else /* buffer_type == BUFFER_TYPE_SKB. Routed message */
		err = rlnh_send_routed((struct sk_buff *)payload, 
				       payload_size, from, to, buffer_type);
	return err;
}

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
int linx_rlnh_hunt(const char *name, LINX_SPID owner, LINX_SPID from)
{
	struct sock *owner_sk;
	struct sock *from_sk = NULL;
	int err = 0;

	linx_trace_enter(LINX_TRACEGROUP_IPC,
			 "%s, 0x%x, 0x%x ",
			 name == NULL ? "null" : name, owner, from);

	LINX_ASSERT(name != NULL);
	LINX_ASSERT(strlen(name) != 0);
	LINX_ASSERT(owner != LINX_ILLEGAL_SPID);
	LINX_ASSERT(from != LINX_ILLEGAL_SPID);

	/* Lock the owner socket. */
	err = lock_socket(owner, &owner_sk);
	/* The owner socket can be bound or unbound, but of peer type.
	 * The from socket can be bound and of any type. */
	if (err != 0)
		return err;
	check_socket(owner_sk,
		     LINX_SOCK_STATE_UNBOUND | LINX_SOCK_STATE_BOUND,
		     LINX_SOCK_TYPE_PEER);

	/* Lock the from socket. */
	err = lock_socket(from, &from_sk);
	if (err != 0) {
		unlock_socket(owner_sk);
		return err;
	}
	check_socket(from_sk, LINX_SOCK_STATE_BOUND, LINX_SOCK_TYPE_ANY);

	/* Hunt for the name. */
	err = rlnh_hunt(linx_sk(owner_sk)->rlnh, name, owner, from);

	/* Unlock the sockets. */
	unlock_socket(from_sk);
	unlock_socket(owner_sk);

	return err;
}

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
int linx_rlnh_ioctl(LINX_SPID spid, unsigned int cmd, unsigned long arg)
{
	int err;
	struct sock *sk;

	linx_trace_enter(LINX_TRACEGROUP_IPC,
			 "0x%x, %d, 0x%x", spid, cmd, (uint32_t) arg);

	LINX_ASSERT(spid != LINX_ILLEGAL_SPID);

	/* Lock the owner socket. */
	err = lock_socket(spid, &sk);
	if (err != 0)
		return err;
	check_socket(sk, LINX_SOCK_STATE_ANY, LINX_SOCK_TYPE_ANY);

	/* Hunt for the name. */
	err = rlnh_ioctl(spid, cmd, arg);

	/* Unlock the sockets. */
	unlock_socket(sk);

	return err;
}
