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

/*****************************************************************************
 * Linux OS Adaption Layer for RLNH
 *****************************************************************************/

#include <linux/delay.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <linux/completion.h>
#include <asm/atomic.h>
#include <net/sock.h>

#include <af_linx.h>
#include <ipc.h>
#include <linx_assert.h>
#include <linx_mem.h>
#include <rlnh.h>
#include <rlnh/rlnh_queue.h>
#include <rlnh/rlnh_proto.h>
#include <rlnh/rlnh_link.h>
#include <linx_trace.h>
#include <buf_types.h>

#include <cfg/db.h>
#include <cfg/db_proc.h>
#include <linux/db_ioctl.h>
#include <linux/rlnh_db_ioctl.h>

/*****************************************************************************
 * Reset the version number, default is the latest version. Results in other
 * side believing it speaks to an older version of RLNH.
 *****************************************************************************/

#ifdef RLNH_VERSION
#if RLNH_VERSION < 1 || RLNH_VERSION > 2
#error "Invalid RLNH Protocol version"
#else
#undef RLNH_PROTOCOL_VERSION
#define RLNH_PROTOCOL_VERSION RLNH_VERSION
#endif
#endif

/*****************************************************************************
 * Global variables, constansts, structures and macros.
 *****************************************************************************/

extern struct workqueue_struct *linx_workqueue;

/*****************************************************************************
 * Type definitions
 *****************************************************************************/

struct DisconnectLinkData {
	LINX_RLNH rlnh;
	struct work_struct work;
};

struct linx_queue_data {
	LINX_RLNH rlnh;
	uint32_t linkaddr;
	uint32_t peer_linkaddr;
	uint32_t version;
	LINX_SPID victim;
	LINX_SPID hunter;
	struct work_struct work;
	uint8_t co_index;
	char name[1];
};

/* RLNH protocol messages */
union RlnhMsg {
	struct RlnhInit init;
	struct RlnhInitReply init_reply;
	struct RlnhPublish publish;
	struct RlnhQueryName query_name;
	struct RlnhUnpublish unpublish;
	struct RlnhUnpublishAck unpublish_ack;
	struct RlnhPublishPeer publish_peer;
};

/* Object representing one link on the RLNH level */
struct cm_handle {
	struct RlnhObj *ro;
	uint8_t co_index;
};

#define STATE_CONNECTED 0
#define STATE_DISCONNECTED 1

#define MAX_CONNS_PER_LINK 2
struct RlnhObj {
#ifdef ERRORCHECKS
#define RLNH_OBJ_MAGIC 0xabbadabb
	uint32_t magic;
#endif
	/* Spid for this Link instance to use when attach */
	LINX_SPID spid;

	uint32_t idx;

	uint32_t array_size;
	LINX_SPID *addrmap_local;
	LINX_SPID *addrmap_remote;
	spinlock_t addrmap_lock;

	uint32_t pending_destroy;
	struct completion ready_for_destroy;
	int state;

	struct linx_queue_data *disconn[MAX_CONNS_PER_LINK];

	uint32_t version;

        char *feat;
	char *attr;

/* prototyping -> 0 is primary, 1 is oob */
        int num_cons;
        char *conn_name[MAX_CONNS_PER_LINK];
	struct RlnhLinkIF *conn_dc[MAX_CONNS_PER_LINK];
	struct RlnhLinkObj *conn_obj[MAX_CONNS_PER_LINK];
	struct cm_handle conn_handle[MAX_CONNS_PER_LINK];
	int connected_called[MAX_CONNS_PER_LINK];
	spinlock_t conn_called_lock;


	struct RlnhQueue *sig_queue;
	spinlock_t sig_queue_lock;

	uint32_t expected_msg_type;

	void *buffered_sig;
	uint32_t buffered_size;
	uint32_t buffered_type;

#ifdef ASSERT
	int lm_deliver_ok;
	int os_transmit_ok;
#endif
	uint32_t bit_array_len;
	uint32_t *bit_array;
	spinlock_t bit_array_lock;

	uint32_t link_name_len;
	char link_name[1];
};

/*****************************************************************************
 * Defines
 *****************************************************************************/


/* For Linux kernel 2.6.20 the workqueues where changed */
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20))
#define LINX_WORKQ_TYPE void
#define LINX_WORKQ_GETARG(arg) (arg)
#define LINX_INIT_WORK(work,func,arg) INIT_WORK((work),(func),(arg))
#else
#define LINX_WORKQ_TYPE struct work_struct
#define LINX_WORKQ_GETARG(arg) \
        container_of((arg), struct linx_queue_data, work)
#define LINX_INIT_WORK(work,func,arg) INIT_WORK((work),(func))
#endif

#ifdef ERRORCHECKS
#define assert_rlnh_obj(rlnh_obj) do {                                  \
   LINX_ASSERT(rlnh_obj != NULL);                                       \
   LINX_ASSERT(rlnh_obj->magic == RLNH_OBJ_MAGIC);                      \
   LINX_ASSERT(rlnh_obj->link_name_len != 0);                           \
   LINX_ASSERT(strlen(rlnh_obj->link_name) == rlnh_obj->link_name_len); \
   LINX_ASSERT(rlnh_obj->conn_dc != NULL);                              \
   LINX_ASSERT(rlnh_obj->conn_obj[RLNHCM] != NULL);                     \
   LINX_ASSERT(rlnh_obj->bit_array_len != 0);                           \
   LINX_ASSERT(rlnh_obj->bit_array != NULL);                            \
 } while(0)
#define SET_LM_DELIVER_OK(rlnh_obj, on) rlnh_obj->lm_deliver_ok = (on)
#define ASSERT_LM_DELIVER_OK(rlnh_obj) LINX_ASSERT(rlnh_obj->lm_deliver_ok)
#define ASSERT_LM_DELIVER_NOT_OK(rlnh_obj) \
        LINX_ASSERT(!rlnh_obj->lm_deliver_ok)
#define SET_OS_TRANSMIT_OK(rlnh_obj, on) rlnh_obj->os_transmit_ok = (on)
#define ASSERT_OS_TRANSMIT_OK(rlnh_obj) LINX_ASSERT(rlnh_obj->os_transmit_ok)
#define ASSERT_OS_TRANSMIT_NOT_OK(rlnh_obj) \
LINX_ASSERT(!rlnh_obj->os_transmit_ok)

#else

#define assert_rlnh_obj(rlnh_obj)
#define SET_LM_DELIVER_OK(rlnh_obj, on)
#define ASSERT_LM_DELIVER_OK(rlnh_obj)
#define ASSERT_LM_DELIVER_NOT_OK(rlnh_obj)
#define SET_OS_TRANSMIT_OK(rlnh_obj, on)
#define ASSERT_OS_TRANSMIT_OK(rlnh_obj)
#define ASSERT_OS_TRANSMIT_NOT_OK(rlnh_obj)

#endif

/* Defines for downcalls  */

#define CM_INITIALIZE(ro, i, uc) \
(ro)->conn_dc[i]->init((ro)->conn_obj[i], &(ro)->conn_handle[i], &uc)
#define CM_CONNECT(ro, i) (ro)->conn_dc[i]->connect(ro->conn_obj[i])
#define CM_DISCONNECT(ro, i) (ro)->conn_dc[i]->disconnect(ro->conn_obj[i])
#define CM_FINALIZE(ro, i) (ro)->conn_dc[i]->finalize(ro->conn_obj[i])
#define CM_TRANSMIT(ro, i, buf_type, src, dst, buf_size, buf) \
(ro)->conn_dc[i]->transmit((ro)->conn_obj[i], buf_type, src, dst, buf_size, buf)

/* This workaround is only needed for vanilla kernels earlier than 2.6.12.
 * See README for details. */
#if defined(LINX_KERNEL_WORKAROUND_1)

static inline void linx_down_read_irq(struct rw_semaphore *lock)
{
	int rv;
	do {
		unsigned long flags;
		local_irq_save(flags);
		rv = down_read_trylock(lock);
		local_irq_restore(flags);
	} while (!rv);
}

static inline int linx_down_read_trylock_irq(struct rw_semaphore *lock)
{
	int rv;
	unsigned long flags;
	local_irq_save(flags);
	rv = down_read_trylock(lock);
	local_irq_restore(flags);
	return rv;
}

static inline void linx_up_read_irq(struct rw_semaphore *lock)
{
	unsigned long flags;
	local_irq_save(flags);
	up_read(lock);
	local_irq_restore(flags);
}

static inline void linx_down_write_irq(struct rw_semaphore *lock)
{
	int rv;
	do {
		unsigned long flags;
		local_irq_save(flags);
		rv = down_write_trylock(lock);
		local_irq_restore(flags);
	} while (!rv);
}

static inline void linx_up_write_irq(struct rw_semaphore *lock)
{
	unsigned long flags;
	local_irq_save(flags);
	up_write(lock);
	local_irq_restore(flags);
}

#else

#define linx_down_read_irq(lock)          down_read(lock)
#define linx_down_read_trylock_irq(lock)  down_read_trylock(lock)
#define linx_up_read_irq(lock)            up_read(lock)
#define linx_down_write_irq(lock)         down_write(lock)
#define linx_up_write_irq(lock)           up_write(lock)

#endif

#define RLNHCM 0
#define OOBCM  1

#define rlnh_transmit_ctrl_msg(rlnh_obj, size, msg)                       \
      (rlnh_obj)->conn_dc[RLNHCM]->transmit((rlnh_obj)->conn_obj[RLNHCM], \
                                            BUFFER_TYPE_KERNEL,           \
                                            RLNH_LINKADDR,                \
                                            RLNH_LINKADDR,                \
                                            size,                         \
                                            msg)

#if defined(RLNH_BIG_ENDIAN)
#define RLNH_HTONL(x) ((uint32_t) x)
#define RLNH_NTOHL(x) ((uint32_t) x)
#elif defined(RLNH_LITTLE_ENDIAN)
#define RLNH_HTONL(x) ((uint32_t)(((x) << 24) & 0xff000000) | \
                                 (((x) <<  8) & 0x00ff0000) | \
                                 (((x) >>  8) & 0x0000ff00) | \
                                 (((x) >> 24) & 0x000000ff))
#define RLNH_NTOHL(x) RLNH_HTONL(x)
#else
#error must define RLNH_BIG_ENDIAN or RLNH_LITTLE_ENDIAN
#endif

#ifdef ARCH_HAS_NO_FFS
static int ffs(int val)
{
	int idx = 1;
	if (val == 0) {
		return 0;
	}
	if ((val & 0x0000FFFF) == 0) {
		val >>= 16;
		idx += 16;
	}
	if ((val & 0x000000FF) == 0) {
		val >>= 8;
		idx += 8;
	}
	if ((val & 0x0000000F) == 0) {
		val >>= 4;
		idx += 4;
	}
	if ((val & 0x00000003) == 0) {
		val >>= 2;
		idx += 2;
	}
	if ((val & 0x00000001) == 0) {
		val >>= 1;
		idx += 1;
	}
	return idx;
}
#endif

#define rlnh_debug(fmt, args...) \
linx_debug(LINX_TRACEGROUP_RLNH, fmt, ##args)

/*****************************************************************************
 * Keep track of RLNH objects
 *****************************************************************************/

struct RlnhObjContainer {
	struct RlnhObj *rlnh_obj;
	struct rw_semaphore sem;
	uint32_t ins;		/* Instance/Generation number for this entry */
};

struct LinkArray {
	spinlock_t lock;
	uint32_t count;
	struct RlnhObjContainer la[1];
};

static struct LinkArray *link_array;

#define rlnh_obj_ins(p) (((p) >> 16) & 0xFFFF)
#define rlnh_obj_idx(p) ((p) & 0xFFFF)
#define ins_idx_to_rlnh(ins,idx) (((ins) << 16) | ((idx) & 0xFFFF))

#define CONNECTING   0
#define CONNECTED    1
#define DISCONNECTED 2

static void change_conn_state(struct RlnhObj *rlnh_obj, uint8_t index,
			      int state)
{
	spin_lock_bh(&rlnh_obj->conn_called_lock);
	rlnh_obj->connected_called[index] = state;
	spin_unlock_bh(&rlnh_obj->conn_called_lock);
}

static int is_connected(struct RlnhObj *rlnh_obj, uint8_t index)
{
	int ret = 1;
	spin_lock_bh(&rlnh_obj->conn_called_lock);
	if (CONNECTED != rlnh_obj->connected_called[index])
		ret = 0;
	spin_unlock_bh(&rlnh_obj->conn_called_lock);
	return ret;
}

static int is_disconnected(struct RlnhObj *rlnh_obj, uint8_t index)
{
	int ret = 1;
	spin_lock_bh(&rlnh_obj->conn_called_lock);
	if (DISCONNECTED != rlnh_obj->connected_called[index])
		ret = 0;
	spin_unlock_bh(&rlnh_obj->conn_called_lock);
	return ret;
}

static int all_conns_connected(struct RlnhObj *rlnh_obj)
{
	int i = 0, ret = 1;
	spin_lock_bh(&rlnh_obj->conn_called_lock);
	for(i = 0; i < MAX_CONNS_PER_LINK; i++) {
		if(rlnh_obj->conn_obj[i] != NULL &&
		   rlnh_obj->connected_called[i] != CONNECTED) {
			ret = 0;
			break;
		}
	}
	spin_unlock_bh(&rlnh_obj->conn_called_lock);
	return ret;
}

static int register_rlnh_obj(struct RlnhObj *rlnh_obj, const char *name,
			     LINX_RLNH *ret_rlnh)
{
	uint32_t idx;
	struct RlnhObj *tmp;

	/* Update the global list of links */
	spin_lock_bh(&link_array->lock);

	/* check for an rlnh object with the same link name. */
	for (idx = 0; idx < linx_max_links; idx++) {
		if (likely(link_array->la[idx].rlnh_obj == NULL))
			continue;
		tmp = (struct RlnhObj *)link_array->la[idx].rlnh_obj;
		if (strcmp(tmp->link_name, name) == 0) {
			spin_unlock_bh(&link_array->lock);
			linx_info("Link name '%s' is not unique.",
				  tmp->link_name);
			return -EADDRINUSE;
		}
	}

	/* Find a empty entry in the link array */
	for (idx = 0; idx < linx_max_links; idx++) {
		if (unlikely(link_array->la[idx].rlnh_obj != NULL)) {
			continue;
		}
		link_array->la[idx].rlnh_obj = rlnh_obj;
		init_rwsem(&link_array->la[idx].sem);
		link_array->count++;
		break;
	}
	spin_unlock_bh(&link_array->lock);

	if (unlikely(idx == linx_max_links)) {
		linx_err("Maximum number of links (%d) exceeded",
			 linx_max_links);
		return -ENOBUFS;
	}

	rlnh_obj->idx = idx;
	*ret_rlnh = ins_idx_to_rlnh(link_array->la[idx].ins, rlnh_obj->idx);

	LINX_ASSERT(*ret_rlnh != LINX_ILLEGAL_RLNH);

	return 0;
}

/* This function must be called with link_array->la[id].sem taken */
static struct RlnhObj *unregister_rlnh_obj_and_release(LINX_RLNH rlnh)
{
	struct RlnhObj *rlnh_obj;
	struct RlnhObjContainer *cont = &link_array->la[rlnh_obj_idx(rlnh)];

	/* Update the global list of links */
	spin_lock_bh(&link_array->lock);

	rlnh_obj = cont->rlnh_obj;

	cont->rlnh_obj = NULL;

	/* Important to incremeant the instance number here so
	 * rlnh_obj = NULL is not returned with a locked entry
	 * in get_rlnh_obj. */
	cont->ins += 1;
	cont->ins &= 0xFFFF;

	/* Instance number is not allowed to be LINX_ILLEGAL_RLNH  */
	cont->ins += (cont->ins == LINX_ILLEGAL_RLNH ? 1 : 0);

	link_array->count--;

	spin_unlock_bh(&link_array->lock);

	linx_up_write_irq(&cont->sem);

	return rlnh_obj;
}

/*
 * get_rlnh_obj
 *
 * returns pointer to rlnh_obj if no one has taken the write lock,
 * i.e. the link is beeing disconnected. the rlnh_obj is safe from
 * removal while the read lock has been taken. the rlnh_obj must
 * be released when the rlnh_obj is no longer being used by calling
 * release_rlnh_obj.
 */
static inline struct RlnhObj *try_get_rlnh_obj(LINX_RLNH rlnh)
{
	struct RlnhObjContainer *cont = &link_array->la[rlnh_obj_idx(rlnh)];
	if (likely(linx_down_read_trylock_irq(&cont->sem))) {
		if (likely(cont->ins == rlnh_obj_ins(rlnh))) {
			return cont->rlnh_obj;
		}
		linx_up_read_irq(&cont->sem);
	}
	return NULL;
}

static inline struct RlnhObj *get_rlnh_obj(LINX_RLNH rlnh)
{
	struct RlnhObjContainer *cont = &link_array->la[rlnh_obj_idx(rlnh)];
	linx_down_read_irq(&cont->sem);
	if (likely(cont->ins == rlnh_obj_ins(rlnh))) {
		return cont->rlnh_obj;
	}
	linx_up_read_irq(&cont->sem);
	return NULL;
}

static inline void release_rlnh_obj(LINX_RLNH rlnh)
{
	linx_up_read_irq(&link_array->la[rlnh_obj_idx(rlnh)].sem);
}

static inline struct RlnhObj *get_rlnh_obj_exclusive(LINX_RLNH rlnh)
{
	struct RlnhObjContainer *cont = &link_array->la[rlnh_obj_idx(rlnh)];
	linx_down_write_irq(&cont->sem);
	if (likely(cont->ins == rlnh_obj_ins(rlnh))) {
		return cont->rlnh_obj;
	}
	linx_up_write_irq(&cont->sem);
	return NULL;
}

static inline void release_rlnh_obj_exclusive(LINX_RLNH rlnh)
{
	linx_up_write_irq(&link_array->la[rlnh_obj_idx(rlnh)].sem);
}

/*****************************************************************************
 * Link address functions - (per socket and per link)
 *****************************************************************************/

#define BITARRAY_EXTENDSIZE 4

#define bit_array_get(array, index) \
        (array[(index-1) >> 5] &  (1UL << ((index-1) & 0x1F)))
#define bit_array_set(array, index) \
        (array[(index-1) >> 5] |= (1UL << ((index-1) & 0x1F)))
#define bit_array_unset(array, index) \
        (array[(index-1) >> 5] &= ~(1UL << ((index-1) & 0x1F)))

static inline uint32_t find_free_linkaddr(struct RlnhObj *rlnh_obj)
{
	uint32_t idx = 0;
	rlnh_debug("Searching for free linkaddr");
	while (idx < rlnh_obj->bit_array_len) {
		uint32_t la;
		uint32_t first_one_pos;
		/* Check one uint32_t at the time. */
		first_one_pos = ffs(rlnh_obj->bit_array[idx]);
		if (unlikely(first_one_pos == 0)) {
			idx++;
			continue;
		}
		la = 32 * idx + first_one_pos;
		spin_lock_bh(&rlnh_obj->bit_array_lock);
		if (unlikely(!bit_array_get(rlnh_obj->bit_array, la))) {
			/* Someone else has interrupted us and taken the
			 * free idx that we found. Keep searching. */
			spin_unlock_bh(&rlnh_obj->bit_array_lock);
			continue;
		}
		bit_array_unset(rlnh_obj->bit_array, la);
		spin_unlock_bh(&rlnh_obj->bit_array_lock);
		return la;
	}
	return 0;
}

static inline uint32_t alloc_linkaddr(struct RlnhObj *rlnh_obj)
{
	uint32_t la = 0;

	for (;;) {
		uint32_t bit_array_len;
		uint32_t *new_bit_array;
		void *tmp;

		/* Check if there is a free linkaddress that can be reused. */
		la = find_free_linkaddr(rlnh_obj);
		if (likely(la != 0)) {
			break;
		}

		/* All link addresses are allocated, extend the bit array. */
		bit_array_len = rlnh_obj->bit_array_len;
		new_bit_array = linx_kmalloc(sizeof(uint32_t) *
					     (bit_array_len +
					      BITARRAY_EXTENDSIZE));

		if (unlikely(new_bit_array == NULL)) {
			/* This is taken care of in caller */
			return 0;
		}

		/* Set all new bits to 1 */
		memset(new_bit_array + bit_array_len,
		       -1, BITARRAY_EXTENDSIZE * sizeof(uint32_t));

		spin_lock_bh(&rlnh_obj->bit_array_lock);

		if (unlikely(rlnh_obj->bit_array_len > bit_array_len)) {
			/* Someone else has interrupted us and
			 * extended the bit_array
			 * already. Free our buffer and use
			 * the existing bit array. */
			spin_unlock_bh(&rlnh_obj->bit_array_lock);
			tmp = new_bit_array;
		} else {
			/* Copy the old data to the new bit array. */
			memcpy(new_bit_array,
			       rlnh_obj->bit_array,
			       sizeof(uint32_t) * bit_array_len);

			tmp = rlnh_obj->bit_array;
			rlnh_obj->bit_array = new_bit_array;
			rlnh_obj->bit_array_len += BITARRAY_EXTENDSIZE;

			spin_unlock_bh(&rlnh_obj->bit_array_lock);
		}
		linx_kfree(tmp);
	}

	return la;
}

static inline void free_linkaddr(struct RlnhObj *rlnh_obj, uint32_t la)
{
	LINX_ASSERT(la <= 32 * rlnh_obj->bit_array_len);

	spin_lock_bh(&rlnh_obj->bit_array_lock);

	/* Set the link address state to 1 in the bit array to indicate that
	 * the link address can be reused. */
	bit_array_set(rlnh_obj->bit_array, la);

	spin_unlock_bh(&rlnh_obj->bit_array_lock);
}

/*****************************************************************************
 * Internal helper functions
 *****************************************************************************/

static int distribute_peer(struct RlnhObj *rlnh_obj, LINX_SPID spid,
			   LINX_SPID src_la)
{
	int la, la_old, err;
	size_t size;
	union RlnhMsg *msg;
	uint32_t hdr = 0;

	la = alloc_linkaddr(rlnh_obj);
	if (unlikely(la == 0))
		return -ENOMEM; /* bitarray could not be extended */

	/* Check if linkaddr returned from Core fits in our array */
	if (unlikely(la > rlnh_obj->array_size)) {
		free_linkaddr(rlnh_obj, la);
		return -E2BIG;
	}
	rlnh_debug("spid %#x was allocated linkaddr %#x", spid, la);

	/* Lock to update addrmap_local */
	spin_lock_bh(&rlnh_obj->addrmap_lock);

	err = ipc_get_peer_hd(spid, (uint32_t *)&la_old);
	if (unlikely(err < 0)) {
		spin_unlock_bh(&rlnh_obj->addrmap_lock);
		return err;
	}

	if (unlikely(la_old != 0)) {
		/* Someone else has already allocated and set a linkaddr. */
		spin_unlock_bh(&rlnh_obj->addrmap_lock);
		free_linkaddr(rlnh_obj, la);
		return la_old;
	}

	err = ipc_set_peer_hd(spid, la);
	if (unlikely(err < 0)) {
		spin_unlock_bh(&rlnh_obj->addrmap_lock);
		return err;
	}

	spin_unlock_bh(&rlnh_obj->addrmap_lock);

	size = sizeof(struct RlnhPublishPeer);
	msg = linx_kmalloc(size);
	if (unlikely(msg == NULL))
		return -ENOMEM;

	hdr = set_type(hdr, RLNH_PUBLISH_PEER);
	msg->publish_peer.main_hdr = RLNH_HTONL(hdr);
	msg->publish_peer.linkaddr = RLNH_HTONL(la);
	msg->publish_peer.peer_linkaddr = RLNH_HTONL(src_la);

	rlnh_debug("TX: PUBLISH PEER (la:%#x peer_la:%#x)", la, src_la);
	err = rlnh_transmit_ctrl_msg(rlnh_obj, size, msg);
	linx_kfree(msg);
        if (err != 0)
                return err;

	return la;
}

static uint32_t distribute_proc_lock(struct RlnhObj *rlnh_obj, LINX_SPID spid,
				     struct sock **sk_unlock)
{
	uint32_t la, la_old, size, name_len;
	int err;
	const char *name;
	union RlnhMsg *msg;
	uint32_t hdr = 0;

	/* NOTE: ipc_spid_to_name returns with locked socket if successful */
	name = ipc_spid_to_name(spid, sk_unlock);

	if (unlikely(name == NULL)) {
		return 0;
	}

	name_len = strlen(name);

	la = alloc_linkaddr(rlnh_obj);
	ERROR_ON(la == 0);

	/* Check if linkaddr returned from Core fits in our array */
	if (unlikely(la > rlnh_obj->array_size)) {
		free_linkaddr(rlnh_obj, la);
		err = -E2BIG;
		goto error;
	}

	rlnh_debug("spid %#x was allocated linkaddr %#x", spid, la);

	/* Lock to update addrmap_local */
	spin_lock_bh(&rlnh_obj->addrmap_lock);

	err = ipc_get_sender_hd(spid, rlnh_obj->idx, &la_old);
	if (unlikely(err < 0)) {
		spin_unlock_bh(&rlnh_obj->addrmap_lock);
		goto error;
	}

	if (unlikely(la_old != 0)) {
		/* Someone else has already allocated and set a linkaddr. */
		spin_unlock_bh(&rlnh_obj->addrmap_lock);
		free_linkaddr(rlnh_obj, la);
		return la_old;
	}

	err = ipc_set_sender_hd(spid, rlnh_obj->idx, la);
	if (unlikely(err < 0)) {
		spin_unlock_bh(&rlnh_obj->addrmap_lock);
		goto error;
	}

	rlnh_obj->addrmap_local[la] = spid;

	rlnh_debug("set addrmap_local[%d] = %#x", la, spid);
	spin_unlock_bh(&rlnh_obj->addrmap_lock);

	size = offsetof(union RlnhMsg, publish.name) + name_len + 1;

	/* Extend to a multiple of uint32_t */
	size = (size + (sizeof(uint32_t) - 1)) & ~(sizeof(uint32_t) - 1);

	msg = linx_kmalloc(size);
	if (unlikely(msg == NULL)) {
		err = -ENOMEM;
		goto error;
	}

	hdr = set_type(hdr, RLNH_PUBLISH);
	msg->publish.main_hdr = RLNH_HTONL(hdr);
	msg->publish.linkaddr = RLNH_HTONL(la);
	memcpy(msg->publish.name, name, name_len + 1);

	rlnh_debug("TX: PUBLISH (name: '%s', la: %#x)", name, la);

	err = rlnh_transmit_ctrl_msg(rlnh_obj, size, msg);
	linx_kfree(msg);
        if (err != 0)
		goto failed_to_publish;

	/* Socket is left locked here! */
	return la;

 failed_to_publish:
	spin_lock_bh(&rlnh_obj->addrmap_lock);
	rlnh_obj->addrmap_local[la] = LINX_ILLEGAL_SPID;		
	(void)ipc_set_sender_hd(spid, rlnh_obj->idx, 0);
	free_linkaddr(rlnh_obj, la);
	spin_unlock_bh(&rlnh_obj->addrmap_lock);
 error:
	/* error, release the lock on the socket */
	sock_put(*sk_unlock);
	return err;
}

/*****************************************************************************
 * Functions executed in workqueue context.
 *****************************************************************************/


/*
 * wq_init
 */

static void wq_init(LINX_WORKQ_TYPE *arg)
{
	union RlnhMsg *msg;
	struct linx_queue_data *wq_data = LINX_WORKQ_GETARG(arg);
	struct RlnhObj *rlnh_obj;
	uint32_t hdr = 0;
	
	rlnh_obj = try_get_rlnh_obj(wq_data->rlnh);
	if (unlikely(rlnh_obj == NULL)) {
		goto out;
	}
	assert_rlnh_obj(rlnh_obj);

	msg = linx_kmalloc(sizeof(struct RlnhInit));
	if (unlikely(msg == NULL)) {
		CM_DISCONNECT(rlnh_obj, 0);
		goto unlock_and_out;
	}

	hdr = set_type(hdr, RLNH_INIT);

	msg->init.main_hdr = RLNH_HTONL(hdr);
	msg->init.version = RLNH_HTONL(RLNH_PROTOCOL_VERSION);

	rlnh_debug("TX: INIT (version=%d)", RLNH_PROTOCOL_VERSION);
	
        /* If Tx fails, CM will disconnect, sit tight... */
	(void)rlnh_transmit_ctrl_msg(rlnh_obj, sizeof(struct RlnhInit), msg);
	linx_kfree(msg);

 unlock_and_out:
	release_rlnh_obj(wq_data->rlnh);
 out:
	linx_kfree(wq_data);
}

/*
 * wq_init_reply
 */

static void wq_init_reply(LINX_WORKQ_TYPE *arg)
{
	struct linx_queue_data *wq_data = LINX_WORKQ_GETARG(arg);
	struct RlnhObj *rlnh_obj;
	union RlnhMsg *msg;
	size_t size;
	uint32_t hdr = 0;
	
	rlnh_obj = try_get_rlnh_obj(wq_data->rlnh);
	if (unlikely(rlnh_obj == NULL)) {
		goto out;
	}
	assert_rlnh_obj(rlnh_obj);

	size = sizeof(struct RlnhInitReply) + 1;
	msg = linx_kmalloc(size);

	if (unlikely(msg == NULL)) {
		CM_DISCONNECT(rlnh_obj, 0);
		goto unlock_and_out;
	}

	hdr = set_type(hdr, RLNH_INIT_REPLY);

	msg->init_reply.main_hdr = RLNH_HTONL(hdr);

	rlnh_obj->version = RLNH_PROTOCOL_VERSION;

	if (unlikely(wq_data->version <= RLNH_PROTOCOL_VERSION)) {
		rlnh_obj->version = wq_data->version;
		msg->init_reply.status = RLNH_HTONL(RLNH_PROTOCOL_SUPPORTED);
	} else
		msg->init_reply.status =
			RLNH_HTONL(RLNH_PROTOCOL_NOT_SUPPORTED);

	/* No features exist yet. */
	msg->init_reply.features[0] = '\0';

	rlnh_debug("TX: INIT_REPLY (status=%d)",
		   RLNH_NTOHL(msg->init_reply.status));

	/* If Tx fails, CM will disconnect, sit tight... */
	(void)rlnh_transmit_ctrl_msg(rlnh_obj, size, msg);
	linx_kfree(msg);
	
 unlock_and_out:
	release_rlnh_obj(wq_data->rlnh);
 out:
	linx_kfree(wq_data);
}

/*
 * wq_query_name
 */

static void wq_query_name(LINX_WORKQ_TYPE * arg)
{
	int err;
	struct RlnhObj *rlnh_obj;
	struct linx_queue_data *wq_data = LINX_WORKQ_GETARG(arg);

	LINX_SPID src_spid;

	LINX_ASSERT(wq_data != NULL);
	LINX_ASSERT(wq_data->linkaddr != 0);
	LINX_ASSERT(wq_data->name != NULL);
	LINX_ASSERT(wq_data->rlnh != LINX_ILLEGAL_RLNH);

	rlnh_obj = try_get_rlnh_obj(wq_data->rlnh);
	if (unlikely(rlnh_obj == NULL)) {
		goto out;
	}
	assert_rlnh_obj(rlnh_obj);

	rlnh_debug("get addrmap_remotel[%d] => %#x", wq_data->linkaddr,
		   rlnh_obj->addrmap_remote[wq_data->linkaddr]);

	src_spid = rlnh_obj->addrmap_remote[wq_data->linkaddr];

	if (unlikely(rlnh_obj->spid == LINX_ILLEGAL_SPID)) {
		/* Link has been disconnected */
		goto unlock_and_out;
	}

	if (unlikely(src_spid == LINX_ILLEGAL_SPID)) {
		goto unlock_and_out;
	}

	rlnh_debug("QUERY_NAME: '%s' (from spid %#x [la: %#x])",
		   wq_data->name, src_spid, wq_data->linkaddr);

	err = ipc_hunt(rlnh_obj->spid, wq_data->name, src_spid);

	if (unlikely(err != 0)) {
		rlnh_debug("QUERY_NAME: Hunt failed");
		CM_DISCONNECT(rlnh_obj, 0);
	}

 unlock_and_out:
	release_rlnh_obj(wq_data->rlnh);
 out:
	linx_kfree(wq_data);
}

/*
 * wq_publish_name
 */

static void wq_publish_name(LINX_WORKQ_TYPE * arg)
{
	struct linx_queue_data *wq_data = LINX_WORKQ_GETARG(arg);
	char *peer_name = NULL;
	struct RlnhObj *rlnh_obj;

	LINX_SPID peer_spid, dst_spid;

	struct RlnhQueueNode *n, *np;

	LINX_ASSERT(wq_data != NULL);
	LINX_ASSERT(wq_data->name != NULL);
	LINX_ASSERT(wq_data->rlnh != LINX_ILLEGAL_RLNH);

	rlnh_obj = try_get_rlnh_obj(wq_data->rlnh);
	if (unlikely(rlnh_obj == NULL)) {
		goto out;
	}
	assert_rlnh_obj(rlnh_obj);

	peer_name = linx_kmalloc(strlen(wq_data->name) +
				 rlnh_obj->link_name_len + 2);

	if (unlikely(peer_name == NULL)) {
		rlnh_debug("Failed to allocate memory");
		CM_DISCONNECT(rlnh_obj, 0);
		goto unlock_and_out;
	}

	memcpy(peer_name, rlnh_obj->link_name, rlnh_obj->link_name_len);

	peer_name[rlnh_obj->link_name_len] = '/';

	memcpy(peer_name + rlnh_obj->link_name_len + 1,
	       wq_data->name, strlen(wq_data->name) + 1);

	peer_spid = ipc_create_peer(wq_data->rlnh, peer_name,
				    wq_data->linkaddr);

	if (unlikely(peer_spid == LINX_ILLEGAL_SPID)) {
		rlnh_debug("Failed to create peer.");
		linx_kfree(peer_name);
		CM_DISCONNECT(rlnh_obj, 0);
		goto unlock_and_out;
	}

	rlnh_debug("set addrmap_remotel[%d] = %#x, peer '%s' created",
		   wq_data->linkaddr, peer_spid, peer_name);

	/* Deliver the signal queue... */
	spin_lock_bh(&rlnh_obj->sig_queue_lock);
	do {
		n = rlnh_queue_get(rlnh_obj->sig_queue, wq_data->linkaddr);
		spin_unlock_bh(&rlnh_obj->sig_queue_lock);
		while (n != NULL) {
			int err;
			LINX_ASSERT(n->sig != NULL);
			LINX_ASSERT(n->dst_la != 0);

			dst_spid = rlnh_obj->addrmap_local[n->dst_la];

			err = ipc_send_signal(n->sig, n->size,
					      dst_spid, peer_spid,
					      n->buffer_type);

			if (unlikely(err < 0)) {
				CM_DISCONNECT(rlnh_obj, 0);
			}
			np = n;
			n = n->next;
			LINX_ASSERT(np != NULL);
			linx_kfree(np);
		}
		spin_lock_bh(&rlnh_obj->sig_queue_lock);
	} while (!rlnh_queue_is_empty(rlnh_obj->sig_queue, wq_data->linkaddr));

	rlnh_obj->addrmap_remote[wq_data->linkaddr] = peer_spid;

	spin_unlock_bh(&rlnh_obj->sig_queue_lock);

	linx_kfree(peer_name);

 unlock_and_out:
	release_rlnh_obj(wq_data->rlnh);
 out:
	linx_kfree(wq_data);
}

/*
 * wq_unpublish
 */

static void wq_unpublish(LINX_WORKQ_TYPE * arg)
{
	struct linx_queue_data *wq_data = LINX_WORKQ_GETARG(arg);
	struct RlnhObj *rlnh_obj;
	union RlnhMsg *msg;
	int size;
	uint32_t hdr = 0;

	LINX_SPID spid;

	LINX_ASSERT(wq_data != NULL);
	LINX_ASSERT(wq_data->linkaddr != 0);
	LINX_ASSERT(wq_data->rlnh != LINX_ILLEGAL_RLNH);

	rlnh_obj = try_get_rlnh_obj(wq_data->rlnh);
	if (unlikely(rlnh_obj == NULL)) {
		goto out;
	}
	assert_rlnh_obj(rlnh_obj);

	rlnh_debug("get addrmap_remotel[%d] => %#x", wq_data->linkaddr,
		   rlnh_obj->addrmap_remote[wq_data->linkaddr]);

	spid = rlnh_obj->addrmap_remote[wq_data->linkaddr];

	if (unlikely(spid == LINX_ILLEGAL_SPID)) {
		goto unlock_and_out;
	}

	if (likely(ipc_local_peer(spid) != 0)) {
		if (unlikely(ipc_remove_peer(spid) < 0)) {
			goto unlock_and_out;
		}
	}

	rlnh_obj->addrmap_remote[wq_data->linkaddr] = LINX_ILLEGAL_SPID;

	/* Send a UNPUBLISH_ACK msg to the remote RLNH */
	size = sizeof(struct RlnhUnpublish);
	msg = linx_kmalloc(size);

	if (unlikely(msg == NULL)) {
		CM_DISCONNECT(rlnh_obj, 0);
		goto unlock_and_out;
	}

	hdr = set_type(hdr, RLNH_UNPUBLISH_ACK);
	msg->unpublish_ack.main_hdr = RLNH_HTONL(hdr);
	msg->unpublish_ack.linkaddr = RLNH_HTONL(wq_data->linkaddr);

	rlnh_debug("TX: UNPUBLISH_ACK (la: %#x)", wq_data->linkaddr);

        /* If Tx fails, CM will disconnect, sit tight... */
	(void)rlnh_transmit_ctrl_msg(rlnh_obj, size, msg);
	linx_kfree(msg);

 unlock_and_out:
	release_rlnh_obj(wq_data->rlnh);
 out:
	linx_kfree(wq_data);
}

/*
 * wq_connect_link
 */

static void wq_connect_link(LINX_WORKQ_TYPE * arg)
{
	struct linx_queue_data *wq_data = LINX_WORKQ_GETARG(arg);
	struct RlnhObj *rlnh_obj;

	LINX_ASSERT(wq_data != NULL);
	LINX_ASSERT(wq_data->rlnh != LINX_ILLEGAL_RLNH);

	rlnh_debug("wq_connect_link: (rlnh:%u)", wq_data->rlnh);

	rlnh_obj = try_get_rlnh_obj(wq_data->rlnh);

	rlnh_debug("wq_connect_link (rlnh:%p)", rlnh_obj);

	if (unlikely(rlnh_obj == NULL)) {
		goto out;
	}
	assert_rlnh_obj(rlnh_obj);

	rlnh_obj->spid = ipc_create_peer(wq_data->rlnh, rlnh_obj->link_name, 0);

	if (unlikely(rlnh_obj->spid == LINX_ILLEGAL_SPID)) {
		rlnh_debug("Failed to create link socket.");
		CM_DISCONNECT(rlnh_obj, 0);
		goto unlock_and_out;
	}

	rlnh_debug("ADD HUNT PATH(%s,%#x)",
		   rlnh_obj->link_name, rlnh_obj->spid);

	if (unlikely(ipc_add_hunt_path(rlnh_obj->link_name,
				       rlnh_obj->spid, rlnh_obj->attr) != 0)) {
		rlnh_debug("Failed to add hunt path");
		/* Nothing to do if ipc_remove_peer returns err. */
		(void)ipc_remove_peer(rlnh_obj->spid);
		CM_DISCONNECT(rlnh_obj, 0);
		goto unlock_and_out;
	}

	linx_info("Hunt path \"%s/\" available (RLNH version:%d)",
		  rlnh_obj->link_name, rlnh_obj->version);

	rlnh_obj->state = STATE_CONNECTED;

 unlock_and_out:
	release_rlnh_obj(wq_data->rlnh);
 out:
	linx_kfree(wq_data);

	return;

}


/* Forward declaration */
static void wq_rlnh_tear_down_link(LINX_WORKQ_TYPE * arg);


/*
 * wq_disconnect_link
 *
 * Runs in the worker thread, should only be queued by disconnected,
 * performs work that can't run in tasklet (interrupt) context.
 *
 */
static void wq_disconnect_link(LINX_WORKQ_TYPE * arg)
{
	struct linx_queue_data *wq_data = LINX_WORKQ_GETARG(arg);

	struct RlnhObj *rlnh_obj;
	uint32_t la;
	LINX_RLNH rlnh;
	LINX_SPID spid;
	uint8_t co_index;

	LINX_ASSERT(wq_data != NULL);
	LINX_ASSERT(wq_data->rlnh != LINX_ILLEGAL_RLNH);

	rlnh = wq_data->rlnh;
	co_index = wq_data->co_index;

	rlnh_obj = get_rlnh_obj_exclusive(rlnh);
	if (unlikely(rlnh_obj == NULL)) {
		goto out;
	}
	assert_rlnh_obj(rlnh_obj);

	/* Clear all remote mappings and "phantom" peers */
	for (la = 1; la <= rlnh_obj->array_size; la++) {
		LINX_SPID spid;

		spid = rlnh_obj->addrmap_remote[la];
		if (likely(spid != LINX_ILLEGAL_SPID)) {
			rlnh_debug("Free local spid %#x (la:%u)",
				   spid, la);
			rlnh_obj->addrmap_remote[la] =LINX_ILLEGAL_SPID;
			if (ipc_local_peer(spid) != 0)
				(void)ipc_remove_peer(spid);
		}

		spid = rlnh_obj->addrmap_local[la];
		if (likely(spid != LINX_ILLEGAL_SPID)) {
			rlnh_debug("Free remote spid %#x (la:%u)",
				   spid, la);
			rlnh_obj->addrmap_local[la] = LINX_ILLEGAL_SPID;
			(void)ipc_set_sender_hd(spid, rlnh_obj->idx, 0);
		}
	}

	if(rlnh_obj->spid != LINX_ILLEGAL_SPID) {
		spid = rlnh_obj->spid;
		rlnh_obj->spid = LINX_ILLEGAL_SPID;
		(void)ipc_remove_hunt_path(spid);
		(void)ipc_remove_peer(spid);
		linx_info("Hunt path \"%s/\" unavailable", rlnh_obj->link_name);
		rlnh_obj->state = STATE_DISCONNECTED;
	}

	/* The write lock must first be released before calling
	 * rlnh_connect_link and the rlnh_obj must be verified. */


	release_rlnh_obj_exclusive(rlnh);

	rlnh_obj = try_get_rlnh_obj(rlnh);

	if (unlikely(rlnh_obj == NULL)) {
		return;
	}

	SET_OS_TRANSMIT_OK(rlnh_obj, 0);

	/* Revert to "init state". */
	rlnh_obj->expected_msg_type = RLNH_INIT;
	memset(rlnh_obj->bit_array, -1,
	       sizeof(uint32_t) * rlnh_obj->bit_array_len);
	if (rlnh_obj->buffered_sig != NULL) {
		kfree_skb((struct sk_buff *)rlnh_obj->buffered_sig);
		rlnh_obj->buffered_sig = NULL;
	}

	if (likely(0 == rlnh_obj->pending_destroy)) {
		/* Tell the link manager to setup the connection and to notify
		 * us when its done via the lnhcb_connected() upcall. */
		change_conn_state(rlnh_obj, co_index, CONNECTING);
		CM_CONNECT(rlnh_obj, co_index);

	} else {
		/* Shutdown in progress - set connection to disconnected
		 * and schedule the tear down task */
		change_conn_state(rlnh_obj, co_index, DISCONNECTED);
		wq_data = linx_kmalloc(sizeof(*wq_data));
		wq_data->rlnh = rlnh_obj->disconn[RLNHCM]->rlnh;
		LINX_INIT_WORK(&wq_data->work, wq_rlnh_tear_down_link, wq_data);
		(void)queue_work(linx_workqueue, &wq_data->work);
	}
	release_rlnh_obj(rlnh);

 out:
	/* wq_data freed by destroy link */
	return;
}

/******************************************************************************
 * Handle incoming messages from the remote RLNH.
 ******************************************************************************/

static inline int handle_rlnh_init(struct RlnhObj *rlnh_obj, uint32_t version)
{
	struct linx_queue_data *wq_data;
	
	wq_data = linx_kmalloc(sizeof(*wq_data));
	if (unlikely(wq_data == NULL)) {
		rlnh_debug("Failed to allocate memory.");
		return -ENOMEM;
	}
	
	/* The next expected msg is the reply to our RLNH_INIT msg */
	rlnh_obj->expected_msg_type = RLNH_INIT_REPLY;

	wq_data->rlnh = rlnh_obj->disconn[RLNHCM]->rlnh;
	wq_data->version = version;
	LINX_INIT_WORK(&wq_data->work, wq_init_reply, wq_data);
	(void)queue_work(linx_workqueue, &wq_data->work);

	return 0;
}

/*
 * handle_rlnh_init_reply
 *
 * Init reply sent from remote RLNH, setup the link.
 *
 */

static inline int handle_rlnh_init_reply(struct RlnhObj *rlnh_obj,
					 uint32_t status, char *features)
{
	struct linx_queue_data *wq_data;

	/* This version of RLNH has no features */
	(void)features;

	if (unlikely(status != RLNH_PROTOCOL_SUPPORTED)) {
		/* Peer does not support our version of the protocol */
		linx_info("Remote RLNH version is %d", rlnh_obj->version);
	}

	rlnh_debug("RX: Connect link with version=%d", rlnh_obj->version);

	/* Accept any message from now on. */
	rlnh_obj->expected_msg_type = 0;

	/* Tell OS layer that the link is up. */
	ASSERT_OS_TRANSMIT_NOT_OK(rlnh_obj);
	SET_OS_TRANSMIT_OK(rlnh_obj, 1);

	/* Connect link */
	wq_data = linx_kmalloc(sizeof(*wq_data));

	if (unlikely(!wq_data)) {
		rlnh_debug("Failed to allocate memory.");
		return -ENOMEM;
	}

	wq_data->rlnh = rlnh_obj->disconn[RLNHCM]->rlnh;

	LINX_INIT_WORK(&wq_data->work, wq_connect_link, wq_data);
	(void)queue_work(linx_workqueue, &wq_data->work);

	return 0;
}

/*
 * handle_rlnh_query_name
 *
 * Ask the OS layer to resolve the name. It will respond
 * with an rlnh_publish() call when it has found the name.
 *
 */

static inline int handle_rlnh_query_name(struct RlnhObj *rlnh_obj,
					 const char *name, uint32_t linkaddr)
{
	struct linx_queue_data *wq_data;

	wq_data = linx_kmalloc(sizeof(*wq_data) + strlen(name) + 1);

	if (unlikely(wq_data == NULL)) {
		rlnh_debug("Failed to allocate memory");
		return -ENOMEM;
	}

	wq_data->rlnh = rlnh_obj->disconn[RLNHCM]->rlnh;
	wq_data->linkaddr = linkaddr;
	memcpy(wq_data->name, name, strlen(name) + 1);

	LINX_INIT_WORK(&wq_data->work, wq_query_name, wq_data);
	(void)queue_work(linx_workqueue, &wq_data->work);

	return 0;
}

/*
 * handle_rlnh_publish
 *
 * A remote name has been published.
 *
 */

static inline int handle_rlnh_publish(struct RlnhObj *rlnh_obj,
				      const char *name, uint32_t linkaddr)
{
	struct linx_queue_data *wq_data;

	wq_data = linx_kmalloc(sizeof(*wq_data) + strlen(name) + 1);

	if (unlikely(wq_data == NULL)) {
		rlnh_debug("Failed to allocate memory.");
		return -ENOMEM;
	}

	wq_data->rlnh = rlnh_obj->disconn[RLNHCM]->rlnh;
	wq_data->linkaddr = linkaddr;
	memcpy(wq_data->name, name, strlen(name) + 1);

	LINX_INIT_WORK(&wq_data->work, wq_publish_name, wq_data);
	(void)queue_work(linx_workqueue, &wq_data->work);

	return 0;
}

/*
 * handle_rlnh_unpublish
 *
 * A remote object has been unpublished, release_linkaddr()
 * is called when the link address association is terminated
 *
 */

static inline int handle_rlnh_unpublish(struct RlnhObj *rlnh_obj,
					uint32_t linkaddr)
{
	struct linx_queue_data *wq_data;

	wq_data = linx_kmalloc(sizeof(*wq_data));

	if (unlikely(wq_data == NULL)) {
		rlnh_debug("Failed to allocate memory.");
		return -ENOMEM;
	}

	wq_data->rlnh = rlnh_obj->disconn[RLNHCM]->rlnh;
	wq_data->linkaddr = linkaddr;

	LINX_INIT_WORK(&wq_data->work, wq_unpublish, wq_data);
	(void)queue_work(linx_workqueue, &wq_data->work);

	return 0;
}

static inline void handle_rlnh_msg(struct RlnhObj *rlnh_obj, uint32_t size,
				   void *sig, LINX_OSBOOLEAN payload_skb)
{
	uint32_t msg_type;
	union RlnhMsg *msg;
	struct sk_buff *skb = NULL;
	int rv = 0;
	uint32_t la, version, status, peer_la;
	LINX_SPID spid;

	if (payload_skb) {
		/* Buffer is a skb */
		skb = (struct sk_buff *)sig;
		msg = (union RlnhMsg *)(skb->data);
	} else {
		/* Buffer was allocated with kmalloc */
		msg = (union RlnhMsg *)sig;
	}

	/* Convert signo to host endian */
	msg_type = type(RLNH_NTOHL(((uint32_t *) msg)[0]));

	/* Expected messages are only when creating a connection */
	if (unlikely(rlnh_obj->expected_msg_type != 0 &&
		     msg_type != rlnh_obj->expected_msg_type)) {
		linx_err("RLNH unexpected msg_no: %x (expected %x)",
			 msg_type, rlnh_obj->expected_msg_type);
		goto err;
	}

	switch (msg_type) {
	case RLNH_INIT:
		version = RLNH_NTOHL(msg->init.version);
		rlnh_debug("RX: INIT (version:%d)", version);
		rv = handle_rlnh_init(rlnh_obj, version);
		if (rv < 0) {
			goto err;
		}
		break;
	case RLNH_INIT_REPLY:
		status = RLNH_NTOHL(msg->init_reply.status);
		rlnh_debug("RX: INIT_REPLY (status:%d)", status);
		rv = handle_rlnh_init_reply(rlnh_obj, status,
					    msg->init_reply.features);
		if (rv < 0) {
			goto err;
		}
		break;
	case RLNH_QUERY_NAME:
		la = RLNH_NTOHL(msg->query_name.linkaddr);
		rlnh_debug("RX: QUERY_NAME (name:'%s', la:%#x)",
			   msg->query_name.name, la);
		if(la > rlnh_obj->array_size) {
			rlnh_debug("RX: QUERY_NAME - Invalid link address %d", la);
			goto err;
		}
		rv = handle_rlnh_query_name(rlnh_obj, msg->query_name.name, la);
		if (rv < 0) {
			goto err;
		}
		break;
	case RLNH_PUBLISH:
		la = RLNH_NTOHL(msg->publish.linkaddr);
		rlnh_debug("RX: PUBLISH (name:'%s', la:%#x)",
			   msg->publish.name, la);
		if(la > rlnh_obj->array_size) {
			rlnh_debug("RX: PUBLISH - Invalid link address %d",la);
			goto err;
		}
		rv = handle_rlnh_publish(rlnh_obj, msg->query_name.name, la);
		if (rv < 0) {
			goto err;
		}
		break;
	case RLNH_UNPUBLISH:
		la = RLNH_NTOHL(msg->unpublish.linkaddr);
		rlnh_debug("RX: UNPUBLISH (la:%#x)", la);
		if(la > rlnh_obj->array_size) {
			rlnh_debug("RX: UNPUBLISH - Invalid link address %d",la);
			goto err;
		}
		rv = handle_rlnh_unpublish(rlnh_obj, la);
		if (rv < 0) {
			goto err;
		}
		break;
	case RLNH_UNPUBLISH_ACK:
		la = RLNH_NTOHL(msg->unpublish_ack.linkaddr);
		if(la > rlnh_obj->array_size) {
			rlnh_debug("RX: UNPUBLISH_ACK - Invalid link address %d",la);
			goto err;
		}
		/* The remote node has terminated its references to the link
		 * address. It is now ok to reuse this link address. */
		rlnh_debug("RX: UNPUBLISH_ACK (la:%#x)", la);
		free_linkaddr(rlnh_obj, la);
		break;
	case RLNH_PUBLISH_PEER:
		la = RLNH_NTOHL(msg->publish_peer.linkaddr);
		peer_la = RLNH_NTOHL(msg->publish_peer.peer_linkaddr);
		if(peer_la > rlnh_obj->array_size || 
		   la > rlnh_obj->array_size) {
			rlnh_debug("RX: QUERY_NAME - Invalid link address peer_la %d / la %d",
					peer_la, la);
			goto err;
		}
		rlnh_debug("RX: PUBLISH_PEER (la:%#x, peer_la:%#x)",
			   la, peer_la);
		rlnh_debug("get addrmap_local[%d] => %#x",
			   peer_la, rlnh_obj->addrmap_local[peer_la]);
		spid = rlnh_obj->addrmap_local[peer_la];
		if (unlikely(spid == LINX_ILLEGAL_SPID)) {
			goto out;
		}
		rlnh_debug("set addrmap_remote[%d] => %#x", la, spid);
		rlnh_obj->addrmap_remote[la] = spid;
		break;
	default:
		/* Unknown msg received. */
		linx_err("unknown msg (%d, size:%d) received", msg_type, size);
		break;
	}
 out:
	if (payload_skb)
		kfree_skb(skb);
	else
		linx_kfree(sig);
	return;
 err:
	/* Disconnect link */
	CM_DISCONNECT(rlnh_obj, 0);
	goto out;
}

/*
 * lnhcb_deliver
 *
 * Called by CM when a message has been received
 *
 */
static int lnhcb_deliver(void *rlnh_obj_p,
			 uint32_t buffer_type,
			 uint32_t la_src,
			 uint32_t la_dst, uint32_t size, void *sig)
{
	struct RlnhObj *rlnh_obj = ((struct cm_handle *)rlnh_obj_p)->ro;
	struct sk_buff *skb = sig;
	int err = 0;
	uint8_t co_index = ((struct cm_handle *)rlnh_obj_p)->co_index;
	LINX_SPID src_spid;
	LINX_SPID dst_spid;
	LINX_OSBOOLEAN payload_skb = BUF_TYPE_SKB(buffer_type);

	LINX_ASSERT(sig != NULL);
	LINX_ASSERT(size >= 4);

	assert_rlnh_obj(rlnh_obj);
	/*
         * If two connections are tied to this link and on the remote side both
	 * connections have called connected then a RLNH_INIT message could be
	 * received before both connection on this side have called connected.
	 * Therefore buffer the RLNH_INIT message until an reply is received on
	 * the local sides RLNH_INIT message since that message is not sent
	 * until both connections have called connected.
	 */
	if(!all_conns_connected(rlnh_obj)) {
		if (unlikely(la_dst == RLNH_LINKADDR)) {
			if (rlnh_obj->buffered_sig == NULL) {
				rlnh_obj->buffered_sig = sig;
				rlnh_obj->buffered_size = size;
				rlnh_obj->buffered_type = buffer_type;
			} else {
				/* Should not happen! */
				linx_warn("A signal is already buffered by "
					  "RLNH, should not happed!\n");
				kfree_skb((struct sk_buff *)sig);
			}
		} else
			kfree_skb((struct sk_buff *)sig);
		return 0;
	}

	/* Deliver buffered sig if any */
	if (unlikely(rlnh_obj->buffered_sig != NULL)) {
		handle_rlnh_msg(rlnh_obj,
				rlnh_obj->buffered_size,
				rlnh_obj->buffered_sig,
				BUF_TYPE_SKB(rlnh_obj->buffered_type));
		rlnh_obj->buffered_sig = NULL;
	}

	/* Check if the receiver is LINX itself. */
	if (unlikely(la_dst == RLNH_LINKADDR)) {
		/* Check if the rlnh message is on the correct connection. */
		if(co_index != RLNHCM) {
			linx_warn("Received RLNH Message on wrong connection");
			goto out;
		}
		handle_rlnh_msg(rlnh_obj, size, sig, payload_skb);
		goto out;
	}

	if(co_index == OOBCM && !BUF_TYPE_OOB(buffer_type)) 
		buffer_type |= BUFFER_TYPE_OOB; /* add oob if oobcm did not */
	
	LINX_ASSERT(la_src != 0);
	LINX_ASSERT(la_src <= rlnh_obj->array_size);
	LINX_ASSERT(la_dst <= rlnh_obj->array_size);

	rlnh_debug("%#x -> %#x (la), addrmap_local[%d] => spid:%x",
		   la_src, la_dst, la_dst, rlnh_obj->addrmap_local[la_dst]);

	dst_spid = rlnh_obj->addrmap_local[la_dst];

	if (unlikely(dst_spid == LINX_ILLEGAL_SPID)) {
		rlnh_debug("dst_la %#x unknown, dropping signal", la_dst);
		if (payload_skb) {
			kfree_skb(skb);
		} else {
			linx_kfree(sig);
		}
		goto out;
	}
#ifdef RLNH_LITTLE_ENDIAN
	/* Endian convert signo */
	if (likely(payload_skb)) {
		struct linx_skb_cb *cb = (struct linx_skb_cb *)skb->cb;
		/* Store host byte order signo in control block.  When
		 * the message is received we compare the stored signo
		 * to message filter and copies also the stored signo
		 * to userspace.  We never touch the skb-data
		 * confusing other users of the skb. */
		cb->signo = ntohl(((uint32_t *) skb->data)[0]);
	} else {
		((uint32_t *) sig)[0] = ntohl(((uint32_t *) sig)[0]);
	}
#else
	if (likely(payload_skb)) {
		struct linx_skb_cb *cb = (struct linx_skb_cb *)skb->cb;
		/* Store signo in control block.  There no need for
		 * byte order conversion but it simplifies the
		 * linx_recvmsg code. */
		cb->signo = ((uint32_t *) skb->data)[0];
	}
#endif

	rlnh_debug("get addrmap_remotel[%d] => %#x",
		   la_src, rlnh_obj->addrmap_remote[la_src]);

	src_spid = rlnh_obj->addrmap_remote[la_src];
	if (unlikely(src_spid == LINX_ILLEGAL_SPID)) {
		spin_lock_bh(&rlnh_obj->sig_queue_lock);
		src_spid = rlnh_obj->addrmap_remote[la_src];
		if (unlikely(src_spid == LINX_ILLEGAL_SPID)) {
			rlnh_debug("  la_src %#x has no 'phantom' - "
				   "enqueue msg", la_src);
			rlnh_queue_enqueue(rlnh_obj, rlnh_obj->sig_queue,
					   la_src, la_dst,
					   sig, size, buffer_type);
			spin_unlock_bh(&rlnh_obj->sig_queue_lock);
			goto out;
		}
		spin_unlock_bh(&rlnh_obj->sig_queue_lock);
	}

	rlnh_debug("%#x -> %#x (spid)", src_spid, dst_spid);

	err = ipc_send_signal(sig, size, dst_spid, src_spid, buffer_type);

	if (unlikely(err < 0)) {
		CM_DISCONNECT(rlnh_obj, 0);
	}
 out:
	return err;
}

/*
 * lnhcb_alloc
 *
 * Allocate a buffer.
 *
 */

static void *lnhcb_alloc(void *rlnh_obj_p, uint32_t buffer_type, uint32_t size)
{
	void *buf;
	if(!BUF_TYPE_KERN(buffer_type)) {
		linx_err("Not supported yet\n");
		return 0;
	}
	LINX_ASSERT(size != 0);

	buf = linx_kmalloc(size);

	if (unlikely(buf == NULL)) {
		struct RlnhObj *rlnh_obj = ((struct cm_handle *)rlnh_obj_p)->ro;
		uint8_t index = ((struct cm_handle *)rlnh_obj_p)->co_index;
		CM_DISCONNECT(rlnh_obj, index);
	}

	return buf;
}

/*
 * lnhcb_free
 *
 * Free a buffer allocated by lnhcb_alloc
 *
 */

static void lnhcb_free(void *rlnh_obj_p, uint32_t buffer_type, void *sigp)
{
	(void)rlnh_obj_p;
	if(!BUF_TYPE_KERN(buffer_type)) {
		linx_err("Not supported yet\n");
		return;
	}
	LINX_ASSERT(sigp != NULL);
	linx_kfree(sigp);
}

/*
 * lnhcb_error
 *
 * Called by CM when an error occurs, this results in a stack dump in Linux.
 *
 */

static void lnhcb_error(void *rlnh_obj_p, void *error_data)
{
	(void)rlnh_obj_p;
	linx_err("CM reported error :%p", error_data);
	dump_stack();
}

/*
 * lnhcb_connected
 *
 * Can by CM when a conenction is available.
 */

static void lnhcb_connected(void *rlnh_obj_p)
{
	struct RlnhObj *rlnh_obj = ((struct cm_handle *)rlnh_obj_p)->ro;
	uint32_t co_index = ((struct cm_handle *)rlnh_obj_p)->co_index;
	struct linx_queue_data *wq_data;
	
	assert_rlnh_obj(rlnh_obj);

	rlnh_debug("lnhcb_connected (rlnh_obj: 0x%p)", rlnh_obj);

	change_conn_state(rlnh_obj, co_index, CONNECTED);

	/* wait until all connections have connected */
	if(!all_conns_connected(rlnh_obj))
		return;

	/* schedule wq_init(...) */
	wq_data = linx_kmalloc(sizeof(*wq_data));
	if (unlikely(wq_data == NULL)) {
		rlnh_debug("Failed to allocate memory.");
		CM_DISCONNECT(rlnh_obj, 0);
		return;
	}
	
	wq_data->rlnh = rlnh_obj->disconn[RLNHCM]->rlnh;
	LINX_INIT_WORK(&wq_data->work, wq_init, wq_data);
	(void)queue_work(linx_workqueue, &wq_data->work);
}


/*
 * lnhcb_disconnected
 *
 * Can by CM when a connection is no longer available.
 */

static void lnhcb_disconnected(void *rlnh_obj_p)
{
	struct RlnhObj *rlnh_obj = ((struct cm_handle *)rlnh_obj_p)->ro;
	uint8_t co_index = ((struct cm_handle *)rlnh_obj_p)->co_index;
	int i = MAX_CONNS_PER_LINK;
	assert_rlnh_obj(rlnh_obj);
	SET_LM_DELIVER_OK(rlnh_obj, 0);
	(void)queue_work(linx_workqueue, &rlnh_obj->disconn[co_index]->work);
	/* disconnect other connections associated with this link */
	while(i--)
		if(i != co_index &&
		   rlnh_obj->conn_obj[i] != NULL &&
		   is_connected(rlnh_obj, i))
			CM_DISCONNECT(rlnh_obj, i);
}

struct RlnhLinkUCIF rlnhLinkUCIF = {
	RLNH_LINK_UC_IF_VERSION,
	lnhcb_deliver,
	lnhcb_alloc,
	lnhcb_free,
	lnhcb_error,
	lnhcb_connected,
	lnhcb_disconnected
};

/*****************************************************************************
 * Functions to create and destroy RLNH links.
 *****************************************************************************/

#define uptr(p, n) ((u8 __user *)(p) + (n))
#define kptr(p, n) ((u8 *)(p) + (n))

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 13))
static char *linx_kstrdup(const char *s, unsigned int gfp)
{
        size_t len;
        char *p;

        if (s == NULL)
                return NULL;

        len = strlen(s) + 1;
        p = kmalloc(len, gfp);
        if (p == NULL)
                return NULL;

        return memcpy(p, s, len);
}
#else
#define linx_kstrdup kstrdup
#endif

/* DB templates etc. */
static const struct db_param rlnh_params[] = {
        DB_PARAM_ARR("con_name", DB_PTR | DB_STRING, conn_name, struct RlnhObj),
        DB_PARAM_ARR("con_cookie", DB_PTR | DB_VOID, conn_obj, struct RlnhObj),
        DB_PARAM_ARR("con_dc", DB_PTR | DB_VOID, conn_dc, struct RlnhObj),
        DB_PARAM("attributes", DB_PTR | DB_STRING, attr, struct RlnhObj),
	DB_PARAM("state", DB_INT, state, struct RlnhObj),

        DB_PARAM_END,
};

static void *rlnh_create(void __user *arg);
static int rlnh_delete(void *cookie, void __user *arg);

static const struct db_template rlnh_template = {
        .owner = THIS_MODULE,
        .create = rlnh_create,
        .destroy = rlnh_delete,
        .param = rlnh_params
};

static size_t sizeof_arguments(struct rlnh_ioctl_create *p)
{
        int n;
        size_t size;

        size = sizeof(*p) + p->name_len + 1 + p->attr_len + 1 + p->feat_len + 1;
        for (n = 0; n < p->num_cons; n++)
                size += p->con_name_len[n] + 1;
        return size;
}

static struct rlnh_ioctl_create *copy_arguments_from_user(void __user *arg)
{
        struct rlnh_ioctl_create k, *kp;
        size_t size;

        if (copy_from_user(&k, arg, sizeof(k)) != 0)
                return ERR_PTR(-EFAULT);

        size = sizeof_arguments(&k);
        kp = kmalloc(size, GFP_KERNEL);
        if (kp == NULL)
                return ERR_PTR(-ENOMEM);

        if (copy_from_user(kp, arg, size) != 0) {
                kfree(kp);
                return ERR_PTR(-EFAULT);
        }
        return kp;
}

static int conn_in_use(const struct RlnhObj *p)
{
	struct RlnhObj *q;
        int k, i, j;

	spin_lock_bh(&link_array->lock);
	for (k = 0; k < linx_max_links; k++) {
		if (likely(link_array->la[k].rlnh_obj == NULL ||
                           link_array->la[k].rlnh_obj == p))
			continue;

                q = (struct RlnhObj *)link_array->la[k].rlnh_obj;

                for (i = 0; i < p->num_cons; i++) {
                        for (j = 0; j < q->num_cons; j++) {
                                if (strcmp(p->conn_name[i], q->conn_name[j]) == 0)
                                        goto out; /* Match! */
                        }
                }
        }
        spin_unlock_bh(&link_array->lock);
        return 0;
 out:
        spin_unlock_bh(&link_array->lock);
        linx_info("Connection '%s' is already used by '%s'.", p->conn_name[i],
                  q->link_name);
        return 1;
}

static int rlnh_setup_link(struct RlnhObj *rlnh_obj);
static int rlnh_tear_down_link(struct RlnhObj *rlnh_obj);

#ifdef CONFIG_64BIT
#define u64_to_ptr(ptr) ptr
#else
#define u64_to_ptr(ptr) (unsigned long *)((unsigned int)ptr)
#endif

static struct db_value *get_value(const char *conn_name, const char *var_name,
                                  size_t var_size)
{
        size_t len;
        char *name;
        struct db_value *v;
        int status;

        len = strlen(conn_name) + strlen(var_name) + 2; /* Extra / and \0 */
        name = kmalloc(len, GFP_KERNEL);
        if (name == NULL)
                return ERR_PTR(-ENOMEM);

        sprintf(name, "%s/%s", conn_name, var_name);

        v = kmalloc(sizeof(*v) + var_size, GFP_KERNEL);
        if (v == NULL) {
                kfree(name);
                return ERR_PTR(-ENOMEM);
        }

        status = db_get_value(name, v, v->buf, var_size);
        if (status != 0) {
                kfree(name);
                kfree(v);
                return ERR_PTR(status);
        }

        kfree(name);
        return v;
}

static int get_u64(const char *conn_name, const char *var_name, u64 *v64)
{
        struct db_value *v;

        v = get_value(conn_name, var_name, sizeof(*v64));
        if (IS_ERR(v))
                return (int)PTR_ERR(v);

        memcpy(v64, v->buf, sizeof(*v64));

        kfree(v);
        return 0;
}

static struct RlnhLinkObj *get_cookie(const char *conn_name)
{
        u64 cookie;
        int status;

        status = get_u64(conn_name, "con_cookie", &cookie);
        if (status != 0)
                return ERR_PTR(status);

        return (struct RlnhLinkObj *)((unsigned long)cookie);
}

static struct RlnhLinkIF *get_dc(const char *conn_name)
{
        u64 dc;
        int status;

        status = get_u64(conn_name, "con_dc", &dc);
        if (status != 0)
                return ERR_PTR(status);

        return (struct RlnhLinkIF *)((unsigned long)dc);
}

static void *rlnh_create(void __user *arg)
{
        struct rlnh_ioctl_create *p;
        struct RlnhObj *q;
        char *conn_name;
        int status;

        /*
         * Get RLNH arguments from user-space.
         */
        p = copy_arguments_from_user(arg);
        if (IS_ERR(p))
                return p;

        /*
         * Allocate and initialize a RLNH object.
         */
        q = kmalloc(sizeof(*q) + p->name_len + 1, GFP_KERNEL);
        if (q == NULL) {
                kfree(p);
                return ERR_PTR(-ENOMEM);
        }
        memset(q, 0, sizeof(*q));

        strcpy(q->link_name, (char *)kptr(p, p->name));
        q->link_name_len = strlen(q->link_name);

        q->attr = linx_kstrdup((char *)kptr(p, p->attr), GFP_KERNEL);
        if (q->attr == NULL) {
                status = -ENOMEM;
                goto out;
        }

        q->feat = linx_kstrdup((char *)kptr(p, p->feat), GFP_KERNEL);
        if (q->feat == NULL) {
                status = -ENOMEM;
                goto out;
        }

        if (p->num_cons > ARRAY_SIZE(q->conn_name)) {
                status = -E2BIG;
                goto out;
        }

        for (; q->num_cons < p->num_cons; q->num_cons++) {
                conn_name = (char *)kptr(p, p->con_name[q->num_cons]);
                q->conn_name[q->num_cons] = linx_kstrdup(conn_name, GFP_KERNEL);
                if (q->conn_name[q->num_cons] == NULL) {
                        status = -ENOMEM;
                        goto out;
                }
                q->conn_obj[q->num_cons] = get_cookie(conn_name);
                if (IS_ERR(q->conn_obj[q->num_cons])) {
                        status = (int)PTR_ERR(q->conn_obj[q->num_cons]);
                        goto out;
                }
                q->conn_dc[q->num_cons] = get_dc(conn_name);
                if (IS_ERR(q->conn_dc[q->num_cons])) {
                        status = (int)PTR_ERR(q->conn_dc[q->num_cons]);
                        goto out;
                }
        }

        /*
         * Continue with link setup...
         */
        /* Add semaphore to serialize link setup! */
        if (rlnh_setup_link(q) != 0) {
                status = -EINVAL; /* ECANCELED isn't defined in 2.6.9. */
                goto out;
        }

        kfree(p);
        return q;
 out:
        for (; q->num_cons > 0; q->num_cons--)
                kfree(q->conn_name[q->num_cons - 1]);
        if (q->feat != NULL)
                kfree(q->feat);
        if (q->attr != NULL)
                kfree(q->attr);
        kfree(q);
        kfree(p);
        return ERR_PTR(status);
}

static int rlnh_delete(void *cookie, void __user *arg)
{
        struct RlnhObj *p;
        int status;
        int n;

        (void)arg;
        p = cookie;
        status = 0;

        if (rlnh_tear_down_link(p) != 0)
                status = -EINVAL; /* ECANCELED isn't defined in 2.6.9. */

        for (n = 0; n < p->num_cons; n++)
                kfree(p->conn_name[n]);
        if (p->feat != NULL)
                kfree(p->feat);
        if (p->attr != NULL)
                kfree(p->attr);
        kfree(p);

        return status;
}

static int rlnh_setup_link(struct RlnhObj *rlnh_obj)
{
	LINX_RLNH rlnh = LINX_ILLEGAL_RLNH;
	int j;
	int err;

	if (unlikely(RLNH_LINK_IF_VERSION !=
                     rlnh_obj->conn_dc[RLNHCM]->if_version)) {
		linx_err("Incompatible link if versions (was %d expected %d.",
			 rlnh_obj->conn_dc[RLNHCM]->if_version,
			 RLNH_LINK_IF_VERSION);
		err = -ENOEXEC;
		goto fail;
	}

	err = register_rlnh_obj(rlnh_obj, rlnh_obj->link_name, &rlnh);
	if (unlikely(err != 0)) {
		goto fail;
	}

        /*
         * We need to register the RLNH object before we can check if
         * the connection(s) already is used by another link.
         *
         * Note: there is a create link race, which may cause both creates
         *       to fail (acceptable, we don't want more locks...).
         *       X is swapped out after register_rlnh_obj() but before
         *       conn_in_use() as taken its spinlock.
         *       Y is swapped in and calls register_rlnh_obj() and
         *       conn_in_use(), which fails due to X's register_rlnh_obj.
         *       Y is swapped out before it has called
         *       unregister_rlnh_obj_and_release() and X is swapped in and
         *       calls conn_in_use(), which also fails.
         *
         *       Not very likely to happen and it's not a disaster if it
         *       actually happens...
         *
         *       When this code is re-designed, make sure that the create link
         *       sequence is serialized (e.g. semaphore).
         */
        if (conn_in_use(rlnh_obj) != 0) {
		err = -EACCES;
                goto fail;
        }

	rlnh_obj->expected_msg_type = RLNH_INIT;
	rlnh_obj->spid = LINX_ILLEGAL_SPID;
#ifdef ERRORCHECKS
	rlnh_obj->magic = RLNH_OBJ_MAGIC;
#endif
	for(j = 0; j < MAX_CONNS_PER_LINK; j++) {
		rlnh_obj->connected_called[j] = 0;
		rlnh_obj->conn_handle[j].ro = rlnh_obj;
		rlnh_obj->conn_handle[j].co_index = j;

		/* Setup disconnect work queue entry */
		rlnh_obj->disconn[j] =
			linx_kmalloc(sizeof(struct linx_queue_data));
		if (unlikely(rlnh_obj->disconn[j] == NULL)) {
			err = -ENOMEM;
			goto fail;
		}
		rlnh_obj->disconn[j]->rlnh = rlnh;
		rlnh_obj->disconn[j]->co_index = j;

		LINX_INIT_WORK(&rlnh_obj->disconn[j]->work,
			       wq_disconnect_link,
			       (void *)(rlnh_obj->disconn[j]));
	}
	spin_lock_init(&rlnh_obj->conn_called_lock);

	init_completion(&rlnh_obj->ready_for_destroy);

	/* Setup signal queue */
	spin_lock_init(&rlnh_obj->sig_queue_lock);
	rlnh_obj->sig_queue = linx_kmalloc(sizeof(*(rlnh_obj->sig_queue)));
	if (unlikely(rlnh_obj->sig_queue == NULL)) {
		err = -ENOMEM;
		goto fail;
	}
	if (unlikely(rlnh_queue_init(rlnh_obj, rlnh_obj->sig_queue) < 0)) {
		err = -ENOMEM;
		goto fail;
	}

	/* Setup bit array */
	rlnh_obj->bit_array_len = BITARRAY_EXTENDSIZE;
	spin_lock_init(&rlnh_obj->bit_array_lock);
	rlnh_obj->bit_array = linx_kmalloc(sizeof(uint32_t) *
					   BITARRAY_EXTENDSIZE);
	if (unlikely(rlnh_obj->bit_array == NULL)) {
		err = -ENOMEM;
		goto fail;
	}
	memset(rlnh_obj->bit_array, -1, sizeof(uint32_t) * BITARRAY_EXTENDSIZE);

	SET_LM_DELIVER_OK(rlnh_obj, 0);
	SET_OS_TRANSMIT_OK(rlnh_obj, 0);

        /*
         * Initialize all connections. CtrlMsgs will only be accepted from first
         * connection.
         */
	for(j = 0; j < MAX_CONNS_PER_LINK; j++) {
		if(rlnh_obj->conn_dc[j] != NULL)
			CM_INITIALIZE(rlnh_obj, j, rlnhLinkUCIF);
	}

	/* Create the address maps */
	rlnh_obj->array_size = linx_max_sockets_per_link;
	rlnh_obj->addrmap_local =
		linx_kmalloc((rlnh_obj->array_size + 1) * sizeof(LINX_SPID));
	if (unlikely(rlnh_obj->addrmap_local == NULL)) {
		err = -ENOMEM;
		goto fail;
	}
	memset(rlnh_obj->addrmap_local, LINX_ILLEGAL_SPID,
	       (rlnh_obj->array_size + 1) * sizeof(LINX_SPID));

	rlnh_obj->addrmap_remote =
		linx_kmalloc((rlnh_obj->array_size + 1) * sizeof(LINX_SPID));
	if (unlikely(rlnh_obj->addrmap_remote == NULL)) {
		err = -ENOMEM;
		goto fail;
	}
	memset(rlnh_obj->addrmap_remote, LINX_ILLEGAL_SPID,
	       (rlnh_obj->array_size + 1) * sizeof(LINX_SPID));

	spin_lock_init(&rlnh_obj->addrmap_lock);

	SET_OS_TRANSMIT_OK(rlnh_obj, 0);

	rlnh_obj->state = STATE_DISCONNECTED;

	for(j = 0; j < MAX_CONNS_PER_LINK; j++) {
		if(rlnh_obj->conn_dc[j] != NULL)
			CM_CONNECT(rlnh_obj, j);
	}

	return 0;

 fail:
	/* Unregister the rlnh_obj */
	if (rlnh != LINX_ILLEGAL_RLNH) {
		(void)get_rlnh_obj_exclusive(rlnh);
		unregister_rlnh_obj_and_release(rlnh);
	}
	if (rlnh_obj->sig_queue)
		linx_kfree(rlnh_obj->sig_queue);
	if (rlnh_obj->addrmap_local)
		linx_kfree(rlnh_obj->addrmap_local);
	if (rlnh_obj->addrmap_remote)
		linx_kfree(rlnh_obj->addrmap_remote);
	for(j = 0; j < MAX_CONNS_PER_LINK; j++) {
		if (rlnh_obj->disconn[j] != NULL)
			linx_kfree(rlnh_obj->disconn[j]);
	}
	return err;
}

static void wq_rlnh_tear_down_link(LINX_WORKQ_TYPE * arg)
{
	struct linx_queue_data *wq_data = LINX_WORKQ_GETARG(arg);
	struct RlnhObj *rlnh_obj;
	int j, still_connected = 0;
	uint32_t la;

	rlnh_obj = try_get_rlnh_obj(wq_data->rlnh);
	if (unlikely(rlnh_obj == NULL))
		goto out;

	rlnh_obj->pending_destroy = 1;

	for (j = 0; j < MAX_CONNS_PER_LINK; j ++) {
		if (NULL != rlnh_obj->conn_obj[j] &&
		    0 == is_disconnected(rlnh_obj, j)) {
			still_connected = 1;
			CM_DISCONNECT(rlnh_obj, j);
		}
	}
	release_rlnh_obj(wq_data->rlnh);

	if (still_connected)
		goto out;

	rlnh_obj = get_rlnh_obj_exclusive(wq_data->rlnh);
	if (unlikely(rlnh_obj == NULL))
		goto out;

	rlnh_obj = unregister_rlnh_obj_and_release(wq_data->rlnh);

	/* After this point no one will access rlnh_obj longer */

	for (la = 1; la <= rlnh_obj->array_size; la++) {
		struct RlnhQueueNode *n, *np;
		do {
			n = rlnh_queue_get(rlnh_obj->sig_queue, la);
			while (n != NULL) {
				LINX_ASSERT(n->sig != NULL);
				LINX_ASSERT(n->dst_la != 0);
				if (BUF_TYPE_SKB(n->buffer_type)) {
					struct sk_buff *skb =
						(struct sk_buff *)n->sig;
					kfree_skb(skb);
				} else {
					linx_kfree(n->sig);
				}
				np = n;
				n = n->next;
				LINX_ASSERT(np != NULL);
				linx_kfree(np);
			}
		} while (!rlnh_queue_is_empty(rlnh_obj->sig_queue, la));
	}

	rlnh_queue_exit(rlnh_obj, rlnh_obj->sig_queue);

	/* Tell CM that the conn_obj will no longer be used. */
	for(j = 0; j < MAX_CONNS_PER_LINK; j++) {
		if(rlnh_obj->conn_dc[j] != NULL)
			CM_FINALIZE(rlnh_obj, j);
	}
	/* Free up the arrays */
	linx_kfree(rlnh_obj->bit_array);
	linx_kfree(rlnh_obj->addrmap_remote);
	linx_kfree(rlnh_obj->addrmap_local);
	linx_kfree(rlnh_obj->sig_queue);

	if (rlnh_obj->buffered_sig != NULL) {
		kfree_skb((struct sk_buff *)rlnh_obj->buffered_sig);
		rlnh_obj->buffered_sig = NULL;
	}

	for(j = 0; j < MAX_CONNS_PER_LINK; j++) {
		if(rlnh_obj->disconn[j] != NULL)
			linx_kfree(rlnh_obj->disconn[j]);
	}
	complete(&rlnh_obj->ready_for_destroy);
 out:
	linx_kfree(wq_data);
}

static int rlnh_tear_down_link(struct RlnhObj *rlnh_obj)
{
	struct linx_queue_data *wq_data;

	LINX_RLNH rlnh = rlnh_obj->disconn[RLNHCM]->rlnh;

	rlnh_obj = get_rlnh_obj(rlnh);
	if (unlikely(rlnh_obj == NULL)) {
		return -1;
	}

	wq_data = linx_kmalloc(sizeof(*wq_data));

	if (unlikely(!wq_data)) {
		return -ENOMEM;
	}

	wq_data->rlnh = rlnh_obj->disconn[RLNHCM]->rlnh;

	release_rlnh_obj(rlnh);

	LINX_INIT_WORK(&wq_data->work, wq_rlnh_tear_down_link, wq_data);
	(void)queue_work(linx_workqueue, &wq_data->work);

	wait_for_completion(&rlnh_obj->ready_for_destroy);

	return 0;
}

/*****************************************************************************
 * Down calls from the IPC
 *****************************************************************************/

/*
 * wq_rlnh_hunt_resolved
 *
 * Runs in the worker thread, should only be queued by rlnh_hunt_resolved,
 * performs work that can't run in tasklet (interrupt) context.
 *
 */

static void wq_rlnh_hunt_resolved(LINX_WORKQ_TYPE * arg)
{
	struct linx_queue_data *wq_data = LINX_WORKQ_GETARG(arg);

	struct RlnhObj *rlnh_obj = NULL;
	uint32_t linkaddr;
	int err;
	LINX_OSATTREF attref;
	struct sock *sk_victim;

	LINX_ASSERT(wq_data != NULL);
	LINX_ASSERT(wq_data->victim != LINX_ILLEGAL_SPID);
	LINX_ASSERT(wq_data->hunter != LINX_ILLEGAL_SPID);
	LINX_ASSERT(wq_data->name != NULL);
	LINX_ASSERT(wq_data->rlnh != LINX_ILLEGAL_RLNH);

	rlnh_obj = try_get_rlnh_obj(wq_data->rlnh);
	if (unlikely(rlnh_obj == NULL)) {
		goto out;
	}
	assert_rlnh_obj(rlnh_obj);

	rlnh_debug("hunt resolved for '%s' victim:%#x hunter:%#x",
		   wq_data->name, wq_data->victim, wq_data->hunter);

	if (unlikely(rlnh_obj->spid == LINX_ILLEGAL_SPID)) {
		/* Link has been disconnected */
		goto unlock_and_out;
	}

	if (unlikely(ipc_get_sender_hd(wq_data->victim, rlnh_obj->idx,
				       &linkaddr) < 0)) {
		goto unlock_and_out;
	}

	if (unlikely(linkaddr != 0)) {
		goto unlock_and_out;
	}

	err = distribute_proc_lock(rlnh_obj, wq_data->victim, &sk_victim);
	if (unlikely(err <= 0)) {
		CM_DISCONNECT(rlnh_obj, 0);
		goto unlock_and_out;
	}
	linkaddr = err;

	rlnh_debug("ATTACH to:%#x from:%#x", wq_data->victim, rlnh_obj->spid);

	/* LINX attaches to the vicitim socket */
	err = ipc_attach(wq_data->victim, rlnh_obj->spid, NULL, &attref);

	/* Unlock the socket that was locked in distribute_proc_lock */
	sock_put(sk_victim);

	if (unlikely(err != 0)) {
		CM_DISCONNECT(rlnh_obj, 0);
	}

 unlock_and_out:
	release_rlnh_obj(wq_data->rlnh);
 out:
	linx_kfree(wq_data);
}

/*
 * rlnh_hunt_resolved
 *
 * Hunt resolved.
 *
 * Returns -errno on failure else 0.
 *
 * Can be called from tasklet (interrupt) context.
 *
 */

int rlnh_hunt_resolved(LINX_RLNH rlnh,
		       const char *name, LINX_SPID victim, LINX_SPID hunter)
{
	struct linx_queue_data *wq_data;

	LINX_ASSERT(rlnh != LINX_ILLEGAL_RLNH);
	LINX_ASSERT(name != NULL);
	LINX_ASSERT(victim != LINX_ILLEGAL_SPID);
	LINX_ASSERT(hunter != LINX_ILLEGAL_SPID);

	wq_data = linx_kmalloc(sizeof(*wq_data) + strlen(name) + 1);

	if (unlikely(!wq_data)) {
		/* Disconnect */
		struct RlnhObj *rlnh_obj;
		rlnh_obj = try_get_rlnh_obj(rlnh);
		if (likely(rlnh_obj != NULL)) {
			CM_DISCONNECT(rlnh_obj, 0);
			release_rlnh_obj(rlnh);
		}
		return -ENOMEM;
	}

	wq_data->rlnh = rlnh;
	wq_data->victim = victim;
	wq_data->hunter = hunter;

	memcpy(wq_data->name, name, strlen(name) + 1);

	LINX_INIT_WORK(&wq_data->work, wq_rlnh_hunt_resolved, wq_data);

	queue_work(linx_workqueue, &wq_data->work);

	return 0;
}

/*
 * wq_rlnh_attach_notification
 *
 * Runs in the worker thread, should only be queued by
 * rlnh_attach_notification, performs work that can't run in tasklet
 * (interrupt) context.
 *
 * Send a UNPUBLISH msg to the remote RLNH. We will receive a UNPUBLISH_ACK
 * when it has terminated the link address association, then we can reuse
 * this link address.
 */
static void wq_rlnh_attach_notification(LINX_WORKQ_TYPE * arg)
{
	struct linx_queue_data *wq_data = LINX_WORKQ_GETARG(arg);
	struct RlnhObj *rlnh_obj;
	union RlnhMsg *msg;
	int size;
	uint32_t hdr = 0;

	LINX_ASSERT(wq_data != NULL);
	LINX_ASSERT(wq_data->rlnh != LINX_ILLEGAL_RLNH);

	rlnh_obj = try_get_rlnh_obj(wq_data->rlnh);

	if (unlikely(rlnh_obj == NULL)) {
		goto out;
	}

	assert_rlnh_obj(rlnh_obj);

	if (rlnh_obj->spid == LINX_ILLEGAL_SPID) {
		/* Link is disconnected */
		goto unlock_and_out;
	}

	size = sizeof(struct RlnhUnpublish);
	msg = linx_kmalloc(size);
	if (unlikely(msg == NULL)) {
		goto unlock_and_out;
	}

	hdr = set_type(hdr, RLNH_UNPUBLISH);
	msg->unpublish.main_hdr = RLNH_HTONL(hdr);
	msg->unpublish.linkaddr = RLNH_HTONL(wq_data->linkaddr);

	rlnh_debug("TX: UNPUBLISH (la: %#x)", wq_data->linkaddr);

        /* If Tx fails, CM will disconnect, sit tight... */
	(void)rlnh_transmit_ctrl_msg(rlnh_obj, size, msg);
	if (unlikely(wq_data->peer_linkaddr != 0)) {
		msg->unpublish.linkaddr = RLNH_HTONL(wq_data->peer_linkaddr);
		rlnh_debug("TX: UNPUBLISH PEER (la: %#x)",
			   wq_data->peer_linkaddr);
                /* If Tx fails, CM will disconnect, sit tight... */
		(void)rlnh_transmit_ctrl_msg(rlnh_obj, size, msg);
	}

	linx_kfree(msg);

 unlock_and_out:
	release_rlnh_obj(wq_data->rlnh);
 out:
	linx_kfree(wq_data);
}

/* Attach notification, a local socket was closed.
 * returns -errno on failure else 0.
 */

int rlnh_attach_notification(LINX_RLNH rlnh, LINX_SPID spid)
{
	struct linx_queue_data *wq_data = NULL;
	uint32_t la = 0;
	uint32_t peer_la = 0;
	uint32_t err = 0;
	struct RlnhObj *rlnh_obj;

	rlnh_obj = try_get_rlnh_obj(rlnh);

	if (unlikely(rlnh_obj == NULL)) {
		goto out;
	}

	assert_rlnh_obj(rlnh_obj);

	rlnh_debug("rlnh_attach_notification (spid: %#x)", spid);

	if (unlikely(ipc_get_sender_hd(spid, rlnh_obj->idx, &la) < 0)) {
		err = -EINVAL;
		goto unlock_and_out;
	}

	/* This shouldnt matter since "spid" is being removed anyway */
	(void)ipc_set_sender_hd(spid, rlnh_obj->idx, 0);

	if (unlikely(ipc_get_peer_hd(spid, &peer_la) < 0)) {
		err = -EINVAL;
		goto unlock_and_out;
	}

	rlnh_obj->addrmap_local[la] = LINX_ILLEGAL_SPID;

	wq_data = linx_kmalloc(sizeof(*wq_data));

	if (unlikely(!wq_data)) {
		err = -ENOMEM;
		CM_DISCONNECT(rlnh_obj, 0);
		goto unlock_and_out;
	}

	wq_data->rlnh = rlnh;
	wq_data->linkaddr = la;
	wq_data->peer_linkaddr = peer_la;

	LINX_INIT_WORK(&wq_data->work, wq_rlnh_attach_notification, wq_data);
	queue_work(linx_workqueue, &wq_data->work);

 unlock_and_out:
	release_rlnh_obj(rlnh);
 out:
	return err;
}

/*
 * Handle ioctl requests.
 * returns -errno on failure else 0.
 */
int rlnh_ioctl(LINX_SPID spid, unsigned int cmd, unsigned long arg)
{
        (void)spid;
	return db_ioctl_entry(cmd, arg);
}

/* Returns the spid of the link phantom. */
LINX_SPID rlnh_get_spid(LINX_RLNH rlnh)
{
	LINX_SPID spid;
	struct RlnhObj *rlnh_obj;

	LINX_ASSERT(rlnh != LINX_ILLEGAL_SPID);

	rlnh_obj = try_get_rlnh_obj(rlnh);

	if (unlikely(rlnh_obj == NULL)) {
		return LINX_ILLEGAL_SPID;
	}

	spid = rlnh_obj->spid;

	release_rlnh_obj(rlnh);

	return spid;
}

/* Send signal.
 * returns -errno on failure else 0.
 */
int rlnh_send(LINX_RLNH src_rlnh,
	      LINX_RLNH rlnh,
	      void *payload,
	      LINX_OSBUFSIZE payload_size,
	      uint32_t payload_type,
	      LINX_SPID src_spid,
	      uint32_t * src_hd,
	      LINX_SPID dst_spid,
	      uint32_t dst_addr, uint32_t src_dst_addr, uint32_t peer_la)
{
	uint32_t la_src = 0;
	uint32_t la_dst = dst_addr;
	int err = 0;
	struct RlnhObj *rlnh_obj;
	struct sock *sk_src;

	LINX_ASSERT(rlnh != LINX_ILLEGAL_SPID);
	LINX_ASSERT(payload != NULL);
	LINX_ASSERT(payload_size != 0);
	LINX_ASSERT(src_spid != LINX_ILLEGAL_SPID);
	LINX_ASSERT(src_hd != NULL);
	LINX_ASSERT(dst_spid != LINX_ILLEGAL_SPID);

	rlnh_obj = try_get_rlnh_obj(rlnh);

	if (unlikely(rlnh_obj == NULL)) {
		return -ECONNRESET;
	}

	if (unlikely(src_rlnh == rlnh && rlnh_obj->version >= 2)) {
		la_src = peer_la;
		if (unlikely(la_src == 0)) {
			err = distribute_peer(rlnh_obj, src_spid, src_dst_addr);
			if (unlikely(err <= 0))
				goto rlnh_send_done;
			la_src = err;
		}
	} else {

		la_src = src_hd[rlnh_obj->idx];

		if (unlikely(la_src == 0)) {
			LINX_OSATTREF attref;

			if (unlikely(rlnh_obj->spid == LINX_ILLEGAL_SPID)) {
				/* Link has been disconnected */
				goto rlnh_send_done;
			}

			err = distribute_proc_lock(rlnh_obj, src_spid, &sk_src);
			if (unlikely(err <= 0))
				goto rlnh_send_done;
			la_src = err;

			rlnh_debug("rlnh_send: ATTACH to:%#x from:%#x",
				   src_spid, rlnh_obj->spid);

			err = ipc_attach(src_spid,
					 rlnh_obj->spid, NULL, &attref);

			/* Unlock the socket that was locked in
			   distribute_proc_lock */
			sock_put(sk_src);

			if (unlikely(err < 0)) {
				if (unlikely(err != -ECONNRESET)) {
					/* The link was removed during or just
					   before the ipc_attach call. */
					CM_DISCONNECT(rlnh_obj, 0);
				}
				goto rlnh_send_done;
			}
		}
	}

	LINX_ASSERT(la_src != 0);

	if (likely(BUF_TYPE_USER(payload_type))) {
#ifdef RLNH_LITTLE_ENDIAN
		uint32_t signo_localendian, signo_networkendian;

		/* Endian convert signo */
		get_user(signo_localendian, (int __user *)payload);

		signo_networkendian = htonl(signo_localendian);
		put_user(signo_networkendian, (int __user *)payload);
#endif
		if(unlikely(rlnh_obj->conn_dc[OOBCM] != NULL &&
			    BUF_TYPE_OOB(payload_type)))
			err = CM_TRANSMIT(rlnh_obj, OOBCM, payload_type,
					  la_src, la_dst,
					  payload_size, payload);
		else
			err = CM_TRANSMIT(rlnh_obj, RLNHCM, payload_type,
					  la_src, la_dst,
					  payload_size, payload);

#ifdef RLNH_LITTLE_ENDIAN
		put_user(signo_localendian, (int __user *)payload);
#endif
	} else {
		((uint32_t *) payload)[0] = htonl(((uint32_t *) payload)[0]);
		err = CM_TRANSMIT(rlnh_obj, RLNHCM, payload_type,
				  la_src, la_dst,
				  payload_size, payload);
	}
	/* NOTE: If transmit fails, the lower layers take
	 *       care of the disconnect of the link. */

 rlnh_send_done:
	release_rlnh_obj(rlnh);

	return err;
}

/* Hunt for peer.
 * returns -errno on failure else 0.  Send
 * a QUERY_NAME msg to the remote RLNH. The remote RLNH will resolve the
 * name, assign a link address for the object and send us an PUBLISH msg.
 */

int rlnh_hunt(LINX_RLNH rlnh, const char *name, LINX_SPID owner, LINX_SPID from)
{
	uint32_t hunter_la = 0;
	char *remote_name = NULL;
	int err = 0;
	struct RlnhObj *rlnh_obj;
	size_t len, size;
	union RlnhMsg *msg;
	uint32_t hdr = 0;
	struct sock *sk_from;

	LINX_ASSERT(rlnh != LINX_ILLEGAL_RLNH);
	LINX_ASSERT(name != NULL);
	LINX_ASSERT(from != LINX_ILLEGAL_SPID);
	LINX_ASSERT(owner != LINX_ILLEGAL_SPID);

	rlnh_obj = try_get_rlnh_obj(rlnh);

	if (unlikely(rlnh_obj == NULL)) {
		/* Link is no longer valid */
		return 0;
	}

	assert_rlnh_obj(rlnh_obj);

	rlnh_debug("hunt for %s", name);

	err = ipc_get_sender_hd(from, rlnh_obj->idx, &hunter_la);
	if (unlikely(err != 0)) {
		rlnh_debug("Failed to get sender hd.");
		goto out;
	}

	if (likely(hunter_la == 0)) {
		LINX_OSATTREF attref;
		if (unlikely(rlnh_obj->spid == LINX_ILLEGAL_SPID)) {
			/* Link has been disconnected */
			goto out;
		}
		/* Should we force a publish here if from is a phantom?? */
		err = distribute_proc_lock(rlnh_obj, from, &sk_from);
		if (unlikely(err <= 0)) {
			linx_warn("Failed to publish LINX endpoint.");
			goto out;
		}
		hunter_la = err;

		rlnh_debug("ATTACH to:%#x from:%#x", rlnh_obj->spid, from);

		err = ipc_attach(from, rlnh_obj->spid, NULL, &attref);

		/* Unlock the socket that was locked in distribute_proc_lock */
		sock_put(sk_from);

		if (unlikely(err != 0)) {
			rlnh_debug("Failed to attach.");
			goto out;
		}
	}

	remote_name = (char *)name + rlnh_obj->link_name_len + 1;

	len = strlen(remote_name);
	size = offsetof(struct RlnhQueryName, name) + len + 1;

	/* Extend to a multiple of uint32_t */
	size = (size + (sizeof(uint32_t) - 1)) & ~(sizeof(uint32_t) - 1);

	msg = linx_kmalloc(size);
	if (unlikely(msg == NULL)) {
		err = -ENOMEM;
		goto out;
	}

	hdr = set_type(hdr, RLNH_QUERY_NAME);
	msg->query_name.main_hdr = RLNH_HTONL(hdr);
	msg->query_name.linkaddr = RLNH_HTONL(hunter_la);
	memcpy(msg->query_name.name, remote_name, len + 1);

	rlnh_debug("TX: QUERY_NAME (name: '%s', hunter_la: %#x)",
		   msg->query_name.name, hunter_la);

	err = rlnh_transmit_ctrl_msg(rlnh_obj, size, msg);
	linx_kfree(msg);
        if (err != 0)
                goto out;

 out:
	release_rlnh_obj(rlnh);
	return err;

}

int rlnh_disconnect(LINX_RLNH rlnh)
{
	struct RlnhObj *rlnh_obj;
	rlnh_obj = get_rlnh_obj(rlnh);
	if (likely(rlnh_obj != NULL)) {
		CM_DISCONNECT(rlnh_obj, 0);
		release_rlnh_obj(rlnh);
	}
	return 0;
}

/* Init rlnh.
 * returns -errno on failure else 0.
 */

int rlnh_init(void)
{
	uint32_t idx;
	link_array = linx_kmalloc(sizeof(struct LinkArray) +
				  sizeof(struct RlnhObjContainer) *
				  (linx_max_links));
	if (unlikely(link_array == NULL)) {
		rlnh_debug("Failed to allocate memory.");
		return -ENOMEM;
	}

	spin_lock_init(&link_array->lock);
	link_array->count = 0;

	memset(&link_array->la, 0x0,
	       sizeof(struct RlnhObjContainer) * (linx_max_links));

	/* LINX_ILLEGAL_RLNH is reserved for returning error - preset all
	 * instance number to LINX_ILLEGAL_RLNH + 1 */
	for (idx = 0; idx < linx_max_links; idx++) {
		link_array->la[idx].ins = LINX_ILLEGAL_RLNH + 0x1;
	}

        db_add_template(DB_KEY_RLNH, &rlnh_template);
        db_proc_add(DB_KEY_RLNH);

	return 0;
}

int rlnh_finalize(void)
{
        db_proc_del(DB_KEY_RLNH);
        db_del_template(DB_KEY_RLNH);
	linx_kfree(link_array);
	return 0;
}
