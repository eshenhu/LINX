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
#include <asm/atomic.h>
#include <asm/byteorder.h>
#include <linux/interrupt.h>

#include <buf_types.h>
#include <shmcm.h>
#include <shmcm_proto.h>

#ifdef SHMCM_TRACE
static void log_con_pkt(struct RlnhLinkObj *, int);
static void log_transmit(struct RlnhLinkObj *, struct shmcm_uhdr *);
#else
#define log_con_pkt(co, type)
#define log_transmit(co, uhdr)
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16))
#define defq_lock_init(l) init_MUTEX(l)
#define defq_trylock(l) down_trylock(l)
#define defq_lock(l) down(l)
#define defq_unlock(l) up(l)
#else
#define defq_lock_init(l) mutex_init(l)
#define defq_trylock(l) mutex_trylock(l)
#define defq_lock(l) mutex_lock(l)
#define defq_unlock(l) mutex_unlock(l)
#endif

struct defq_elem {
	struct list_head node;
	unsigned int len;
	char data[1];
};

void defq_purge(struct RlnhLinkObj *co)
{
	struct list_head *pos;
	struct list_head *tmp;

	list_for_each_safe(pos, tmp, &co->tx.defq) {
		atomic_dec(&co->tx.defq_size);
		list_del(pos);
		kfree(pos);
	}
}

static struct defq_elem *defq_alloc(struct mb_vec *vec, size_t count)
{
	struct defq_elem *dq_elem;
	unsigned int len;
	unsigned int c;
	unsigned char *ptr;

	for (c = 0, len = 0; c < count; c++)
		len += vec[c].len;

	dq_elem = kmalloc(sizeof(*dq_elem) + len, GFP_KERNEL);
	if (dq_elem == NULL)
		return ERR_PTR(-ENOSPC);

	ptr = (unsigned char *)dq_elem->data;
	dq_elem->len = len;
	while (count-- > 0) {
		if (!vec->type) {
			if (copy_from_user(ptr, vec->base, vec->len) != 0) {
				kfree(dq_elem);
				return ERR_PTR(-EFAULT);
			}
		} else {
			memcpy(ptr, vec->base, vec->len);
		}
		ptr += vec->len;
		vec++;
	}
	return dq_elem;
}

static int defq_tail(struct RlnhLinkObj *co, struct mb_vec *vec, size_t count)
{
	struct defq_elem *dq_elem;

	dq_elem = defq_alloc(vec, count);
	if (IS_ERR(dq_elem))
		return PTR_ERR(dq_elem);

	defq_lock(&co->tx.defq_lock);

	if (atomic_read(&co->tx.defq_size) >= shmcm_defq_max_size) {
		defq_unlock(&co->tx.defq_lock);
		kfree(dq_elem);
		return -ENOSPC;
	}

	atomic_inc(&co->tx.defq_size);
	list_add_tail(&dq_elem->node, &co->tx.defq);
	defq_unlock(&co->tx.defq_lock);
	return 0;
}

static int defq_flush(struct RlnhLinkObj *co)
{
	struct list_head *pos;
	struct list_head *tmp;
	struct defq_elem *dq_elem;
	struct mb_vec vec[1];
	int err = 0;

	if (defq_trylock(&co->tx.defq_lock) == 0)
		return 0;

	list_for_each_safe(pos, tmp, &co->tx.defq) {
		dq_elem = list_entry(pos, struct defq_elem, node);
		mb_set_vec(&vec[0], dq_elem->data, dq_elem->len, 1);
		err = mb_xmit_vec(co->tx.mb, vec, 1);
		if (err < 0)
			break;
		atomic_dec(&co->tx.defq_size);
		list_del(&dq_elem->node);
		kfree(dq_elem);
	}

	defq_unlock(&co->tx.defq_lock);

	return err;
}

static int xmit_vec(struct RlnhLinkObj *co, struct mb_vec *vec, size_t count)
{
	int err = 0;

	if (atomic_read(&co->tx.defq_size) != 0) {
		err = defq_flush(co);
		if (err == -ENOSPC)
			return defq_tail(co, vec, count);
		if (err < 0)
			return err;
	}
	if (mb_xmit_vec(co->tx.mb, vec, count) < 0)
		return defq_tail(co, vec, count);
	return 0;
}

static int xmit_con_pkt(struct RlnhLinkObj *co, void *cpkt, size_t cpkt_sz)
{
        struct mb_vec vec[1];

        mb_set_vec(&vec[0], cpkt, cpkt_sz, 1);
        return xmit_vec(co, vec, ARRAY_SIZE(vec));
}

static int xmit_udata_pkt(struct RlnhLinkObj *co, void *hdr, size_t hdr_sz,
                          void *udata, size_t udata_sz, int utype)
{
        struct mb_vec vec[2];

        mb_set_vec(&vec[0], hdr, hdr_sz, 1);
        mb_set_vec(&vec[1], udata, udata_sz, !BUF_TYPE_USER(utype));
        return xmit_vec(co, vec, ARRAY_SIZE(vec));
}

static int send_con_pkt(struct RlnhLinkObj *co, int type, unsigned int cno)
{
        struct {
                struct shmcm_mhdr mhdr;
                struct shmcm_chdr chdr;
        } pkt;
        int status;

        pkt.mhdr.type = htonl(CON_PKT);
        pkt.mhdr.size = htonl(sizeof(pkt));
        pkt.chdr.type = htonl(type);
        pkt.chdr.cno = htons(cno);
        pkt.chdr.spare = 0;

        log_con_pkt(co, type);

        status = xmit_con_pkt(co, &pkt, sizeof(pkt));
        if (status != 0) {
                shmcm_disconnect(co, -EXMITCPKT(type, status), SHMCM_TX);
                return status;
        }
        co->tx.num_bytes += sizeof(pkt);
        co->tx.num_pkts++;
        return 0;
}

static int send_udata_pkt(struct RlnhLinkObj *co, uint32_t type, uint32_t src,
                          uint32_t dst, uint32_t size, void *data)
{
        struct {
                struct shmcm_mhdr mhdr;
                struct shmcm_uhdr uhdr;
        } hdr;
        unsigned int fragsz;
        unsigned int nfrag;
        unsigned int msgid;
        unsigned char *udata;
        int status;

        fragsz = co->tx.mtu - sizeof(hdr);
        nfrag = (size + (fragsz - 1)) / fragsz;
        msgid = atomic_add_return(1, &co->tx.msgid) & 0xffff;

        hdr.mhdr.type = htonl(UDATA_1_PKT);
        hdr.mhdr.size = htonl(co->tx.mtu);
        hdr.uhdr.cno = htons(co->cno);
        hdr.uhdr.msgid = htons(msgid);
        hdr.uhdr.src = htonl(src);
        hdr.uhdr.dst = htonl(dst);
        hdr.uhdr.size = htonl(size);
        hdr.uhdr.addr = 0;

        log_transmit(co, &hdr.uhdr);

        udata = data;
        while (--nfrag > 0) {
                status = xmit_udata_pkt(co, &hdr, sizeof(hdr), udata, fragsz,
                                        type);
                if (status != 0) {
                        atomic_set(&co->tx.dc_transmit_ok, 0);
                        shmcm_disconnect(co, status, SHMCM_TX);
                        return status;
                }
                udata += fragsz;
                size -= fragsz;
                co->tx.num_bytes += co->tx.mtu;
                co->tx.num_pkts++;
        }

        hdr.mhdr.size = htonl(sizeof(hdr) + size);
        status = xmit_udata_pkt(co, &hdr, sizeof(hdr), udata, size, type);
        if (status != 0) {
                atomic_set(&co->tx.dc_transmit_ok, 0);
                shmcm_disconnect(co, status, SHMCM_TX);
                return status;
        }
        co->tx.num_bytes += (sizeof(hdr) + size);
        co->tx.num_pkts++;
        return 0;
}

void shmcm_send_con_pkt(struct RlnhLinkObj *co, int type, unsigned int cno)
{
        /* Note: transmit-lock is only used for user-data! */
        send_con_pkt(co, type, cno);
}

int shmcm_dc_transmit(struct RlnhLinkObj *co, uint32_t type, uint32_t src,
                      uint32_t dst, uint32_t size, void *data)
{
        int status;

        /*
         * Some words about dc_transmit_ok and dc_transmit_lock...
         *
         * - dc_transmit_ok is used to immediately stop a user-process
         *   from doing any more dc_transmits (i.e. send system call) while
         *   the disconnect job sits in the workqueue, waiting to be scheduled.
         *   This can happen if an user-process do a send system calls, which
         *   fails (error code returned to user). This results in a disconnect
         *   request. However, if the user ignores the return code and do a new
         *   send system call, it may succeed (disconnect still in the workqueue)
         *   and we have an out-of-order situation. Note: other user-processes
         *   may still be in the dc_transmit code and transmit user-data.
         *
         * - dc_transmit_lock is used to prevent any process to do any more
         *   dc_transmits. Once shmcm_disable_dc_transmit returns, the workqueue
         *   knows that no one can run dc_transmit and there is no one left
         *   inside dc_transmit.
         */
        if (atomic_read(&co->tx.dc_transmit_ok) == 0)
                return 0; /* Silently drop signal, disconnect in progress. */
        if (shmcm_trylock(&co->tx.dc_transmit_lock) == 0)
                return 0; /* Silently drop signal, disconnect in progress. */
        status = send_udata_pkt(co, type, src, dst, size, data);
        shmcm_unlock(&co->tx.dc_transmit_lock);

        return status;
}

void shmcm_enable_dc_transmit(struct RlnhLinkObj *co)
{
        atomic_set(&co->tx.dc_transmit_ok, 1);
        reset_shmcm_lock(&co->tx.dc_transmit_lock, 1);
}

void shmcm_disable_dc_transmit(struct RlnhLinkObj *co)
{
	atomic_set(&co->tx.dc_transmit_ok, 0);
        synchronize_shmcm_lock(&co->tx.dc_transmit_lock);
	defq_purge(co);
}

int shmcm_init_tx(struct RlnhLinkObj *co, unsigned int nslot, unsigned int mtu)
{
        co->tx.mtu = mtu;
        co->tx.nslot = nslot;
        init_shmcm_lock(&co->tx.dc_transmit_lock, 0);
        co->tx.mb = mb_register_tx_client(co->mailbox, co->tx.mtu,
                                          co->tx.nslot);
        if (co->tx.mb == NULL) {
                printk(KERN_WARNING "shmcm: couldn't register TX mailbox\n");
                return -EINVAL;
        }
	INIT_LIST_HEAD(&co->tx.defq);
	atomic_set(&co->tx.defq_size, 0);
	defq_lock_init(&co->tx.defq_lock);
        return 0;
}

void shmcm_cleanup_tx(struct RlnhLinkObj *co)
{
        mb_unregister_tx_client(co->mailbox);
        /*
         * CON packets may be inserted after dc_transmit has been disabled.
         */
	defq_purge(co);
}

/*
 * =============================================================================
 * Some trace functions...
 * =============================================================================
 */
#ifdef SHMCM_TRACE
static void log_con_pkt(struct RlnhLinkObj *co, int type)
{
        printk("%s(%d): SHMCM_SEND_CON_PKT(%d)\n", co->con_name, co->state,
               type);
}

static void log_transmit(struct RlnhLinkObj *co, struct shmcm_uhdr *uhdr)
{
        printk("%s(%d): SHMCM_DC_TRANSMIT(%u, %u, %u)\n", co->con_name,
               co->state, ntohl(uhdr->src), ntohl(uhdr->dst),
               ntohl(uhdr->size));
}
#endif
