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

#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linx_assert.h>
#include <linx_trace.h>
#include <linx_mem.h>

atomic_t linx_total_kmallocs = ATOMIC_INIT(0);
atomic_t linx_total_kfrees = ATOMIC_INIT(0);

atomic_t linx_total_vmallocs = ATOMIC_INIT(0);
atomic_t linx_total_vfrees = ATOMIC_INIT(0);

#ifdef ERRORCHECKS_MEM

HLIST_HEAD(linx_kmallocs);
spinlock_t linx_kmallocs_lock;

struct linx_kmalloc_data {
	struct hlist_node node;
	void *ptr;
	size_t size;
	char *fl;
	int ln;
};

HLIST_HEAD(linx_vmallocs);
spinlock_t linx_vmallocs_lock;

struct linx_vmalloc_data {
	struct hlist_node node;
	void *ptr;
	size_t size;
	char *fl;
	int ln;
};

void linx_mem_init(void)
{
	spin_lock_init(&linx_kmallocs_lock);
	spin_lock_init(&linx_vmallocs_lock);
}

void linx_kcheck(void *ptr, const char *fl, int ln)
{
	struct linx_kmalloc_data *ctr_data;
	uint8_t *endmark;
	int part_of_kmallocs = 0;

	if (ptr == NULL) {
		linx_err("Failed buffer check %p.", ptr);
		ERROR();
		return;
	}

	spin_lock_bh(&linx_kmallocs_lock);
	ctr_data = hlist_empty(&linx_kmallocs) ?
	    NULL : hlist_entry(linx_kmallocs.first,
			       struct linx_kmalloc_data, node);
	while (ctr_data != NULL) {
		if (ptr == ctr_data->ptr)
			part_of_kmallocs = 1;

		endmark = ctr_data->ptr;
		endmark += ctr_data->size;
		if (endmark[0] != 0x11 ||
		    endmark[1] != 0x11 ||
		    endmark[2] != 0x11 || endmark[3] != 0x11) {
			linx_err("Failed buffer check %p, %s[%d]",
				 ctr_data->ptr, ctr_data->fl, ctr_data->ln);
			spin_unlock_bh(&linx_kmallocs_lock);
			ERROR();
			return;
		}
		ctr_data = ctr_data->node.next ?
		    hlist_entry(ctr_data->node.next,
				struct linx_kmalloc_data, node) : NULL;
	}
	spin_unlock_bh(&linx_kmallocs_lock);
	if (part_of_kmallocs == 0) {
		linx_err("Tried to free %p (%s,%d)\n", ptr, fl, ln);
		linx_kdump();
	}
	LINX_ASSERT(part_of_kmallocs != 0);
}

void linx_kdump(void)
{
	struct linx_kmalloc_data *ctr_data;

	spin_lock_bh(&linx_kmallocs_lock);
	ctr_data = hlist_empty(&linx_kmallocs) ? NULL :
	    hlist_entry(linx_kmallocs.first, struct linx_kmalloc_data, node);
	while (ctr_data != NULL) {
		linx_err("kbuffer %p[%zd] ln:%d fl:%s",
			 ctr_data->ptr, ctr_data->size,
			 ctr_data->ln, ctr_data->fl);
		ctr_data = ctr_data->node.next ?
		    hlist_entry(ctr_data->node.next,
				struct linx_kmalloc_data, node) : NULL;
	}
	spin_unlock_bh(&linx_kmallocs_lock);
}

void *linx_kmalloc_errorchecks(size_t size, unsigned int flags,
			       const char *fl, int ln)
{
	struct linx_kmalloc_data *ctr_data;
	uint8_t *endmark;

	ctr_data = kmalloc(sizeof(*ctr_data) + size + sizeof(uint32_t) +
			   strlen(fl) + 1, flags);
	if (ctr_data == NULL)
		return NULL;

	ctr_data->ptr = ctr_data + 1;

	INIT_HLIST_NODE(&ctr_data->node);
	ctr_data->size = size;
	ctr_data->ln = ln;

	endmark = ctr_data->ptr;
	endmark += size;
	endmark[0] = 0x11;
	endmark[1] = 0x11;
	endmark[2] = 0x11;
	endmark[3] = 0x11;

	/*
	 * We can't save a pointer to the __FILE__ since the string might
	 * reside in a kernel module that has been unloaded at the time when
	 * the pointer is used...
	 */
	ctr_data->fl = (char *)endmark + sizeof(uint32_t);
	strcpy(ctr_data->fl, fl);

	spin_lock_bh(&linx_kmallocs_lock);
	hlist_add_head(&ctr_data->node, &linx_kmallocs);
	spin_unlock_bh(&linx_kmallocs_lock);

	if (!in_atomic())
		linx_kcheck(ctr_data->ptr, fl, ln);

	return ctr_data->ptr;
}

void linx_kfree_errorchecks(void *ptr, const char *fl, int ln)
{
	struct linx_kmalloc_data *ctr_data;

	if (!in_atomic())
		linx_kcheck(ptr, fl, ln);

	ctr_data = ((struct linx_kmalloc_data *)ptr) - 1;

	spin_lock_bh(&linx_kmallocs_lock);
	hlist_del(&ctr_data->node);
	spin_unlock_bh(&linx_kmallocs_lock);

	kfree(ctr_data);
}

void linx_vcheck(void *ptr, const char *fl, int ln)
{
	struct linx_vmalloc_data *ctr_data;
	uint8_t *endmark;
	int part_of_vmallocs = 0;

	if (ptr == NULL) {
		linx_err("Failed buffer check %p.", ptr);
		ERROR();
		return;
	}

	spin_lock_bh(&linx_vmallocs_lock);
	ctr_data = hlist_empty(&linx_vmallocs) ?
	    NULL : hlist_entry(linx_vmallocs.first,
			       struct linx_vmalloc_data, node);
	while (ctr_data != NULL) {
		if (ptr == ctr_data->ptr)
			part_of_vmallocs = 1;

		endmark = ctr_data->ptr;
		endmark += ctr_data->size;
		if (endmark[0] != 0x11 ||
		    endmark[1] != 0x11 ||
		    endmark[2] != 0x11 || endmark[3] != 0x11) {
			linx_err("Failed buffer check %p, %s[%d]",
				 ctr_data->ptr, ctr_data->fl, ctr_data->ln);
			spin_unlock_bh(&linx_vmallocs_lock);
			ERROR();
			return;
		}
		ctr_data = ctr_data->node.next ?
		    hlist_entry(ctr_data->node.next,
				struct linx_vmalloc_data, node) : NULL;
	}
	spin_unlock_bh(&linx_vmallocs_lock);
	if (part_of_vmallocs == 0) {
		printk("Tried to free %p\n", ptr);
		linx_kdump();
	}
	LINX_ASSERT(part_of_vmallocs != 0);
}

void linx_vdump(void)
{
	struct linx_vmalloc_data *ctr_data;

	spin_lock_bh(&linx_vmallocs_lock);
	ctr_data = hlist_empty(&linx_vmallocs) ? NULL :
	    hlist_entry(linx_vmallocs.first, struct linx_vmalloc_data, node);
	while (ctr_data != NULL) {
		linx_err("kbuffer %p[%zd] ln:%d fl:%s",
			 ctr_data->ptr, ctr_data->size,
			 ctr_data->ln, ctr_data->fl);
		ctr_data = ctr_data->node.next ?
		    hlist_entry(ctr_data->node.next,
				struct linx_vmalloc_data, node) : NULL;
	}
	spin_unlock_bh(&linx_vmallocs_lock);
}

void *linx_vmalloc_errorchecks(size_t size, const char *fl, int ln)
{
	struct linx_vmalloc_data *ctr_data;
	uint8_t *endmark;

	ctr_data = vmalloc(sizeof(*ctr_data) + size + sizeof(uint32_t) +
			   strlen(fl) + 1);
	if (ctr_data == NULL)
		return NULL;

	ctr_data->ptr = ctr_data + 1;

	INIT_HLIST_NODE(&ctr_data->node);
	ctr_data->size = size;
	ctr_data->ln = ln;

	endmark = ctr_data->ptr;
	endmark += size;
	endmark[0] = 0x11;
	endmark[1] = 0x11;
	endmark[2] = 0x11;
	endmark[3] = 0x11;

	/*
	 * See comment in linx_kmalloc_errorchecks()...
	 */
	ctr_data->fl = (char *)endmark + sizeof(uint32_t);
	strcpy(ctr_data->fl, fl);

	spin_lock_bh(&linx_vmallocs_lock);
	hlist_add_head(&ctr_data->node, &linx_vmallocs);
	spin_unlock_bh(&linx_vmallocs_lock);

	if (!in_atomic())
		linx_vcheck(ctr_data->ptr, fl, ln);

	return ctr_data->ptr;
}

void linx_vfree_errorchecks(void *ptr, const char *fl, int ln)
{
	struct linx_vmalloc_data *ctr_data;

	if (!in_atomic())
		linx_vcheck(ptr, fl, ln);

	ctr_data = ((struct linx_vmalloc_data *)ptr) - 1;

	spin_lock_bh(&linx_vmallocs_lock);
	hlist_del(&ctr_data->node);
	spin_unlock_bh(&linx_vmallocs_lock);

	vfree(ctr_data);
}
#endif

long linx_validate_kmallocs(void)
{
	long sum = atomic_read(&linx_total_kmallocs) -
	    atomic_read(&linx_total_kfrees);
	if (sum) {
		linx_debug(LINX_TRACEGROUP_GENERAL,
			   "kmallocs: %d, kfrees: %d",
			   atomic_read(&linx_total_kmallocs),
			   atomic_read(&linx_total_kfrees));

#ifdef ERRORCHECKS_MEM
		linx_kdump();
#endif
	}
	return sum;
}

long linx_validate_vmallocs(void)
{
	long sum = atomic_read(&linx_total_vmallocs) -
	    atomic_read(&linx_total_vfrees);
	if (sum) {
		linx_debug(LINX_TRACEGROUP_GENERAL,
			   "vmallocs: %d, vfrees: %d",
			   atomic_read(&linx_total_vmallocs),
			   atomic_read(&linx_total_vfrees));
#ifdef ERRORCHECKS_MEM
		linx_vdump();
#endif
	}
	return sum;
}

EXPORT_SYMBOL(linx_total_kfrees);
EXPORT_SYMBOL(linx_total_kmallocs);
#ifdef ERRORCHECKS_MEM
EXPORT_SYMBOL(linx_kmalloc_errorchecks);
EXPORT_SYMBOL(linx_kfree_errorchecks);
#endif
