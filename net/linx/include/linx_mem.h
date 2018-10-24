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

#ifndef __LINX_MEM_H__
#define __LINX_MEM_H__

#include <linux/hardirq.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linx_assert.h>

extern atomic_t linx_total_kmallocs;
extern atomic_t linx_total_kfrees;

extern atomic_t linx_total_vmallocs;
extern atomic_t linx_total_vfrees;

#ifdef ERRORCHECKS_MEM
#define LINX_INTERNAL_KCHECK(a, b, c) linx_kcheck(a, b, c)
#else
#define LINX_INTERNAL_KCHECK(a, b, c) do {} while(0)
#endif

long linx_validate_kmallocs(void);

long linx_validate_vmallocs(void);

#ifdef ERRORCHECKS_MEM

void linx_mem_init(void);

void *linx_kmalloc_errorchecks(size_t size, unsigned int flags,
			       const char *fl, int ln);

void linx_kfree_errorchecks(void *ptr, const char *fl, int ln);

void linx_kcheck(void *ptr, const char *fl, int ln);

void linx_kdump(void);

void *linx_vmalloc_errorchecks(size_t size, const char *fl, int ln);

void linx_vfree_errorchecks(void *ptr, const char *fl, int ln);

void linx_vcheck(void *ptr, const char *fl, int ln);

void linx_vdump(void);
#endif

static inline void *
#ifndef ERRORCHECKS_MEM
do_linx_kmalloc(size_t size)
#else
do_linx_kmalloc(size_t size, const char *fl, int ln)
#endif
{
	unsigned int flags;
	void *p;

	if (unlikely(in_atomic()))
		flags = GFP_ATOMIC;
	else
		flags = GFP_KERNEL;

#ifndef ERRORCHECKS_MEM
	p = kmalloc(size, flags);
#else
	p = linx_kmalloc_errorchecks(size, flags, fl, ln);
#endif

	if (p != NULL)
		atomic_inc(&linx_total_kmallocs);

	return p;
}

#ifndef ERRORCHECKS_MEM
#define linx_kmalloc(size) do_linx_kmalloc(size)
#else
#define linx_kmalloc(size) \
        do_linx_kmalloc(size, __FILE__, __LINE__)
#endif

static inline void
#ifndef ERRORCHECKS_MEM
do_linx_kfree(void *ptr)
#else
do_linx_kfree(void *ptr, const char *fl, int ln)
#endif
{
	atomic_inc(&linx_total_kfrees);
#ifdef ERRORCHECKS_MEM
	linx_kfree_errorchecks(ptr, fl, ln);
#else
	kfree(ptr);
#endif

}

#ifndef ERRORCHECKS_MEM
#define linx_kfree(size) do_linx_kfree(size)
#else
#define linx_kfree(size) \
        do_linx_kfree(size, __FILE__, __LINE__)
#endif

static inline void *
#ifndef ERRORCHECKS_MEM
do_linx_vmalloc(size_t size)
#else
do_linx_vmalloc(size_t size, const char *fl, int ln)
#endif
{
	void *p;

	LINX_ASSERT(!in_atomic());

#ifndef ERRORCHECKS_MEM
	p = vmalloc(size);
#else
	p = linx_vmalloc_errorchecks(size, fl, ln);
#endif

	if (p != NULL)
		atomic_inc(&linx_total_vmallocs);

	return p;
}

#ifndef ERRORCHECKS_MEM
#define linx_vmalloc(size) do_linx_vmalloc(size)
#else
#define linx_vmalloc(size) \
        do_linx_vmalloc(size, __FILE__, __LINE__)
#endif

static inline void
#ifndef ERRORCHECKS_MEM
do_linx_vfree(void *ptr)
#else
do_linx_vfree(void *ptr, const char *fl, int ln)
#endif
{
	atomic_inc(&linx_total_vfrees);
#ifdef ERRORCHECKS_MEM
	linx_vfree_errorchecks(ptr, fl, ln);
#else
	vfree(ptr);
#endif

}

#ifndef ERRORCHECKS_MEM
#define linx_vfree(size) do_linx_vfree(size)
#else
#define linx_vfree(size) \
        do_linx_vfree(size, __FILE__, __LINE__)
#endif

#endif
