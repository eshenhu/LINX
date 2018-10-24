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

#ifndef __ECM_DEBUG_H
#define __ECM_DEBUG_H

#include <ecm_kutils.h>

struct ecm_vbuf {
        char *buf;
        char *writep;
        size_t count;
};

extern void ecm_init_vbuf(struct ecm_vbuf *vbuf);
extern void ecm_fini_vbuf(struct ecm_vbuf *vbuf);
extern void ecm_flush_vbuf(struct ecm_vbuf *vbuf);
extern int ecm_vbufprintf(struct ecm_vbuf *vbuf, const char *fmt, ...);

#if defined(ECM_DEBUG_MEMLEAK)
#undef KMALLOC
#undef KSTRDUP
#undef KZALLOC
#undef KFREE

#define KMALLOC(size, gfp) ecm_kmalloc(size, gfp, __FILE__, __LINE__)
#define KSTRDUP(s, gfp) ecm_kstrdup(s, gfp, __FILE__, __LINE__)
#define KZALLOC(size, gfp) ecm_kzalloc(size, gfp, __FILE__, __LINE__)
#define KFREE(p) ecm_kfree(p)
#else
#define KMALLOC(size, gfp) kmalloc(size, gfp)
#define KSTRDUP(s, gfp) kstrdup(s, gfp)
#define KZALLOC(size, gfp) kzalloc(size, gfp)
#define KFREE(p) kfree(p)
#endif

extern void ecm_kmalloc_init(void);
extern void ecm_kmalloc_fini(void);
extern void *ecm_kmalloc(size_t size, gfp_t flags, const char *file, int line);
extern char *ecm_kstrdup(const char *s, gfp_t gfp, const char *file, int line);
extern void *ecm_kzalloc(size_t size, gfp_t flags, const char *file, int line);
extern void ecm_kfree(void *obj);

#if defined(LOG_ECM_WORK)
#define log_ecm_work(x) log_ecm_work__(x)
#endif

#ifdef ERRORCHECKS

#define ERROR_ON(arg) BUG_ON(arg)
#define ERROR() BUG()

#else

#define ERROR_ON(arg) do { if (arg){ \
			 printk("ERROR_ON@%s(%d)\n", __FUNCTION__, __LINE__);\
			 dump_stack(); } \
			} while (0)
#define ERROR() do { printk("ERROR@%s(%d)\n", __FUNCTION__, __LINE__); dump_stack(); } while(0)
#endif


#include <linux/netdevice.h>
extern void debug_print_pkt(struct sk_buff *skb);

#endif
