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

#ifndef __LINX_TRACE_H__
#define __LINX_TRACE_H__

#define linx_info(fmt, args...) printk(KERN_INFO "LINX: " fmt "\n", ##args)
#ifdef LINX_RBLOG
#include <rblog.h>
#define l_printk rblog
#else
#define l_printk printk
#endif

#define linx_warn(fmt, args...) \
        if (printk_ratelimit()) { \
           l_printk(KERN_WARNING "LINX: WARNING - " fmt "\n", ##args); \
        }

#define linx_err(fmt, args...) \
	l_printk(KERN_ERR "LINX: ERROR - " fmt "	\n", \
	       ##args)

/* Trace groups */
#define LINX_TRACEGROUP_GENERAL   0
#define LINX_TRACEGROUP_AF_LINX   1
#define LINX_TRACEGROUP_IPC       2
#define LINX_TRACEGROUP_RLNH      3
#define LINX_TRACEGROUP_ETH_CM    4
#define LINX_TRACEGROUP_TCP_CM    5
#define LINX_NUM_TRACEGROUPS      6
#define LINX_TRACEGROUP_TRACE_MSG 7

/* Priorities, maps to linux/kernel.h KERN_* levels */
#define LINX_TRACE_ERR       3
#define LINX_TRACE_WARNING   4
#define LINX_TRACE_INFO      6
#define LINX_TRACE_DEBUG     7

#include <linux/kernel.h>
#include <linux/interrupt.h>

/* Initilize trace */
void linx_trace_init(void);
/* Enable trace for group, print msgs with prio <= threshold */
void linx_trace_enable(int group, int threshold);
/* Disable trace for group */
void linx_trace_disable(int group);
/* Enable/disable tracing of function enter/exit points */
void linx_trace_enter_exit(int val);

extern int linx_trace_levels[];
extern int linx_trace_functions;
extern const char *linx_tracegroup_names[];

#ifdef TRACE

extern spinlock_t linx_trace_lock;
extern int linx_trace_lock_hd;

#define linx_trace_lock()   spin_lock_bh(&linx_trace_lock)
#define linx_trace_unlock() spin_unlock_bh(&linx_trace_lock)

/* Displays msg on given prio (if allowed by threshold for group) */
#define linx_trace(priority, group, fmt, args...) \
do { \
  if (priority <= linx_trace_levels[group]) { \
    linx_trace_lock(); \
		l_printk("<%d> LINX [%s]: " fmt ", " __FILE__":%-4d \n", \
		       priority, linx_tracegroup_names[group], \
		       ##args, __LINE__); \
    linx_trace_unlock(); \
  } \
} while(0)

/* Displays msg on DEBUG prio (if allowed by threshold for group),
 * the log msg will also include the function name */
#define linx_debug(group, fmt, args...) \
do { \
  if (LINX_TRACE_DEBUG <= linx_trace_levels[group]) { \
    linx_trace_lock(); \
		l_printk(KERN_DEBUG "LINX [%s, %s()]: " fmt ", " \
		       __FILE__":%-4d\n", \
           linx_tracegroup_names[group], \
		       __FUNCTION__, ##args, __LINE__); \
    linx_trace_unlock(); \
  } \
} while(0)

/* Displays msg on DEBUG prio (if function trace is enabled) */
#define linx_trace_enter(group, fmt, args...) \
do { \
  if (linx_trace_functions) { \
    linx_trace_lock(); \
		l_printk(KERN_DEBUG "LINX [%s]: Enter %s(), " fmt ", " \
		       __FILE__":%-4d \n", \
		       linx_tracegroup_names[group], \
		       __FUNCTION__, ##args, __LINE__); \
    linx_trace_unlock(); \
  } \
} while(0)

/* Displays msg on DEBUG prio (if function trace is enabled) */
#define linx_trace_exit(group, fmt, args...) \
do { \
  if (linx_trace_functions) { \
    linx_trace_lock(); \
		l_printk(KERN_DEBUG "LINX [%s]: Exit  %s(), " fmt ", " \
		       __FILE__":%-4d \n", \
		       linx_tracegroup_names[group], \
		       __FUNCTION__, ##args, __LINE__); \
    linx_trace_unlock(); \
  } \
} while(0)

#else

#define linx_debug(group, fmt, args...)
#define linx_trace(priority, group, fmt, args...)
#define linx_trace_enter(group, fmt, args...)
#define linx_trace_exit(group, fmt, args...)

#endif

#ifdef TRACE_HEX_AND_ASCII
#define DUMP_HEX_AND_ASCII(b, l) dump_hex_and_ascii(b, l)

void dump_hex_and_ascii(const uint8_t * buf, int size)
{
	int i;

	for (i = 0; i < size; i += 16) {
		int j;

		for (j = 0; j < 16 && j + i < size; j++)
			l_printk("%02x ", buf[j + i]);

		for (j *= 3; j < 52; j++)
			l_printk(" ");

		l_printk("\"");
		for (j = 0; j < 16 && j + i < size; j++)
			if (isprint(buf[i + j]))
				l_printk("%c", buf[i + j]);
			else
				l_printk(".");
		l_printk("\"\n");
	}
}

#else
#define DUMP_HEX_AND_ASCII(b, l) do {} while (0)
#endif

#endif
