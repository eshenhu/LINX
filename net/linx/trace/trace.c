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

#include "linx_trace.h"
#include <linux/module.h>

spinlock_t linx_trace_lock;

int linx_trace_lock_hd;
int linx_trace_functions;

int linx_trace_levels[LINX_NUM_TRACEGROUPS] = {
	LINX_TRACE_INFO,
	LINX_TRACE_INFO,
	LINX_TRACE_INFO,
	LINX_TRACE_INFO,
	LINX_TRACE_INFO,
	LINX_TRACE_INFO
};

const char *linx_tracegroup_names[LINX_NUM_TRACEGROUPS] = {
	"general",
	"af_linx",
	"ipc",
	"rlnh",
	"eth_cm",
	"tcp_cm"
};

void linx_trace_init(void)
{
	spin_lock_init(&linx_trace_lock);
	linx_trace_lock_hd = 0;
	linx_trace_functions = 0;
}

void linx_trace_enable(int group, int threshold)
{
	linx_trace_levels[group] = threshold;
}

void linx_trace_disable(int group)
{
	linx_trace_levels[group] = 0;
}

void linx_trace_enter_exit(int val)
{
	linx_trace_functions = val;
}

EXPORT_SYMBOL(linx_trace_init);
EXPORT_SYMBOL(linx_trace_functions);
EXPORT_SYMBOL(linx_tracegroup_names);
EXPORT_SYMBOL(linx_trace_levels);
EXPORT_SYMBOL(linx_trace_lock);
