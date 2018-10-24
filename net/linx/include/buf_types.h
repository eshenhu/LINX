/*
 * Copyright (c) 2006-2008, Enea Software AB
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

#ifndef __BUF_TYPES_H__
#define __BUF_TYPES_H__

/* buffer types. the two lsb's indicate othogonal values */
enum {
	BUFFER_TYPE_USER = 0,
	BUFFER_TYPE_KERNEL = 1,
	BUFFER_TYPE_SKB = 2,
	BUFFER_TYPE_UNKNOWN = 3,
	BUFFER_TYPE_OOB = 4,
};
#define BUF_TYPE_USER(t) ((t & 0x3) == BUFFER_TYPE_USER)
#define BUF_TYPE_KERN(t) ((t & 0x3) == BUFFER_TYPE_KERNEL)
#define BUF_TYPE_SKB(t) ((t & 0x3) == BUFFER_TYPE_SKB)
#define BUF_TYPE_UNK(t) ((t & 0x3) == BUFFER_TYPE_UNKNOWN)
#define BUF_TYPE_OOB(t) (t & BUFFER_TYPE_OOB)

#endif
