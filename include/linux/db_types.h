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

/*
 * File: db_types.h
 */
#ifndef __DB_TYPES_H
#define __DB_TYPES_H

#define DB_MSK 0x00ff
#define DB_PTR 0x0100
#define DB_TMP 0x0200
#define DB_HEX 0x0400 /* Hexadecimal notation. */
#define DB_ARR 0x0800
#define DB_INV 0x1000 /* Invisible, don't show. */
#define DB_RSV 0x8000 /* Reserved, don't use. */

#define DB_VOID       0
#define DB_CHAR       1
#define DB_UCHAR      2
#define DB_SHORT      3
#define DB_USHORT     4
#define DB_INT        5
#define DB_UINT       6
#define DB_LONG       7
#define DB_ULONG      8
#define DB_LONGLONG   9
#define DB_ULONGLONG 10
#define DB_INT8      11
#define DB_UINT8     12
#define DB_INT16     13
#define DB_UINT16    14
#define DB_INT32     15
#define DB_UINT32    16
#define DB_INT64     17
#define DB_UINT64    18
#define DB_STRING    19 /* This is a bastard... */

#endif
