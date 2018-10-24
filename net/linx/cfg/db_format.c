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
 * File: db_format.c
 */
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linx_assert.h>
#include "db.h"
#include "db_format.h"

struct vbuf {
        char *writep;
        size_t count;
};

static int vbuf_printf(struct vbuf *vbuf, const char *fmt, ...)
{
        va_list args;
        int n;

        va_start(args, fmt);
        n = vsnprintf(vbuf->writep, vbuf->count, fmt, args);
        va_end(args);

        if (n < 0)
                return n;

        if (n >= vbuf->count) {
                *vbuf->writep = '\0'; /* Undo vsnprintf! */
                return -ENOMEM;
        }

        vbuf->writep += n;
        vbuf->count -= n;
        return n;
}

static size_t scalar_sizeof(int type)
{
        switch (type & DB_MSK) {
        case DB_CHAR:
        case DB_INT8:
        case DB_UCHAR:
        case DB_UINT8:
                return sizeof(char);
        case DB_SHORT:
        case DB_INT16:
        case DB_USHORT:
        case DB_UINT16:
                return sizeof(short);
        case DB_INT:
        case DB_INT32:
        case DB_UINT:
        case DB_UINT32:
                return sizeof(int);
        case DB_LONG:
        case DB_ULONG:
                return sizeof(long);
        case DB_LONGLONG:
        case DB_INT64:
        case DB_ULONGLONG:
        case DB_UINT64:
                return sizeof(long long);
        case DB_STRING:
                return 0; /* N/A */
        case DB_VOID:
                return (type & DB_PTR) ? sizeof(void *) : 0;
        default:
                ERROR();
                return -EINVAL;
        }
}

static int scalar_tostrx(struct vbuf *vbuf, int type, void *v)
{
        switch (type & DB_MSK) {
        case DB_INT8:
                return vbuf_printf(vbuf, "%#x", (int)*((int8_t *)v));
        case DB_UCHAR:
        case DB_UINT8:
                return vbuf_printf(vbuf, "%#x", (unsigned)*((unsigned char *)v));
        case DB_SHORT:
        case DB_INT16:
        case DB_USHORT:
        case DB_UINT16:
                return vbuf_printf(vbuf, "%#hx", *((unsigned short *)v));
        case DB_INT:
        case DB_INT32:
        case DB_UINT:
        case DB_UINT32:
                return vbuf_printf(vbuf, "%#x", *((unsigned int *)v));
        case DB_LONG:
        case DB_ULONG:
                return vbuf_printf(vbuf, "%#lx", *((unsigned long *)v));
        case DB_LONGLONG:
        case DB_INT64:
        case DB_ULONGLONG:
        case DB_UINT64:
                return vbuf_printf(vbuf, "%#llx", *((unsigned long long *)v));
        default:
                ERROR();
                return -EINVAL;
        }
}

static int scalar_tostrd(struct vbuf *vbuf, int type, void *v)
{
        switch (type & DB_MSK) {
        case DB_INT8:
                return vbuf_printf(vbuf, "%d", (int)*((int8_t *)v));
        case DB_UCHAR:
        case DB_UINT8:
                return vbuf_printf(vbuf, "%u", (unsigned)*((unsigned char *)v));
        case DB_SHORT:
        case DB_INT16:
                return vbuf_printf(vbuf, "%hd", *((short *)v));
        case DB_USHORT:
        case DB_UINT16:
                return vbuf_printf(vbuf, "%hu", *((unsigned short *)v));
        case DB_INT:
        case DB_INT32:
                return vbuf_printf(vbuf, "%d", *((int *)v));
        case DB_UINT:
        case DB_UINT32:
                return vbuf_printf(vbuf, "%u", *((unsigned int *)v));
        case DB_LONG:
                return vbuf_printf(vbuf, "%ld", *((long *)v));
        case DB_ULONG:
                return vbuf_printf(vbuf, "%lu", *((unsigned long *)v));
        case DB_LONGLONG:
        case DB_INT64:
                return vbuf_printf(vbuf, "%lld", *((long long *)v));
        case DB_ULONGLONG:
        case DB_UINT64:
                return vbuf_printf(vbuf, "%llu", *((unsigned long long *)v));
        default:
                ERROR();
                return -EINVAL;
        }
}

static int scalar_tostr(struct vbuf *vbuf, int type, void *v)
{
        char c;

        switch (type & DB_MSK) {
        case DB_CHAR:
                c = *((char *)v);
                return vbuf_printf(vbuf, "%c", isprint(c) ? c : '.');
        case DB_STRING:
                return vbuf_printf(vbuf, "%s", (char *)v);
        default:
                if (type & DB_HEX)
                        return scalar_tostrx(vbuf, type, v);
                else
                        return scalar_tostrd(vbuf, type, v);
        }
}

static int ptr_tostr(struct vbuf *vbuf, int type, void *v)
{
        if (v != NULL) {
                if ((type & DB_MSK) == DB_VOID)
                        return vbuf_printf(vbuf, "%p", v);
                else
                        return scalar_tostr(vbuf, type, v);
        } else
                return vbuf_printf(vbuf, "(null)");
}

static int elem_tostr(struct vbuf *vbuf, int type, void *v)
{
        if (type & DB_PTR)
                return ptr_tostr(vbuf, type, v ? *((char **)v) : NULL);
        else
                return scalar_tostr(vbuf, type, v);
}

static int array_tostr(struct vbuf *vbuf, int type, int nent, int size, void *v)
{
        int n;

        for (; nent > 1; nent--) {
                n = elem_tostr(vbuf, type, v);
                if (n < 0)
                        return n;

                n = vbuf_printf(vbuf, ", "); /* Array element separator. */
                if (n < 0)
                        return n;

                v = (void *)((unsigned long)v + size);
        }
        return elem_tostr(vbuf, type, v);
}

static int get_vptr(const struct db_param *p, void *item, void **v)
{
        if (p->get != NULL)
                return p->get(item, v);

        if (p->offset < 0)
                return -EINVAL; /* No-member param's must have a get-func! */

        if ((p->type & DB_PTR) && !(p->type & DB_ARR))
                *v = *((char **)((char *)item + p->offset));
        else
                *v = (char *)item + p->offset;

        return p->type;
}

int db_format_tostr(const struct db_param *p, void *item, char *buf, size_t n)
{
        struct vbuf vbuf;
        void *v;
        int type;
        int status;

        ERROR_ON(item == NULL);

        vbuf.writep = buf;
        vbuf.count = n;
        
        type = get_vptr(p, item, &v);
        if (type < 0)
                return type;

        if (type & DB_ARR)
                status = array_tostr(&vbuf, type, p->nelem, p->size, v);
        else if (type & DB_PTR)
                status = ptr_tostr(&vbuf, type, v);
        else
                status = scalar_tostr(&vbuf, type, v);

        if (type & DB_TMP)
                kfree(v);

        return (status < 0 ? status : 0);
}

static int vbuf_put(struct vbuf *vbuf, void *v, int size)
{
        if (size > vbuf->count)
                return -ENOMEM;

        memcpy(vbuf->writep, v, size);
        vbuf->writep += size;

        return 0;
}

static int scalar_toraw(struct vbuf *vbuf, int type, int size, void *v)
{
        switch (type & DB_MSK) {
        case DB_VOID:
                ERROR();
                return -EINVAL;
        case DB_STRING:
                return vbuf_put(vbuf, v, strlen(v) + 1);
        default:
                return vbuf_put(vbuf, v, size);
        }
}

static int ptr_toraw(struct vbuf *vbuf, int type, int size, void *v)
{
        unsigned long long null;

        if (v == NULL) {
                /*
                 * Note:
                 * If we get a null pointer, we add a zero value. We
                 * can not ignore a null pointer, since the caller
                 * expects to get a scalar value. Also, arrays require
                 * that all elements are put into the buffer.
                 *
                 * The size parameter will truncate null to correct
                 * number of bytes.
                 */
                null = (unsigned long long)0;
                v = &null;
        }
        if ((type & DB_MSK) == DB_VOID) {
                /*
                 * Note:
                 * The (void *) is a special case, we return the pointer
                 * and not what it is pointing to, which is done for all
                 * other pointers...
                 */
                return vbuf_put(vbuf, &v, size);
        } else {
                /*
                 * Note:
                 * Get what the pointer points to, first we must convert
                 * the size. Size is sizeof pointer, e.g. sizeof(int *), and
                 * not sizeof element, e.g. sizeof(int), which we need...
                 */
                return scalar_toraw(vbuf, type, (int)scalar_sizeof(type), v);
        }
}

static int elem_toraw(struct vbuf *vbuf, int type, int size, void *v)
{
        if (type & DB_PTR)
                return ptr_toraw(vbuf, type, size, v ? *((char **)v) : NULL);
        else
                return scalar_toraw(vbuf, type, size, v);
}

static int array_toraw(struct vbuf *vbuf, int type, int nent, int size, void *v)
{
        int n;

        for (; nent > 1; nent--) {
                n = elem_toraw(vbuf, type, size, v);
                if (n < 0)
                        return n;

                v = (void *)((unsigned long)v + size);
        }
        return elem_toraw(vbuf, type, size, v);
}

int db_format_toraw(const struct db_param *p, void *item, char *buf, size_t n,
                    int *objtype, size_t *objsz, size_t *nobj)
{
        struct vbuf vbuf;
        void *v;
        int type;
        int status;

        ERROR_ON(item == NULL);

        vbuf.writep = buf;
        vbuf.count = n;
        
        type = get_vptr(p, item, &v);
        if (type < 0)
                return type;

        if (type & DB_ARR)
                status = array_toraw(&vbuf, type, p->nelem, p->size, v);
        else if (type & DB_PTR)
                status = ptr_toraw(&vbuf, type, p->size, v);
        else
                status = scalar_toraw(&vbuf, type, p->size, v);

        if (type & DB_TMP)
                kfree(v);

        if (status == 0) {
                /* Return scalar type and size. */
                *objtype = type & DB_MSK;
                *objsz = scalar_sizeof(type);
                *nobj = (size_t)p->nelem;
                return 0;
        } else {
                return status;
        }
}
