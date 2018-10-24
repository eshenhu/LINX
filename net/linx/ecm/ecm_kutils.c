/*
 *  Copyright (c) 2008-2009, Enea Software AB .
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <linux/ctype.h>
#include <linux/slab.h>
#include <ecm_kutils.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,13))
#if defined(GFP_IS_INT)
char *kstrdup(const char *s, int gfp)
#else
char *kstrdup(const char *s, unsigned int gfp)
#endif
{
        size_t len;
        char *buf;

        if (!s)
                return NULL;
        
        len = strlen(s) + 1;
        buf = kmalloc(len, gfp);
        if (buf)
                memcpy(buf, s, len);
        return buf;
}
#endif

#ifdef ECM_KZALLOC
void *kzalloc(size_t size, gfp_t flags)
{
        void *ret = kmalloc(size, flags);

        if (ret)
                memset(ret, 0, size);
        return ret;
}
#endif
