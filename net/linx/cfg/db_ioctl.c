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
#include <linux/gfp.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/db_ioctl.h>
#include "db.h"
#include "db_private.h"
#include "db_format.h"

#define uptr(p, n) ((u8 __user *)(p) + (n))
#define kptr(p, n) ((u8 *)(p) + (n))

static void *memdup_from_user(const void __user *u, size_t n)
{
	void *p;

        p = kmalloc(n, GFP_KERNEL);
	if (p == NULL)
		return ERR_PTR(-ENOMEM);

	if (copy_from_user(p, u, n) == 0)
                return p;
        else {
		kfree(p);
		return ERR_PTR(-EFAULT);
	}
}

static int ioctl_create(struct db_ioctl_create __user *u)
{
        struct db_ioctl_create k;
        char *key;
        const struct db_template *template;
        int status;
        void *p;

        if (copy_from_user(&k, u, sizeof(k)) != 0)
                return -EFAULT;
        key = memdup_from_user(uptr(u, k.key), k.key_len + 1);
        if (IS_ERR(key))
                return (int)PTR_ERR(key);

        LOG_ENTRY("%s", key);

        status = db_template_get(key, &template);
        if (status != 0) {
                if (status == -ENOENT) {
                        /* No entry in DB, try auto-load module... */
                        status = db_try_install_module(key);
                        if (status != 0)
                                goto out;
                        status = db_template_get(key, &template);
                        if (status != 0)
                                goto out;
                } else {
                        goto out;
                }
        }

        p = template->create(uptr(u, k.arg));
        if (IS_ERR(p)) {
                status = (int)PTR_ERR(p);
                goto out;
        }

        status = db_add_item(key, p);
        if (status != 0) {
                (void)template->destroy(p, NULL);
                goto out;
        }
        
        status = 0;
  out:
        db_template_put(key, &template);
        kfree(key);
        LOG_EXIT("%d", status);
        return status;
}

static int ioctl_delete(struct db_ioctl_delete __user *u)
{
        struct db_ioctl_delete k;
        char *key;
        const struct db_template *template;
        int status;
        void *p;

        if (copy_from_user(&k, u, sizeof(k)) != 0)
                return -EFAULT;
        key = memdup_from_user(uptr(u, k.key), k.key_len + 1);
        if (IS_ERR(key))
                return (int)PTR_ERR(key);

        LOG_ENTRY("%s", key);

        status = db_template_get(key, &template);
        if (status != 0)
                goto out;

        status = db_del_item(key, &p);
        if (status != 0)
                goto out;

        status = template->destroy(p, uptr(u, k.arg));
        if (status != 0)
                goto out;

        status = 0;
  out:
        db_template_put(key, &template);
        kfree(key);
        LOG_EXIT("%d", status);
        return status;
}

static int ioctl_get(struct db_ioctl_get __user *u)
{
        struct db_ioctl_get tmp, *k;
        size_t size;
        size_t objsz;
        size_t nobj;
        int status;
        int type;
        char *key;
        void *item;
        const struct db_template *template;
        const struct db_param *param;

        if (copy_from_user(&tmp, u, sizeof(tmp)) != 0)
                return -EFAULT;
        size = sizeof(*k) + tmp.key_len + 1 + tmp.value_size;
        k = kmalloc(size, GFP_KERNEL);
        if (k == NULL)
                return -ENOMEM;
        if (copy_from_user(k, u, size) != 0) {
                status = -EFAULT;
                goto out_30;
        }
        key = (char *)kptr(k, k->key);

        LOG_ENTRY("%s", key);

        status = db_template_get(key, &template);
        if (status != 0)
                goto out_30;

        status = db_item_get(key, &item);
        if (status != 0)
                goto out_20;

        param = db_lookup_param(key, template);
        if (param == NULL) {
                status = -ENOENT;
                goto out_10;
        }

        db_format_toraw(param, item, (char *)kptr(k, k->value), k->value_size,
                        &type, &objsz, &nobj);

        k->type = (short)type;
        k->objsz = (short)objsz;
        k->nobj = (short)nobj;
        
        if (copy_to_user(u, k, size) != 0) {
                status = -EFAULT;
                goto out_10;
        }

        status = 0;

  out_10:
        db_item_put(key, &item);
  out_20:
        db_template_put(key, &template);
  out_30:
        kfree(k);
        LOG_EXIT("%d", status);
        return status;
}

static int add_to_ubuf(const char *s, u8 __user **u, u32 *size)
{
        size_t nbytes;

        nbytes = strlen(s) + 1;
        if (nbytes > *size)
                return -ENOMEM;
        if (copy_to_user(*u, s, nbytes) != 0)
                return -EFAULT;
        *u += nbytes;
        *size -= nbytes;

        return 0;
}

static int list_items(const char *key, u8 __user *u, u32 usize)
{
        struct list_head *list, *p;
        loff_t pos;
        int status;
        unsigned int modno;

        status = db_list_get(key, &list);
        if (status != 0)
                return status;
        pos = 0;
        p = db_list_start(list, pos++, &modno);
        while (p != NULL) {
                status = add_to_ubuf(db_list_name(p), &u, &usize);
                if (status != 0)
                        goto out;
                p = db_list_next(list, pos++, p, &modno);
        }
        status = add_to_ubuf("", &u, &usize); /* Add an extra '\0'. */
  out:
        db_list_stop(list, p);
        db_list_put(key, &list);

        return status;
}

static int list_params(const struct db_param *list, u8 __user *u, u32 usize)
{
        const struct db_param *p;
        int status;

        db_param_for_each(p, list) {
                status = add_to_ubuf(p->name, &u, &usize);
                if (status != 0)
                        goto out;
        }
        status = add_to_ubuf("", &u, &usize); /* Add an extra '\0'. */
  out:
        return status;
}

static int ioctl_list(struct db_ioctl_list __user *u)
{
        struct db_ioctl_list k;
        char *key;
        const struct db_template *t;
        int status;

        if (copy_from_user(&k, u, sizeof(k)) != 0)
                return -EFAULT;
        key = memdup_from_user(uptr(u, k.key), k.key_len + 1);
        if (IS_ERR(key))
                return (int)PTR_ERR(key);

        LOG_ENTRY("%s", key);

        status = db_template_get(key, &t);
        if (status != 0)
                goto out_20;

        if (k.flags & DB_IOCTL_LIST_F_ITEMS) {
                status = list_items(key, uptr(u, k.list), k.list_size);
                if (status != 0)
                        goto out_10;
        } else {
                status = list_params(t->param, uptr(u, k.list), k.list_size);
                if (status != 0)
                        goto out_10;
        }

        status = 0;

  out_10:
        db_template_put(key, &t);
  out_20:
        kfree(key);
        LOG_EXIT("%d", status);
        return status;
}

int db_ioctl_entry(unsigned int cmd, unsigned long arg)
{
        switch (cmd) {
        case DB_IOCTL_CREATE:
                return ioctl_create((struct db_ioctl_create __user *)arg);
        case DB_IOCTL_DELETE:
                return ioctl_delete((struct db_ioctl_delete __user *)arg);
        case DB_IOCTL_GET:
                return ioctl_get((struct db_ioctl_get __user *)arg);
        case DB_IOCTL_LIST:
                return ioctl_list((struct db_ioctl_list __user *)arg);
        default:
                return -ENOTTY;
        }
}
