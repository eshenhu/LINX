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
#include <asm/atomic.h>
#include <linux/version.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
#include <linux/semaphore.h>
#else
#include <asm/semaphore.h>
#endif
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linx_assert.h>
#include "db.h"
#include "db_private.h"
#include "db_format.h"


struct tobj_head {
        struct list_head node;
        struct list_head tobj_list;
        atomic_t refcnt;
        unsigned int modno;
        const struct db_template *template;
        char name[0];
};

struct tobj {
        struct list_head node;
        atomic_t refcnt;
        void *item;
        char name[0];
};

static LIST_HEAD(db_list);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37))
static DEFINE_SEMAPHORE(db_list_sem);
#else
static DECLARE_MUTEX(db_list_sem);
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 23))
static char *kstrndup(const char *s, size_t max,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 14))
                      unsigned int gfp)
#else
                      gfp_t gfp)
#endif
{
        size_t len;
        char *p;

        if (s == NULL)
                return NULL;

        len = strnlen(s, max);
        p = kmalloc(len + 1, gfp);
        if (p == NULL)
                return NULL;        

        memcpy(p, s, len);
        *(p + len) = '\0';
        return p;
}
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18))
static inline int list_is_last(const struct list_head *list,
                               const struct list_head *head)
{
        return list->next == head;
}
#endif

static size_t count_strings(const char *s, const char *delimiters)
{
        size_t k, strc;

        /*
         * E.g. /a/b, ///a//b/ or a/b should all result in 2.
         */
        strc = 0;
        while (*s != '\0') {
                k = strcspn(s, delimiters);
                if (k != 0)
                        strc++;
                s += k;
                s += strspn(s, delimiters);
        }
        return strc;
}

static void split_string_free(char **strv)
{
        char **p;

        if (strv != NULL) {
                p = strv;
                while (*p != NULL)
                        kfree(*p++);

                kfree(strv);
        }
}

static char **split_string(const char *s, const char *delimiters, size_t *strc)
{
        char **strv, **p;
        size_t k;

        k = count_strings(s, delimiters);
        if (k == 0)
                return NULL;

        p = kmalloc((k + 1)*sizeof(*p), GFP_KERNEL);
        if (p == NULL)
                return NULL;

        strv = p;
        *strc = k;

        while (*s != '\0') {
                k = strcspn(s, delimiters);
                if (k != 0) {
                        *p = kstrndup(s, k, GFP_KERNEL);
                        if (*p == NULL) {
                                split_string_free(strv);
                                return NULL;
                        }
                        p++;
                }
                s += k;
                s += strspn(s, delimiters);
        }
        *p = NULL;

        return strv;
}

static struct tobj_head *lookup_tobj_head(const struct list_head *list,
                                          const char *name)
{
        struct tobj_head *p;
        struct list_head *item;

        list_for_each(item, list) {
                p = container_of(item, struct tobj_head, node);
                if (strcmp(name, p->name) == 0)
                        return p;
        }
        return NULL;
}

static struct tobj *lookup_tobj(const struct list_head *list, const char *name)
{
        struct tobj *p;
        struct list_head *item;

        list_for_each(item, list) {
                p = container_of(item, struct tobj, node);
                if (strcmp(name, p->name) == 0)
                        return p;
        }
        return NULL;
}

int db_add_template(const char *name, const struct db_template *template)
{
        struct tobj_head *p;
        char **strv;
        size_t strc;
        int status;

        LOG_ENTRY("%s, %p", name, template);
        strv = split_string(name, "/", &strc);
        if (strv == NULL) {
                status = -ENOMEM;
                goto out_20;
        }
        if (down_interruptible(&db_list_sem) != 0) {
                status = -ERESTARTSYS;
                goto out_20;
        }
        p = lookup_tobj_head(&db_list, strv[0]);
        if (p != NULL) {
                status = -EEXIST;
                goto out_10;
        }
        p = kmalloc(sizeof(*p) + strlen(strv[0]) + 1, GFP_KERNEL);
        if (p == NULL) {
                status = -ENOMEM;
                goto out_10;
        }
        INIT_LIST_HEAD(&p->tobj_list);
        p->template = template;
        p->modno = 0;
        atomic_set(&p->refcnt, 0);
        strcpy(p->name, strv[0]);
        list_add(&p->node, &db_list);
        status = 0;
  out_10:
        up(&db_list_sem);
  out_20:
        split_string_free(strv);
        LOG_EXIT("%d", status);
        return status;
}
EXPORT_SYMBOL(db_add_template);

int db_del_template(const char *name)
{
        struct tobj_head *p;
        char **strv;
        size_t strc;
        int status;

        LOG_ENTRY("%s", name);
        strv = split_string(name, "/", &strc);
        if (strv == NULL) {
                status = -ENOMEM;
                goto out_20;
        }
        if (down_interruptible(&db_list_sem) != 0) {
                status = -ERESTARTSYS;
                goto out_20;
        }
        p = lookup_tobj_head(&db_list, strv[0]);
        if (p == NULL) {
                status = -ENOENT;
                goto out_10;
        }
        if ((atomic_read(&p->refcnt) != 0) || !list_empty(&p->tobj_list)) {
                status = -EBUSY;
                goto out_10;
        }
        list_del(&p->node);        
        kfree(p);
        status = 0;
  out_10:
        up(&db_list_sem);
  out_20:
        split_string_free(strv);
        LOG_EXIT("%d", status);
        return status;
}
EXPORT_SYMBOL(db_del_template);

/* Check if cm is last in name, a cm key looks like this <media>cm */
static char *strrcm(const char *name)
{
        char *p;

        for (p = (char *)name;; p++) {
                p = strstr(p, "cm");
                if (p == NULL)
                        return NULL;
                if (*(p + 2) == '\0')
                        break;                
        }
        return ((p - name) != 0) ? p : NULL;
}

/* Only support for CM LKMs, i.e. linx_<media>_cm.ko */
static int try_install_module(const char *name)
{
        char *p;
        char *media;
        int status;

        p = strrcm(name);
        if (p == NULL)
                return -EINVAL; /* Not a CM key */

        media = kstrndup(name, (size_t)(p - name), GFP_KERNEL); 
        if (media == NULL)
                return -ENOMEM;

        status = request_module("linx_%s_cm", media);
        if (status != 0)
                status = -EINVAL; /* status contains modprobe's exit code */

        kfree(media);

        return status;
}

int db_try_install_module(const char *name)
{
        char **strv;
        size_t strc;
        int status;

        LOG_ENTRY("%s", name);
        strv = split_string(name, "/", &strc);
        if (strv == NULL) {
                status = -ENOMEM;
                goto out;
        }
        status = try_install_module(strv[0]);
  out:
        split_string_free(strv);
        LOG_EXIT("%d", status);
        return status;        
}

int db_template_get(const char *name, const struct db_template **template)
{
        struct tobj_head *p;
        char **strv;
        size_t strc;
        int status;

        LOG_ENTRY("%s", name);
        strv = split_string(name, "/", &strc);
        if (strv == NULL) {
                status = -ENOMEM;
                goto out_20;
        }
        if (down_interruptible(&db_list_sem) != 0) {
                status = -ERESTARTSYS;
                goto out_20;
        }
        p = lookup_tobj_head(&db_list, strv[0]);
        if (p == NULL) {
                status = -ENOENT;
                goto out_10;
        }
        if (!try_module_get(p->template->owner)) {
                status = -ENOENT; /* Module has been unloaded! */
                goto out_10;
        }
        atomic_inc(&p->refcnt);
        *template = p->template;
        status = 0;
  out_10:
        up(&db_list_sem);
  out_20:
        split_string_free(strv);
        LOG_EXIT("%d, %p", status, *template);
        return status;
}

int db_template_put(const char *name, const struct db_template **template)
{
        struct tobj_head *p;
        char **strv;
        size_t strc;
        int status;

        LOG_ENTRY("%s, %p", name, *template);
        strv = split_string(name, "/", &strc);
        if (strv == NULL) {
                status = -ENOMEM;
                goto out_20;
        }
        if (down_interruptible(&db_list_sem) != 0) {
                status = -ERESTARTSYS;
                goto out_20;
        }
        p = lookup_tobj_head(&db_list, strv[0]);
        if (p == NULL) {
                status = -ENOENT;
                goto out_10;
        }
        *template = NULL;
        atomic_dec(&p->refcnt);
        module_put(p->template->owner);
        status = 0;
  out_10:
        up(&db_list_sem);
  out_20:
        split_string_free(strv);
        LOG_EXIT("%d", status);
        return status;
}

int db_add_item(const char *name, void *item)
{
        struct tobj_head *p;
        struct tobj *tobj;
        char **strv;
        size_t strc;
        int status;

        LOG_ENTRY("%s, %p", name, item);
        strv = split_string(name, "/", &strc);
        if (strv == NULL) {
                status = -ENOMEM;
                goto out_20;
        }
        if (down_interruptible(&db_list_sem) != 0) {
                status = -ERESTARTSYS;
                goto out_20;
        }
        p = lookup_tobj_head(&db_list, strv[0]);
        if (p == NULL) {
                status = -ENOENT;
                goto out_10;
        }
        tobj = lookup_tobj(&p->tobj_list, strv[1]);
        if (tobj != NULL) {
                status = -EEXIST;
                goto out_10;
        }
        tobj = kmalloc(sizeof(*tobj) + strlen(strv[1]) + 1, GFP_KERNEL);
        if (tobj == NULL) {
                status = -ENOMEM;
                goto out_10;
        }
        tobj->item = item;
        atomic_set(&tobj->refcnt, 0);
        strcpy(tobj->name, strv[1]);
        list_add(&tobj->node, &p->tobj_list);
        p->modno++;
        status = 0;
  out_10:
        up(&db_list_sem);
  out_20:
        split_string_free(strv);
        LOG_EXIT("%d", status);
        return status;
}

int db_del_item(const char *name, void **item)
{
        struct tobj_head *p;
        struct tobj *tobj;
        char **strv;
        size_t strc;
        int status;

        LOG_ENTRY("%s", name);
        strv = split_string(name, "/", &strc);
        if (strv == NULL) {
                status = -ENOMEM;
                goto out_20;
        }
        if (down_interruptible(&db_list_sem) != 0) {
                status = -ERESTARTSYS;
                goto out_20;
        }
        p = lookup_tobj_head(&db_list, strv[0]);
        if (p == NULL) {
                status = -ENOENT;
                goto out_10;
        }
        tobj = lookup_tobj(&p->tobj_list, strv[1]);
        if (tobj == NULL) {
                status = -ENOENT;
                goto out_10;
        }
        if (atomic_read(&tobj->refcnt) != 0) {
                status = -EBUSY;
                goto out_10;
        }
        *item = tobj->item;
        list_del(&tobj->node);
        kfree(tobj);
        p->modno++;
        status = 0;
  out_10:
        up(&db_list_sem);
  out_20:
        split_string_free(strv);
        LOG_EXIT("%d, %p", status, *item);
        return status;
}

int db_item_get(const char *name, void **item)
{
        struct tobj_head *p;
        struct tobj *tobj;
        char **strv;
        size_t strc;
        int status;

        LOG_ENTRY("%s", name);
        strv = split_string(name, "/", &strc);
        if (strv == NULL) {
                status = -ENOMEM;
                goto out_20;
        }
        if (down_interruptible(&db_list_sem) != 0) {
                status = -ERESTARTSYS;
                goto out_20;
        }
        p = lookup_tobj_head(&db_list, strv[0]);
        if (p == NULL) {
                status = -ENOENT;
                goto out_10;
        }
        tobj = lookup_tobj(&p->tobj_list, strv[1]);
        if (tobj == NULL) {
                status = -ENOENT;
                goto out_10;
        }
        atomic_inc(&tobj->refcnt);
        *item = tobj->item;
        status = 0;
  out_10:
        up(&db_list_sem);
  out_20:
        split_string_free(strv);
        LOG_EXIT("%d, %p", status, *item);
        return status;
}

int db_item_put(const char *name, void **item)
{
        struct tobj_head *p;
        struct tobj *tobj;
        char **strv;
        size_t strc;
        int status;

        LOG_ENTRY("%s, %p", name, *item);
        strv = split_string(name, "/", &strc);
        if (strv == NULL) {
                status = -ENOMEM;
                goto out_20;
        }
        if (down_interruptible(&db_list_sem) != 0) {
                status = -ERESTARTSYS;
                goto out_20;
        }
        p = lookup_tobj_head(&db_list, strv[0]);
        if (p == NULL) {
                status = -ENOENT;
                goto out_10;
        }
        tobj = lookup_tobj(&p->tobj_list, strv[1]);
        if (tobj == NULL) {
                status = -ENOENT;
                goto out_10;
        }
        if (tobj->item != *item) {
                status = -EINVAL;
                goto out_10;
        }
        *item = NULL;
        atomic_dec(&tobj->refcnt);
        status = 0;
  out_10:
        up(&db_list_sem);
  out_20:
        split_string_free(strv);
        LOG_EXIT("%d", status);
        return status;
}

int db_list_get(const char *name, struct list_head **list)
{
        struct tobj_head *p;
        char **strv;
        size_t strc;
        int status;

        LOG_ENTRY("%s", name);
        strv = split_string(name, "/", &strc);
        if (strv == NULL) {
                status = -ENOMEM;
                goto out_20;
        }
        if (down_interruptible(&db_list_sem) != 0) {
                status = -ERESTARTSYS;
                goto out_20;
        }
        p = lookup_tobj_head(&db_list, strv[0]);
        if (p == NULL) {
                status = -ENOENT;
                goto out_10;
        }
        atomic_inc(&p->refcnt);
        *list = &p->tobj_list;
        status = 0;
  out_10:
        up(&db_list_sem);
  out_20:
        split_string_free(strv);
        LOG_EXIT("%d, %p", status, *list);
        return status;        
}

int db_list_put(const char *name, struct list_head **list)
{
        struct tobj_head *p;
        char **strv;
        size_t strc;
        int status;

        LOG_ENTRY("%s, %p", name, *list);
        strv = split_string(name, "/", &strc);
        if (strv == NULL) {
                status = -ENOMEM;
                goto out_20;
        }
        if (down_interruptible(&db_list_sem) != 0) {
                status = -ERESTARTSYS;
                goto out_20;
        }
        p = lookup_tobj_head(&db_list, strv[0]);
        if (p == NULL) {
                status = -ENOENT;
                goto out_10;
        }
        atomic_dec(&p->refcnt);
        *list = NULL;
        status = 0;
  out_10:
        up(&db_list_sem);
  out_20:
        split_string_free(strv);
        LOG_EXIT("%d", status);
        return status;        
}

struct list_head *db_list_start(struct list_head *list, loff_t pos,
                                unsigned int *modno)
{
        struct list_head *cursor;        
        (void)modno; /* Let's kept a modification number in the API. */

        down(&db_list_sem);

        list_for_each(cursor, list) {
                if (pos-- == 0)
                        return cursor;
        }
        return NULL;
}

struct list_head *db_list_next(struct list_head *list, loff_t pos,
                               struct list_head *cursor, unsigned int *modno)
{
        (void)modno; /* Let's keep a modification number in the API. */
        return list_is_last(cursor, list) ? NULL : cursor->next;
}

void db_list_stop(struct list_head *head, struct list_head *cursor)
{
        up(&db_list_sem);
}

const char *db_list_name(struct list_head *cursor)
{
        struct tobj *tobj;

        ERROR_ON(cursor == NULL);
                
        tobj = list_entry(cursor, struct tobj, node);
        return tobj->name;        
}

void *db_list_item(struct list_head *cursor)
{
        struct tobj *tobj;

        ERROR_ON(cursor == NULL);

        tobj = list_entry(cursor, struct tobj, node);
        return tobj->item;
}

const struct db_param *db_lookup_param(const char *key,
                                       const struct db_template *template)
{
        const struct db_param *cursor;
        const char *name;

        name = strrchr(key, '/'); /* Not good enough.... */
        if (name == NULL)
                return NULL;
        name += 1;

        db_param_for_each(cursor, template->param) {
                if (strcmp(cursor->name, name) == 0)
                        return cursor;
        }

        return NULL;
}

int db_get_value(const char *key, struct db_value *v, void *buf, size_t bufsz)
{
        void *item;
        const struct db_template *template;
        const struct db_param *param;
        int status;

        status = db_template_get(key, &template);
        if (status != 0)
                return status;

        status = db_item_get(key, &item);
        if (status != 0) {
                db_template_put(key, &template);
                return status;
        }

        param = db_lookup_param(key, template);
        if (param != NULL)
                status = db_format_toraw(param, item, buf, bufsz, &v->type,
                                         &v->objsz, &v->nobj);                
        else
                status = -ENOENT;

        db_item_put(key, &item);
        db_template_put(key, &template);
        
        return status;
}
EXPORT_SYMBOL(db_get_value);
