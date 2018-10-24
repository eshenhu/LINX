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
#include <linux/module.h>
#ifndef CONFIG_PROC_FS
#define CONFIG_PROC_FS
#endif
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/version.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24))
#include <net/net_namespace.h>
#endif
#include "db.h"
#include "db_private.h"
#include "db_format.h"

struct db_seq {
	const struct db_template *template;
        struct list_head *list;
        unsigned int modno;
};

static void *db_seq_start(struct seq_file *s, loff_t *pos);
static void db_seq_stop(struct seq_file *s, void *v);
static void *db_seq_next(struct seq_file *s, void *v, loff_t *pos);
static int db_seq_show(struct seq_file *s, void *v);

static struct seq_operations db_seq_ops = {
	.start = db_seq_start,
	.stop = db_seq_stop,
	.next = db_seq_next,
	.show = db_seq_show,
};

static int db_proc_open(struct inode *inode, struct file *file);
static int db_proc_release(struct inode *inode, struct file *file);

static struct file_operations db_proc_file_ops = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
	.owner = THIS_MODULE,
#endif
	.open = db_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = db_proc_release,
};

static struct proc_dir_entry *db_proc_root;

static void *db_seq_start(struct seq_file *s, loff_t *pos)
{
	struct db_seq *p;

        LOG_ENTRY("%p, %lld", s, *pos);
	p = s->private;
        return db_list_start(p->list, *pos, &p->modno);
}

static void db_seq_stop(struct seq_file *s, void *v)
{
	struct db_seq *p;

        LOG_ENTRY("%p, %p", s, v);
	p = s->private;
        db_list_stop(p->list, v);
}

static void *db_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct db_seq *p;

        LOG_ENTRY("%p, %p, %lld", s, v, *pos);
        (*pos)++;
	p = s->private;
	return db_list_next(p->list, *pos, v, &p->modno);
}

static int db_seq_show(struct seq_file *s, void *v)
{
	struct db_seq *p;
	char *buf;
        int status;
        const struct db_param *q;

        LOG_ENTRY("%p, %p", s, v);
	buf = (char *)__get_free_page(GFP_KERNEL);
	if (buf == NULL)
		return -ENOMEM;

	p = s->private;
        status = 0;

        seq_printf(s, "%s\n", db_list_name(v));
        db_param_for_each(q, p->template->param) {
                seq_printf(s, "\t%s: ", q->name);
                status = db_format_tostr(q, db_list_item(v), buf, PAGE_SIZE);
                if (status < 0)
                        return status;
                seq_printf(s, "%s\n", buf);
        }
        seq_printf(s, "\n");

	free_page((unsigned long)buf);
	return status;
}

static int db_proc_open(struct inode *inode, struct file *file)
{
	struct seq_file *s;
	struct db_seq *p;
	int status;

        LOG_ENTRY("%p, %p", inode, file);
	p = kmalloc(sizeof(*p), GFP_KERNEL);
	if (p == NULL)
		return -ENOMEM;

	status = seq_open(file, &db_seq_ops);
	if (status != 0)
                goto out_20;

        status = db_template_get(PDE(inode)->name, &p->template);
        if (status != 0)
                goto out_20;

        status = db_list_get(PDE(inode)->name, &p->list);
        if (status != 0)
                goto out_10;

	s = file->private_data;
	s->private = p;
	return 0;

  out_10:
        db_template_put(PDE(inode)->name, &p->template);
  out_20:
        kfree(p);
        return status;
}

static int db_proc_release(struct inode *inode, struct file *file)
{
	struct seq_file *s;
	struct db_seq *p;
	int status;

        LOG_ENTRY("%p, %p", inode, file);
	s = file->private_data;
	p = s->private;

        status = db_list_put(PDE(inode)->name, &p->list);
        if (status != 0)
                return status;

        status = db_template_put(PDE(inode)->name, &p->template);
        if (status != 0)
                return status;

	return seq_release_private(inode, file);
}

int db_proc_init(const char *name)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
        db_proc_root = proc_mkdir(name, proc_net);
#else
        db_proc_root = proc_mkdir(name, init_net.proc_net);
#endif
        if (db_proc_root == NULL)
                return -EINVAL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
	db_proc_root->owner = THIS_MODULE;
#endif
        return 0;
}

void db_proc_cleanup(const char *name)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
        remove_proc_entry(name, proc_net);
#else
        remove_proc_entry(name, init_net.proc_net);
#endif
        db_proc_root = NULL;
}

int db_proc_add(const char *name)
{
        struct proc_dir_entry *pde;

        pde = create_proc_entry(name, 0444, db_proc_root);
        if (pde == NULL)
                return -EINVAL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
	pde->owner = THIS_MODULE;
#endif
        pde->proc_fops = &db_proc_file_ops;
        return 0;
}
EXPORT_SYMBOL(db_proc_add);

int db_proc_del(const char *name)
{
        remove_proc_entry(name, db_proc_root);
        return 0;
}
EXPORT_SYMBOL(db_proc_del);
