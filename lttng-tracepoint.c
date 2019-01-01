/* SPDX-License-Identifier: (GPL-2.0 or LGPL-2.1)
 *
 * lttng-tracepoint.c
 *
 * LTTng adaptation layer for Linux kernel 3.15+ tracepoints.
 *
 * Copyright (C) 2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <linux/mutex.h>
#include <linux/err.h>
#include <linux/notifier.h>
#include <linux/tracepoint.h>
#include <linux/slab.h>
#include <linux/jhash.h>
#include <linux/module.h>

#include <lttng-tracepoint.h>
#include <wrapper/list.h>
#include <wrapper/tracepoint.h>

#include <linux/fs.h>
#include <asm/segment.h>
#include <linux/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/sched.h>

/*
 * Protect the tracepoint table. lttng_tracepoint_mutex nests within
 * kernel/tracepoint.c tp_modlist_mutex. kernel/tracepoint.c
 * tracepoint_mutex nests within lttng_tracepoint_mutex.
 */
static
DEFINE_MUTEX(lttng_tracepoint_mutex);

#define TRACEPOINT_HASH_BITS 6
#define TRACEPOINT_TABLE_SIZE (1 << TRACEPOINT_HASH_BITS)
static
struct hlist_head tracepoint_table[TRACEPOINT_TABLE_SIZE];

/*
 * The tracepoint entry is the node contained within the hash table. It
 * is a mapping from the "string" key to the struct tracepoint pointer.
 */
struct tracepoint_entry {
	struct hlist_node hlist;
	struct tracepoint *tp;
	int refcount;
	struct list_head probes;
	char name[0];
};

struct lttng_tp_probe {
	struct tracepoint_func tp_func;
	struct list_head list;
};

static
int add_probe(struct tracepoint_entry *e, void *probe, void *data)
{
	struct lttng_tp_probe *p;
	int found = 0;

	list_for_each_entry(p, &e->probes, list) {
		if (p->tp_func.func == probe && p->tp_func.data == data) {
			found = 1;
			break;
		}
	}
	if (found)
		return -EEXIST;
	p = kmalloc(sizeof(struct lttng_tp_probe), GFP_KERNEL);
	if (!p)
		return -ENOMEM;
	p->tp_func.func = probe;
	p->tp_func.data = data;
	list_add(&p->list, &e->probes);
	return 0;
}

static
int remove_probe(struct tracepoint_entry *e, void *probe, void *data)
{
	struct lttng_tp_probe *p;
	int found = 0;

	list_for_each_entry(p, &e->probes, list) {
		if (p->tp_func.func == probe && p->tp_func.data == data) {
			found = 1;
			break;
		}
	}
	if (found) {
		list_del(&p->list);
		kfree(p);
		return 0;
	} else {
		WARN_ON(1);
		return -ENOENT;
	}
}

/*
 * Get tracepoint if the tracepoint is present in the tracepoint hash table.
 * Must be called with lttng_tracepoint_mutex held.
 * Returns NULL if not present.
 */
static
struct tracepoint_entry *get_tracepoint(const char *name)
{
	struct hlist_head *head;
	struct tracepoint_entry *e;
	u32 hash = jhash(name, strlen(name), 0);

	head = &tracepoint_table[hash & (TRACEPOINT_TABLE_SIZE - 1)];
	lttng_hlist_for_each_entry(e, head, hlist) {
		if (!strcmp(name, e->name))
			return e;
	}
	return NULL;
}

/*
 * Add the tracepoint to the tracepoint hash table. Must be called with
 * lttng_tracepoint_mutex held.
 */
static
struct tracepoint_entry *add_tracepoint(const char *name)
{
	struct hlist_head *head;
	struct tracepoint_entry *e;
	size_t name_len = strlen(name) + 1;
	u32 hash = jhash(name, name_len - 1, 0);

	head = &tracepoint_table[hash & (TRACEPOINT_TABLE_SIZE - 1)];
	lttng_hlist_for_each_entry(e, head, hlist) {
		if (!strcmp(name, e->name)) {
			printk(KERN_NOTICE
				"tracepoint %s busy\n", name);
			return ERR_PTR(-EEXIST);        /* Already there */
		}
	}
	/*
	 * Using kmalloc here to allocate a variable length element. Could
	 * cause some memory fragmentation if overused.
	 */
	e = kmalloc(sizeof(struct tracepoint_entry) + name_len, GFP_KERNEL);
	if (!e)
		return ERR_PTR(-ENOMEM);
	memcpy(&e->name[0], name, name_len);
	e->tp = NULL;
	e->refcount = 0;
	INIT_LIST_HEAD(&e->probes);
	hlist_add_head(&e->hlist, head);
	return e;
}

/*
 * Remove the tracepoint from the tracepoint hash table. Must be called
 * with lttng_tracepoint_mutex held.
 */
static
void remove_tracepoint(struct tracepoint_entry *e)
{
	hlist_del(&e->hlist);
	kfree(e);
}

int lttng_tracepoint_probe_register(const char *name, void *probe, void *data)
{
	struct tracepoint_entry *e;
	int ret = 0;

	mutex_lock(&lttng_tracepoint_mutex);
	e = get_tracepoint(name);
	if (!e) {
		e = add_tracepoint(name);
		if (IS_ERR(e)) {
			ret = PTR_ERR(e);
			goto end;
		}
	}
	/* add (probe, data) to entry */
	ret = add_probe(e, probe, data);
	if (ret)
		goto end;
	e->refcount++;
	if (e->tp) {
		ret = tracepoint_probe_register(e->tp, probe, data);
		WARN_ON_ONCE(ret);
		ret = 0;
	}
end:
	mutex_unlock(&lttng_tracepoint_mutex);
	return ret;
}

int lttng_tracepoint_probe_unregister(const char *name, void *probe, void *data)
{
	struct tracepoint_entry *e;
	int ret = 0;

	mutex_lock(&lttng_tracepoint_mutex);
	e = get_tracepoint(name);
	if (!e) {
		ret = -ENOENT;
		goto end;
	}
	/* remove (probe, data) from entry */
	ret = remove_probe(e, probe, data);
	if (ret)
		goto end;
	if (e->tp) {
		ret = tracepoint_probe_unregister(e->tp, probe, data);
		WARN_ON_ONCE(ret);
		ret = 0;
	}
	if (!--e->refcount)
		remove_tracepoint(e);
end:
	mutex_unlock(&lttng_tracepoint_mutex);
	return ret;
}

#ifdef CONFIG_MODULES

static
int lttng_tracepoint_coming(struct tp_module *tp_mod)
{
	int i;

	mutex_lock(&lttng_tracepoint_mutex);
	for (i = 0; i < tp_mod->mod->num_tracepoints; i++) {
		struct tracepoint *tp;
		struct tracepoint_entry *e;
		struct lttng_tp_probe *p;

		tp = lttng_tracepoint_ptr_deref(&tp_mod->mod->tracepoints_ptrs[i]);
		e = get_tracepoint(tp->name);
		if (!e) {
			e = add_tracepoint(tp->name);
			if (IS_ERR(e)) {
				pr_warn("LTTng: error (%ld) adding tracepoint\n",
					PTR_ERR(e));
				continue;
			}
		}
		/* If already enabled, just check consistency */
		if (e->tp) {
			WARN_ON(e->tp != tp);
			continue;
		}
		e->tp = tp;
		e->refcount++;
		/* register each (probe, data) */
		list_for_each_entry(p, &e->probes, list) {
			int ret;

			ret = tracepoint_probe_register(e->tp,
					p->tp_func.func, p->tp_func.data);
			WARN_ON_ONCE(ret);
		}
	}
	mutex_unlock(&lttng_tracepoint_mutex);
	return 0;
}

static
int lttng_tracepoint_going(struct tp_module *tp_mod)
{
	int i;

	mutex_lock(&lttng_tracepoint_mutex);
	for (i = 0; i < tp_mod->mod->num_tracepoints; i++) {
		struct tracepoint *tp;
		struct tracepoint_entry *e;
		struct lttng_tp_probe *p;

		tp = lttng_tracepoint_ptr_deref(&tp_mod->mod->tracepoints_ptrs[i]);
		e = get_tracepoint(tp->name);
		if (!e || !e->tp)
			continue;
		/* unregister each (probe, data) */
		list_for_each_entry(p, &e->probes, list) {
			int ret;

			ret = tracepoint_probe_unregister(e->tp,
					p->tp_func.func, p->tp_func.data);
			WARN_ON_ONCE(ret);
		}
		e->tp = NULL;
		if (!--e->refcount)
			remove_tracepoint(e);
	}
	mutex_unlock(&lttng_tracepoint_mutex);
	return 0;
}

static
int lttng_tracepoint_notify(struct notifier_block *self,
		unsigned long val, void *data)
{
	struct tp_module *tp_mod = data;
	int ret = 0;

	switch (val) {
	case MODULE_STATE_COMING:
		ret = lttng_tracepoint_coming(tp_mod);
		break;
	case MODULE_STATE_GOING:
		ret = lttng_tracepoint_going(tp_mod);
		break;
	default:
		break;
	}
	return ret;
}

static
struct notifier_block lttng_tracepoint_notifier = {
	.notifier_call = lttng_tracepoint_notify,
	.priority = 0,
};

static
struct file *file_open(const char *path, int flags, int rights) {
	struct file *filp = NULL;
	mm_segment_t oldfs;
	int err = 0;
	oldfs = get_fs();
	set_fs(get_ds());
	filp = filp_open(path, flags, rights);
	set_fs(oldfs);
	if (IS_ERR(filp)) {
		err = PTR_ERR(filp);
		return NULL;
	}
	return filp;
}

static
void file_close(struct file *file) {
	filp_close(file, NULL);
}

int file_sync(struct file *file) {
	vfs_fsync(file, 0);
	return 0;
}

struct file *log_file_fd;

static
int lttng_tracepoint_module_init(void)
{
	log_file_fd = file_open("/home/umit/research/lttng/lttng-log.txt", O_CREAT | O_RDONLY | O_WRONLY, 666);
	if (log_file_fd == NULL)
		printk(KERN_DEBUG "*** Cannot open the filei\n");
	return register_tracepoint_module_notifier(&lttng_tracepoint_notifier);
}

static
void lttng_tracepoint_module_exit(void)
{
	file_sync(log_file_fd);
	file_close(log_file_fd);
	WARN_ON(unregister_tracepoint_module_notifier(&lttng_tracepoint_notifier));
}

#else /* #ifdef CONFIG_MODULES */

static
int lttng_tracepoint_module_init(void)
{
	return 0;
}

static
void lttng_tracepoint_module_exit(void)
{
}

#endif /* #else #ifdef CONFIG_MODULES */

static
void lttng_kernel_tracepoint_add(struct tracepoint *tp, void *priv)
{
	struct tracepoint_entry *e;
	struct lttng_tp_probe *p;
	int *ret = priv;

	mutex_lock(&lttng_tracepoint_mutex);
	e = get_tracepoint(tp->name);
	if (!e) {
		e = add_tracepoint(tp->name);
		if (IS_ERR(e)) {
			pr_warn("LTTng: error (%ld) adding tracepoint\n",
				PTR_ERR(e));
			*ret = (int) PTR_ERR(e);
			goto end;
		}
	}
	/* If already enabled, just check consistency */
	if (e->tp) {
		WARN_ON(e->tp != tp);
		goto end;
	}
	e->tp = tp;
	e->refcount++;
	/* register each (probe, data) */
	list_for_each_entry(p, &e->probes, list) {
		int ret;

		ret = tracepoint_probe_register(e->tp,
				p->tp_func.func, p->tp_func.data);
		WARN_ON_ONCE(ret);
	}
end:
	mutex_unlock(&lttng_tracepoint_mutex);
}

static
void lttng_kernel_tracepoint_remove(struct tracepoint *tp, void *priv)
{
	struct tracepoint_entry *e;
	int *ret = priv;

	mutex_lock(&lttng_tracepoint_mutex);
	e = get_tracepoint(tp->name);
	if (!e || e->refcount != 1 || !list_empty(&e->probes)) {
		*ret = -EINVAL;
		goto end;
	}
	remove_tracepoint(e);
end:
	mutex_unlock(&lttng_tracepoint_mutex);
}

int __init lttng_tracepoint_init(void)
{
	int ret = 0;

	for_each_kernel_tracepoint(lttng_kernel_tracepoint_add, &ret);
	if (ret)
		goto error;
	ret = lttng_tracepoint_module_init();
	if (ret)
		goto error_module;
	return 0;

error_module:
	{
		int error_ret = 0;

		for_each_kernel_tracepoint(lttng_kernel_tracepoint_remove,
				&error_ret);
		WARN_ON(error_ret);
	}
error:
	return ret;
}

void lttng_tracepoint_exit(void)
{
	int i, ret = 0;

	lttng_tracepoint_module_exit();
	for_each_kernel_tracepoint(lttng_kernel_tracepoint_remove, &ret);
	WARN_ON(ret);
	mutex_lock(&lttng_tracepoint_mutex);
	for (i = 0; i < TRACEPOINT_TABLE_SIZE; i++) {
		struct hlist_head *head = &tracepoint_table[i];

		/* All tracepoints should be removed */
		WARN_ON(!hlist_empty(head));
	}
	mutex_unlock(&lttng_tracepoint_mutex);
}
