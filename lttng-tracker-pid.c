/* SPDX-License-Identifier: (GPL-2.0 or LGPL-2.1)
 *
 * lttng-tracker-pid.c
 *
 * LTTng Process ID tracking.
 *
 * Copyright (C) 2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/seq_file.h>
#include <linux/stringify.h>
#include <linux/hash.h>
#include <linux/rcupdate.h>

#include <wrapper/tracepoint.h>
#include <wrapper/rcu.h>
#include <wrapper/list.h>
#include <lttng-events.h>

#include <lttng-capture-buffer.h>

extern atomic64_t syscall_record_id;

/*
 * Hash table is allocated and freed when there are no possible
 * concurrent lookups (ensured by the alloc/free caller). However,
 * there can be concurrent RCU lookups vs add/del operations.
 *
 * Concurrent updates of the PID hash table are forbidden: the caller
 * must ensure mutual exclusion. This is currently done by holding the
 * sessions_mutex across calls to create, destroy, add, and del
 * functions of this API.
 */
int lttng_pid_tracker_get_node_pid(const struct lttng_pid_hash_node *node)
{
	return node->pid;
}

/*
 * Lookup performed from RCU read-side critical section (RCU sched),
 * protected by preemption off at the tracepoint call site.
 * Return 1 if found, 0 if not found.
 */
bool lttng_pid_tracker_lookup(struct lttng_pid_tracker *lpf, int pid)
{
	struct hlist_head *head;
	struct lttng_pid_hash_node *e;
        long record_id;
	uint32_t hash = hash_32(pid, 32);
	head = &lpf->pid_hash[hash & (LTTNG_PID_TABLE_SIZE - 1)];
	lttng_hlist_for_each_entry_rcu(e, head, hlist) {
		if (pid == e->pid &&
		    current->tgid == e->pid) {
			record_id = atomic64_add_return(1, &syscall_record_id);
			fsl_pid_record_id_map(current->pid,
					      record_id);
			return true;	/* Found */
                }
	}
	return false;
}
EXPORT_SYMBOL_GPL(lttng_pid_tracker_lookup);

/*
 * Tracker add and del operations support concurrent RCU lookups.
 */
int lttng_pid_tracker_add(struct lttng_pid_tracker *lpf, int pid)
{
	struct hlist_head *head;
	struct lttng_pid_hash_node *e;
	uint32_t hash = hash_32(pid, 32);

        printk(KERN_DEBUG "fsl-ds-logging: pid added %d\n", pid);
        atomic64_set(&syscall_record_id, 0);
        head = &lpf->pid_hash[hash & (LTTNG_PID_TABLE_SIZE - 1)];
	lttng_hlist_for_each_entry(e, head, hlist) {
		if (pid == e->pid)
			return -EEXIST;
	}
	e = kmalloc(sizeof(struct lttng_pid_hash_node), GFP_KERNEL);
	if (!e)
		return -ENOMEM;
	e->pid = pid;
	hlist_add_head_rcu(&e->hlist, head);
	return 0;
}

static
void pid_tracker_del_node_rcu(struct lttng_pid_hash_node *e)
{
	hlist_del_rcu(&e->hlist);
	/*
	 * We choose to use a heavyweight synchronize on removal here,
	 * since removal of a PID from the tracker mask is a rare
	 * operation, and we don't want to use more cache lines than
	 * what we really need when doing the PID lookups, so we don't
	 * want to afford adding a rcu_head field to those pid hash
	 * node.
	 */
	synchronize_trace();
	kfree(e);
}

/*
 * This removal is only used on destroy, so it does not need to support
 * concurrent RCU lookups.
 */
static
void pid_tracker_del_node(struct lttng_pid_hash_node *e)
{
	hlist_del(&e->hlist);
	kfree(e);
}

int lttng_pid_tracker_del(struct lttng_pid_tracker *lpf, int pid)
{
	struct hlist_head *head;
	struct lttng_pid_hash_node *e;
	uint32_t hash = hash_32(pid, 32);

	head = &lpf->pid_hash[hash & (LTTNG_PID_TABLE_SIZE - 1)];
	/*
	 * No need of _safe iteration, because we stop traversal as soon
	 * as we remove the entry.
	 */
	lttng_hlist_for_each_entry(e, head, hlist) {
		if (pid == e->pid) {
			pid_tracker_del_node_rcu(e);
			return 0;
		}
	}
	return -ENOENT;	/* Not found */
}

struct lttng_pid_tracker *lttng_pid_tracker_create(void)
{
	return kzalloc(sizeof(struct lttng_pid_tracker), GFP_KERNEL);
}

void lttng_pid_tracker_destroy(struct lttng_pid_tracker *lpf)
{
	int i;

	for (i = 0; i < LTTNG_PID_TABLE_SIZE; i++) {
		struct hlist_head *head = &lpf->pid_hash[i];
		struct lttng_pid_hash_node *e;
		struct hlist_node *tmp;

		lttng_hlist_for_each_entry_safe(e, tmp, head, hlist)
			pid_tracker_del_node(e);
	}
	kfree(lpf);
}
