/* SPDX-License-Identifier: (GPL-2.0 or LGPL-2.1)
 *
 * probes/lttng-probe-filemap.c
 *
 * LTTng filemap probes.
 *
 */

#include <linux/module.h>
#include <lttng-tracer.h>

/*
 * Create the tracepoint static inlines from the kernel to validate that our
 * trace event macros match the kernel we run on.
 */
#include <trace/events/filemap.h>

#include <lttng-kernel-version.h>
#include <wrapper/tracepoint.h>

/*
 * Create LTTng tracepoint probes.
 */
#define LTTNG_PACKAGE_BUILD
#define CREATE_TRACE_POINTS
#define TRACE_INCLUDE_PATH instrumentation/events/lttng-module

#include <lttng-capture-buffer.h>
#include <instrumentation/events/lttng-module/filemap.h>

void reset_inode_hash(void) {
	struct hlist_head *head;
	struct lttng_inode_hash_node *iterater;

        head = &inode_hash[0];
	lttng_hlist_for_each_entry(iterater, head, hlist)
	{
		iterater->min = INT_MAX;
		iterater->max = 0;
	}
}
EXPORT_SYMBOL(reset_inode_hash);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("LTTng filemap probes");
MODULE_VERSION(__stringify(LTTNG_MODULES_MAJOR_VERSION) "."
	__stringify(LTTNG_MODULES_MINOR_VERSION) "."
	__stringify(LTTNG_MODULES_PATCHLEVEL_VERSION)
	LTTNG_MODULES_EXTRAVERSION);
