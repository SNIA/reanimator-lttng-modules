/* SPDX-License-Identifier: (GPL-2.0 or LGPL-2.1)
 *
 * probes/lttng-probe-filemap.c
 *
 * LTTng filemap probes.
 *
 */

#include <linux/module.h>
#include <lttng-tracer.h>
#include <trace/events/filemap.h>
#include <wrapper/tracepoint.h>
#include <lttng-kernel-version.h>

#define LTTNG_PACKAGE_BUILD
#define CREATE_TRACE_POINTS
#define TRACE_INCLUDE_PATH instrumentation/events/lttng-module

#include <instrumentation/events/lttng-module/filemap.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Umit Akgun <umit@fsl.cs.sunysb.edu>");
MODULE_DESCRIPTION("LTTng filemap probes");
MODULE_VERSION(__stringify(LTTNG_MODULES_MAJOR_VERSION) "."
	__stringify(LTTNG_MODULES_MINOR_VERSION) "."
	__stringify(LTTNG_MODULES_PATCHLEVEL_VERSION)
	LTTNG_MODULES_EXTRAVERSION);
