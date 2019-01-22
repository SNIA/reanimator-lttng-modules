/* SPDX-License-Identifier: (GPL-2.0 or LGPL-2.1)
 *
 * lttng-capture-buffer.c
 *
 * Copyright (C) 2018 FSL Stony Brook University
 */

#ifndef FSL_LTTNG_SYSCALL_HANDLERS
#define FSL_LTTNG_SYSCALL_HANDLERS

#include <lttng-capture-buffer.h>

void read_syscall_handler(fsl_event_type event, unsigned long *args,
			  unsigned int nr_args);

#endif