/* SPDX-License-Identifier: (GPL-2.0 or LGPL-2.1)
 *
 * lttng-capture-buffer.c
 *
 * Copyright (C) 2018 FSL Stony Brook University
 */

#include <fsl-lttng-syscall-handlers.h>

void read_syscall_handler(fsl_event_type event, unsigned long *args,
			  unsigned int nr_args)
{
	if (event == syscall_buffer_enter) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], args[2]);
}

void write_syscall_handler(fsl_event_type event, unsigned long *args,
			   unsigned int nr_args)
{
	if (event == syscall_buffer_enter) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], args[2]);
}

void stat_family_syscall_handler(fsl_event_type event, unsigned long *args,
				 unsigned int nr_args)
{
	if (event == syscall_buffer_enter) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], sizeof(struct stat));
}
