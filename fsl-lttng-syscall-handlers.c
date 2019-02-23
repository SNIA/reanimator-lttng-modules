/* SPDX-License-Identifier: (GPL-2.0 or LGPL-2.1)
 *
 * lttng-capture-buffer.c
 *
 * Copyright (C) 2018 FSL Stony Brook University
 */

#include <fsl-lttng-syscall-handlers.h>
#include <uapi/asm-generic/statfs.h>
#include <uapi/asm-generic/fcntl.h>
#include <uapi/linux/utime.h>

void read_syscall_handler(fsl_event_type event, unsigned long *args,
			  unsigned int nr_args)
{
	if (event == syscall_buffer_enter || (void *)args[1] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], args[2]);
}

void write_syscall_handler(fsl_event_type event, unsigned long *args,
			   unsigned int nr_args)
{
	if (event == syscall_buffer_enter || (void *)args[1] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], args[2]);
}

void stat_family_syscall_handler(fsl_event_type event, unsigned long *args,
				 unsigned int nr_args)
{
	if (event == syscall_buffer_enter || (void *)args[1] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], sizeof(struct stat));
}

void newfstatat_syscall_handler(fsl_event_type event, unsigned long *args,
				unsigned int nr_args)
{
	if (event == syscall_buffer_enter || (void *)args[2] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[2], sizeof(struct stat));
}

void statfs_family_syscall_handler(fsl_event_type event, unsigned long *args,
				   unsigned int nr_args)
{
	if (event == syscall_buffer_enter || (void *)args[1] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], sizeof(struct statfs));
}

void readlink_syscall_handler(fsl_event_type event, unsigned long *args,
			      unsigned int nr_args)
{
	if (event == syscall_buffer_enter || (void *)args[1] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], args[2]);
}

void utime_syscall_handler(fsl_event_type event, unsigned long *args,
			   unsigned int nr_args)
{
	if (event == syscall_buffer_enter || (void *)args[1] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], sizeof(struct utimbuf));
}

void utimes_syscall_handler(fsl_event_type event, unsigned long *args,
			    unsigned int nr_args)
{
	if (event == syscall_buffer_enter || (void *)args[1] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], 2 * sizeof(struct timeval));
}

void utimensat_syscall_handler(fsl_event_type event, unsigned long *args,
			       unsigned int nr_args)
{
	if (event == syscall_buffer_enter || (void *)args[2] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[2], 2 * sizeof(struct timespec));
}

void pipe_syscall_handler(fsl_event_type event, unsigned long *args,
			  unsigned int nr_args)
{
	if (event == syscall_buffer_enter || (void *)args[0] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[0], 2 * sizeof(int));
}

void fcntl_syscall_handler(fsl_event_type event, unsigned long *args,
			   unsigned int nr_args)
{
	if (event == syscall_buffer_enter) {
		return;
	}
	if (args[1] == F_SETLK || args[1] == F_SETLKW || args[1] == F_GETLK) {
		copy_user_buffer_to_file((void *)args[2], sizeof(struct flock));
	}
}

void getdents_syscall_handler(fsl_event_type event, unsigned long *args,
			      unsigned int nr_args)
{
	if (event == syscall_buffer_enter || (void *)args[1] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], args[2]);
}
