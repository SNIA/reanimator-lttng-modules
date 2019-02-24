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
void write_syscall_handler(fsl_event_type event, unsigned long *args,
			   unsigned int nr_args);
void stat_family_syscall_handler(fsl_event_type event, unsigned long *args,
				 unsigned int nr_args);
void statfs_family_syscall_handler(fsl_event_type event, unsigned long *args,
				   unsigned int nr_args);
void readlink_syscall_handler(fsl_event_type event, unsigned long *args,
			      unsigned int nr_args);
void utime_syscall_handler(fsl_event_type event, unsigned long *args,
			   unsigned int nr_args);
void newfstatat_syscall_handler(fsl_event_type event, unsigned long *args,
				unsigned int nr_args);
void utimes_syscall_handler(fsl_event_type event, unsigned long *args,
			    unsigned int nr_args);
void utimensat_syscall_handler(fsl_event_type event, unsigned long *args,
			       unsigned int nr_args);
void pipe_syscall_handler(fsl_event_type event, unsigned long *args,
			  unsigned int nr_args);
void fcntl_syscall_handler(fsl_event_type event, unsigned long *args,
			   unsigned int nr_args);
void getdents_syscall_handler(fsl_event_type event, unsigned long *args,
			      unsigned int nr_args);
void setrlimit_syscall_handler(fsl_event_type event, unsigned long *args,
			       unsigned int nr_args);
void getrlimit_syscall_handler(fsl_event_type event, unsigned long *args,
			       unsigned int nr_args);
void xattr_syscall_handler(fsl_event_type event, unsigned long *args,
			   unsigned int nr_args);

#endif
