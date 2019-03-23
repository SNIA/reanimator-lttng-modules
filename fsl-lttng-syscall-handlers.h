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
			  unsigned int nr_args, long ret);
void write_syscall_handler(fsl_event_type event, unsigned long *args,
			   unsigned int nr_args, long ret);
void stat_family_syscall_handler(fsl_event_type event, unsigned long *args,
				 unsigned int nr_args, long ret);
void statfs_family_syscall_handler(fsl_event_type event, unsigned long *args,
				   unsigned int nr_args, long ret);
void readlink_syscall_handler(fsl_event_type event, unsigned long *args,
			      unsigned int nr_args, long ret);
void utime_syscall_handler(fsl_event_type event, unsigned long *args,
			   unsigned int nr_args, long ret);
void newfstatat_syscall_handler(fsl_event_type event, unsigned long *args,
				unsigned int nr_args, long ret);
void utimes_syscall_handler(fsl_event_type event, unsigned long *args,
			    unsigned int nr_args, long ret);
void utimensat_syscall_handler(fsl_event_type event, unsigned long *args,
			       unsigned int nr_args, long ret);
void pipe_syscall_handler(fsl_event_type event, unsigned long *args,
			  unsigned int nr_args, long ret);
void fcntl_syscall_handler(fsl_event_type event, unsigned long *args,
			   unsigned int nr_args, long ret);
void getdents_syscall_handler(fsl_event_type event, unsigned long *args,
			      unsigned int nr_args, long ret);
void setrlimit_syscall_handler(fsl_event_type event, unsigned long *args,
			       unsigned int nr_args, long ret);
void getrlimit_syscall_handler(fsl_event_type event, unsigned long *args,
			       unsigned int nr_args, long ret);
void xattr_syscall_handler(fsl_event_type event, unsigned long *args,
			   unsigned int nr_args, long ret);
void listxattr_syscall_handler(fsl_event_type event, unsigned long *args,
			       unsigned int nr_args, long ret);
void connect_syscall_handler(fsl_event_type event, unsigned long *args,
			     unsigned int nr_args, long ret);
void bind_syscall_handler(fsl_event_type event, unsigned long *args,
			  unsigned int nr_args, long ret);
void socketpair_syscall_handler(fsl_event_type event, unsigned long *args,
				unsigned int nr_args, long ret);
void socketopt_syscall_handler(fsl_event_type event, unsigned long *args,
			       unsigned int nr_args, long ret);
void recvfrom_syscall_handler(fsl_event_type event, unsigned long *args,
			      unsigned int nr_args, long ret);
void send_recv_msg_syscall_handler(fsl_event_type event, unsigned long *args,
				   unsigned int nr_args, long ret);
void sendto_syscall_handler(fsl_event_type event, unsigned long *args,
			    unsigned int nr_args, long ret);
void ioctl_syscall_handler(fsl_event_type event, unsigned long *args,
			   unsigned int nr_args, long ret);
void getsocketopt_syscall_handler(fsl_event_type event, unsigned long *args,
				  unsigned int nr_args, long ret);

#endif
