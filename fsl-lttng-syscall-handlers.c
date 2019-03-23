/* SPDX-License-Identifier: (GPL-2.0 or LGPL-2.1)
 *
 * lttng-capture-buffer.c
 *
 * Copyright (C) 2018 FSL Stony Brook University
 */

#include <fsl-lttng-syscall-handlers.h>
#include <uapi/asm-generic/statfs.h>
#include <uapi/asm-generic/fcntl.h>
#include <uapi/asm-generic/termios.h>
#include <uapi/linux/utime.h>
#include <linux/socket.h>
#include <uapi/linux/fs.h>
#include <asm/ioctls.h>

void read_syscall_handler(fsl_event_type event, unsigned long *args,
			  unsigned int nr_args, long ret)
{
	if (event == syscall_buffer_enter || (void *)args[1] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], args[2]);
}

void write_syscall_handler(fsl_event_type event, unsigned long *args,
			   unsigned int nr_args, long ret)
{
	if (event == syscall_buffer_enter || (void *)args[1] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], args[2]);
}

void stat_family_syscall_handler(fsl_event_type event, unsigned long *args,
				 unsigned int nr_args, long ret)
{
	if (event == syscall_buffer_enter || (void *)args[1] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], sizeof(struct stat));
}

void newfstatat_syscall_handler(fsl_event_type event, unsigned long *args,
				unsigned int nr_args, long ret)
{
	if (event == syscall_buffer_enter || (void *)args[2] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[2], sizeof(struct stat));
}

void statfs_family_syscall_handler(fsl_event_type event, unsigned long *args,
				   unsigned int nr_args, long ret)
{
	if (event == syscall_buffer_enter || (void *)args[1] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], sizeof(struct statfs));
}

void readlink_syscall_handler(fsl_event_type event, unsigned long *args,
			      unsigned int nr_args, long ret)
{
	if (event == syscall_buffer_enter || (void *)args[1] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], args[2]);
}

void utime_syscall_handler(fsl_event_type event, unsigned long *args,
			   unsigned int nr_args, long ret)
{
	if (event == syscall_buffer_enter || (void *)args[1] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], sizeof(struct utimbuf));
}

void utimes_syscall_handler(fsl_event_type event, unsigned long *args,
			    unsigned int nr_args, long ret)
{
	if (event == syscall_buffer_enter || (void *)args[1] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], 2 * sizeof(struct timeval));
}

void utimensat_syscall_handler(fsl_event_type event, unsigned long *args,
			       unsigned int nr_args, long ret)
{
	if (event == syscall_buffer_enter || (void *)args[2] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[2], 2 * sizeof(struct timespec));
}

void pipe_syscall_handler(fsl_event_type event, unsigned long *args,
			  unsigned int nr_args, long ret)
{
	if (event == syscall_buffer_enter || (void *)args[0] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[0], 2 * sizeof(int));
}

void fcntl_syscall_handler(fsl_event_type event, unsigned long *args,
			   unsigned int nr_args, long ret)
{
	if (event == syscall_buffer_enter) {
		return;
	}
	if (args[1] == F_SETLK || args[1] == F_SETLKW || args[1] == F_GETLK) {
		copy_user_buffer_to_file((void *)args[2], sizeof(struct flock));
	}
}

void getdents_syscall_handler(fsl_event_type event, unsigned long *args,
			      unsigned int nr_args, long ret)
{
	if (event == syscall_buffer_enter || (void *)args[1] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], ret);
}

void setrlimit_syscall_handler(fsl_event_type event, unsigned long *args,
			       unsigned int nr_args, long ret)
{
	if (event == syscall_buffer_enter || (void *)args[1] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], sizeof(struct rlimit));
}

void getrlimit_syscall_handler(fsl_event_type event, unsigned long *args,
			       unsigned int nr_args, long ret)
{
	if (event == syscall_buffer_enter || (void *)args[1] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], sizeof(struct rlimit));
}

void xattr_syscall_handler(fsl_event_type event, unsigned long *args,
			   unsigned int nr_args, long ret)
{
	if (event == syscall_buffer_enter || (void *)args[2] == NULL) {
		return;
	}
	// copy_user_buffer_to_file((void *)args[2], args[3]);
}

void listxattr_syscall_handler(fsl_event_type event, unsigned long *args,
			       unsigned int nr_args, long ret)
{
	if (event == syscall_buffer_enter || (void *)args[1] == NULL) {
		return;
	}
	// copy_user_buffer_to_file((void *)args[1], args[2]);
}

void connect_syscall_handler(fsl_event_type event, unsigned long *args,
			     unsigned int nr_args, long ret)
{
	if (event == syscall_buffer_enter || (void *)args[1] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], args[2]);
}

void bind_syscall_handler(fsl_event_type event, unsigned long *args,
			  unsigned int nr_args, long ret)
{
	if (event == syscall_buffer_enter || (void *)args[1] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], args[2]);
}

void socketpair_syscall_handler(fsl_event_type event, unsigned long *args,
				unsigned int nr_args, long ret)
{
	if (event == syscall_buffer_enter || (void *)args[3] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[3], 2 * sizeof(int));
}

void socketopt_syscall_handler(fsl_event_type event, unsigned long *args,
			       unsigned int nr_args, long ret)
{
	if (event == syscall_buffer_enter || (void *)args[3] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[3], args[4]);
}

void getsocketopt_syscall_handler(fsl_event_type event, unsigned long *args,
				  unsigned int nr_args, long ret)
{
	unsigned long size = 0;
	if (event == syscall_buffer_enter || (void *)args[3] == NULL) {
		return;
	}
	copy_user_buffer((void *)args[4], sizeof(uint32_t), (void *)&size);
	args[4] = size;
	copy_user_buffer_to_file((void *)args[3], args[4]);
}

void recvfrom_syscall_handler(fsl_event_type event, unsigned long *args,
			      unsigned int nr_args, long ret)
{
	if (event == syscall_buffer_enter || (void *)args[1] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], args[2]);
}

void send_recv_msg_syscall_handler(fsl_event_type event, unsigned long *args,
				   unsigned int nr_args, long ret)
{
	if (event == syscall_buffer_enter || (void *)args[1] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], sizeof(struct msghdr));
}

// TODO(Umit): not completed copy sockaddr also
void sendto_syscall_handler(fsl_event_type event, unsigned long *args,
			    unsigned int nr_args, long ret)
{
	if (event == syscall_buffer_enter || (void *)args[1] == NULL) {
		return;
	}
	copy_user_buffer_to_file((void *)args[1], args[2]);
}

void ioctl_syscall_handler(fsl_event_type event, unsigned long *args,
			   unsigned int nr_args, long ret)
{
	if (event == syscall_buffer_enter) {
		return;
	}

	switch (args[1]) {
	case FS_IOC_GETVERSION: {
		if ((void *)args[2] != NULL) {
			copy_user_buffer_to_file((void *)args[2], sizeof(int));
		}
		break;
	}
	case TIOCGPGRP: {
		if ((void *)args[2] != NULL) {
			copy_user_buffer_to_file((void *)args[2], sizeof(int));
		}
		break;
	}
	case TIOCGWINSZ: {
		if ((void *)args[2] != NULL) {
			copy_user_buffer_to_file((void *)args[2],
						 sizeof(struct winsize));
		}
		break;
	}
	case TCGETS: {
		if ((void *)args[2] != NULL) {
			copy_user_buffer_to_file((void *)args[2],
						 sizeof(struct termios));
		}
		break;
	}
	default:
		break;
	}
}
