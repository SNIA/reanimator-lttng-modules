/* SPDX-License-Identifier: (GPL-2.0 or LGPL-2.1)
 *
 * lttng-capture-buffer.h
 *
 * Copyright (C) 2018 FSL Stony Brook University
 */

#ifndef _LTTNG_CAPTUREBUFFER_H
#define _LTTNG_CAPTUREBUFFER_H

#include <linux/fs.h>
#include <asm/segment.h>
#include <linux/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <wrapper/list.h>
#include <asm/syscall.h>
#include <linux/bitmap.h>

// #define VERBOSE_SYS_CALLS

#define LOG_PATH "/tmp/lttng-log.txt"
#define BUFFER_PATH "/tmp/buffer-capture.dat"

#define FSL_LTTNG_PID_HASH_BITS 10
#define FSL_LTTNG_PID_TABLE_SIZE (1 << FSL_LTTNG_PID_HASH_BITS)

struct buffer_header {
	atomic64_t record_id;
	size_t sizeOfBuffer;
	char buffer[0];
};

struct fsl_lttng_pid_tracker {
	struct hlist_head pid_hash[FSL_LTTNG_PID_TABLE_SIZE];
};

struct fsl_lttng_pid_hash_node {
	struct hlist_node hlist;
	int pid;
	long record_id;
};

enum fsl_syscall_event {
	syscall_buffer_enter,
	syscall_buffer_exit,
	syscall_buffer_compat
};

typedef enum fsl_syscall_event fsl_event_type;

typedef void (*syscall_buffer_handler)(fsl_event_type event,
				       unsigned long *args,
				       unsigned int nr_args);

bool start_buffer_capturing(void);
bool end_buffer_capturing(void);

void log_syscall_args(long syscall_no, unsigned long *args,
		      unsigned int nr_args);
void fsl_pid_record_id_map(int pid, long record_id);
void fsl_syscall_buffer_handler(long syscall_no, fsl_event_type event,
				unsigned long *args, unsigned int nr_args);
void copy_user_buffer_to_file(void *user_buffer, unsigned long size);
long fsl_pid_record_id_lookup(int pid);
bool copy_user_buffer(void *user_addr, unsigned long size, void *copy_buffer);

#endif
