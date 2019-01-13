/* SPDX-License-Identifier: (GPL-2.0 or LGPL-2.1)
 *
 * lttng-capture-buffer.h
 *
 * Copyright (C) 2018 FSL Stony Brook University
 */

#ifndef _LTTNG_CAPTUREBUFFER_H
#define _LTTNG_CAPTUREBUFFER_H

// #define VERBOSE_SYS_CALLS

#define LOG_PATH "/tmp/lttng-log.txt"
#define BUFFER_PATH "/tmp/buffer-capture.dat"

#define FSL_LTTNG_PID_HASH_BITS 10
#define FSL_LTTNG_PID_TABLE_SIZE (1 << FSL_LTTNG_PID_HASH_BITS)

bool start_buffer_capturing(void);
bool end_buffer_capturing(void);
bool sync_buffers(void);

void log_syscall_args(long syscall_no, unsigned long *args,
		      unsigned int nr_args);
void copy_user_buffer_to_file(atomic64_t *record_id, void *user_buffer,
			      unsigned long size);
void fsl_pid_record_id_map(int pid, long record_id);

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

#endif
