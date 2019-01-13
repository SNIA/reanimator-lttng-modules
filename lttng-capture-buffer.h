/* SPDX-License-Identifier: (GPL-2.0 or LGPL-2.1)
 *
 * lttng-capture-buffer.h
 *
 * Copyright (C) 2018 FSL Stony Brook University
 */

#ifndef _LTTNG_CAPTUREBUFFER_H
#define _LTTNG_CAPTUREBUFFER_H

#define LOG_PATH "/tmp/lttng-log.txt"
#define BUFFER_PATH "/tmp/buffer-capture.dat"

bool start_buffer_capturing(void);
bool end_buffer_capturing(void);
bool sync_buffers(void);

void log_syscall_args(long syscall_no, unsigned long *args,
		      unsigned int nr_args);
void copy_user_buffer_to_file(atomic64_t *record_id, atomic64_t *read_cnt,
			      void *user_buffer, unsigned long size);

// #define VERBOSE_SYS_CALLS

#endif
