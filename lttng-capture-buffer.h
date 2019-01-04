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

#define LOG_PATH "/tmp/lttng-log.txt"

bool start_buffer_capturing(void);
bool end_buffer_capturing(void);

#endif
