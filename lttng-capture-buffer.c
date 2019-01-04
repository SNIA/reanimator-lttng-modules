/* SPDX-License-Identifier: (GPL-2.0 or LGPL-2.1)
 *
 * lttng-capture-buffer.c
 *
 * Copyright (C) 2018 FSL Stony Brook University
 */

#include <lttng-capture-buffer.h>

static struct file *file_open(const char *path, int flags, int rights);
static int file_close(struct file *file);
static int file_sync(struct file *file);

struct file *log_file_fd;

bool start_buffer_capturing(void) {
	log_file_fd = file_open(LOG_PATH, O_CREAT | O_RDWR, 0777);
	if (log_file_fd == NULL) {
		printk(KERN_DEBUG "*** Can not open the log file\n");
		return false;
        } else {
		return true;
	}
}

bool end_buffer_capturing(void) {
	return file_sync(log_file_fd) && file_close(log_file_fd);;
}

static
struct file *file_open(const char *path, int flags, int rights) {
	struct file *filp = NULL;
	mm_segment_t oldfs;
	int err = 0;
	oldfs = get_fs();
	set_fs(get_ds());
	filp = filp_open(path, flags, rights);
	set_fs(oldfs);
	if (IS_ERR(filp)) {
		err = PTR_ERR(filp);
		return NULL;
	}
	return filp;
}

static
int file_close(struct file *file) {
	return filp_close(file, NULL);
}

static
int file_sync(struct file *file) {
	vfs_fsync(file, 0);
	return 0;
}
