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
static int file_write(struct file *file, unsigned char *data,
		      unsigned int size);

static struct file *log_file_fd;
static loff_t log_file_offset = 0;

bool start_buffer_capturing(void)
{
	log_file_fd = file_open(LOG_PATH, O_CREAT | O_RDWR, 0777);
	if (log_file_fd == NULL) {
		printk(KERN_DEBUG
		       "fsl-ds-logging: Can not open the log file\n");
		return false;
	} else {
		return true;
	}
}

bool end_buffer_capturing(void)
{
	return file_sync(log_file_fd) && file_close(log_file_fd);
}

void log_syscall_args(long syscall_no, unsigned long *args,
		      unsigned int nr_args)
{
	int print_len = 200, arg_len = 50;
	char print_buffer[200] = {0};
	char arg_buffer[50] = {0};
	int arg_idx;
	int ret = -1;
	int buffer_length = 0;

	snprintf(print_buffer, print_len, "%ld ", syscall_no);

	for (arg_idx = 0; arg_idx < nr_args; arg_idx++) {
		snprintf(arg_buffer, arg_len, "%ld ", args[arg_idx]);
		strcat(print_buffer, arg_buffer);
	}
	strcat(print_buffer, "\n");

	buffer_length = strlen(print_buffer);
	do {
		ret = file_write(log_file_fd, print_buffer, buffer_length);
	} while (ret < 0);
}

static struct file *file_open(const char *path, int flags, int rights)
{
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

static int file_write(struct file *file, unsigned char *data, unsigned int size)
{
	mm_segment_t oldfs;
	int ret;
	oldfs = get_fs();
	set_fs(get_ds());
	ret = vfs_write(file, data, size, &log_file_offset);
	set_fs(oldfs);
	return ret;
}


static int file_close(struct file *file)
{
	return filp_close(file, NULL);
}

static int file_sync(struct file *file)
{
	vfs_fsync(file, 0);
	return 0;
}
