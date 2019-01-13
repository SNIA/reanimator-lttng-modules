/* SPDX-License-Identifier: (GPL-2.0 or LGPL-2.1)
 *
 * lttng-capture-buffer.c
 *
 * Copyright (C) 2018 FSL Stony Brook University
 */

#include <linux/fs.h>
#include <asm/segment.h>
#include <linux/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <lttng-capture-buffer.h>

static struct file *file_open(const char *path, int flags, int rights);
static int file_close(struct file *file);
static int file_sync(struct file *file);
static int file_write(struct file *file, const char *data, unsigned int size,
		      loff_t *offset);
static bool copy_user_buffer(void *user_addr, unsigned long size,
			     void *copy_buffer);

static struct file *log_file_fd;
static struct file *buffer_file_fd;
static loff_t log_file_offset = 0;
static loff_t buffer_file_offset = 0;

struct buffer_header {
	atomic64_t record_id;
	size_t sizeOfBuffer;
	char buffer[0];
};

extern atomic64_t syscall_exit_buffer_cnt;

bool start_buffer_capturing(void)
{
	log_file_fd =
		file_open(LOG_PATH, O_CREAT | O_WRONLY | O_LARGEFILE, 0777);
	if (log_file_fd == NULL) {
		printk(KERN_DEBUG
		       "fsl-ds-logging: Can not open the log file\n");
		return false;
	}

	buffer_file_fd =
		file_open(BUFFER_PATH, O_CREAT | O_WRONLY | O_LARGEFILE, 0777);
	if (buffer_file_fd == NULL) {
		printk(KERN_DEBUG
		       "fsl-ds-logging: Can not open the buffer file\n");
		return false;
	}

	return true;
}

bool sync_buffers(void)
{
	bool log_result = true, buffer_result = true;
	if (log_file_fd != NULL) {
		log_result &= file_sync(log_file_fd);
		if (!log_result) {
			printk(KERN_DEBUG
			       "fsl-ds-logging: file sync for logging failed");
		}
	} else {
		printk(KERN_DEBUG "fsl-ds-logging: logging fd is NULL");
	}

	if (buffer_file_fd != NULL) {
		buffer_result &= file_sync(buffer_file_fd);
		if (!log_result) {
			printk(KERN_DEBUG
			       "fsl-ds-logging: file sync for capturing buffer failed");
		}
	} else {
		printk(KERN_DEBUG "fsl-ds-logging: buffer fd is NULL");
	}

	printk(KERN_DEBUG "fsl-ds-logging: number of read syscalls %ld",
	       atomic64_read(&syscall_exit_buffer_cnt));

	return buffer_result && log_result;
}

bool end_buffer_capturing(void)
{
	bool log_result = true, buffer_result = true;
	if (log_file_fd != NULL) {
		log_result &= file_sync(log_file_fd);
		if (!log_result) {
			printk(KERN_DEBUG
			       "fsl-ds-logging: file sync for logging failed");
		}
		log_result &= file_close(log_file_fd);
		printk(KERN_DEBUG "fsl-ds-logging: log file closed with %s",
		       log_result ? "fail" : "success");
	} else {
		printk(KERN_DEBUG "fsl-ds-logging: logging fd is NULL");
	}

	if (buffer_file_fd != NULL) {
		buffer_result &= file_sync(buffer_file_fd);
		if (!log_result) {
			printk(KERN_DEBUG
			       "fsl-ds-logging: file sync for capturing buffer failed");
		}
		buffer_result &= file_close(buffer_file_fd);
		printk(KERN_DEBUG "fsl-ds-logging: log file closed with %s",
		       log_result ? "fail" : "success");
	} else {
		printk(KERN_DEBUG "fsl-ds-logging: buffer fd is NULL");
	}

	return buffer_result && log_result;
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

	if (log_file_fd == NULL) {
		return;
	}

	snprintf(print_buffer, print_len, "%ld ", syscall_no);

	for (arg_idx = 0; arg_idx < nr_args; arg_idx++) {
		snprintf(arg_buffer, arg_len, "%ld ", args[arg_idx]);
		strcat(print_buffer, arg_buffer);
	}
	strcat(print_buffer, "\n");

	buffer_length = strlen(print_buffer);
	do {
		ret = file_write(log_file_fd, print_buffer, buffer_length,
				 &log_file_offset);
	} while (ret < 0);
}

void copy_user_buffer_to_file(atomic64_t *record_id, atomic64_t *read_cnt,
			      void *user_buffer, unsigned long size)
{
	long total_size = sizeof(struct buffer_header) + size;
	struct buffer_header *kernel_buffer = (struct buffer_header *)kcalloc(
		total_size, sizeof(char), GFP_KERNEL);

	if (buffer_file_fd == NULL || kernel_buffer == NULL) {
		return;
	}

	kernel_buffer->record_id = *record_id;
	kernel_buffer->sizeOfBuffer = size;
	if (copy_user_buffer(user_buffer, size,
			     (void *)&kernel_buffer->buffer)) {
		file_write(buffer_file_fd, (void *)kernel_buffer, total_size,
			   &buffer_file_offset);
	}
	kfree(kernel_buffer);
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

static bool copy_user_buffer(void *user_addr, unsigned long size,
			     void *copy_buffer)
{
	mm_segment_t old_fs;
	unsigned long ret;

	if (user_addr == NULL || copy_buffer == NULL) {
		printk(KERN_DEBUG
		       "fsl-ds-logging: could not get user addresses correctly");
		return false;
	}

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	pagefault_disable();

	if (unlikely(!access_ok(VERIFY_READ,
				(__force const char __user *)user_addr,
				size))) {
		printk(KERN_DEBUG
		       "fsl-ds-logging: user buffer is not readable");
		return false;
	}

	do {
		ret = __copy_from_user_inatomic(
			copy_buffer, (__force const char __user *)(user_addr),
			size);
	} while (ret != 0);

	pagefault_enable();
	set_fs(old_fs);

	return true;
}

static int file_write(struct file *file, const char *data, unsigned int size,
		      loff_t *offset)
{
	mm_segment_t oldfs;
	int ret;
	oldfs = get_fs();
	set_fs(get_ds());
	ret = vfs_write(file, data, size, offset);
	set_fs(oldfs);
	return ret;
}


static int file_close(struct file *file)
{
	return filp_close(file, NULL);
}

static int file_sync(struct file *file)
{
	int bytes_not_synced = vfs_fsync(file, 0);
	return bytes_not_synced == 0;
}
