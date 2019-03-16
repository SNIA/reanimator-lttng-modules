/* SPDX-License-Identifier: (GPL-2.0 or LGPL-2.1)
 *
 * lttng-capture-buffer.c
 *
 * Copyright (C) 2018 FSL Stony Brook University
 */

#include <lttng-capture-buffer.h>
#include <fsl-lttng-syscall-handlers.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/spinlock_types.h>
#include <linux/vmalloc.h>
#include <linux/kernel.h>

#define SET_BUFFER_CAPTURE_SYSCALL_HANDLER(syscall, handler)                   \
	bitmap_set(fsl_syscall_buffer_map, syscall, 1);                        \
	syscall_buf_handlers[syscall] = &handler;

#define MAX_KMALLOC_SIZE 256 * 1024

static struct file *file_open(const char *path, int flags, int rights);
static int file_close(struct file *file);
static int file_sync(struct file *file);
static int file_write(struct file *file, const char *data, unsigned int size,
		      loff_t *offset);
static void initialize_syscall_buffer_map(void);

static bool buffer_capturing_online = false;
static struct file *log_file_fd;
static struct file *buffer_file_fd;
static loff_t log_file_offset = 0;
static loff_t buffer_file_offset = 0;
DEFINE_SPINLOCK(write_lock);

struct hlist_head pid_record_id[FSL_LTTNG_PID_TABLE_SIZE];

atomic64_t syscall_record_id = {0};
extern atomic64_t syscall_exit_buffer_cnt;

DECLARE_BITMAP(fsl_syscall_buffer_map, NR_syscalls);
syscall_buffer_handler syscall_buf_handlers[NR_syscalls];

bool start_buffer_capturing(void)
{
	log_file_fd = buffer_file_fd = NULL;

	log_file_fd = file_open(LOG_PATH, O_WRONLY | O_LARGEFILE, 0777);
	if (log_file_fd == NULL) {
		log_file_fd = file_open(LOG_PATH,
					O_CREAT | O_WRONLY | O_LARGEFILE, 0777);
	}
	if (log_file_fd == NULL) {
		printk(KERN_DEBUG
		       "fsl-ds-logging: Can not open the log file\n");
		return false;
	}

	buffer_file_fd = file_open(BUFFER_PATH, O_WRONLY | O_LARGEFILE, 0777);
	if (buffer_file_fd == NULL) {
		buffer_file_fd = file_open(
			BUFFER_PATH, O_CREAT | O_WRONLY | O_LARGEFILE, 0777);
		printk(KERN_DEBUG "fsl-ds-logging: created new buffer file");

	} else {
		printk(KERN_DEBUG "fsl-ds-logging: using existing buffer file");
	}

	if (buffer_file_fd == NULL) {
		printk(KERN_DEBUG
		       "fsl-ds-logging: Can not open the buffer file\n");
		return false;
	}

	initialize_syscall_buffer_map();

	buffer_capturing_online = true;

	printk(KERN_DEBUG
	       "fsl-ds-logging: fsl-tracepoint started buffer capturing\n");

	return true;
}

bool end_buffer_capturing(void)
{
	struct hlist_head *head;
	struct fsl_lttng_pid_hash_node *node;
	bool log_result = true, buffer_result = true;

	buffer_capturing_online = false;

	if (log_file_fd != NULL) {
		log_result &= file_sync(log_file_fd);
		if (!log_result) {
			printk(KERN_DEBUG
			       "fsl-ds-logging: file sync for logging failed");
		}
		file_end_write(log_file_fd);
		log_result &= file_close(log_file_fd);
		printk(KERN_DEBUG "fsl-ds-logging: log file closed with %s",
		       log_result ? "fail" : "success");
	} else {
		printk(KERN_DEBUG "fsl-ds-logging: logging fd is NULL");
	}

	if (buffer_file_fd != NULL) {
		buffer_result &= file_sync(buffer_file_fd);
		if (!buffer_result) {
			printk(KERN_DEBUG
			       "fsl-ds-logging: file sync for capturing buffer failed");
		}
		file_end_write(buffer_file_fd);
		buffer_result &= file_close(buffer_file_fd);
		printk(KERN_DEBUG "fsl-ds-logging: buffer file closed with %s",
		       buffer_result ? "fail" : "success");
	} else {
		printk(KERN_DEBUG "fsl-ds-logging: buffer fd is NULL");
	}

	printk(KERN_DEBUG "fsl-ds-logging: number of read syscalls %lld",
	       atomic64_read(&syscall_exit_buffer_cnt));

	log_file_offset = buffer_file_offset = 0;
	atomic64_set(&syscall_exit_buffer_cnt, 0);
	atomic64_set(&syscall_record_id, 0);
	head = &pid_record_id[0];
	lttng_hlist_for_each_entry(node, head, hlist)
	{
		node->record_id = 0;
	}

	printk(KERN_DEBUG
	       "fsl-ds-logging: fsl-tracepoint stopped buffer capturing\n");
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
	ret = file_write(log_file_fd, print_buffer, buffer_length,
			 &log_file_offset);

	if (ret < 0) {
		printk(KERN_ERR "fsl-ds-logging: failed while writing logs\n");
	}
}

void copy_user_buffer_to_file(void *user_buffer, unsigned long size)
{
	int ret = -1;
	long total_size = sizeof(struct buffer_header) + size;
	loff_t write_offset;
	struct buffer_header *kernel_buffer = NULL;
	bool virtual_kernel_memory_allocation = false;

	if (total_size <= MAX_KMALLOC_SIZE) {
		kernel_buffer =
			(struct buffer_header *)kmalloc(total_size, GFP_KERNEL);
		if (kernel_buffer == NULL) {
			kernel_buffer =
				(struct buffer_header *)vmalloc(total_size);
			virtual_kernel_memory_allocation = true;
		}
	} else {
		if (total_size >= MAX_KMALLOC_SIZE * 1024) {
			dump_stack();
			return;
		}
		kernel_buffer = (struct buffer_header *)vmalloc(total_size);
		virtual_kernel_memory_allocation = true;
	}

	if (buffer_file_fd == NULL || kernel_buffer == NULL
	    || buffer_capturing_online == false) {
		return;
	}

	atomic64_set(&(kernel_buffer->record_id),
		     fsl_pid_record_id_lookup(current->pid));
	kernel_buffer->sizeOfBuffer = size;
	if (copy_user_buffer(user_buffer, size,
			     (void *)&kernel_buffer->buffer)) {
		spin_lock(&write_lock);
		write_offset = buffer_file_offset;
		buffer_file_offset += total_size;
		spin_unlock(&write_lock);
		ret = file_write(buffer_file_fd, (void *)kernel_buffer,
				 total_size, &write_offset);
		if (ret < 0) {
			printk(KERN_ERR
			       "fsl-ds-logging: failed while writing captured buffers\n");
		}
	}
	if (!virtual_kernel_memory_allocation) {
		kfree(kernel_buffer);
	} else {
		vfree(kernel_buffer);
	}
}

void fsl_pid_record_id_map(int pid, long record_id)
{
	struct hlist_head *head;
	struct fsl_lttng_pid_hash_node *node;
	uint32_t hash = hash_32(pid, 32);

	head = &pid_record_id[hash & (FSL_LTTNG_PID_TABLE_SIZE - 1)];
	lttng_hlist_for_each_entry(node, head, hlist)
	{
		if (pid == node->pid) {
			node->record_id = record_id;
			return;
		}
	}
	node = kmalloc(sizeof(struct fsl_lttng_pid_hash_node), GFP_KERNEL);
	if (!node)
		return;
	node->pid = pid;
	node->record_id = record_id;
	hlist_add_head_rcu(&node->hlist, head);
}

void fsl_syscall_buffer_handler(long syscall_no, fsl_event_type event,
				unsigned long *args, unsigned int nr_args)
{
	if (event == syscall_buffer_compat) {
		return;
	}
	if (test_bit(syscall_no, fsl_syscall_buffer_map)
	    && fsl_pid_record_id_lookup(current->pid) != -1) {
		syscall_buffer_handler handler =
			syscall_buf_handlers[syscall_no];
		handler(event, args, nr_args);
	}
}

long fsl_pid_record_id_lookup(int pid)
{
	struct hlist_head *head;
	struct fsl_lttng_pid_hash_node *node;
	uint32_t hash = hash_32(pid, 32);

	head = &pid_record_id[hash & (FSL_LTTNG_PID_TABLE_SIZE - 1)];
	lttng_hlist_for_each_entry(node, head, hlist)
	{
		if (pid == node->pid) {
			return node->record_id;
		}
	}
	return -1;
}

bool copy_user_buffer(void *user_addr, unsigned long size, void *copy_buffer)
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

	ret = __copy_from_user_inatomic(
		copy_buffer, (__force const char __user *)(user_addr), size);
	if (ret < 0) {
		printk(KERN_ERR
		       "fsl-ds-logging: failed while copying user buffers\n");
	}

	pagefault_enable();
	set_fs(old_fs);

	return true;
}

static void initialize_syscall_buffer_map(void)
{
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_read, read_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_write, write_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_fstat,
					   stat_family_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_stat,
					   stat_family_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_lstat,
					   stat_family_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_pread64, read_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_pwrite64,
					   write_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_statfs,
					   statfs_family_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_fstatfs,
					   statfs_family_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_readlink,
					   readlink_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_utime, utime_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_utimes, utimes_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_utimensat,
					   utimensat_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_newfstatat,
					   newfstatat_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_pipe, pipe_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_pipe2, pipe_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_fcntl, fcntl_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_getdents,
					   getdents_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_setrlimit,
					   setrlimit_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_getrlimit,
					   getrlimit_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_setxattr,
					   xattr_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_lsetxattr,
					   xattr_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_getxattr,
					   xattr_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_lgetxattr,
					   xattr_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_fsetxattr,
					   xattr_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_fgetxattr,
					   xattr_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_listxattr,
					   listxattr_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_llistxattr,
					   listxattr_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_flistxattr,
					   listxattr_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_connect,
					   connect_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_bind, bind_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_socketpair,
					   socketpair_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_setsockopt,
					   socketopt_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_getsockopt,
					   getsocketopt_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_recvfrom,
					   recvfrom_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_recvmsg,
					   send_recv_msg_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_sendmsg,
					   send_recv_msg_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_sendto, sendto_syscall_handler);
	SET_BUFFER_CAPTURE_SYSCALL_HANDLER(__NR_ioctl, ioctl_syscall_handler);
}

static struct file *file_open(const char *path, int flags, int rights)
{
	struct file *filp = NULL;
	struct kstat stat;
	mm_segment_t oldfs;
	int err = 0;
	oldfs = get_fs();
	set_fs(get_ds());
	filp = filp_open(path, flags, rights);
	vfs_stat(BUFFER_PATH, &stat);
	set_fs(oldfs);
	if (IS_ERR(filp)) {
		err = PTR_ERR(filp);
		return NULL;
	}
	return filp;
}

static int file_close(struct file *file)
{
	int result = 0;
	mm_segment_t oldfs;
	oldfs = get_fs();
	set_fs(get_ds());
	result = filp_close(file, NULL);
	set_fs(oldfs);
	return result;
}

static int file_write(struct file *file, const char *data, unsigned int size,
		      loff_t *offset)
{
	mm_segment_t oldfs;
	int ret;
	oldfs = get_fs();
	set_fs(get_ds());
	if (file == NULL || data == NULL || size == 0 || offset == NULL) {
		set_fs(oldfs);
		return EBADFD;
	}
	ret = vfs_write(file, data, size, offset);
	set_fs(oldfs);
	return ret;
}

static int file_sync(struct file *file)
{
	int bytes_not_synced = 0;
	mm_segment_t oldfs;
	oldfs = get_fs();
	set_fs(get_ds());
	bytes_not_synced = vfs_fsync(file, 0);
	set_fs(oldfs);
	return bytes_not_synced == 0;
}
