// Copyright FSL Stony Brook

#ifndef FILEMAP_TYPES
#define FILEMAP_TYPES

#include <linux/list.h>
#include <linux/fs.h>
#include <linux/spinlock_types.h>

extern struct hlist_head inode_hash[1024];
extern struct hlist_head file_hash[1024];
extern spinlock_t inode_hash_lock;

struct lttng_page_list {
	void *addr;
	struct list_head list;
};

struct lttng_inode_hash_node {
	struct hlist_node hlist;
	unsigned long ino;
	unsigned long min;
	unsigned long max;
	struct lttng_page_list list;
};

struct fsl_file_hash_node {
	struct hlist_node hlist;
	char path[256];
	char *filepath;
	unsigned int ra_pages;
	unsigned long ino;
};

#endif
