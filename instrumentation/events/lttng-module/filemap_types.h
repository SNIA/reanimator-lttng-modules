// Copyright FSL Stony Brook

#ifndef FILEMAP_TYPES
#define FILEMAP_TYPES

#include <linux/list.h>
#include <linux/fs.h>

extern struct hlist_head inode_hash[1024];
extern struct hlist_head file_hash[1024];

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

#endif
