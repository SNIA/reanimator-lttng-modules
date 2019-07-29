// Copyright FSL Stony Brook

#ifndef FILEMAP_TYPES
#define FILEMAP_TYPES

extern struct hlist_head inode_hash[1024];

struct lttng_inode_hash_node {
	struct hlist_node hlist;
	unsigned long ino;
	unsigned long min;
	unsigned long max;
};

#endif
