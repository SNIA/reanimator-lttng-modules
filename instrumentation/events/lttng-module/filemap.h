/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM filemap

#if !defined(LTTNG_TRACE_FILEMAP_H) || defined(TRACE_HEADER_MULTI_READ)
#define LTTNG_TRACE_FILEMAP_H

#include <probes/lttng-tracepoint-event.h>
#include <linux/types.h>
#include <linux/tracepoint.h>
#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <linux/device.h>
#include <linux/kdev_t.h>
#include <linux/errseq.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/hash.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <wrapper/rcu.h>
#include <wrapper/list.h>
#include "filemap_types.h"

// #define MMAP_DEBUGGING

LTTNG_TRACEPOINT_EVENT_CLASS_CODE(mm_filemap_op_page_cache,

	TP_PROTO(struct page *page),

	TP_ARGS(page),

	TP_locvar(
            uint64_t hash;
            struct hlist_head *head;
            struct fsl_file_hash_node *f_node;
            struct lttng_inode_hash_node *e;
            struct lttng_page_list *newpage;
            struct file *file;
            char path[256];
            char *filepath;
            void *page_cached_addr;
            bool new_one;
	),

	TP_code_pre(
                tp_locvar->new_one = false;
                tp_locvar->page_cached_addr = page_address(page);
                tp_locvar->hash = hash_64(page->mapping->host->i_ino, 64);
		tp_locvar->head = &inode_hash[tp_locvar->hash & 1023];
		lttng_hlist_for_each_entry(tp_locvar->e, tp_locvar->head, hlist)
		{
			if (page->mapping->host->i_ino == tp_locvar->e->ino) {
                          tp_locvar->e->min = min(page->index, tp_locvar->e->min);
                          tp_locvar->e->max = max(page->index, tp_locvar->e->max);
                          tp_locvar->newpage = kmalloc(sizeof(struct lttng_page_list), GFP_KERNEL);
                          tp_locvar->newpage->addr = tp_locvar->page_cached_addr;
                          #ifdef MMAP_DEBUGGING
                          printk("fsl-ds-logging: newly added addr %p and index %lu ino %ld", tp_locvar->newpage->addr,
                                 page->index, page->mapping->host->i_ino);
                          #endif
                          list_add(&tp_locvar->newpage->list, &tp_locvar->e->list.list);
                          tp_locvar->new_one = true;
			}
		}
                if (!tp_locvar->new_one) {
                  tp_locvar->e = kmalloc(sizeof(struct lttng_inode_hash_node), GFP_KERNEL);
                  if (tp_locvar->e) {
                    tp_locvar->e->ino = page->mapping->host->i_ino;
                    tp_locvar->e->min = page->index;
                    tp_locvar->e->max = page->index;
                    INIT_LIST_HEAD(&tp_locvar->e->list.list);
                    tp_locvar->e->list.addr = tp_locvar->page_cached_addr;
                    tp_locvar->newpage = kmalloc(sizeof(struct lttng_page_list), GFP_KERNEL);
                    tp_locvar->newpage->addr = tp_locvar->page_cached_addr;
                    #ifdef MMAP_DEBUGGING
                    printk("fsl-ds-logging: newly added addr %p and index %lu ino %ld", tp_locvar->newpage->addr,
                           page->index, page->mapping->host->i_ino);
                    #endif
                    list_add(&tp_locvar->newpage->list, &tp_locvar->e->list.list);
                    #ifdef MMAP_DEBUGGING
                    if (page->mapping->host)
                      printk("fsl-ds-logging: first newly added addr %p and index %lu ino %ld", tp_locvar->page_cached_addr,
                             page->index, page->mapping->host->i_ino);
                    #endif
                    hlist_add_head_rcu(&tp_locvar->e->hlist, tp_locvar->head);
                  } else {
                    printk("fsl-ds-logging: not enough memory add to page cache");
                  }
                }

                tp_locvar->file = NULL;
                if (file_hash != NULL) {
                  tp_locvar->hash = hash_64(page->mapping->host->i_ino, 64);
                  tp_locvar->head = &file_hash[tp_locvar->hash & 1023];
                  hlist_for_each_entry(tp_locvar->f_node, tp_locvar->head, hlist) {
                    if (tp_locvar->f_node->ino == page->mapping->host->i_ino) {
                      tp_locvar->file = tp_locvar->f_node->f;
                      printk("fnode %ld %p", tp_locvar->f_node->ino, tp_locvar->f_node->f);
                    }
                  }

                  if (tp_locvar->file != NULL) {
                    // tp_locvar->filepath = dentry_path_raw(tp_locvar->file->f_path.dentry, tp_locvar->path, 256);
                    printk("file path: %ld %p", page->mapping->host->i_ino, tp_locvar->file);
                  }
                }
	),
        
	TP_FIELDS(
		ctf_integer(unsigned long, pfn, page_to_pfn(page))
		ctf_integer(unsigned long, i_ino, page->mapping->host->i_ino)
		ctf_integer(unsigned long, index, page->index)
                // ctf_string(filepath, tp_locvar->file ? tp_locvar->filepath : "")
		ctf_integer(dev_t, s_dev, page->mapping->host->i_sb
					    ? page->mapping->host->i_sb->s_dev
					    : page->mapping->host->i_rdev)
                  ),

        TP_code_post()
)

LTTNG_TRACEPOINT_EVENT_CLASS_CODE(mm_filemap_op_fsl,

	TP_PROTO(struct page *page, struct file* file, int origin, unsigned long address),

	TP_ARGS(page, file, origin, address),

	TP_locvar(
            struct files_struct *files;
            uint64_t index;
            struct fdtable *fdtable;
            int fdtable_counter;
            bool fd_found;
            void *page_cached_addr;
            uint64_t hash;
            struct hlist_head *head;
            struct lttng_inode_hash_node *e;
            struct list_head *cursor;
            struct lttng_page_list *entry;
            int idx;
            int number_of_pages;
            char *buffer;
            char path[256];
            char *filepath;
            int min, max;
	),

	TP_code_pre(
            tp_locvar->page_cached_addr = page_address(page);
            tp_locvar->index = page->index;
            tp_locvar->files = current->files;
            tp_locvar->fdtable = files_fdtable(tp_locvar->files);
            tp_locvar->fdtable_counter = 0;
            tp_locvar->fd_found = 0;
            tp_locvar->number_of_pages = 0;
            tp_locvar->buffer = NULL;
            tp_locvar->filepath = dentry_path_raw(file->f_path.dentry, tp_locvar->path, 256);
            while(tp_locvar->fdtable->fd[tp_locvar->fdtable_counter] != NULL) {
              if (tp_locvar->fdtable->fd[tp_locvar->fdtable_counter] == file) {
                tp_locvar->fd_found = 1;
                break;
              }
              tp_locvar->fdtable_counter++;
            }
            if (tp_locvar->fd_found == 0 || strstr(tp_locvar->filepath, ".so")) {
              tp_locvar->fdtable_counter = -1;
            }
            tp_locvar->hash = hash_64(page->mapping->host->i_ino, 64);
	    tp_locvar->head = &inode_hash[tp_locvar->hash & 1023];
            #ifdef MMAP_DEBUGGING
            printk("fsl-ds-logging: fsl read addr %p and fd %d", tp_locvar->page_cached_addr, tp_locvar->fdtable_counter);
            printk("file path: %s", tp_locvar->filepath);
            #endif
            lttng_hlist_for_each_entry(tp_locvar->e, tp_locvar->head, hlist)
            {
              if (page->mapping->host->i_ino == tp_locvar->e->ino) {
                if (tp_locvar->e->min == INT_MAX)
                  continue;
                #ifdef MMAP_DEBUGGING
                printk("fsl-ds-logging: min page index %ld max page index %ld reason %d",
                       tp_locvar->e->min, tp_locvar->e->max, origin);
                #endif
                tp_locvar->number_of_pages = tp_locvar->e->max - tp_locvar->e->min + 1;
                tp_locvar->e->min = INT_MAX;
                tp_locvar->e->max = 0;
              }
            }
	),

	TP_FIELDS(
		ctf_integer(unsigned long, pfn, page_to_pfn(page))
		ctf_integer(unsigned long, i_ino, page->mapping->host->i_ino)
		ctf_integer(unsigned long, index, tp_locvar->index)
		ctf_integer(unsigned long, org_index, page->index)
                ctf_integer(unsigned long, addr, address)
                ctf_integer(long, fd, tp_locvar->fdtable_counter)
                ctf_string(filepath, tp_locvar->filepath)
                ctf_integer(int, reason, origin)
                ctf_integer(int, min, tp_locvar->number_of_pages)
                ctf_integer(int, max, tp_locvar->number_of_pages)
                ctf_integer(dev_t, s_dev, page->mapping->host->i_sb
					    ? page->mapping->host->i_sb->s_dev
					    : page->mapping->host->i_rdev)
                  ),

	TP_code_post()

)


LTTNG_TRACEPOINT_EVENT_INSTANCE(mm_filemap_op_page_cache,
				mm_filemap_delete_from_page_cache,
				TP_PROTO(struct page *page),
				TP_ARGS(page)
)

LTTNG_TRACEPOINT_EVENT_INSTANCE(mm_filemap_op_page_cache,
				mm_filemap_add_to_page_cache,
				TP_PROTO(struct page *page),
				TP_ARGS(page)
)

LTTNG_TRACEPOINT_EVENT_INSTANCE(mm_filemap_op_fsl,
				mm_filemap_fsl_read,
				TP_PROTO(struct page *page, struct file* file, int origin, unsigned long address),
				TP_ARGS(page, file, origin, address)
)

LTTNG_TRACEPOINT_EVENT(
	filemap_set_wb_err,
	TP_PROTO(struct address_space *mapping, errseq_t eseq),

	TP_ARGS(mapping, eseq),

	TP_FIELDS(
		ctf_integer(unsigned long, i_no, mapping->host->i_ino)
		ctf_integer(errseq_t, errseq, eseq)
		ctf_integer(dev_t, s_dev, mapping->host->i_sb
					      ? mapping->host->i_sb->s_dev
					      : mapping->host->i_rdev)
                  )
)

LTTNG_TRACEPOINT_EVENT(
	file_check_and_advance_wb_err,
	TP_PROTO(struct file *file, errseq_t old),

	TP_ARGS(file, old),

	TP_FIELDS(
		ctf_integer(errseq_t, old, old)
		ctf_integer(errseq_t, new, file->f_wb_err)
		ctf_integer(unsigned long, i_no, file->f_mapping->host->i_ino)
		ctf_integer(struct file *, file, file)
		ctf_integer(dev_t, s_dev, file->f_mapping->host->i_sb
					  ? file->f_mapping->host->i_sb->s_dev
					  : file->f_mapping->host->i_rdev)
                  )
)

#endif /* LTTNG_TRACE_FILEMAP_H */

/* This part must be outside protection */
#include <probes/define_trace.h>
