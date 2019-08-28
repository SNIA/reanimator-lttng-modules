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
#include <wrapper/rcu.h>
#include <wrapper/list.h>
#include "filemap_types.h"

LTTNG_TRACEPOINT_EVENT_CLASS_CODE(
	mm_filemap_op_page_cache,

	TP_PROTO(struct page *page),

	TP_ARGS(page),

	TP_locvar(
            uint64_t hash;
            struct hlist_head *head;
            struct lttng_inode_hash_node *e;
            struct lttng_page_list *newpage;
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
                          printk("fsl-ds-logging: newly added addr %p and index %lu ino %ld", tp_locvar->newpage->addr,
                                 page->index, page->mapping->host->i_ino);
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
                    if (page->mapping->host)
                      printk("fsl-ds-logging: first newly added addr %p and index %lu ino %ld", tp_locvar->page_cached_addr,
                             page->index, page->mapping->host->i_ino);
                    hlist_add_head_rcu(&tp_locvar->e->hlist, tp_locvar->head);
                  } else {
                    printk("fsl-ds-logging: not enough memory add to page cache");
                  }
                }
	),
        
	TP_FIELDS(
		ctf_integer(unsigned long, pfn, page_to_pfn(page))
		ctf_integer(unsigned long, i_ino, page->mapping->host->i_ino)
		ctf_integer(unsigned long, index, page->index)
		ctf_integer(dev_t, s_dev, page->mapping->host->i_sb
					    ? page->mapping->host->i_sb->s_dev
					    : page->mapping->host->i_rdev)
                  ),

        TP_code_post()
)

LTTNG_TRACEPOINT_EVENT_CLASS_CODE(
	mm_filemap_op_fsl,

	TP_PROTO(struct page *page, struct file* file),

	TP_ARGS(page, file),

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
            while(tp_locvar->fdtable->fd[tp_locvar->fdtable_counter] != NULL) {
              if (tp_locvar->fdtable->fd[tp_locvar->fdtable_counter] == file) {
                tp_locvar->fd_found = 1;
                break;
              }
              tp_locvar->fdtable_counter++;
            }
            if (tp_locvar->fd_found == 0) {
              tp_locvar->fdtable_counter = -1;
            }
            tp_locvar->hash = hash_64(page->mapping->host->i_ino, 64);
	    tp_locvar->head = &inode_hash[tp_locvar->hash & 1023];
            printk("fsl-ds-logging: fsl read addr %p and fd %d", tp_locvar->page_cached_addr, tp_locvar->fdtable_counter);

            lttng_hlist_for_each_entry(tp_locvar->e, tp_locvar->head, hlist)
            {
              if (page->mapping->host->i_ino == tp_locvar->e->ino) {
                if (tp_locvar->e->min == INT_MAX)
                  continue;
                printk("fsl-ds-logging: min page index %ld max page index %ld",
                       tp_locvar->e->min, tp_locvar->e->max);
                tp_locvar->number_of_pages = tp_locvar->e->max - tp_locvar->e->min + 1;
                tp_locvar->buffer = kmalloc(tp_locvar->number_of_pages * PAGE_SIZE, GFP_KERNEL);
                tp_locvar->idx = 0;
                
                if (tp_locvar->number_of_pages > 1) {
                  list_for_each_prev(tp_locvar->cursor, &tp_locvar->e->list.list) {
                    tp_locvar->entry = list_entry(tp_locvar->cursor, struct lttng_page_list, list);
                    printk("fsl-ds-logging: page addr %p", tp_locvar->entry->addr);
                    memcpy(tp_locvar->buffer + (PAGE_SIZE * tp_locvar->idx), tp_locvar->entry->addr, PAGE_SIZE);
                    tp_locvar->idx++;
                  }
                } else {
                  memcpy(tp_locvar->buffer, tp_locvar->e->list.addr, PAGE_SIZE);
                }
                tp_locvar->index = (tp_locvar->e->min < tp_locvar->index) ? tp_locvar->e->min : tp_locvar->index;
             delete_all:
                list_for_each(tp_locvar->cursor, &tp_locvar->e->list.list) {
                  tp_locvar->entry = list_entry(tp_locvar->cursor, struct lttng_page_list, list);
                  list_del(&tp_locvar->entry->list);
                  kfree(tp_locvar->entry);
                  if (tp_locvar->number_of_pages == 1)
                    break;
                  goto delete_all;
                }
                
                tp_locvar->e->min = INT_MAX;
                tp_locvar->e->max = 0;
              }
            }

            if (tp_locvar->number_of_pages > 0) {
              printk("fsl-ds-logging: #pages %d", tp_locvar->number_of_pages);
              copy_kernel_buffer_to_file(tp_locvar->buffer, tp_locvar->number_of_pages * PAGE_SIZE);
              kfree(tp_locvar->buffer);
            }
            printk("fsl-ds-logging: #pages %d handled", tp_locvar->number_of_pages);
	),

	TP_FIELDS(
		ctf_integer(unsigned long, pfn, page_to_pfn(page))
		ctf_integer(unsigned long, i_ino, page->mapping->host->i_ino)
		ctf_integer(unsigned long, index, tp_locvar->index)
                ctf_integer(long, fd, tp_locvar->fdtable_counter)
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
				TP_PROTO(struct page *page, struct file* file),
				TP_ARGS(page, file)
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
