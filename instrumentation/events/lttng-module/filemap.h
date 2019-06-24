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

LTTNG_TRACEPOINT_EVENT_CLASS(
	mm_filemap_op_page_cache,

	TP_PROTO(struct page *page),

	TP_ARGS(page),

	TP_FIELDS(
		ctf_integer(unsigned long, pfn, page_to_pfn(page))
		ctf_integer(unsigned long, i_ino, page->mapping->host->i_ino)
		ctf_integer(unsigned long, index, page->index)
		ctf_integer(dev_t, s_dev, page->mapping->host->i_sb
					    ? page->mapping->host->i_sb->s_dev
					    : page->mapping->host->i_rdev)
                  )
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
