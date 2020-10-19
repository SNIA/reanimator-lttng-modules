/* SPDX-License-Identifier: (GPL-2.0 or LGPL-2.1)
 *
 * lttng-context-cpu-id.c
 *
 * LTTng CPU id context.
 *
 * Copyright (c) 2019 Erez Zadok
 * Copyright (c) 2019 Ibrahim Umit Akgun */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <lttng-events.h>
#include <wrapper/ringbuffer/frontend_types.h>
#include <wrapper/vmalloc.h>
#include <lttng-tracer.h>
#include <lttng-capture-buffer.h>

static
size_t fsl_record_id_get_size(size_t offset)
{
	size_t size = 0;

	size += lib_ring_buffer_align(offset, lttng_alignof(long));
	size += sizeof(long);
	return size;
}

static
void fsl_record_id_record(struct lttng_ctx_field *field,
		struct lib_ring_buffer_ctx *ctx,
		struct lttng_channel *chan)
{
	long record_id;

        record_id = fsl_pid_record_id_lookup(current->pid);
	lib_ring_buffer_align_ctx(ctx, lttng_alignof(record_id));
	chan->ops->event_write(ctx, &record_id, sizeof(record_id));
}

static
void fsl_record_id_get_value(struct lttng_ctx_field *field,
		struct lttng_probe_ctx *lttng_probe_ctx,
		union lttng_ctx_value *value)
{
	value->s64 = fsl_pid_record_id_lookup(current->pid);
}

int lttng_add_fsl_record_id_to_ctx(struct lttng_ctx **ctx)
{
	struct lttng_ctx_field *field;

	field = lttng_append_context(ctx);
	if (!field)
		return -ENOMEM;
	if (lttng_find_context(*ctx, "fsl_record_id")) {
		lttng_remove_context_field(ctx, field);
		return -EEXIST;
	}
	field->event_field.name = "fsl_record_id";
	field->event_field.type.atype = atype_integer;
	field->event_field.type.u.basic.integer.size = sizeof(long) * CHAR_BIT;
	field->event_field.type.u.basic.integer.alignment = lttng_alignof(long) * CHAR_BIT;
	field->event_field.type.u.basic.integer.signedness = lttng_is_signed_type(long);
	field->event_field.type.u.basic.integer.reverse_byte_order = 0;
	field->event_field.type.u.basic.integer.base = 10;
	field->event_field.type.u.basic.integer.encoding = lttng_encode_none;
	field->get_size = fsl_record_id_get_size;
	field->record = fsl_record_id_record;
	field->get_value = fsl_record_id_get_value;
	lttng_context_update(*ctx);
	wrapper_vmalloc_sync_all();
	return 0;
}
EXPORT_SYMBOL_GPL(lttng_add_fsl_record_id_to_ctx);
