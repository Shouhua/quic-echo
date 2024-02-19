#ifndef STREAM_H
#define STREAM_H

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include "list.h"

struct _Stream
{
	int64_t id;
	struct list_head buffer; // data list
	size_t sent_offset;
	size_t acked_offset;

	struct list_head link; // 用于connection中的streams
};

typedef struct _Stream Stream;
typedef struct _Stream_Data Stream_Data;

Stream *stream_new(int64_t stream_id);
void stream_free_list(struct list_head *streams);
void stream_free(Stream *s);
struct list_head *stream_get_link(Stream *s);
int64_t stream_get_id(Stream *s);
Stream *stream_get_by_id(struct list_head *streams, int64_t stream_id);
int stream_push_data(Stream *s, uint8_t *data, size_t data_size);
uint8_t *stream_peek_data(Stream *s, size_t *data_size);
void stream_mark_sent(Stream *s, size_t offset);
void stream_mark_acked(Stream *s, size_t offset);

#endif