#include "stream.h"

struct _Stream_Data
{
	uint8_t *data;
	size_t data_size;
	struct list_head link;
};

Stream *stream_new(int64_t stream_id)
{
	Stream *s = (Stream *)malloc(sizeof(Stream));
	s->id = stream_id;
	init_list_head(&s->buffer);
	init_list_head(&s->link);
	s->sent_offset = 0;
	s->acked_offset = 0;

	return s;
}

void stream_free(Stream *s)
{
	if (!s)
		return;

	struct list_head *el, *el1;
	list_for_each_safe(el, el1, &s->buffer)
	{
		Stream_Data *sd = list_entry(el, Stream_Data, link);
		list_del(el);
		free(sd->data);
		free(sd);
	}
	free(s);
}

void stream_free_list(struct list_head *streams)
{
	if (!streams)
		return;
	struct list_head *el, *el1;
	list_for_each_safe(el, el1, streams)
	{
		list_del(el);
		Stream *stream = list_entry(el, Stream, link);
		if (stream)
			stream_free(stream);
	}
}

struct list_head *stream_get_link(Stream *s)
{
	return &s->link;
}

int64_t stream_get_id(Stream *s)
{
	return s->id;
}

int stream_push_data(Stream *s, uint8_t *data, size_t data_size)
{
	Stream_Data *sd = (Stream_Data *)malloc(sizeof(Stream_Data));
	sd->data = data;
	sd->data_size = data_size;
	init_list_head(&sd->link);
	list_add_tail(&sd->link, &s->buffer);
	return 0;
}

Stream *stream_get_by_id(struct list_head *streams, int64_t stream_id)
{
	struct list_head *el, *el1;
	list_for_each_safe(el, el1, streams)
	{
		Stream *stream = list_entry(el, Stream, link);
		if (stream_get_id(stream) == stream_id)
			return stream;
	}
	return NULL;
}

uint8_t *stream_peek_data(Stream *s, size_t *data_size)
{
	size_t start_offset = s->sent_offset - s->acked_offset;
	size_t offset = 0;

	struct list_head *el, *el1;
	list_for_each_safe(el, el1, &s->buffer)
	{
		Stream_Data *sd = list_entry(el, Stream_Data, link);
		if (start_offset - offset < sd->data_size)
		{
			*data_size = sd->data_size - (start_offset - offset);
			return sd->data + (start_offset - offset);
		}
		offset += sd->data_size;
	}
	*data_size = 0;
	return NULL;
}

void stream_mark_sent(Stream *s, size_t offset)
{
	s->sent_offset += offset;
}

void stream_mark_acked(Stream *s, size_t offset)
{
	struct list_head *el, *el1;
	list_for_each_safe(el, el1, &s->buffer)
	{
		Stream_Data *sd = list_entry(el, Stream_Data, link);
		if (s->acked_offset + sd->data_size > offset)
			break;
		s->acked_offset += sd->data_size;
		list_del(el);
		free(sd);
	}
}