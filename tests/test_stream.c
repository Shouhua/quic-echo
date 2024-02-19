#include <stdio.h>
#include <string.h>

#include "../stream.h"
#include "../list.h"

int main(int argc, char *argv[])
{
	(void)(argc);
	(void)(argv);

	char *foo = "foo";
	size_t foolen = strlen(foo);
	char *bar = "bare";
	size_t barlen = strlen(bar);

	Stream *stream0 = stream_new(0);
	stream_push_data(stream0, (uint8_t *)foo, foolen);
	stream_push_data(stream0, (uint8_t *)bar, barlen);

	uint8_t *data1;
	size_t data1_len;
	data1 = stream_peek_data(stream0, &data1_len);
	fprintf(stdout, "data: %s, size: %ld\n", data1, data1_len);
	stream_mark_sent(stream0, data1_len);
	stream_mark_acked(stream0, data1_len);
	data1 = stream_peek_data(stream0, &data1_len);
	fprintf(stdout, "data: %s, size: %ld\n", data1, data1_len);

	stream_free(stream0);
}