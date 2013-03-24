#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H

#include <string.h>

enum HTTP_METHOD {
    HTTP_GET = 0,
    HTTP_PUT,
    HTTP_POST,
    HTTP_METHOD_COUNT
};

enum HTTP_STATUS {
    HTTP_STATUS_OK = 200
};

typedef struct http_header_field {
    char *name;
	char *value;
	int  valid;
} http_header_field_t;

typedef struct http_request {
	int method;
    char *path;
    char *params;
	size_t field_count;
	http_header_field_t *fields;
} http_request_t;


typedef struct http_parser {
    const char *data;
    size_t len;

    http_request_t req;

    char *parse_ptr;
} http_parser_t;


void http_parser_init(http_parser_t *parser);
http_request_t *parse_http_request(http_parser_t *parser, const char *data, size_t len);
void http_parser_free(http_parser_t *parser);

#endif

/* vim: set ts=4 sw=4 tw=80 et :*/
