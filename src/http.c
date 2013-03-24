#include "http.h"
#include "util.h"

#include <ctype.h>
#include <stdlib.h>
#include <bsd/string.h>

#define PATH_LEN 1024

static const char separator[] = "()<>@,;:\\\"/[]?={} \t";
static const char *method_names[] = {
    "GET",
    "PUT",
    "POST"
};

static int is_ctl(char c)
{
    return ((int)c >= 0 && (int)c <= 31)  || (int)c == 127;
}

static int is_token(char c)
{
    if (c > 127) 
        return 0;

    return !!!strchr(separator, c);
}

static int parse_string(http_parser_t *parser, const char *s, size_t len)
{
    char *old_ptr;

    if (parser == NULL || s == NULL || len == 0)
        return 1;

    if (len > strlen(s))
        return 1;

    old_ptr = parser->parse_ptr;
    while (len >= 0 && *old_ptr && *s && *old_ptr == *s) {
        old_ptr++;
        s++;
        len--;
    }

    if (len != 0)
        return 1;

    parser->parse_ptr = old_ptr;
    return 0;
}


static int parse_char(http_parser_t *parser, char c)
{
    if (parser == NULL)
        return 1;

    if (parser->parse_ptr - parser->data >= parser->len - 1)
        return 1;

    if (*parser->parse_ptr == c) {
        parser->parse_ptr++;
        return 0;
    }

    return 1;
}

static int parse_crlf(http_parser_t *parser)
{
    if (parse_char(parser, '\r'))
        return 1; 
    if (parse_char(parser, '\n'))
        return 1;
    return 0;
}

static int parse_digit(http_parser_t *parser)
{
    if (parser->parse_ptr - parser->data >= parser->len - 1)
        return 1;
    if (isdigit(*parser->parse_ptr)) {
        parser->parse_ptr++;
        return 0;
    }
    return 1;
}

static char *parse_token(http_parser_t *parser)
{
    char *old_ptr, *start, *token;

    old_ptr = parser->parse_ptr;
    start = old_ptr;
    do {
        if (old_ptr - parser->data >= parser->len)
            return NULL;

        if (is_token(*old_ptr))
            old_ptr++;
        else
            break;
    } while (1);

    parser->parse_ptr = old_ptr;

    token = malloc(old_ptr - start + 1);
    ASSERT(token != NULL);

    strncpy(token, start, old_ptr - start);
    token[old_ptr - start] = '\0';

    return token;
}

static int parse_absolute_path(http_parser_t *parser)
{
    char *path, *token;

    path = malloc(PATH_LEN);
    ASSERT(path != NULL);

    memset(path, 0, PATH_LEN);
    do {
        if (parser->parse_ptr - parser->data >= parser->len)
            return 1;

        if (parse_char(parser, '/'))
            break;

        token = parse_token(parser);
        if (!token)
            return 1;

        strlcat(path, "/", PATH_LEN);
        strlcat(path, token, PATH_LEN);
        free(token);
    } while (1);

    parser->req.path = path;
    return 0;
}

static int parse_http_version(http_parser_t *parser)
{

    if (parse_string(parser, "HTTP/", 5))
        goto err;

    if (parse_digit(parser))
        goto err;

    if (parse_char(parser, '.'))
        goto err;

    if (parse_digit(parser))
        goto err;

    return 0;
err:
    // restore state
    return 1;
}

static int parse_params(http_parser_t *parser)
{
    char *token;

    parser->req.params = 0;
    if (parse_char(parser, '?'))
        return 1;

    do {
        token = parse_token(parser);
        if (!token)
            break;

        if (parser->req.params == 0)
            parser->req.params = token;
        else {
            /* parser->req.params only has strlen(_) bytes allocated
             * add 1 for the following '=' and 1 for NULL terminator
             */ 
            size_t newsize = strlen(parser->req.params) + strlen(token) + 1 + 1;

            parser->req.params = realloc(parser->req.params, newsize);
            ASSERT(parser->req.params != NULL);

            strlcat(parser->req.params, token, newsize);
            free(token);
        }

        if (parse_char(parser, '='))
            break;

        /* This is safe since we reallocated above */
        strcat(parser->req.params, "=");
    } while (1);
    return 0;
}

static int parse_method(http_parser_t *parser)
{
    size_t i;

    for (i = 0; i < HTTP_METHOD_COUNT; i++)
        if (parse_string(parser, method_names[i], strlen(method_names[i])))
            continue;

    if (i == HTTP_METHOD_COUNT)
        return 1;

    parser->req.method = i;
    return 0;
}

static int add_field(http_parser_t *parser)
{
    size_t field;

    for (field = 0; field < parser->req.field_count; field++)
        if (parser->req.fields[field].valid == 0) {
            break;
        }
    if (field == parser->req.field_count) {
        size_t newsz = 2 * parser->req.field_count * sizeof(http_header_field_t);

        parser->req.field_count *= 2;
        parser->req.fields = realloc(parser->req.fields, newsz);
        memset(parser->req.fields + field, 0, newsz / 2);
        parser->req.fields[field].valid = 1;
    }

    return field;
}

static char *parse_field_content(http_parser_t *parser)
{
    char *start, *str, ch;

    start = parser->parse_ptr;
    do {
        if (parser->parse_ptr - parser->data >= parser->len)
            break;

        ch = *parser->parse_ptr;
        if (is_ctl(ch))
            break;
        if (!parse_crlf(parser))
            break;
        parser->parse_ptr++;
    } while (1);

    if (parser->parse_ptr - start == 0)
        return NULL;

    str = malloc(parser->parse_ptr - start + 1);
    ASSERT(str != NULL);

    strncpy(str, start, parser->parse_ptr - start);
    str[parser->parse_ptr - start] = '\0';

    return str;
}

static int parse_message_header(http_parser_t *parser)
{
    int field_num;
    http_header_field_t *field;

    field_num = add_field(parser);
    field = &parser->req.fields[field_num];

    field->valid = 0;
    parse_crlf(parser);
    field->name = parse_token(parser);
    if (!field)
        return 1;

    if (parse_char(parser, ':')) {
        free(field->name);
        return 1;
    }

    // optional
    while (parse_char(parser, ' ') == 0)
        ;
    field->value = parse_field_content(parser);
    if (!field->value)
        return 1;
    while (parse_char(parser, ' ') == 0)
        ;

    field->valid = 1;
    return 0;
}


void http_parser_init(http_parser_t *parser)
{
    memset(parser, 0, sizeof *parser);

    parser->req.fields = malloc(2 * sizeof(http_header_field_t));
    ASSERT(parser->req.fields != NULL);

    parser->req.field_count = 2;
    parser->req.fields[0].valid = parser->req.fields[1].valid = 0;
}

void http_parser_free(http_parser_t *parser)
{
    size_t i;

    if (!parser)
        return;

    for (i = 0; i < parser->req.field_count; i++) {
        if (parser->req.fields[i].valid == 1) {
            free(parser->req.fields[i].name);
            free(parser->req.fields[i].value);
        }
    }
    free(parser->req.fields);
    if (parser->req.path)
        free(parser->req.path);
    if (parser->req.params)
        free(parser->req.params);
}

http_request_t *parse_http_request(http_parser_t *parser, const char *data, size_t len)
{
    if (!parser || !data || !len)
        return NULL;

    parser->data = data;
    parser->len = len;

    parser->parse_ptr = (char*)data;

    parse_method(parser);
    parse_char(parser, ' ');
    parse_absolute_path(parser);
    parse_params(parser);
    parse_char(parser, ' ');
    parse_http_version(parser);
    parse_crlf(parser);
    while (parse_message_header(parser) == 0)
        ;

    return &parser->req;
}

/* vim: set ts=4 sw=4 tw=80 et :*/

