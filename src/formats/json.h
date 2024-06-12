#ifndef JSON_H
#define JSON_H

#include <jansson.h>
#include <hiredis/hiredis.h>
#include <hiredis/async.h>

struct cmd;
struct http_client;

void
json_reply(redisAsyncContext *c, void *r, void *privdata);

char *
json_string_output(json_t *j, const char *jsonp);

struct cmd *
json_ws_extract(struct http_client *c, const char *p, size_t sz);

char*
json_ws_error(int http_status, const char *msg, size_t msg_sz, size_t *out_sz);

int json_register_parser(const char *buf, size_t len, const char *format, char *outcmd, size_t outlen);
int json_fileset_parser(const char *buf, size_t len, const char *format, char *outcmd, size_t outlen);
int json_fileset_machine_parser(const char *buf, size_t len, const char *format, char *outcmd, size_t outlen);
int json_trace_parser(const char *buf, size_t len, const char *format, char *outcmd, size_t outlen);

void json_hscan_reply(redisAsyncContext *c, void *r, void *privdata);
void json_api_reply(redisAsyncContext *c, void *r, void *privdata);

#endif
