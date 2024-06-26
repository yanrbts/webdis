#ifndef CMD_H
#define CMD_H

#include <stdlib.h>
#include <hiredis/async.h>
#include <sys/queue.h>
#include <event.h>
#include <evhttp.h>

struct evhttp_request;
struct http_client;
struct server;
struct worker;
struct cmd;
struct rqparam;

typedef void (*formatting_fun)(redisAsyncContext *, void *, void *);
typedef char* (*ws_error_fun)(int http_status, const char *msg, size_t msg_sz, size_t *out_sz);

typedef enum {
	CMD_SENT,
	CMD_PARAM_ERROR,
	CMD_ACL_FAIL,
	CMD_REDIS_UNAVAIL
} cmd_response_t;

typedef enum {
	WB_REGISTER,
	WB_FILESET,
	WB_FILEGET,
	WB_FILEGETALL,
	WB_TRACESET,
	WB_TRACEGET
} functype;

struct cmd {
	int fd;

	int count;
	char **argv;
	size_t *argv_len;
	struct rqparam *rparam;
	functype ftype;

	/* HTTP data */
	char *mime; /* forced output content-type */
	int mime_free; /* need to free mime buffer */

	char *filename; /* content-disposition attachment */

	char *if_none_match; /* used with ETags */
	char *jsonp; /* jsonp wrapper */
	char *separator; /* list separator for raw lists */
	int keep_alive;

	/* various flags */
	int started_responding;
	int is_websocket;
	int http_version;
	int database;

	struct http_client *http_client;
	struct http_client *pub_sub_client;
	redisAsyncContext *ac;
	struct worker *w;
};

struct subscription {
	struct server *s;
	struct cmd *cmd;
};

struct rqparam {
	functype ftype;
	union {
		/* user register */
		struct {
			char *machine;
			char *data;
			int flag;
		} ureg;
		
		/* file set */
		struct {
			char *fileuuid;
			char *machine;
			char *data;
		} fset;

		/* trace set */
		struct {
			char *fileuuid;
			char *traceid;
			char *data;
		} tset;

		/* file get */
		char *fileuuid;

		/* file get all */
		/* trace get */
		struct {
			char *uuid;
			long long page;
		} fpage;
	} param;
};

struct multicmd {
	char *cmdline;
	int count;
};

typedef int(*jparsefunc)(const char *buf, size_t len, struct server *s, struct rqparam *r);

struct apientry {
	char *uri;                  /* HTTP URI */
	void *cmdline;				/* command */
	int count;					/* Number of command parameters */
	jparsefunc	func;			/* Request parsing function */
	formatting_fun replyfunc;	/* Request response function */
	functype ftype;				/* Interface Type */
};

struct cmd *
cmd_new(struct http_client *c, int count);

void
cmd_free_argv(struct cmd *c);

void
cmd_free(struct cmd *c);

void 
rqparam_free(struct rqparam *r);

cmd_response_t
cmd_run(struct worker *w, struct http_client *client,
		const char *uri, size_t uri_len,
		const char *body, size_t body_len);

cmd_response_t
cmd_run_api(struct worker *w, struct http_client *client,
		const char *uri, size_t uri_len,
		const char *body, size_t body_len);

int
cmd_select_format(struct http_client *client, struct cmd *cmd,
		const char *uri, size_t uri_len, formatting_fun *f_format);

int
cmd_is_subscribe_args(struct cmd *cmd);

int
cmd_is_unsubscribe_args(struct cmd *cmd);

int
cmd_is_subscribe(struct cmd *cmd);

void
cmd_send(struct cmd *cmd, formatting_fun f_format);

void
cmd_send_format(struct cmd *cmd, formatting_fun f_format, const char *fmt);

void
cmd_setup(struct cmd *cmd, struct http_client *client);

#endif
