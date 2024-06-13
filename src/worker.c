#include "worker.h"
#include "client.h"
#include "http.h"
#include "cmd.h"
#include "pool.h"
#include "slog.h"
#include "websocket.h"
#include "conf.h"
#include "server.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <event.h>
#include <string.h>
#include <netinet/tcp.h>
#include "formats/common.h"

struct worker *
worker_new(struct server *s) {

	int ret;
	struct worker *w = calloc(1, sizeof(struct worker));
	w->s = s;

	/* setup communication link */
	ret = pipe(w->link);
	(void)ret;

	/* Redis connection pool */
	w->pool = pool_new(w, s->cfg->pool_size_per_thread);

	return w;
}

void
worker_free(struct worker *w) {
	struct timeval tv = {1, 100000}; // 1.1 seconds

	if (w == NULL)
		return;
	/* The pthread_cancel() function sends a cancellation request to the thread thread. 
	 * Whether and when the tar‐get thread reacts to the cancellation request depends 
	 * on two attributes that are under the control of  that thread: its cancelability 
	 * state and type.*/
	pthread_cancel(w->thread);
	event_base_loopexit(w->base, &tv);
	/* Wait for the child thread to end */
	pthread_join(w->thread, NULL);
	
	pool_free(w->pool);
	free(w);
}

void
worker_can_read(int fd, short event, void *p) {

	struct http_client *c = p;
	int ret, nparsed;

	(void)fd;
	(void)event;

	ret = http_client_read(c);
	if(ret <= 0) {
		if((client_error_t)ret == CLIENT_DISCONNECTED) {
			return;
		} else if (c->failed_alloc || (client_error_t)ret == CLIENT_OOM) {
			slog(c->w->s, WEBDIS_DEBUG, "503", 3);
			http_send_error(c, 503, "Service Unavailable");
			return;
		}
	}

	if(!c->is_websocket) {
		/* run parser */
		nparsed = http_client_execute(c);

		if(c->failed_alloc) {
			slog(c->w->s, WEBDIS_DEBUG, "503", 3);
			http_send_error(c, 503, "Service Unavailable");
		} else if (c->parser.flags & F_CONNECTION_CLOSE && c->fully_read) {
			/* only close if requested *and* we've already read the request in full */
			c->broken = 1;
		} else if(c->is_websocket) {

			/* Got websocket data */
			c->ws = ws_client_new(c);
			if(!c->ws) {
				c->broken = 1;
			} else {
				free(c->buffer);
				c->buffer = NULL;
				c->sz = 0;

				/* send response, and start managing fd from websocket.c */
				int reply_ret = ws_handshake_reply(c->ws);
				if(reply_ret < 0) {
					c->ws->http_client = NULL; /* detach to prevent double free */
					ws_close_if_able(c->ws);
					c->broken = 1;
				} else {
					unsigned int processed = 0;
					int process_ret = ws_process_read_data(c->ws, &processed);
					if(process_ret == WS_ERROR) {
						c->broken = 1; /* likely connection was closed */
					}
				}
			}

			/* clean up what remains in HTTP client */
			free(c->buffer);
			c->buffer = NULL;
			c->sz = 0;
		} else if(nparsed != ret) {
			slog(c->w->s, WEBDIS_DEBUG, "400", 3);
			http_send_error(c, 400, "Bad Request");
		} else if(c->request_sz > c->s->cfg->http_max_request_size) {
			slog(c->w->s, WEBDIS_DEBUG, "413", 3);
			http_send_error(c, 413, "Request Entity Too Large");
		}
	}

	if(c->broken) { /* terminate client */
		if(c->is_websocket) { /* only close for WS since HTTP might use keep-alive */
			close(c->fd);
		}
		http_client_free(c);
	} else { /* start monitoring input again */
		if(!c->is_websocket) { /* all communication handled by WS code from now on */
			worker_monitor_input(c);
		}
	}
}

/**
 * Monitor client FD for possible reads.
 */
void
worker_monitor_input(struct http_client *c) {
	event_set(&c->ev, c->fd, EV_READ, worker_can_read, c);
	event_base_set(c->w->base, &c->ev);
	event_add(&c->ev, NULL);
}

/**
 * Called when a client is sent to this worker.
 */
static void
worker_on_new_client(int pipefd, short event, void *ptr) {

	struct http_client *c;
	unsigned long addr;

	(void)event;
	(void)ptr;

	/* Get client from messaging pipe */
	int ret = read(pipefd, &addr, sizeof(addr));
	if(ret == sizeof(addr)) {
		c = (struct http_client*)addr;

		/* monitor client for input */
		worker_monitor_input(c);
	}
}

static void
worker_pool_connect(struct worker *w) {
	int i;
	/* create connections */
	for(i = 0; i < w->pool->count; ++i) {
		pool_connect(w->pool, w->s->cfg->database, 1);
	}
}

static void*
worker_main(void *p) {

	struct worker *w = p;
	struct event ev;

	/* pthread_setcancelstate is used to enable or disable the cancellation 
	 * state of a thread. The following are detailed descriptions of the two states:
	 * PTHREAD_CANCEL_ENABLE: The thread can respond to cancellation requests. 
	 * When the thread reaches a cancellation point (such as pthread_testcancel, 
	 * pthread_join, pthread_cond_wait, etc.), it checks whether there is a cancellation request. 
	 * If so, it responds to the cancellation request and terminates the thread.
	 * PTHREAD_CANCEL_DISABLE: The thread ignores cancellation requests. 
	 * Even if the thread is canceled by other threads, the thread will not 
	 * respond and continue to execute.*/
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

	/* setup libevent */
	w->base = event_base_new();

	/* monitor pipe link */
	event_set(&ev, w->link[0], EV_READ | EV_PERSIST, worker_on_new_client, w);
	event_base_set(w->base, &ev);
	event_add(&ev, NULL);

	/* connect to Redis */
	worker_pool_connect(w);
	/* loop */
	event_base_dispatch(w->base);

	event_del(&ev);
	event_base_free(w->base);
	return NULL;
}

void
worker_start(struct worker *w) {
	pthread_create(&w->thread, NULL, worker_main, w);
}

/**
 * Queue new client to process
 */
void
worker_add_client(struct worker *w, struct http_client *c) {
	/* write into pipe link */
	unsigned long addr = (unsigned long)c;
	int ret = write(w->link[1], &addr, sizeof(addr));
	(void)ret;
}

/**
 * Called when a client has finished reading input and can create a cmd
 */
void
worker_process_client(struct http_client *c) {
	/* check that the command can be executed */
	struct worker *w = c->w;
	cmd_response_t ret = CMD_PARAM_ERROR;
	switch(c->parser.method) {
		case HTTP_GET:
			if(c->path_sz == 16 && memcmp(c->path, "/crossdomain.xml", 16) == 0) {
				http_crossdomain(c);
				return;
			}
			slog(w->s, WEBDIS_DEBUG, c->path, c->path_sz);
			ret = cmd_run(c->w, c, 1+c->path, c->path_sz-1, NULL, 0);
			break;

		case HTTP_POST:
			slog(w->s, WEBDIS_DEBUG, c->path, c->path_sz);
			// ret = cmd_run(c->w, c, c->body, c->body_sz, NULL, 0);
			ret = cmd_run_api(c->w, c, 1+c->path, c->path_sz-1, c->body, c->body_sz);
			break;

		case HTTP_PUT:
			slog(w->s, WEBDIS_DEBUG, c->path, c->path_sz);
			ret = cmd_run(c->w, c, 1+c->path, c->path_sz-1,
					c->body, c->body_sz);
			break;

		case HTTP_OPTIONS:
			http_send_options(c);
			return;

		default:
			slog(w->s, WEBDIS_DEBUG, "405", 3);
			http_send_error(c, 405, "Method Not Allowed");
			return;
	}

	switch(ret) {
		case CMD_ACL_FAIL:
		case CMD_PARAM_ERROR:
			slog(w->s, WEBDIS_DEBUG, "403", 3);
			http_send_error(c, 403, "Forbidden");
			break;

		case CMD_REDIS_UNAVAIL:
			slog(w->s, WEBDIS_DEBUG, "503", 3);
			http_send_error(c, 503, "Service Unavailable");
			break;
		default:
			break;
	}
}

