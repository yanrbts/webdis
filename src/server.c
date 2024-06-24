#include "server.h"
#include "worker.h"
#include "client.h"
#include "conf.h"
#include "tls.h"
#include "version.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <limits.h>

char *ascii_logo ="\n" 
"    __                                      | Version: %s\n"                       
"   / /__________  ______   _____  _____     | Port: %d \n"
"  / //_/ ___/ _ \\/ ___/ | / / _ \\/ ___/     | PID: %ld\n"
" / ,< (__  )  __/ /   | |/ /  __/ /         | Author: Yanruibing\n"   
"/_/|_/____/\\___/_/    |___/\\___/_/          | Web: http://www.kxyk.com \n\n";

/**
 * Sets up a non-blocking socket
 */
static int
socket_setup(struct server *s, const char *ip, int port) {
	int reuse = 1;
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	int fd, ret;

	memset(&addr, 0, sizeof(addr));
#if defined __BSD__
	addr.sin_len = sizeof(struct sockaddr_in);
#endif
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	addr.sin_addr.s_addr = inet_addr(ip);

	/* this sad list of tests could use a Maybe monad... */

	/* create socket */
	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (-1 == fd) {
		slog(s, WEBDIS_ERROR, strerror(errno), 0);
		return -1;
	}

	/* reuse address if we've bound to it before. */
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse,
				sizeof(reuse)) < 0) {
		slog(s, WEBDIS_ERROR, strerror(errno), 0);
		return -1;
	}

	/* set socket as non-blocking. */
	ret = fcntl(fd, F_SETFL, O_NONBLOCK);
	if (0 != ret) {
		slog(s, WEBDIS_ERROR, strerror(errno), 0);
		return -1;
	}

	/* bind */
	ret = bind(fd, (struct sockaddr*)&addr, len);
	if (0 != ret) {
		slog(s, WEBDIS_ERROR, strerror(errno), 0);
		return -1;
	}

	/* listen */
	ret = listen(fd, SOMAXCONN);
	if (0 != ret) {
		slog(s, WEBDIS_ERROR, strerror(errno), 0);
		return -1;
	}

	if (getsockname(fd, (struct sockaddr *)&addr, &len) != -1) {
		char buffer[256] = {0};
		int len;
		int port_num = ntohs(addr.sin_port);

		len = snprintf(buffer, sizeof(buffer), 
					"Webdis listening on port %d",
					port_num);
		if (len < 0) {
			/* len < 0 */
			slog(s, WEBDIS_INFO, "snprintf error", 0);
		} else if ((size_t)len >= sizeof(buffer)) {
			buffer[sizeof(buffer) - 1] = '\0';
			slog(s, WEBDIS_INFO, buffer, 0);
		} else {
			/* 0 < len < sizeof(buffer)*/
			slog(s, WEBDIS_INFO, buffer, (size_t)len);
		}
    }

	/* there you go, ready to accept! */
	return fd;
}

#ifdef HAVE_SSL
static void
server_init_ssl(struct server *s) {
	redisInitOpenSSL();

	/* Create SSL context, see docs in cfg.h */
	s->ssl_context = redisCreateSSLContext(
		s->cfg->ssl.ca_cert_bundle,
		s->cfg->ssl.path_to_certs,
		s->cfg->ssl.client_cert_pem,
		s->cfg->ssl.client_key_pem,
		s->cfg->ssl.redis_sni,
		&s->ssl_error);

	if(s->ssl_context == NULL || s->ssl_error != 0) {
		fprintf(stderr, "SSL error: %s\n",
				(s->ssl_error != 0)
					? redisSSLContextGetError(s->ssl_error)
					: "Unknown error");
		exit(EXIT_FAILURE);
	}
}
#endif

struct server *
server_new(const char *cfg_file) {
	int i;
	struct server *s = calloc(1, sizeof(struct server));

	s->log.fd = -1;
	s->cfg = conf_read(cfg_file);

	/* initialize logging as soon as we've read the config file */
	slog_init(s);

#ifdef HAVE_SSL
	if(s->cfg->ssl.enabled) {
		server_init_ssl(s);
	}
#endif

	/* workers */
	s->w = calloc(s->cfg->http_threads, sizeof(struct worker*));
	for(i = 0; i < s->cfg->http_threads; ++i) {
		s->w[i] = worker_new(s);
	}

	pthread_mutex_init(&s->auth_log_mutex, NULL);
	return s;
}

void 
server_stop(struct server *s) {
	int i;

	for(i = 0; i < s->cfg->http_threads; ++i) {
		worker_free(s->w[i]);
	}
	free(s->w);
	// event_free(&s->ev);
	pthread_mutex_destroy(&s->auth_log_mutex);
	conf_free(s->cfg);

	free(s);
}

static void
server_can_accept(int fd, short event, void *ptr) {
	struct server *s = ptr;
	struct worker *w;
	struct http_client *c;
	int client_fd;
	struct sockaddr_in addr;
	socklen_t addr_sz = sizeof(addr);
	int on = 1;
	(void)event;

	/* select worker to send the client to */
	w = s->w[s->next_worker];

	/* accept client */
	client_fd = accept(fd, (struct sockaddr*)&addr, &addr_sz);

	/* make non-blocking */
	int status = ioctl(client_fd, FIONBIO, &on);
	if (status == -1) {
		char log_msg[200];
		int log_msg_sz = snprintf(log_msg, sizeof(log_msg),
			"ioctl failed (%d): %s", errno, strerror(errno));
		slog(s, WEBDIS_ERROR, log_msg, log_msg_sz);
	}

	/* create client and send to worker. */
	if(client_fd > 0) {
		c = http_client_new(w, client_fd, addr.sin_addr.s_addr);
		worker_add_client(w, c);

		/* loop over ring of workers */
		s->next_worker = (s->next_worker + 1) % s->cfg->http_threads;
	} else { /* too many connections */
		char log_msg[200];
		int log_msg_sz = snprintf(log_msg, sizeof(log_msg),
			"accept failed (%d): %s", errno, strerror(errno));
		slog(s, WEBDIS_ERROR, log_msg, log_msg_sz);
	}
}

/**
 * Daemonize server.
 * (taken from Redis)
 */
static void
server_daemonize(struct server *s, const char *pidfile) {
	int fd;

	if (fork() != 0) exit(0); /* parent exits */
	setsid(); /* create a new session */

	/* Every output goes to /dev/null. */
	if ((fd = open("/dev/null", O_RDWR, 0)) != -1) {
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		if (fd > STDERR_FILENO) close(fd);
	}

	/* write pidfile */
	if (pidfile) {
		int pid_fd = open(pidfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if(pid_fd > 0) {
			char pid_buffer[(CHAR_BIT * sizeof(int) / 3) + 3]; /* max length for int */
			int pid_sz = snprintf(pid_buffer, sizeof(pid_buffer), "%d\n", (int)getpid());
			ssize_t written;
			int written_total = 0;
			while((written = write(pid_fd, pid_buffer + written_total, pid_sz - written_total)) > 0
				&& written_total < pid_sz) {
				written_total += written;
			}
			close(pid_fd);
		} else {
			const char err_msg[] = "Failed to create PID file";
			slog(s, WEBDIS_ERROR, err_msg, sizeof(err_msg)-1);
			if(errno) {
				char *errno_msg = strerror(errno);
				slog(s, WEBDIS_ERROR, errno_msg, strlen(errno_msg));
			}
		}
	}
}

/* global pointer to the server object, used in signal handlers */
static struct server *__server;

static void
server_handle_signal(int id) {

	int ret;
	switch(id) {
		case SIGHUP:
			slog_init(__server);
			break;
		case SIGTERM:
		case SIGINT:
			slog(__server, WEBDIS_INFO, "Webdis terminating", 0);
			ret = fsync(__server->log.fd);
			(void)ret;
			close(__server->log.fd);
			server_stop(__server);
			exit(0);
			break;
		default:
			break;
	}
}

static void
server_install_signal_handlers(struct server *s) {
	__server = s;

	signal(SIGHUP,  server_handle_signal);
	signal(SIGTERM, server_handle_signal);
	signal(SIGINT,  server_handle_signal);
}

int
server_start(struct server *s) {
	int i, ret;

	/* initialize libevent */
	s->base = event_base_new();

	if(s->cfg->daemonize) {
		server_daemonize(s, s->cfg->pidfile);

		/* sometimes event mech gets lost on fork */
		if(event_reinit(s->base) != 0) {
			slog(s, WEBDIS_ERROR, "Error: event_reinit failed after fork", 0);
		}
	}
	/* print logo */
	dprintf(s->log.fd, ascii_logo, WEBDIS_VERSION, s->cfg->http_port, getpid());

	/* ignore sigpipe */
#ifdef SIGPIPE
	signal(SIGPIPE, SIG_IGN);
#endif

	/* install signal handlers */
	server_install_signal_handlers(s);

	/* start worker threads */
	for(i = 0; i < s->cfg->http_threads; ++i) {
		worker_start(s->w[i]);
	}

	/* create socket */
	s->fd = socket_setup(s, s->cfg->http_host, s->cfg->http_port);
	if(s->fd < 0) {
		return -1;
	}

	s->ssl_ctx = ssl_init(&s->cfg->wbssl);

	/*set keepalive socket option to do with half connection*/
	int keep_alive = 1;
	setsockopt(s->fd , SOL_SOCKET, SO_KEEPALIVE, (void*)&keep_alive, sizeof(keep_alive));

	/* start http server */
	event_set(&s->ev, s->fd, EV_READ | EV_PERSIST, server_can_accept, s);
	event_base_set(s->base, &s->ev);
	ret = event_add(&s->ev, NULL);

	if(ret < 0) {
		slog(s, WEBDIS_ERROR, "Error calling event_add on socket", 0);
		return -1;
	}
	
	/* initialize fsync timer once libevent is set up */
	slog_fsync_init(s);

	slog(s, WEBDIS_INFO, "Webdis " WEBDIS_VERSION " up and running", 0);
	event_base_dispatch(s->base);
	event_base_free(s->base);
	return 0;
}

