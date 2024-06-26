#ifndef CONF_H
#define CONF_H

#include <sys/types.h>
#include "slog.h"

struct auth {
	/* 1 if only password is used, 0 for username + password */
	int use_legacy_auth;
	char *username;
	char *password;
};

#ifdef HTTP_SSL
struct httpssl {
	char *cert_file;                /* Server side and optionally client side cert file name */
	char *key_file;                 /* Private key filename for cert_file */
	char *key_file_pass;            /* Optional password for key_file */
	char *client_cert_file;         /* Certificate to use as a client; if none, use cert_file */
	char *client_key_file;          /* Private key filename for client_cert_file */
	char *client_key_file_pass;     /* Optional password for client_key_file */
	char *dh_params_file;
	char *ca_cert_file;
	char *ca_cert_dir;
	char *protocols;
	char *ciphers;
	char *ciphersuites;
	int prefer_server_ciphers;
	int session_caching;
	int session_cache_size;
	int session_cache_timeout;
};
#endif

struct conf {
	/* connection to Redis */
	char *redis_host;
	int redis_port;
	struct auth *redis_auth;

	/* HTTP server interface */
	char *http_host;
	int http_port;
	int http_threads;
	size_t http_max_request_size;

	/* pool size, one pool per worker thread */
	int pool_size_per_thread;

	/* daemonize process, off by default */
	int daemonize;
	char *pidfile;

	/* WebSocket support, off by default */
	int websockets;

	/* database number */
	int database;

	/* ACL */
	struct acl *perms;

	/* user/group */
	uid_t user;
	gid_t group;

	/* Logging */
	char *logfile;
	log_level verbosity;
	struct {
		log_fsync_mode mode;
		int period_millis; /* only used with LOG_FSYNC_MILLIS */
	} log_fsync;

	/* HiRedis options */
	struct {
		int keep_alive_sec; /* passed to redisEnableKeepAliveWithInterval, > 0 to enable */
	} hiredis_opts;

#ifdef HAVE_SSL
	/* SSL */
	struct {
		int enabled;
		char *ca_cert_bundle;  /* File name of trusted CA/ca bundle file, optional */
		char *path_to_certs;   /* Path of trusted certificates, optional */
		char *client_cert_pem; /* File name of client certificate file, optional */
		char *client_key_pem;  /* File name of client private key, optional */
		char *redis_sni;       /* Server name to request (SNI), optional */
	} ssl;
#endif
#ifdef HTTP_SSL
	struct httpssl wbssl;
#endif
	/* Request to serve on “/” */
	char *default_root;
};

struct conf *
conf_read(const char *filename);

void
conf_free(struct conf *conf);

#endif /* CONF_H */
