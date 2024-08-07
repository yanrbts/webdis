#include "json.h"
#include "common.h"
#include "cmd.h"
#include "http.h"
#include "client.h"
#include "slog.h"
#include "worker.h"

#include <string.h>
#include <strings.h>
#include <hiredis/hiredis.h>
#include <hiredis/async.h>

static json_t *
json_wrap_redis_reply(const struct cmd *cmd, const redisReply *r);

void
json_reply(redisAsyncContext *c, void *r, void *privdata) {

	redisReply *reply = r;
	struct cmd *cmd = privdata;
	json_t *j;
	char *jstr;
	(void)c;

	if(cmd == NULL) {
		/* broken connection */
		return;
	}

	if(reply == NULL) { /* broken Redis link */
		format_send_error(cmd, 503, "Service Unavailable");
		return;
	}

	/* encode redis reply as JSON */
	j = json_wrap_redis_reply(cmd, r);

	/* get JSON as string, possibly with JSONP wrapper */
	jstr = json_string_output(j, cmd->jsonp);

	/* send reply */
	format_send_reply(cmd, jstr, strlen(jstr), "application/json");

	/* cleanup */
	json_decref(j);
	free(jstr);
}

/**
 * Parse info message and return object.
 */
static json_t *
json_info_reply(const char *s) {
	const char *p = s;
	size_t sz = strlen(s);

	json_t *jroot = json_object();

	/* TODO: handle new format */

	while(p < s + sz) {
		char *key, *val, *nl, *colon;

		/* find key */
		colon = strchr(p, ':');
		if(!colon) {
			break;
		}
		key = calloc(colon - p + 1, 1);
		memcpy(key, p, colon - p);
		p = colon + 1;

		/* find value */
		nl = strchr(p, '\r');
		if(!nl) {
			free(key);
			break;
		}
		val = calloc(nl - p + 1, 1);
		memcpy(val, p, nl - p);
		p = nl + 1;
		if(*p == '\n') p++;

		/* add to object */
		json_object_set_new(jroot, key, json_string(val));
		free(key);
		free(val);
	}

	return jroot;
}

static json_t *
json_expand_array(const redisReply *r);

static json_t *
json_array_to_keyvalue_reply(const redisReply *r) {
	/* zip keys and values together in a json object */
	json_t *jroot, *jlist;
	unsigned int i;

	if(r->elements % 2 != 0) {
		return NULL;
	}

	jroot = json_object();
	for(i = 0; i < r->elements; i += 2) {
		redisReply *k = r->element[i], *v = r->element[i+1];

		/* keys need to be strings */
		if(k->type != REDIS_REPLY_STRING) {
			json_decref(jroot);
			return NULL;
		}
		switch (v->type) {
		case REDIS_REPLY_NIL:
			json_object_set_new(jroot, k->str, json_null());
			break;

		case REDIS_REPLY_STRING:
			json_object_set_new(jroot, k->str, json_string(v->str));
			break;

		case REDIS_REPLY_INTEGER:
			json_object_set_new(jroot, k->str, json_integer(v->integer));
			break;

		case REDIS_REPLY_ARRAY:
			if(!(jlist = json_expand_array(v))) {
				jlist = json_null();
			}

			json_object_set_new(jroot, k->str, jlist);
			break;

		default:
			json_decref(jroot);
			return NULL;
		}

	}
	return jroot;
}

static json_t *
json_expand_array(const redisReply *r) {

	unsigned int i;
	json_t *jlist, *sublist;
	const redisReply *e;

	jlist = json_array();
	for(i = 0; i < r->elements; ++i) {
		e = r->element[i];
		switch(e->type) {
		case REDIS_REPLY_STATUS:
		case REDIS_REPLY_STRING:
			json_array_append_new(jlist, json_string(e->str));
			break;

		case REDIS_REPLY_INTEGER:
			json_array_append_new(jlist, json_integer(e->integer));
			break;

		case REDIS_REPLY_ARRAY:
			if(!(sublist = json_expand_array(e))) {
				sublist = json_null();
			}
			json_array_append_new(jlist, sublist);
			break;

		case REDIS_REPLY_NIL:
		default:
			json_array_append_new(jlist, json_null());
			break;
		}
	}
	return jlist;
}

static json_t *
json_singlestream_list(const redisReply *r) {

	unsigned int i;
	json_t *jlist, *jmsg, *jsubmsg;
	const redisReply *id, *msg;
	const redisReply *e;

	/* reply on XRANGE / XREVRANGE / XCLAIM and one substream of XREAD / XREADGROUP */
	jlist = json_array();
	for(i = 0; i < r->elements; i++) {
		e = r->element[i];
		if(e->type != REDIS_REPLY_ARRAY || e->elements < 2) {
			continue;
		}
		id = e->element[0];
		msg = e->element[1];
		if(id->type != REDIS_REPLY_STRING || id->len < 1) {
			continue;
		}
		if(msg->type != REDIS_REPLY_ARRAY || msg->elements < 2) {
			continue;
		}
		jmsg = json_object();
		json_object_set_new(jmsg, "id", json_string(id->str));
		if(!(jsubmsg = json_array_to_keyvalue_reply(msg))) {
			jsubmsg = json_null();
		}
		json_object_set_new(jmsg, "msg", jsubmsg);
		json_array_append_new(jlist, jmsg);
	}
	return jlist;
}

static json_t *
json_xreadstream_list(const redisReply *r) {

	unsigned int i;
	json_t *jobj = NULL, *jlist;
	const redisReply *sid, *msglist;
	const redisReply *e;

	/* reply on XREAD / XREADGROUP */
	if(r->elements) {
		jobj = json_object();
	}
	for(i = 0; i < r->elements; i++) {
		e = r->element[i];
		if(e->type != REDIS_REPLY_ARRAY || e->elements < 2) {
			continue;
		}
		sid = e->element[0]; msglist = e->element[1];
		if(sid->type != REDIS_REPLY_STRING || sid->len < 1) {
			continue;
		}
		if(msglist->type != REDIS_REPLY_ARRAY) {
			continue;
		}
		if(!(jlist = json_singlestream_list(msglist))) {
			jlist = json_null();
		}
		json_object_set_new(jobj, sid->str, jlist);
	}
	return jobj;
}

static json_t *
json_xpending_list(const redisReply *r) {

	unsigned int i;
	json_t *jobj, *jlist, *jown;
	const redisReply *own, *msgs;
	const redisReply *e;

	if(r->elements >= 4 && r->element[0]->type == REDIS_REPLY_INTEGER) {
		/* reply on XPENDING <key> <consumergroup> */
		jobj = json_object();
		json_object_set_new(jobj, "msgs", json_integer(r->element[0]->integer));
		if(r->element[1]->type == REDIS_REPLY_STRING) {
			json_object_set_new(jobj, "idmin", json_string(r->element[1]->str));
		}
		if(r->element[2]->type == REDIS_REPLY_STRING) {
			json_object_set_new(jobj, "idmax", json_string(r->element[2]->str));
		}
		if(r->element[3]->type != REDIS_REPLY_ARRAY) {
			return jobj;
		}
		jown = json_object();
		for(i = 0; i < r->element[3]->elements; i++) {
			e = r->element[3]->element[i];
			if(e->type != REDIS_REPLY_ARRAY || e->elements < 2) {
				continue;
			}
			own = e->element[0];
			msgs = e->element[1];
			if(own->type != REDIS_REPLY_STRING) {
				continue;
			}
			switch(msgs->type){
				case REDIS_REPLY_STRING:
					json_object_set_new(jown, own->str, json_string(msgs->str));
					break;

				case REDIS_REPLY_INTEGER:
					json_object_set_new(jown, own->str, json_integer(msgs->integer));
					break;
			}
		}
		json_object_set_new(jobj, "msgsperconsumer", jown);

		return jobj;
	}

	/* reply on XPENDING <key> <consumergroup> <minid> <maxid> <count> ... */
	jlist = json_array();
	for(i = 0; i < r->elements; i++) {
		e = r->element[i];
		if(e->type != REDIS_REPLY_ARRAY || e->elements < 4) {
			continue;
		}
		jobj = json_object();
		if(e->element[0]->type == REDIS_REPLY_STRING) {
			json_object_set_new(jobj, "id", json_string(e->element[0]->str));
		}
		if(e->element[1]->type == REDIS_REPLY_STRING) {
			json_object_set_new(jobj, "owner", json_string(e->element[1]->str));
		}
		if(e->element[2]->type == REDIS_REPLY_INTEGER) {
			json_object_set_new(jobj, "elapsedtime", json_integer(e->element[2]->integer));
		}
		if(e->element[3]->type == REDIS_REPLY_INTEGER) {
			json_object_set_new(jobj, "deliveries", json_integer(e->element[3]->integer));
		}
		json_array_append_new(jlist, jobj);
	}

	return jlist;
}

static json_t *
json_georadius_with_list(const redisReply *r) {

	unsigned int i, j;
	json_t *jobj, *jlist = NULL, *jcoo;
	const redisReply *e;

	/* reply on GEORADIUS* ... WITHCOORD | WITHDIST | WITHHASH */
	jlist = json_array();
	for(i = 0; i < r->elements; i++) {
		e = r->element[i];
		if(e->type != REDIS_REPLY_ARRAY || e->elements < 1) {
			continue;
		}
		jobj = json_object();
		json_object_set_new(jobj, "name", json_string(e->element[0]->str));
		for(j = 1; j < e->elements; j++) {
			switch(e->element[j]->type) {
				case REDIS_REPLY_INTEGER:
					json_object_set_new(jobj, "hash", json_integer(e->element[j]->integer));
					break;

				case REDIS_REPLY_STRING:
					json_object_set_new(jobj, "dist", json_string(e->element[j]->str));
					break;

				case REDIS_REPLY_ARRAY:
					if(e->element[j]->type != REDIS_REPLY_ARRAY || e->element[j]->elements != 2) {
						continue;
					}
					if(e->element[j]->element[0]->type != REDIS_REPLY_STRING || e->element[j]->element[1]->type != REDIS_REPLY_STRING) {
						continue;
					}
					jcoo = json_array();
					json_array_append_new(jcoo, json_string(e->element[j]->element[0]->str));
					json_array_append_new(jcoo, json_string(e->element[j]->element[1]->str));
					json_object_set_new(jobj, "coords", jcoo);
					break;
			}

		}
		json_array_append_new(jlist, jobj);
	}
	return jlist;
}

static json_t *
json_wrap_redis_reply(const struct cmd *cmd, const redisReply *r) {

	json_t *jlist, *jobj, *jroot = json_object(); /* that's what we return */

	/* copy verb, as jansson only takes a char* but not its length. */
	char *verb;
	if(cmd->count) {
		verb = calloc(cmd->argv_len[0]+1, 1);
		memcpy(verb, cmd->argv[0], cmd->argv_len[0]);
	} else {
		verb = strdup("");
	}


	switch(r->type) {
		case REDIS_REPLY_STATUS:
		case REDIS_REPLY_ERROR:
			jlist = json_array();
			json_array_append_new(jlist,
				r->type == REDIS_REPLY_ERROR ? json_false() : json_true());
			json_array_append_new(jlist, json_string(r->str));
			json_object_set_new(jroot, verb, jlist);
			break;

		case REDIS_REPLY_STRING:
			if(strcasecmp(verb, "INFO") == 0) {
				json_object_set_new(jroot, verb, json_info_reply(r->str));
			} else {
				json_object_set_new(jroot, verb, json_string(r->str));
			}
			break;

		case REDIS_REPLY_INTEGER:
			json_object_set_new(jroot, verb, json_integer(r->integer));
			break;

		case REDIS_REPLY_ARRAY:
			if(strcasecmp(verb, "HGETALL") == 0) {
				jobj = json_array_to_keyvalue_reply(r);
				if(jobj) {
					json_object_set_new(jroot, verb, jobj);
				}
				break;
			} else if(strcasecmp(verb, "XRANGE") == 0 || strcasecmp(verb, "XREVRANGE") == 0 ||
					(strcasecmp(verb, "XCLAIM") == 0 &&  r->elements > 0 && r->element[0]->type == REDIS_REPLY_ARRAY)) {
				jobj = json_singlestream_list(r);
				if(jobj) {
					json_object_set_new(jroot, verb, jobj);
				}
				break;
			} else if(strcasecmp(verb, "XREAD") == 0 || strcasecmp(verb, "XREADGROUP") == 0) {
				jobj = json_xreadstream_list(r);
				if(jobj) {
					json_object_set_new(jroot, verb, jobj);
				}
				break;
			} else if(strcasecmp(verb, "XPENDING") == 0) {
				jobj = json_xpending_list(r);
				if(jobj) {
					json_object_set_new(jroot, verb, jobj);
				}
				break;
			} else if(strncasecmp(verb, "GEORADIUS", 9) == 0 && r->elements > 0 && r->element[0]->type == REDIS_REPLY_ARRAY) {
				jobj = json_georadius_with_list(r);
				if(jobj) {
					json_object_set_new(jroot, verb, jobj);
				}
				break;
			}

			if(!(jlist = json_expand_array(r))) {
				jlist = json_null();
			}

			json_object_set_new(jroot, verb, jlist);
			break;

		case REDIS_REPLY_NIL:
		default:
			json_object_set_new(jroot, verb, json_null());
			break;
	}

	free(verb);
	return jroot;
}


char *
json_string_output(json_t *j, const char *jsonp) {

	char *json_reply = json_dumps(j, JSON_COMPACT);

	/* check for JSONP */
	if(jsonp) {
		size_t jsonp_len = strlen(jsonp);
		size_t json_len = strlen(json_reply);
		size_t ret_len = jsonp_len + 1 + json_len + 3;
		char *ret = calloc(1 + ret_len, 1);

		memcpy(ret, jsonp, jsonp_len);
		ret[jsonp_len] = '(';
		memcpy(ret + jsonp_len + 1, json_reply, json_len);
		memcpy(ret + jsonp_len + 1 + json_len, ");\n", 3);
		free(json_reply);

		return ret;
	}

	return json_reply;
}

/* extract JSON from WebSocket frame and fill struct cmd. */
struct cmd *
json_ws_extract(struct http_client *c, const char *p, size_t sz) {

	struct cmd *cmd = NULL;
	json_t *j;
	char *jsonz; /* null-terminated */

	unsigned int i, cur;
	int argc = 0;
	json_error_t jerror;

	(void)c;

	jsonz = calloc(sz + 1, 1);
	memcpy(jsonz, p, sz);
	j = json_loads(jsonz, sz, &jerror);
	free(jsonz);

	if(!j) {
		return NULL;
	}
	if(json_typeof(j) != JSON_ARRAY) {
		json_decref(j);
		return NULL; /* invalid JSON */
	}

	/* count elements */
	for(i = 0; i < json_array_size(j); ++i) {
		json_t *jelem = json_array_get(j, i);

		switch(json_typeof(jelem)) {
			case JSON_STRING:
			case JSON_INTEGER:
				argc++;
				break;

			default:
				break;
		}
	}

	if(!argc) { /* not a single item could be decoded */
		json_decref(j);
		return NULL;
	}

	/* create command and add args */
	cmd = cmd_new(c, argc);
	for(i = 0, cur = 0; i < json_array_size(j); ++i) {
		json_t *jelem = json_array_get(j, i);
		char *tmp;

		switch(json_typeof(jelem)) {
			case JSON_STRING:
				tmp = strdup(json_string_value(jelem));

				cmd->argv[cur] = tmp;
				cmd->argv_len[cur] = strlen(tmp);
				cur++;
				break;

			case JSON_INTEGER:
				tmp = malloc(40);
				sprintf(tmp, "%d", (int)json_integer_value(jelem));

				cmd->argv[cur] = tmp;
				cmd->argv_len[cur] = strlen(tmp);
				cur++;
				break;

			default:
				break;
		}
	}

	json_decref(j);
	return cmd;
}

/* Formats a WebSocket error message */
char* json_ws_error(int http_status, const char *msg, size_t msg_sz, size_t *out_sz) {

	(void)msg_sz; /* unused */
	json_t *jroot = json_object();
	char *jstr;

	/* e.g. {"message": "Forbidden", "error": true, "http_status": 403} */
	/* Note: this is only an equivalent HTTP status code, we're sending a WS message not an HTTP response */
	json_object_set_new(jroot, "error", json_true());
	json_object_set_new(jroot, "message", json_string(msg));
	json_object_set_new(jroot, "http_status", json_integer(http_status));

	jstr = json_string_output(jroot, NULL);
	json_decref(jroot);

	*out_sz = strlen(jstr);
	return jstr;
}
/*************************************API******************************************/

int json_register_parser(const char *buf, size_t len, struct server *s, struct rqparam *r) {
	char *tmp;
	int ret = -1;
	json_t *root;
	json_error_t error;

	(void)len;

	root = json_loads(buf, 0, &error);
	if(!root) {
		char log_msg[200];
		int log_msg_sz = snprintf(log_msg, sizeof(log_msg),
			"register Json loads error failed %s (line %d)", error.text, error.line);
		slog(s, WEBDIS_ERROR, log_msg, log_msg_sz);
		goto end;
	}

	json_t *machine = json_object_get(root, "machine");
	if (!json_is_string(machine)) {
		slog(s, WEBDIS_ERROR, "register Json error, machine is not a string.", 0);
		json_decref(root);
		goto end;
	}

	json_t *flag = json_object_get(root, "flag");
	if (!json_is_integer(flag)) {
		slog(s, WEBDIS_ERROR, "register Json error, flag is not a integer.", 0);
		json_decref(root);
		goto end;
	}
	
	r->ftype = WB_REGISTER;
	r->param.ureg.flag = json_integer_value(flag);
	r->param.ureg.machine = strdup(json_string_value(machine));

	json_object_del(root, "flag");
	tmp = json_string_output(root, NULL);
	r->param.ureg.data = strdup(tmp);
	free(tmp);

	ret = 0;
	json_decref(root);
end:
	return ret;
}

int json_fileset_parser(const char *buf, size_t len, struct server *s, struct rqparam *r) {
	int ret = -1;
	char *tmp;
	json_t *root;
	json_error_t error;

	(void)len;

	root = json_loads(buf, 0, &error);
	if(!root) {
		char log_msg[200];
		int log_msg_sz = snprintf(log_msg, sizeof(log_msg),
			"fileset Json loads error failed %s (line %d)", error.text, error.line);
		slog(s, WEBDIS_ERROR, log_msg, log_msg_sz);
		goto end;
	}

	json_t *uuid = json_object_get(root, "fileuuid");
	if (!json_is_string(uuid)) {
		slog(s, WEBDIS_ERROR, "fileset Json error, uuid is not a string.", 0);
		json_decref(root);
		goto end;
	}

	json_t *machine = json_object_get(root, "machine");
	if (!json_is_string(machine)) {
		slog(s, WEBDIS_ERROR, "fileset Json error, machine is not a string.", 0);
		json_decref(root);
		goto end;
	}

	/* HSET filekey:fileuuid fileuuid '{"machine":"123456", "uuid":"file1","filename":"file1.txt","filepath":"/path/to/file1.txt"}' */
	/* HSET machine:machine fileuuid '{"machine":"123456","uuid":"file1","filename":"file1.txt","filepath":"/path/to/file1.txt"}' */

	r->ftype = WB_FILESET;
	r->param.fset.fileuuid = strdup(json_string_value(uuid));
	r->param.fset.machine = strdup(json_string_value(machine));

	tmp = json_string_output(root, NULL);
	r->param.fset.data = strdup(tmp);
	free(tmp);

	ret = 0;
end:
	if (root) json_decref(root);
	return ret;
}

/* Return the UNIX time in microseconds */
static long long ustime(void) {
    struct timeval tv;
    long long ust;

    gettimeofday(&tv, NULL);
    ust = ((long long)tv.tv_sec)*1000000;
    ust += tv.tv_usec;
    return ust;
}

int json_traceset_parser(const char *buf, size_t len, struct server *s, struct rqparam *r) {
	int ret = -1;
	json_t *root;
	json_error_t error;
	char buffer[64] = {0};

	(void)len;

	root = json_loads(buf, 0, &error);
	if(!root) {
		char log_msg[200];
		int log_msg_sz = snprintf(log_msg, sizeof(log_msg),
			"traceset Json loads error failed %s (line %d)", error.text, error.line);
		slog(s, WEBDIS_ERROR, log_msg, log_msg_sz);
		goto end;
	}

	json_t *uuid = json_object_get(root, "fileuuid");
	if (!json_is_string(uuid)) {
		slog(s, WEBDIS_ERROR, "traceset Json error, uuid is not a string.", 0);
		json_decref(root);
		goto end;
	}

	r->ftype = WB_TRACESET;
	r->param.tset.fileuuid = strdup(json_string_value(uuid));
	snprintf(buffer, sizeof(buffer), "trace:%lld", ustime());
	r->param.tset.traceid = strdup(buffer);

	char *jstr = json_string_output(root, NULL);
	r->param.tset.data = strdup(jstr);

	ret = 0;
	if (jstr) free(jstr);
	json_decref(root);
end:
	return ret;
}

int json_auth_parser(const char *buf, size_t len, struct server *s, struct rqparam *r) {
	int ret = -1;
	json_t *root;
	json_error_t error;
	char buffer[64] = {0};

	(void)len;

	root = json_loads(buf, 0, &error);
	if(!root) {
		char log_msg[200];
		int log_msg_sz = snprintf(log_msg, sizeof(log_msg),
			"authset Json loads error failed %s (line %d)", error.text, error.line);
		slog(s, WEBDIS_ERROR, log_msg, log_msg_sz);
		goto end;
	}

	json_t *uuid = json_object_get(root, "fileuuid");
	if (!json_is_string(uuid)) {
		slog(s, WEBDIS_ERROR, "authset Json error, uuid is not a string.", 0);
		json_decref(root);
		goto end;
	}

	json_t *machine = json_object_get(root, "machine");
	if (!json_is_string(machine)) {
		slog(s, WEBDIS_ERROR, "authset Json error, machine is not a string.", 0);
		json_decref(root);
		goto end;
	}

	json_t *action = json_object_get(root, "action");
	if (!json_is_integer(action)) {
		slog(s, WEBDIS_ERROR, "authset Json error, action is not a integer.", 0);
		json_decref(root);
		goto end;
	}

	r->ftype = WB_AUTHSET;
	r->param.tset.fileuuid = strdup(json_string_value(uuid));
	r->param.tset.machine = strdup(json_string_value(machine));
	r->param.tset.action = json_integer_value(action);
	snprintf(buffer, sizeof(buffer), "trace:%lld", ustime());
	r->param.tset.traceid = strdup(buffer);

	char *jstr = json_string_output(root, NULL);
	r->param.tset.data = strdup(jstr);

	ret = 0;
	if (jstr) free(jstr);
	json_decref(root);
end:
	return ret;
}

int json_fileget_parser(const char *buf, size_t len, struct server *s, struct rqparam *r) {
	int ret = -1;
	json_t *root;
	json_error_t error;

	(void)len;

	root = json_loads(buf, 0, &error);
	if(!root) {
		char log_msg[200];
		int log_msg_sz = snprintf(log_msg, sizeof(log_msg),
			"fileget Json loads error failed %s (line %d)", error.text, error.line);
		slog(s, WEBDIS_ERROR, log_msg, log_msg_sz);
		goto end;
	}

	json_t *uuid = json_object_get(root, "fileuuid");
	if (!json_is_string(uuid)) {
		slog(s, WEBDIS_ERROR, "fileget Json error, uuid is not a string.", 0);
		json_decref(root);
		goto end;
	}

	r->ftype = WB_FILEGET;
	r->param.fileuuid = strdup(json_string_value(uuid));

	ret = 0;
	json_decref(root);
end:
	return ret;
}

int json_traceget_parser(const char *buf, size_t len, struct server *s, struct rqparam *r) {
	int ret = -1;
	json_t *root;
	json_error_t error;

	(void)len;

	root = json_loads(buf, 0, &error);
	if(!root) {
		char log_msg[200];
		int log_msg_sz = snprintf(log_msg, sizeof(log_msg),
			"traceget Json loads error failed %s (line %d)", error.text, error.line);
		slog(s, WEBDIS_ERROR, log_msg, log_msg_sz);
		goto end;
	}

	json_t *uuid = json_object_get(root, "fileuuid");
	if (!json_is_string(uuid)) {
		slog(s, WEBDIS_ERROR, "traceget Json error, uuid is not a string.", 0);
		json_decref(root);
		goto end;
	}

	json_t *page = json_object_get(root, "page");
	if (!json_is_integer(page)) {
		slog(s, WEBDIS_ERROR, "traceget Json error, page is not a integer.", 0);
		json_decref(root);
		goto end;
	}

	r->ftype = WB_TRACEGET;
	r->param.fpage.uuid = strdup(json_string_value(uuid));
	r->param.fpage.page = json_integer_value(page);

	ret = 0;
	json_decref(root);
end:
	return ret;
}

int json_filegetall_parser(const char *buf, size_t len, struct server *s, struct rqparam *r) {
	int ret = -1;
	json_t *root;
	json_error_t error;

	(void)len;

	root = json_loads(buf, 0, &error);
	if(!root) {
		char log_msg[200];
		int log_msg_sz = snprintf(log_msg, sizeof(log_msg),
			"filegetall Json loads error failed %s (line %d)", error.text, error.line);
		slog(s, WEBDIS_ERROR, log_msg, log_msg_sz);
		goto end;
	}

	json_t *machine = json_object_get(root, "machine");
	if (!json_is_string(machine)) {
		slog(s, WEBDIS_ERROR, "filegetall Json error, machine is not a string.", 0);
		json_decref(root);
		goto end;
	}

	json_t *page = json_object_get(root, "page");
	if (!json_is_integer(page)) {
		slog(s, WEBDIS_ERROR, "filegetall Json error, page is not a integer.", 0);
		json_decref(root);
		goto end;
	}

	r->ftype = WB_FILEGETALL;
	r->param.fpage.uuid = strdup(json_string_value(machine));
	r->param.fpage.page = json_integer_value(page);

	ret = 0;
	json_decref(root);
end:
	return ret;
}

int json_filegetauth_parser(const char *buf, size_t len, struct server *s, struct rqparam *r) {
	int ret = -1;
	json_t *root;
	json_error_t error;

	(void)len;

	root = json_loads(buf, 0, &error);
	if(!root) {
		char log_msg[200];
		int log_msg_sz = snprintf(log_msg, sizeof(log_msg),
			"filegetauth Json loads error failed %s (line %d)", error.text, error.line);
		slog(s, WEBDIS_ERROR, log_msg, log_msg_sz);
		goto end;
	}

	json_t *machine = json_object_get(root, "machine");
	if (!json_is_string(machine)) {
		slog(s, WEBDIS_ERROR, "filegetauth Json error, machine is not a string.", 0);
		json_decref(root);
		goto end;
	}

	json_t *page = json_object_get(root, "page");
	if (!json_is_integer(page)) {
		slog(s, WEBDIS_ERROR, "filegetauth Json error, page is not a integer.", 0);
		json_decref(root);
		goto end;
	}

	json_t *action = json_object_get(root, "action");
	if (!json_is_integer(page)) {
		slog(s, WEBDIS_ERROR, "filegetauth Json error, page is not a integer.", 0);
		json_decref(root);
		goto end;
	}

	r->ftype = WB_AUTHGET;
	r->param.authpage.machine = strdup(json_string_value(machine));
	r->param.authpage.page = json_integer_value(page);
	r->param.authpage.action = json_integer_value(action);

	ret = 0;
	json_decref(root);
end:
	return ret;
}

void json_hgetorset_reply(redisAsyncContext *c, void *r, void *privdata) {
	redisReply *reply = r;
	struct cmd *cmd = privdata;
	json_t *jroot;
	char *jstr;

	(void)c;
	/* broken connection */
	if(cmd == NULL) {
		return;
	}
	/* broken Redis link */
	if(reply == NULL) { 
		format_send_error(cmd, 503, "Service Unavailable");
		return;
	}

	jroot = json_object();
	switch(reply->type) {
	case REDIS_REPLY_STATUS:
	case REDIS_REPLY_ERROR:
		if (reply->type == REDIS_REPLY_ERROR)
			slog(cmd->w->s, WEBDIS_ERROR, reply->str, 0);
		json_object_set_new(jroot, 
							"flag", 
							reply->type == REDIS_REPLY_ERROR ? 
							json_string("FAIL") : 
							json_string(reply->str));
		break;

	case REDIS_REPLY_STRING:
		// jtmp = json_loads(reply->str, 0, &error);
		// json_object_update(jroot, jtmp);
		json_object_set_new(jroot, "flag", json_string("OK"));
		json_object_set_new(jroot, "data", json_string(reply->str));
		break;
	case REDIS_REPLY_INTEGER:
		json_object_set_new(jroot, "flag", json_string("OK"));
		break;
	case REDIS_REPLY_NIL:
	default:
		json_object_set_new(jroot, "flag", json_string("FAIL"));
		break;
	}
	/* get JSON as string, possibly with JSONP wrapper */
	jstr = json_string_output(jroot, cmd->jsonp);
	/* send reply */
	format_send_reply(cmd, jstr, strlen(jstr), "application/json");
	/* cleanup */
	json_decref(jroot);
	free(jstr);
}

struct userdata {
	struct server *s;
	char *data;
};

static void get_current_date(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d", tm_info);
}

static time_t get_expiry_time() {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    tm_info->tm_hour = 0;
    tm_info->tm_min = 0;
    tm_info->tm_sec = 0;
    tm_info->tm_mday += 1; // Move to next day
    return mktime(tm_info);
}

// static void sismember_reply(redisAsyncContext *c, void *r, void *privdata) {
// 	char current_date[20];
// 	char counter_key[256];
// 	char set_key[256];
// 	redisReply *reply = r;
// 	struct userdata *u = privdata;
// 	time_t expiry_time, now;
// 	int seconds_to_midnight;

// 	get_current_date(current_date, sizeof(current_date));
// 	snprintf(counter_key, sizeof(counter_key), "login_count:%s", current_date);
// 	snprintf(set_key, sizeof(set_key), "login_users:%s", current_date);

// 	/* Get the Unix timestamp of the next morning */
// 	expiry_time = get_expiry_time();
// 	now = time(NULL);
// 	seconds_to_midnight = (int)difftime(expiry_time, now);

// 	switch(reply->type) {
// 		case REDIS_REPLY_INTEGER:
// 			{
// 				/* There is no record for the current login */
// 				if (reply->integer == 0) {
// 					slog(u->s, WEBDIS_INFO, "First login of the day, record login information", 0);

// 					redisAsyncCommand(c, NULL, NULL, "MULTI");
// 					/* Used to store the user ID that has logged in on that day */
// 					redisAsyncCommand(c, NULL, NULL, "SADD %s %s", set_key, u->data);
// 					/* Used to store the login count for the day */
// 					redisAsyncCommand(c, NULL, NULL, "HINCRBY %s count 1", counter_key);
// 					// redisAsyncCommand(c, NULL, NULL, "INCR total_login_count");
// 					/* Set the expiration time of the collection and counter keys to the next morning */
// 					redisAsyncCommand(c, NULL, NULL, "EXPIRE %s %d", set_key, seconds_to_midnight);
// 					redisAsyncCommand(c, NULL, NULL, "EXPIRE %s %d", counter_key, seconds_to_midnight);
// 					redisAsyncCommand(c, NULL, NULL, "EXEC");
// 				}
// 			}	
// 			break;
// 		default:
// 			slog(u->s, WEBDIS_ERROR, "SISMEMBER command returns incorrect data", 0);
// 			break;
// 	}
// 	free(u->data);
// 	free(u);
// }



/* Determine whether the user has logged in on the day. 
 * If not, start increasing the number of logged-in users 
 * for the day, and the total number of logged-in users 
 * will be increased by one. At the same time, the user 
 * ID of the day will be saved and expired in the 
 * early morning of the next day.*/
// static void json_sismember_exec(redisAsyncContext *c, struct cmd *cmd) {
// 	char current_date[20];
// 	char set_key[256];
// 	struct userdata *ud;

// 	ud = (struct userdata*)calloc(1, sizeof(*ud));
// 	ud->s = cmd->w->s;
// 	ud->data = strdup(cmd->rparam->param.ureg.machine);

// 	get_current_date(current_date, sizeof(current_date));
// 	snprintf(set_key, sizeof(set_key), "login_users:%s", current_date);

// 	/* Determine whether the account has been logged in on the same day*/
// 	redisAsyncCommand(c, sismember_reply, 
// 						(void*)ud, 
// 						"SISMEMBER %s %s", 
// 						set_key, 
// 						cmd->rparam->param.ureg.machine);
// } 

static void sismember_start_reply(redisAsyncContext *c, void *r, void *privdata) {
	(void)c;
	redisReply *reply = r;
	struct userdata *u = privdata;

	if (reply == NULL) {
		slog(u->s, WEBDIS_ERROR, "Null reply received", 0);
		goto end;
	}

	if (reply->type == REDIS_REPLY_ERROR) {
		slog(u->s, WEBDIS_ERROR, reply->str, 0);
		goto end;
	}

	if (reply->type == REDIS_REPLY_INTEGER) {
		if (reply->integer == 1) {
			slog(u->s, WEBDIS_INFO, "Login recorded successfully", 0);
		} else if (reply->integer == 0) {
			slog(u->s, WEBDIS_INFO, "Login not recorded, user already logged in", 0);
		} else {
			char buff[1024];
			snprintf(buff, sizeof(buff), "Unexpected integer reply: %lld", reply->integer);
			slog(u->s, WEBDIS_ERROR, buff, 0);
		}
	} else if (reply->type == REDIS_REPLY_STRING) {
		char buff[1024];
		snprintf(buff, sizeof(buff), "Reply is a string: %s", reply->str);
		slog(u->s, WEBDIS_INFO, buff, 0);
	} else {
		char buff[1024];
		snprintf(buff, sizeof(buff), "Unexpected reply type: %d", reply->type);
		slog(u->s, WEBDIS_ERROR, buff, 0);
	}
end:
	free(u->data);
	free(u);
}

static void user_register_reply(redisAsyncContext *c, void *r, void *privdata) {
    redisReply *reply = r;
    struct cmd *cmd = privdata;
    json_t *jroot = NULL;
    char *jstr;

    (void)c;
    /* broken connection */
    if(cmd == NULL) {
        return;
    }
    /* broken Redis link */
    if(reply == NULL) { 
        format_send_error(cmd, 503, "Service Unavailable");
        return;
    }

    jroot = json_object();
    if(reply->type == REDIS_REPLY_ARRAY && reply->elements == 2) {
        const char *user_data = reply->element[0]->str;
        const char *status = reply->element[1]->str;

        if (strcmp(status, "Added") == 0) {
            slog(cmd->w->s, WEBDIS_INFO, "User added and counted successfully", 0);
			json_object_set_new(jroot, "data", json_string(user_data));
        } else if (strcmp(status, "Already Exists") == 0) {
            slog(cmd->w->s, WEBDIS_INFO, "User already exists", 0);
            json_object_set_new(jroot, "data", json_string(user_data));
        }
        json_object_set_new(jroot, "flag", json_string("OK"));
    } else {
        slog(cmd->w->s, WEBDIS_ERROR, "Unexpected reply from Lua script", 0);
        json_object_set_new(jroot, "flag", json_string("FAIL"));
    }

    /* get JSON as string, possibly with JSONP wrapper */
    jstr = json_string_output(jroot, cmd->jsonp);
    /* send reply */
    format_send_reply(cmd, jstr, strlen(jstr), "application/json");
    /* cleanup */
    json_decref(jroot);
    free(jstr);
}

void user_register(struct cmd *cmd) {
	char current_date[20];
    char counter_key[256], set_key[256], total_login_key[256], userkey[256];

	get_current_date(current_date, sizeof(current_date));

	// Lua script to handle all operations atomically
    const char *lua_script = 
        "local set_key = KEYS[1] "
        "local counter_key = KEYS[2] "
        "local total_login_key = KEYS[3] "
        "local userkey = KEYS[4] "
        "local user_id = ARGV[1] "
        "local user_data = ARGV[2] "
        "local expiry = tonumber(ARGV[3]) "
        "local user_exists = redis.call('HGET', userkey, user_id) "
        "if user_exists then "
		"	 if redis.call('SISMEMBER', set_key, user_id) == 0 then "
        "    	 redis.call('SADD', set_key, user_id) "
        "    	 redis.call('HINCRBY', counter_key, 'count', 1) "
        "    	 redis.call('EXPIRE', set_key, expiry) "
        "    	 redis.call('EXPIRE', counter_key, expiry) "
		"    	 return {user_data, 'Added'} "
		"	 else "
        "    	 return {user_exists, 'Already Exists'} "
		"	 end "
        "else "
        "    redis.call('HSET', userkey, user_id, user_data) "
        "    redis.call('INCR', total_login_key) "
		"	 if redis.call('SISMEMBER', set_key, user_id) == 0 then "
        "    	 redis.call('SADD', set_key, user_id) "
        "    	 redis.call('HINCRBY', counter_key, 'count', 1) "
        "    	 redis.call('EXPIRE', set_key, expiry) "
        "    	 redis.call('EXPIRE', counter_key, expiry) "
        "    	 return {user_data, 'Added'} "
		"	 else "
		"		 return {user_data, 'Already Exists'} "
		"	 end "
        "end ";
	
	snprintf(counter_key, sizeof(counter_key), "login_count:%s", current_date);
    snprintf(set_key, sizeof(set_key), "login_users:%s", current_date);
    snprintf(total_login_key, sizeof(total_login_key), "total_login_count");
    snprintf(userkey, sizeof(userkey), "userkey:%s", cmd->rparam->param.ureg.machine);

    time_t expiry_time = get_expiry_time();
    time_t now = time(NULL);
    int seconds_to_midnight = (int)difftime(expiry_time, now);

    // Execute the Lua script with the necessary keys and arguments
    redisAsyncCommand(cmd->ac, user_register_reply, (void*)cmd, "EVAL %s 4 %s %s %s %s %s %s %d",
        lua_script, set_key, counter_key, total_login_key, userkey, 
        cmd->rparam->param.ureg.machine, cmd->rparam->param.ureg.data, seconds_to_midnight);
}

static void sismember_start(redisAsyncContext *c, struct cmd *cmd) {
	char current_date[20];
	char counter_key[256], set_key[256];
	struct userdata *ud;

	ud = (struct userdata*)calloc(1, sizeof(*ud));
	ud->s = cmd->w->s;
	ud->data = strdup(cmd->rparam->param.ureg.machine);

	get_current_date(current_date, sizeof(current_date));

	// Lua script to handle all operations atomically
	const char *lua_script = 
		"local set_key = KEYS[1] "
		"local counter_key = KEYS[2] "
		"local user_id = ARGV[1] "
		"local expiry = tonumber(ARGV[2]) "
		"if redis.call('SISMEMBER', set_key, user_id) == 0 then "
		"    redis.call('SADD', set_key, user_id) "
		"    redis.call('HINCRBY', counter_key, 'count', 1) "
		"    redis.call('EXPIRE', set_key, expiry) "
		"    redis.call('EXPIRE', counter_key, expiry) "
		"    return 'Added' "
		"else "
        "    return 'Already Exists' "
        "end";
	
	snprintf(counter_key, sizeof(counter_key), "login_count:%s", current_date);
	snprintf(set_key, sizeof(set_key), "login_users:%s", current_date);

	time_t expiry_time = get_expiry_time();
	time_t now = time(NULL);
	int seconds_to_midnight = (int)difftime(expiry_time, now);

	// Execute the Lua script with the necessary keys and arguments
	redisAsyncCommand(c, sismember_start_reply, (void*)ud, "EVAL %s 2 %s %s %s %d",
		lua_script, set_key, counter_key, ud->data, seconds_to_midnight);
}

void json_register_reply(redisAsyncContext *c, void *r, void *privdata) {
	redisReply *reply = r;
	struct cmd *cmd = privdata;
	json_t *jroot = NULL;
	char *jstr;

	(void)c;
	/* broken connection */
	if(cmd == NULL) {
		return;
	}
	/* broken Redis link */
	if(reply == NULL) { 
		format_send_error(cmd, 503, "Service Unavailable");
		return;
	}

	jroot = json_object();
	switch(reply->type) {
	case REDIS_REPLY_NIL: /* user not exist*/
	case REDIS_REPLY_INTEGER: /* insert succrss */
	case REDIS_REPLY_STRING: /* user already exist */
		if (cmd->rparam->param.ureg.flag == 1) {
			/* Insert user successfully */;
			slog(cmd->w->s, WEBDIS_INFO, "Insert user successfully", 0);
			// jtmp = json_loads(cmd->rparam->param.ureg.data, 0, &error);
			// json_object_update(jroot, jtmp);
			json_object_set_new(jroot, "flag", json_string("OK"));
			json_object_set_new(jroot, "data", json_string(cmd->rparam->param.ureg.data));
		} else {
			if (reply->str) {
				/* User already exists */;
				slog(cmd->w->s, WEBDIS_INFO, "User already exists", 0);
				json_object_set_new(jroot, "flag", json_string("OK"));
				json_object_set_new(jroot, "data", json_string(reply->str));
			} else {
				/* Only when the user query does not exist will the total number 
				 * of users be increased by 1 when data is inserted. 
				 * Updated user information will not be recorded.*/
				redisAsyncCommand(c, NULL, NULL, "INCR total_login_count");
				/* User does not exist Start insert 
				 * Here, you must change the flag to insert to 
				 * facilitate the judgment during callback*/;
				cmd->rparam->param.ureg.flag = 1;
				redisAsyncCommand(c, json_register_reply, cmd, 
								"HSET userkey:%s %s %s", 
								cmd->rparam->param.ureg.machine,
								cmd->rparam->param.ureg.machine,
								cmd->rparam->param.ureg.data);
				json_decref(jroot);
				return;
			}
		}
		// json_sismember_exec(c, cmd);
		sismember_start(c, cmd);
		break;
	case REDIS_REPLY_ERROR:
	default:
		slog(cmd->w->s, WEBDIS_ERROR, reply->str, 0);
		json_object_set_new(jroot, "flag", json_string("FAIL"));
		break;
	}
	/* get JSON as string, possibly with JSONP wrapper */
	jstr = json_string_output(jroot, cmd->jsonp);
	/* send reply */
	format_send_reply(cmd, jstr, strlen(jstr), "application/json");
	/* cleanup */
	json_decref(jroot);
	free(jstr);
}

void json_hscan_reply(redisAsyncContext *c, void *r, void *privdata) {
	redisReply *reply = r;
	struct cmd *cmd = privdata;
	char *jstr;
	json_t *jlist, *jroot;

	(void)c;
	/* broken connection */
	if(cmd == NULL)
		return;
	/* broken Redis link */
	if(reply == NULL) {
		format_send_error(cmd, 503, "Service Unavailable");
		return;
	}

	jroot = json_object();

	switch(reply->type) {
		case REDIS_REPLY_STATUS:
		case REDIS_REPLY_ERROR:
			if (reply->type == REDIS_REPLY_ERROR)
				slog(cmd->w->s, WEBDIS_ERROR, reply->str, 0);
			json_object_set_new(jroot, 
								"flag", 
								reply->type == REDIS_REPLY_ERROR 
								? json_string("FAIL") 
								: json_string(reply->str));
			break;

		case REDIS_REPLY_STRING:
			json_object_set_new(jroot, "flag", json_string(reply->str));
			break;
		case REDIS_REPLY_INTEGER:
			json_object_set_new(jroot, "flag", json_integer(reply->integer));
			break;

		case REDIS_REPLY_ARRAY:
			{
				unsigned long long cursor = 0;
				redisReply *keys;

				cursor = strtoull(reply->element[0]->str, NULL, 10);
				json_object_set_new(jroot, "flag", json_string("OK"));
				json_object_set_new(jroot, "page", json_integer(cursor));

				jlist = json_array();
				keys = reply->element[1];
				if (reply->type == REDIS_REPLY_ARRAY) {
					for (size_t i = 0; i < keys->elements; i += 2) {
						redisReply *key = keys->element[i];
						redisReply *value = keys->element[i + 1];
						if (key->type == REDIS_REPLY_STRING && value->type == REDIS_REPLY_STRING) {
							json_array_append_new(jlist, json_string(value->str));
						}
					}
				} else {
					json_array_append_new(jlist, json_null());
				}
				/* Determine the key name based on the number of command parameters. 
				 * This callback function is only used by the filegetall and filegettrace 
				 * interfaces. The number of commands for the filegetall interface is 5, 
				 * and the number of commands for the filegettrace interface is 7.*/
				json_object_set_new(jroot, "data", jlist);
			}
			break;

		case REDIS_REPLY_NIL:
		default:
			json_object_set_new(jroot, "flag", json_string("FAIL"));
			break;
	}
	/* get JSON as string, possibly with JSONP wrapper */
	jstr = json_string_output(jroot, cmd->jsonp);
	/* send reply */
	format_send_reply(cmd, jstr, strlen(jstr), "application/json");
	/* cleanup */
	json_decref(jroot);
	free(jstr);
}

void setCallback(redisAsyncContext *c, void *r, void *privdata) {
	(void)c;
	struct server *s = (struct server *)privdata;

    redisReply *reply = (redisReply *)r;
    if (reply == NULL) return;

    if (reply->type == REDIS_REPLY_ERROR) {
		slog(s, WEBDIS_ERROR, reply->str, 0);
    }
}

void json_multi_reply(redisAsyncContext *c, void *r, void *privdata) {
    redisReply *reply = (redisReply *)r;
	struct cmd *cmd = privdata;

    if (reply == NULL) 
		return;

	redisAsyncCommand(c, setCallback, cmd->w->s, 
					"HSET filekey:%s %s %s", 
					cmd->rparam->param.fset.fileuuid,
					cmd->rparam->param.fset.fileuuid,
					cmd->rparam->param.fset.data);
	
	redisAsyncCommand(c, setCallback, cmd->w->s, 
					"HSET machine:%s %s %s", 
					cmd->rparam->param.fset.machine,
					cmd->rparam->param.fset.fileuuid,
					cmd->rparam->param.fset.data);
	redisAsyncCommand(c, json_exec_reply, cmd, "%s", "EXEC");
}
static void json_del_oldest_auth_reply(redisAsyncContext *c, void *r, void *privdata) {
	char key[64];
	redisReply *reply = (redisReply *)r;
	int action = (int)((intptr_t)privdata);

	if (reply == NULL) 
		return;
	
	if (reply->type == REDIS_REPLY_ARRAY && reply->elements > 0) {
		const char *oldest_date = reply->element[0]->str;
		snprintf(key, sizeof(key), (action == 2 ? "auth:%s" : "apply:%s"), oldest_date);
		redisAsyncCommand(c, NULL, NULL, "DEL %s", key);
		redisAsyncCommand(c, NULL, NULL, "ZREM dates %s", oldest_date);
	}
}
static void json_last_fiveday_auth_reply(redisAsyncContext *c, void *r, void *privdata) {
	redisReply *reply = (redisReply *)r;
	
	if (reply == NULL) 
		return;
	
	/* Determine whether there are more than 5 records. 
	 * If there are more than 5 records, delete the earliest one.*/
	if (reply->type == REDIS_REPLY_INTEGER 
		&& reply->integer > 5) {
		redisAsyncCommand(c, json_del_oldest_auth_reply, privdata, "ZRANGE dates 0 0");
	}
}
/* Record the number of authorizations and applications in the last five days*/
static void json_record_last_fiveday_auth(redisAsyncContext *c, int action) {
	char today_str[11];
	char key[64];
	time_t now, timestamp;
	struct tm *st;

	now = time(NULL);
	st = localtime(&now);
	strftime(today_str, sizeof(today_str), "%Y-%m-%d", st);

	snprintf(key, sizeof(key), (action == 2 ? "auth:%s" : "apply:%s"), today_str);
	/* Increment the count for the current day */
	redisAsyncCommand(c, NULL, NULL, "HINCRBY %s count 1", key);
	/* Use an ordered set to record the date and add a timestamp as a score */
	timestamp = time(NULL);
    redisAsyncCommand(c, NULL, NULL, "ZADD dates %ld %s", timestamp, today_str);
	redisAsyncCommand(c, json_last_fiveday_auth_reply, (void*)(intptr_t)action, "ZCARD dates");
}

void json_authmulti_reply(redisAsyncContext *c, void *r, void *privdata) {
	int ac;
    redisReply *reply = (redisReply *)r;
	struct cmd *cmd = privdata;

    if (reply == NULL) 
		return;

	redisAsyncCommand(c, setCallback, cmd->w->s, 
					"HSET filekey:%s %s %s", 
					cmd->rparam->param.tset.fileuuid,
					cmd->rparam->param.tset.traceid,
					cmd->rparam->param.tset.data);

	ac = cmd->rparam->param.tset.action;
	/*
	 * to determine whether the client triggers authorization or applies for 
	 * authorization operation 1 is application, 2 is authorization
	 */
	if (ac == 1 || ac == 2) {
		char buffer[64] = {0};
		snprintf(buffer, sizeof(buffer), ac == 2 ? "auth:%lld" : "apply:%lld", ustime());
		redisAsyncCommand(c, setCallback, cmd->w->s, 
					"HSET machine:%s %s %s", 
					cmd->rparam->param.tset.machine,
					buffer,
					cmd->rparam->param.tset.data);

		/* Count the number of authorizations or applications in the last 5 days. 
		 * The operation is a bit complicated and may affect performance.*/
		json_record_last_fiveday_auth(c, ac);
	}
	/* Used to store the Overall traceability information  
	 * Convenient for large screen services to obtain this data */
	redisAsyncCommand(c, NULL, NULL, "INCR total_trace_count");
	/* Save the latest 20 traceability information to facilitate 
	 * the large screen service to find the latest traceability information.*/
	redisAsyncCommand(c, NULL, NULL, "LPUSH latest_trace %s", cmd->rparam->param.tset.data);
	redisAsyncCommand(c, NULL, NULL, "LTRIM latest_trace 0 19");

	redisAsyncCommand(c, json_authmulti_exec_reply, cmd, "EXEC");
}

void json_exec_reply(redisAsyncContext *c, void *r, void *privdata) {
	int number = 0;
	redisReply *reply = r;
	struct cmd *cmd = privdata;
	char *jstr;
	json_t *jroot;

	(void)c;
	/* broken connection */
	if(cmd == NULL)
		return;
	/* broken Redis link */
	if(reply == NULL) {
		format_send_error(cmd, 503, "Service Unavailable");
		return;
	}

	jroot = json_object();

	if (reply->type == REDIS_REPLY_ERROR) {
		slog(cmd->w->s, WEBDIS_ERROR, reply->str, 0);
		json_object_set_new(jroot, "flag", json_string("FAIL"));
	} else if (reply->type == REDIS_REPLY_ARRAY) {
		for (size_t i = 0; i < reply->elements; i++) {
            redisReply *element = reply->element[i];

			switch (element->type) {
			case REDIS_REPLY_INTEGER:
				number++;
				break;
			case REDIS_REPLY_STRING:
			case REDIS_REPLY_STATUS:
			case REDIS_REPLY_ERROR:
			default:
				break;
			}
        }
		/* Here we need to determine whether all commands in the transaction 
		 * are executed successfully. Currently, there are two commands in the transaction.*/
		if (number == 2)
			json_object_set_new(jroot, "flag", json_string("OK"));
		else
			json_object_set_new(jroot, "flag", json_string("FAIL"));
	} else {
		json_object_set_new(jroot, "flag", json_null());
	}
	/* get JSON as string, possibly with JSONP wrapper */
	jstr = json_string_output(jroot, cmd->jsonp);
	/* send reply */
	format_send_reply(cmd, jstr, strlen(jstr), "application/json");
	/* cleanup */
	json_decref(jroot);
	free(jstr);
}

void json_authmulti_exec_reply(redisAsyncContext *c, void *r, void *privdata) {
	int number = 0;
	redisReply *reply = r;
	struct cmd *cmd = privdata;
	char *jstr;
	json_t *jroot;

	(void)c;
	/* broken connection */
	if(cmd == NULL)
		return;
	/* broken Redis link */
	if(reply == NULL) {
		format_send_error(cmd, 503, "Service Unavailable");
		return;
	}

	jroot = json_object();

	if (reply->type == REDIS_REPLY_ERROR) {
		slog(cmd->w->s, WEBDIS_ERROR, reply->str, 0);
		json_object_set_new(jroot, "flag", json_string("FAIL"));
	} else if (reply->type == REDIS_REPLY_ARRAY) {
		for (size_t i = 0; i < reply->elements; i++) {
            redisReply *element = reply->element[i];

			switch (element->type) {
			case REDIS_REPLY_INTEGER:
				number++;
				break;
			case REDIS_REPLY_STRING:
			case REDIS_REPLY_STATUS:
			case REDIS_REPLY_ERROR:
			default:
				break;
			}
        }
		/* Here we need to determine whether all commands in the transaction 
		 * are executed successfully. Currently, there are two commands in the transaction.*/
		if (number > 0)
			json_object_set_new(jroot, "flag", json_string("OK"));
		else
			json_object_set_new(jroot, "flag", json_string("FAIL"));
	} else {
		json_object_set_new(jroot, "flag", json_string("FAIL"));
	}
	/* get JSON as string, possibly with JSONP wrapper */
	jstr = json_string_output(jroot, cmd->jsonp);
	/* send reply */
	format_send_reply(cmd, jstr, strlen(jstr), "application/json");
	/* cleanup */
	json_decref(jroot);
	free(jstr);
}
