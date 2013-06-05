/*
 * c6.c: a http server
 *
 * Copyright (C) 2013  linkedshell<www.linkedshell.com>
 *
 * Created:
 * Yue Xiaocheng <yuexiaocheng@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */

#include "c6.h"
#include "mysql.h"

typedef struct {
    char db_host[32];
    char db_user[32];
    char db_passwd[32];
    char db_name[32];
} db_info_s;

enum {
    light_worker = 0,
    tc_worker = 1,
}; // for role

typedef struct {
    int role;
    
    int tc_worker_num;
    int light_worker_num;

    pid_t pid;

    struct ev_loop* loop;

    int listen_sockfd;
    char listen_ip[32];
    unsigned short listen_port;
    unsigned short tc_worker_port;
    struct sockaddr_in listen_addr;
    ev_io listener;

    char log_path[256];
    char access_log_path[256];

    db_info_s db_info;
    MYSQL* db;

    ev_timer timer;

    c6_conn_pt cs;
    int conn_cnt;
    int session_seed;
} CONFIG;

CONFIG glo;

static MYSQL* connect_mysql(db_info_s* di);

static long long now(void);
static void fill_access_time(c6_conn_pt c);

static c6_conn_pt make_conn(int socket, conn_type_t type);
static c6_conn_pt take_conn(int socket, int session);
static void reset_conn(c6_conn_pt c);
static void free_conn(c6_conn_pt c);

static int send_http_rsp(c6_conn_pt c, int status);
static int send_http_nocopy_rsp(c6_conn_pt c, int status, char* out, int len);
static int send_http_simple_rsp(c6_conn_pt c, int status, char* out);
static int send_subreq_http_req(c6_conn_pt c);

static int do_client_send_header(c6_conn_pt c);
static int do_client_send_body(c6_conn_pt c);
static int do_client_recv_header(c6_conn_pt c);
static int do_client_recv_body(c6_conn_pt c);
static void client_send_cb(EV_P_ ev_io *w, int revents);
static void client_recv_cb(EV_P_ ev_io *w, int revents);
static void do_client_close(c6_conn_pt c);

static void accept_cb(EV_P_ ev_io *w, int revents);

static int do_proxy_recv_header(c6_conn_pt c);
static int do_proxy_recv_body(c6_conn_pt c);
static int do_proxy_send_header(c6_conn_pt c);

static void proxy_send_cb(EV_P_ ev_io *w, int revents);
static void proxy_recv_cb(EV_P_ ev_io *w, int revents);
static void do_proxy_close(c6_conn_pt c);

static int do_subreq_recv_header(c6_conn_pt c);
static int do_subreq_recv_body(c6_conn_pt c);
static int do_subreq_send_header(c6_conn_pt c);

static void subreq_send_cb(EV_P_ ev_io *w, int revents);
static void subreq_recv_cb(EV_P_ ev_io *w, int revents);
static void do_subreq_close(c6_conn_pt c);

static c6_conn_pt make_conn(int socket, conn_type_t type) {
    c6_conn_pt c = &(glo.cs[socket]);
    reset_conn(c);
    memset(&c->client_addr, 0x00, sizeof(c->client_addr));
    c->st = type;
    c->sockfd = socket;
    c->start_at = c->active_at = now();
    c->session_id = glo.session_seed++;
    switch (c->st) {
        case sock_type_noused:
            break;
        case sock_type_listen:
            ev_io_init(&c->read_ev, accept_cb, c->sockfd, EV_READ);
            ev_io_start(glo.loop, &c->read_ev);
            break;
        case sock_type_client:
            c->do_close = do_client_close;
            ev_io_init(&c->read_ev, client_recv_cb, c->sockfd, EV_READ);
            ev_io_start(glo.loop, &c->read_ev);
            break;
        case sock_type_subreq:
            c->do_close = do_subreq_close;
            break;
        case sock_type_proxy:
            c->do_close = do_proxy_close;
            break;
        default:
            Error("%s(%d): socket(%d) unknown c_type(%d)\n", __FUNCTION__, __LINE__, socket, type);
            return NULL;
    }
    glo.conn_cnt++;
    return c;
}

static c6_conn_pt take_conn(int socket, int session) {
    c6_conn_pt c = &(glo.cs[socket]);
    if (session == c->session_id)
        return c;
    return NULL;
}

static void free_conn(c6_conn_pt c) {
    reset_conn(c);
    c->st = sock_type_noused;
    if (c->sockfd > 0) {
        close(c->sockfd);
        c->sockfd = socket_unused;
    }
    c->session_id = 0;
    memset(&c->client_addr, 0x00, sizeof(c->client_addr));

    c->start_at = 0;
    c->active_at = 0;

    c->is_keepalive = 0;
    c->real_ip[0] = '\0';
    
    c->begin_ms = 0;
    c->access_time[0] = '\0';
    c->do_timer = NULL;
    c->do_close = NULL;

    ev_io_stop(glo.loop, &c->write_ev);
    ev_io_stop(glo.loop, &c->read_ev);
    
    glo.conn_cnt--;
    return;
}

// for keep-alive
static void reset_conn(c6_conn_pt c) {
    c->e_sockfd = 0;
    c->e_session_id = 0;
    
    c->bytes_sent = 0;
    c->bytes_recved = 0;

    c->head_bytes_to_send = 0;
    c->body_bytes_to_send = 0;

    c->recv_buf[0] = '\0';
    c->send_buf[0] = '\0';

    if (c->body_recv_buf) {
        free(c->body_recv_buf);
        c->body_recv_buf = NULL;
    }
    if (c->body_send_buf) {
        free(c->body_send_buf);
        c->body_send_buf = NULL;
    }

    c->static_file[0] = '\0';
    if (c->static_file_fd > 0) {
        close(c->static_file_fd);
        c->static_file_fd = -1;
    }
    c->offset = 0;

    if (c->header) {
        free(c->header);
        c->header = NULL;
    }
    if (c->rsp_header) {
        free(c->rsp_header);
        c->rsp_header = NULL;
    }
    c->head_length = 0;
    c->content_length = 0;
    c->is_sent_header = 0;
    c->is_recvd_header = 0;
    return;
}

static long long now(void) {
    struct timeval tv;

    gettimeofday(&tv, 0);
    return ((long long)tv.tv_sec*1000*1000 + (long long)tv.tv_usec);
}

static void fill_access_time(c6_conn_pt c) {
    struct timeval tv;
    struct tm* n;
    char time_now[64] = {0};

    gettimeofday(&tv, 0);
    n = localtime(&tv.tv_sec);
    strftime(time_now, sizeof(time_now)-1, "%Y%m%d %H:%M:%S", n);

    int64_t now = (int64_t)tv.tv_sec*1000*1000 + (int64_t)tv.tv_usec;
    c->begin_ms = (long)(now/1000);
    safe_snprintf(c->access_time, sizeof(c->access_time)-1, "%s.%03ld", time_now, (tv.tv_usec/1000));
    return;
}

static void write_access_log(c6_conn_pt c) {
    struct timeval tv;
    struct tm* n;
    char time_now[64] = {0};
    char time_now_hour[64] = {0};
    cJSON* cj = NULL;
    FILE* p = NULL;
    char* client_ip = NULL;
    char* xforward_ip = NULL;
    char* host = NULL;
    char* ua = NULL;
    char* ref = NULL;
    char* first_line = NULL;
    char path[256] = {0};

    static int a[] = { 
        0,0,0,0,0,5,5,5,5,5,
        10,10,10,10,10,15,15,15,15,15,
        20,20,20,20,20,25,25,25,25,25,
        30,30,30,30,30,35,35,35,35,35,
        40,40,40,40,40,45,45,45,45,45,
        50,50,50,50,50,55,55,55,55,55,
    };
    gettimeofday(&tv, 0);
    n = localtime(&tv.tv_sec);
    strftime(time_now, sizeof(time_now)-1, "%Y%m%d %H:%M:%S", n);
    strftime(time_now_hour, sizeof(time_now_hour)-1, "%Y%m%d_%H", n);
    safe_snprintf(path, sizeof(path)-1, "%s_%s%02d.log.%u", 
            glo.access_log_path, time_now_hour, a[n->tm_min], glo.listen_port);

    mkdir_r(path);
    p = fopen(path, "a+");
    if (NULL != p) {
        cj = cJSON_GetObjectItem_EX(c->header, "client_ip");
        if (NULL != cj) {
            client_ip = cj->valuestring;
        }
        cj = cJSON_GetObjectItem_EX(c->header, "x-forwarded-for");
        if (NULL != cj) {
            xforward_ip = cj->valuestring;
        }
        cj = cJSON_GetObjectItem_EX(c->header, "Host");
        if (NULL != cj) {
            host = cj->valuestring;
        }
        cj = cJSON_GetObjectItem_EX(c->header, "User-Agent");
        if (NULL != cj) {
            ua = cj->valuestring;
        }
        cj = cJSON_GetObjectItem_EX(c->header, "Referer");
        if (NULL != cj) {
            ref = cj->valuestring;
        }
        cj = cJSON_GetObjectItem_EX(c->header, "first_line");
        if (NULL != cj) {
            first_line = cj->valuestring;
        }
        fprintf(p, "%s.%03ld - %s %s \"%s\" \"%s\" \"%s\" \"%s\" \"%s\"\n", 
                time_now, (tv.tv_usec/1000), 
                c->real_ip, 
                host ? host : "-", 
                first_line ? first_line : "\"-\"",
                ref? ref : "\"-\"", 
                ua? ua : "\"-\"", 
                client_ip ? client_ip : "-", 
                xforward_ip ? xforward_ip : "-");
        fclose(p);
    }
    else
        Error("%s(%d): can't write access log(%s), something is wrong\n", 
                __FUNCTION__, __LINE__, path);
    int64_t now = (int64_t)tv.tv_sec*1000*1000 + (int64_t)tv.tv_usec;
    c->begin_ms = (long)(now/1000);
    safe_snprintf(c->access_time, sizeof(c->access_time)-1, "%s.%03ld", time_now, (tv.tv_usec/1000));
    return;
}

static int tc_worker_proxy(c6_conn_pt c, char* host, unsigned short port) {
    // first create proxy connection
    int sockfd = -1;
    int nb = 1;
    int ret =0;
    struct sockaddr_in addr;
    c6_conn_pt cproxy = NULL;
    char ip[32];

    get_realip(host, ip, sizeof(ip)-1);

    memset(&addr, 0x00, sizeof(addr));
    if (!inet_aton(ip, &addr.sin_addr)) {
        Error("%s(%d): bad host: %s, ip: %s", __FUNCTION__, __LINE__, host, ip);
        return -1;
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (-1 == sockfd) {
        Error("%s(%d): socket() failed. error(%d): %s\n", __FUNCTION__, __LINE__, errno, strerror(errno));
        return -2;
    }
    if (ioctl(sockfd, FIONBIO, &nb)) {
        Error("%s(%d): ioctl(FIONBIO) failed. error(%d): %s\n", __FUNCTION__, __LINE__, errno, strerror(errno));
        close(sockfd);
        return -3;
    }
    ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if (-1 == ret && EINPROGRESS != errno) {
        Error("%s(%d): connecting to %s:%d failed", 
                __FUNCTION__, __LINE__, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        close(sockfd);
        return -4;
    }
    fcntl(sockfd, F_SETFD, 1);

    cproxy = make_conn(sockfd, sock_type_proxy);
    memcpy(&cproxy->client_addr, &addr, sizeof(struct sockaddr_in));
    cproxy->e_session_id = c->session_id;
    cproxy->e_sockfd = c->sockfd;

    fill_access_time(cproxy);

    c->e_session_id = cproxy->session_id;
    c->e_sockfd = cproxy->sockfd;
    
    // finish create connect, now fill request data and set write event
    memcpy(cproxy->send_buf, c->recv_buf, c->head_length);

    cproxy->head_bytes_to_send = c->head_length;
    cproxy->is_sent_header = 0;
    cproxy->bytes_sent = 0;
    ev_io_init(&cproxy->write_ev, proxy_send_cb, cproxy->sockfd, EV_WRITE);
    ev_io_start(glo.loop, &cproxy->write_ev);
    return 0;
}

static int do_subreq(c6_conn_pt c, char* host, unsigned short port) {
    // first create proxy connection
    int sockfd = -1;
    int nb = 1;
    int ret =0;
    struct sockaddr_in addr;
    c6_conn_pt csq = NULL;
    char ip[32];
    char first_line[1024];

    get_realip(host, ip, sizeof(ip)-1);

    memset(&addr, 0x00, sizeof(addr));
    if (!inet_aton(ip, &addr.sin_addr)) {
        Error("%s(%d): bad host: %s, ip: %s", __FUNCTION__, __LINE__, host, ip);
        return -1;
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (-1 == sockfd) {
        Error("%s(%d): socket() failed. error(%d): %s\n", __FUNCTION__, __LINE__, errno, strerror(errno));
        return -2;
    }
    if (ioctl(sockfd, FIONBIO, &nb)) {
        Error("%s(%d): ioctl(FIONBIO) failed. error(%d): %s\n", __FUNCTION__, __LINE__, errno, strerror(errno));
        close(sockfd);
        return -3;
    }
    ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if (-1 == ret && EINPROGRESS != errno) {
        Error("%s(%d): connecting to %s:%d failed", 
                __FUNCTION__, __LINE__, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        close(sockfd);
        return -4;
    }
    fcntl(sockfd, F_SETFD, 1);

    csq = make_conn(sockfd, sock_type_subreq);
    memcpy(&csq->client_addr, &addr, sizeof(struct sockaddr_in));
    csq->e_session_id = c->session_id;
    csq->e_sockfd = c->sockfd;

    fill_access_time(csq);

    c->e_session_id = csq->session_id;
    c->e_sockfd = csq->sockfd;
    
    // finish create connect, now fill request data and set write event
    safe_snprintf(first_line, sizeof(first_line)-1, "GET %s HTTP/1.1", "/");
    csq->header = cJSON_CreateObject();
    cJSON_AddStringToObject(csq->header, "first_line", first_line);
    cJSON_AddStringToObject(csq->header, "Content-Type", "text/plain;charset=UTF-8");
    cJSON_AddStringToObject(csq->header, "Server", C6_SERVER);
    cJSON_AddStringToObject(csq->header, "Connection", "close");
    safe_snprintf(first_line, sizeof(first_line)-1, "%s:%u", ip, port);
    cJSON_AddStringToObject(csq->header, "Host", first_line);
    
    send_subreq_http_req(csq);
    return 0;
}

// User-Define functions
static int on_test(c6_conn_pt c) {
    int is_tc_work = 0;

    if (light_worker == glo.role && is_tc_work) {
        return tc_worker_proxy(c, "127.0.0.1", glo.tc_worker_port);
    }
    send_http_simple_rsp(c, 200, "ok");
    return 0;
}

static int on_test_tc(c6_conn_pt c) {
    int is_tc_work = 1;

    if (light_worker == glo.role && is_tc_work) {
        return tc_worker_proxy(c, "127.0.0.1", glo.tc_worker_port);
    }
    send_http_simple_rsp(c, 200, "ok");
    return 0;
}

static int on_test_sq(c6_conn_pt c) {
    return do_subreq(c, "www.baidu.com", 80);
}

static int on_fc_login(c6_conn_pt c) {
    char* debug = NULL;
    int ret_code = 0;
    char* out = NULL;
    cJSON* root = NULL, *kv = NULL, *cj = NULL;
    char sql[1024];
    char* email = NULL;
    char* passwd = NULL;

    // parse post body parameters
    if (0 == memcmp(c->method, "POST", sizeof("POST")-1)) {
        http_post_req_param(c->header, c->body_recv_buf, c->content_length);
        debug = cJSON_Print(c->header);
        Info("%s(%d): \n%s\n", __FUNCTION__, __LINE__, debug);
        free(debug);
    }

    kv = cJSON_GetObjectItem_EX(c->header, "param.kv");
    if (NULL == kv) {
        send_http_simple_rsp(c, 400, "parameter wrong");
        return -1;
    }
    cj = cJSON_GetObjectItem_EX(kv, "e");
    if (NULL != cj)
        email = cj->valuestring;
    cj = cJSON_GetObjectItem_EX(kv, "p");
    if (NULL != cj)
        passwd = cj->valuestring;

    root = cJSON_CreateObject();

    safe_snprintf(sql, sizeof(sql)-1, "insert into user(passwd, email, dt_create) values('%s', '%s', now())", 
            passwd, email);
    if (0 != mysql_query(glo.db, sql)) {
        Error("%s(%d): Query failed. error: %s\n", __FUNCTION__, __LINE__, mysql_error(glo.db));
        cJSON_AddNumberToObject(root, "ret_code", -1);
        cJSON_AddStringToObject(root, "ret_msg", mysql_error(glo.db));
        mysql_close(glo.db);
        glo.db = NULL;
    }
    else {
        cJSON_AddNumberToObject(root, "ret_code", ret_code);
        cJSON_AddStringToObject(root, "ret_msg", "success");
        cJSON_AddNumberToObject(root, "uid", mysql_insert_id(glo.db));
    }
    out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    send_http_nocopy_rsp(c, 200, out, strlen(out));
    return 0;
}

static int on_fc_info(c6_conn_pt c) {
    char* debug = NULL;
    int ret_code = 0;
    char* out = NULL;
    cJSON* root = NULL, *kv = NULL, *cj = NULL, *cata = NULL, *cata_item = NULL;
    char sql[1024];
    int uid = 0;
    MYSQL_RES* res = NULL;
    int row_c = 0;
    MYSQL_ROW row;
    int field_c = 0;
    MYSQL_FIELD* fields;
    int i, j;
    int is_tc_work = 1;

    if (light_worker == glo.role && is_tc_work) {
        return tc_worker_proxy(c, "127.0.0.1", glo.tc_worker_port);
    }

    if (0 == memcmp(c->method, "POST", sizeof("POST")-1)) {
        http_post_req_param(c->header, c->body_recv_buf, c->content_length);
        debug = cJSON_Print(c->header);
        Info("%s(%d): \n%s\n", __FUNCTION__, __LINE__, debug);
        free(debug);
    }

    kv = cJSON_GetObjectItem_EX(c->header, "param.kv");
    if (NULL == kv) {
        send_http_simple_rsp(c, 400, "parameter wrong");
        return -1;
    }
    cj = cJSON_GetObjectItem_EX(kv, "uid");
    if (NULL != cj)
        uid = atoi(cj->valuestring);

    root = cJSON_CreateObject();

    safe_snprintf(sql, sizeof(sql)-1, 
            "select c.id, c.name, c.curve_data from user as u left join curve as c on u.id=c.user_id where u.id=%d", uid); 
    if (0 != mysql_query(glo.db, sql)) {
        Error("%s(%d): Query failed. error: %s\n", __FUNCTION__, __LINE__, mysql_error(glo.db));
        cJSON_AddNumberToObject(root, "ret_code", -1);
        cJSON_AddStringToObject(root, "ret_msg", mysql_error(glo.db));
        mysql_close(glo.db);
        glo.db = NULL;
    }
    else {
        res = mysql_store_result(glo.db);
        fields = mysql_fetch_fields(res);
        field_c = mysql_num_fields(res);
        row = mysql_fetch_row(res);
        row_c = mysql_num_rows(res);

        // json
        cJSON_AddNumberToObject(root, "ret_code", ret_code);
        cJSON_AddStringToObject(root, "ret_msg", "success");
        cJSON_AddItemToObject(root, "curve_list", cata=cJSON_CreateArray());
        for (i=0; i<row_c; ++i) {
            row = mysql_fetch_row(res);
            if (row) {
                cJSON_AddItemToArray(cata, cata_item=cJSON_CreateObject());
                for (j=0; j<field_c; ++j) {
                    if (IS_NUM(fields[j].type))
                        cJSON_AddNumberToObject(cata_item, fields[j].name, atoi(row[j]));
                    else
                        cJSON_AddStringToObject(cata_item, fields[j].name, row[j]);
                }
            }
        }
    }
    out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    send_http_nocopy_rsp(c, 200, out, strlen(out));
    return 0;
}

static int on_fc_create_curve(c6_conn_pt c) {
    char* debug = NULL;
    int ret_code = 0;
    char* out = NULL;
    cJSON* root = NULL, *kv = NULL, *cj = NULL;
    static char sql[1024*64];
    char* name = NULL;
    char* data = NULL;
    int uid = 0;

    // parse post body parameters
    if (0 == memcmp(c->method, "POST", sizeof("POST")-1)) {
        http_post_req_param(c->header, c->body_recv_buf, c->content_length);
        debug = cJSON_Print(c->header);
        Info("%s(%d): \n%s\n", __FUNCTION__, __LINE__, debug);
        free(debug);
    }

    kv = cJSON_GetObjectItem_EX(c->header, "param.kv");
    if (NULL == kv) {
        send_http_simple_rsp(c, 400, "parameter wrong");
        return -1;
    }
    cj = cJSON_GetObjectItem_EX(kv, "name");
    if (NULL != cj)
        name = cj->valuestring;
    cj = cJSON_GetObjectItem_EX(kv, "data");
    if (NULL != cj)
        data = cj->valuestring;

    root = cJSON_CreateObject();

    safe_snprintf(sql, sizeof(sql)-1, 
            "insert into curve(name, user_id, curve_data, dt_create) values('%s', %d, '%s', now())", 
            name, uid, data);
    if (0 != mysql_query(glo.db, sql)) {
        Error("%s(%d): Query failed. error: %s\n", __FUNCTION__, __LINE__, mysql_error(glo.db));
        cJSON_AddNumberToObject(root, "ret_code", -1);
        cJSON_AddStringToObject(root, "ret_msg", mysql_error(glo.db));
        mysql_close(glo.db);
        glo.db = NULL;
    }
    else {
        cJSON_AddNumberToObject(root, "ret_code", ret_code);
        cJSON_AddStringToObject(root, "ret_msg", "success");
        cJSON_AddNumberToObject(root, "cvid", mysql_insert_id(glo.db));
    }
    out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    send_http_nocopy_rsp(c, 200, out, strlen(out));
    return 0;
}

static int on_fc_set_curve(c6_conn_pt c) {
    char* debug = NULL;
    int ret_code = 0;
    char* out = NULL;
    cJSON* root = NULL, *kv = NULL, *cj = NULL, *vv = NULL, *dd = NULL, *n1 = NULL, *arr = NULL;
    static char sql[1024*64];
    char* val = NULL;
    char* day = NULL;
    int cvid = 0;
    MYSQL_RES* res = NULL;
    int row_c = 0;
    MYSQL_ROW row;
    int count = 0;
    int is_found = 0;
    int i;

    // parse post body parameters
    if (0 == memcmp(c->method, "POST", sizeof("POST")-1)) {
        http_post_req_param(c->header, c->body_recv_buf, c->content_length);
        debug = cJSON_Print(c->header);
        Info("%s(%d): \n%s\n", __FUNCTION__, __LINE__, debug);
        free(debug);
        debug = NULL;
    }

    kv = cJSON_GetObjectItem_EX(c->header, "param.kv");
    if (NULL == kv) {
        send_http_simple_rsp(c, 400, "parameter wrong");
        return -1;
    }
    cj = cJSON_GetObjectItem_EX(kv, "cvid");
    if (NULL != cj)
        cvid = atoi(cj->valuestring);
    cj = cJSON_GetObjectItem_EX(kv, "d");
    if (NULL != cj)
        day = cj->valuestring;
    cj = cJSON_GetObjectItem_EX(kv, "v");
    if (NULL != cj)
        val = cj->valuestring;

    root = cJSON_CreateObject();

    safe_snprintf(sql, sizeof(sql)-1, 
            "select curve_data from curve where id=%d", cvid); 
    if (0 != mysql_query(glo.db, sql)) {
        Error("%s(%d): Query failed. error: %s\n", __FUNCTION__, __LINE__, mysql_error(glo.db));
        cJSON_AddNumberToObject(root, "ret_code", -1);
        cJSON_AddStringToObject(root, "ret_msg", mysql_error(glo.db));
        mysql_close(glo.db);
        glo.db = NULL;
    }
    else {
        res = mysql_store_result(glo.db);
        row = mysql_fetch_row(res);
        row_c = mysql_num_rows(res);
        if (1 == row_c) {
            cj = cJSON_Parse(row[0]);
            if (NULL == cj) {
                Error("%s(%d): curve_data(%s) is not json format where cvid=%d\n", __FUNCTION__, __LINE__, row[0], cvid);
                cJSON_AddNumberToObject(root, "ret_code", -1);
                cJSON_AddStringToObject(root, "ret_msg", "not json format");
            }
            else {
                n1 = cJSON_CreateObject();
                cJSON_AddStringToObject(n1, "d", day);
                cJSON_AddStringToObject(n1, "v", val);
                
                arr = cJSON_GetObjectItem_EX(cj, "data_list");
                count = cJSON_GetArraySize(arr);
                for (i=0; i<count; ++i) {
                    vv = cJSON_GetArrayItem(arr, i);
                    dd = cJSON_GetObjectItem_EX(vv, "d");
                    if (0 == strcmp(day, dd->valuestring)) {
                        // update it
                        is_found = 1;
                        cJSON_ReplaceItemInArray(arr, i, n1);
                        break;
                    }
                }
                if (0 == is_found) {
                    cJSON_AddItemToArray(arr, n1);
                    is_found = 1;
                }
            }
        }
        else {
            Error("%s(%d): can't find curve_data where cvid=%d\n", __FUNCTION__, __LINE__, cvid);
            cJSON_AddNumberToObject(root, "ret_code", -1);
            cJSON_AddStringToObject(root, "ret_msg", "no data");
        }
    }
    
    if (1 == is_found) {
        debug = cJSON_PrintUnformatted(cj);
        safe_snprintf(sql, sizeof(sql)-1, 
                "update curve set curve_data='%s' where id=%d", 
                debug, cvid);
        free(debug);
        debug = NULL;
        if (0 != mysql_query(glo.db, sql)) {
            Error("%s(%d): Query failed. error: %s\n", __FUNCTION__, __LINE__, mysql_error(glo.db));
            cJSON_AddNumberToObject(root, "ret_code", -1);
            cJSON_AddStringToObject(root, "ret_msg", mysql_error(glo.db));
            mysql_close(glo.db);
            glo.db = NULL;
        }
        else {
            cJSON_AddNumberToObject(root, "ret_code", ret_code);
            cJSON_AddStringToObject(root, "ret_msg", "success");
        }
    }
    out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    send_http_nocopy_rsp(c, 200, out, strlen(out));
    return 0;
}

static int on_fc_get_curve(c6_conn_pt c) {
    char* debug = NULL;
    int ret_code = 0;
    char* out = NULL;
    cJSON* root = NULL, *kv = NULL, *cj = NULL;
    char sql[1024];
    int cvid = 0;
    MYSQL_RES* res = NULL;
    int row_c = 0;
    MYSQL_ROW row;

    if (0 == memcmp(c->method, "POST", sizeof("POST")-1)) {
        http_post_req_param(c->header, c->body_recv_buf, c->content_length);
        debug = cJSON_Print(c->header);
        Info("%s(%d): \n%s\n", __FUNCTION__, __LINE__, debug);
        free(debug);
    }

    kv = cJSON_GetObjectItem_EX(c->header, "param.kv");
    if (NULL == kv) {
        send_http_simple_rsp(c, 400, "parameter wrong");
        return -1;
    }
    cj = cJSON_GetObjectItem_EX(kv, "cvid");
    if (NULL != cj)
        cvid = atoi(cj->valuestring);

    root = cJSON_CreateObject();

    safe_snprintf(sql, sizeof(sql)-1, 
            "select id, name, curve_data from curve where id=%d", cvid); 
    if (0 != mysql_query(glo.db, sql)) {
        Error("%s(%d): Query failed. error: %s\n", __FUNCTION__, __LINE__, mysql_error(glo.db));
        cJSON_AddNumberToObject(root, "ret_code", -1);
        cJSON_AddStringToObject(root, "ret_msg", mysql_error(glo.db));
        mysql_close(glo.db);
        glo.db = NULL;
    }
    else {
        res = mysql_store_result(glo.db);
        row = mysql_fetch_row(res);
        row_c = mysql_num_rows(res);
        if (1 == row_c) {
            // json
            cJSON_AddNumberToObject(root, "ret_code", ret_code);
            cJSON_AddStringToObject(root, "ret_msg", "success");
            cJSON_AddNumberToObject(root, "id", atoi(row[0]));
            cJSON_AddStringToObject(root, "name", row[1]);
            cJSON_AddStringToObject(root, "data", row[2]);
        }
        else {
            Error("%s(%d): can't find curve_data where cvid=%d\n", __FUNCTION__, __LINE__, cvid);
            cJSON_AddNumberToObject(root, "ret_code", -1);
            cJSON_AddStringToObject(root, "ret_msg", "no data");
        }
    }
    out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    send_http_nocopy_rsp(c, 200, out, strlen(out));
    return 0;
}

static int do_work(c6_conn_pt c) {
    write_access_log(c);

    if (NULL == glo.db) {
        glo.db = connect_mysql(&glo.db_info);
    }
    else if (0 == mysql_ping(glo.db)) {
        mysql_close(glo.db);
        glo.db = connect_mysql(&glo.db_info);
    }
    else {
    }
    
    char* cmd = cJSON_GetObjectItem_EX(c->header, "cmd")->valuestring;
    int n = strlen(cmd);
    if ((n == sizeof("/test")-1) && (0 == memcmp(cmd, "/test", sizeof("/test")-1)))
        on_test(c);
    else if ((n == sizeof("/test_tc")-1) && (0 == memcmp(cmd, "/test_tc", sizeof("/test_tc")-1)))
        on_test_tc(c);
    else if ((n == sizeof("/test_sq")-1) && (0 == memcmp(cmd, "/test_sq", sizeof("/test_sq")-1)))
        on_test_sq(c);
    else if ((n == sizeof("/fc/login")-1) && (0 == memcmp(cmd, "/fc/login", sizeof("/fc/login")-1)))
        on_fc_login(c);
    else if ((n == sizeof("/fc/info")-1) && (0 == memcmp(cmd, "/fc/info", sizeof("/fc/info")-1)))
        on_fc_info(c);
    else if ((n == sizeof("/fc/create_curve")-1) && (0 == memcmp(cmd, "/fc/create_curve", sizeof("/fc/create_curve")-1)))
        on_fc_create_curve(c);
    else if ((n == sizeof("/fc/set_curve")-1) && (0 == memcmp(cmd, "/fc/set_curve", sizeof("/fc/set_curve")-1)))
        on_fc_set_curve(c);
    else if ((n == sizeof("/fc/get_curve")-1) && (0 == memcmp(cmd, "/fc/get_curve", sizeof("/fc/get_curve")-1)))
        on_fc_get_curve(c);
    else
        return 400;
    return 200;
}

static int send_subreq_http_req(c6_conn_pt c) {
    if (c->sockfd < 0)
        return 0;
    dyn_buf buf;

    init_buffer(&buf, 1024);
    http_create_request_header(c->header, &buf);
    c->head_bytes_to_send = get_buffer_len(&buf);
    safe_memcpy(c->send_buf, sizeof(c->send_buf), get_buffer(&buf), c->head_bytes_to_send);

    c->is_sent_header = 0;
    c->body_bytes_to_send = 0;
    c->bytes_sent = 0;

    ev_io_init(&c->write_ev, subreq_send_cb, c->sockfd, EV_WRITE);
    ev_io_start(glo.loop, &c->write_ev);
    return 0;
}

static int send_http_rsp(c6_conn_pt c, int status) {
    if (c->sockfd < 0)
        return 0;
    dyn_buf buf;

    init_buffer(&buf, 1024);
    http_create_rsponse_header(c->rsp_header, &buf);
    c->head_bytes_to_send = get_buffer_len(&buf);
    safe_memcpy(c->send_buf, sizeof(c->send_buf), get_buffer(&buf), c->head_bytes_to_send);

    c->body_bytes_to_send = c->content_length;
    c->is_sent_header = 0;
    c->bytes_sent = 0;
    c->status = status;

    ev_io_init(&c->write_ev, client_send_cb, c->sockfd, EV_WRITE);
    ev_io_start(glo.loop, &c->write_ev);
    return 0;
}

static int send_http_nocopy_rsp(c6_conn_pt c, int status, char* out, int len) {
    char first_line[256];

    c->body_send_buf = out;
    c->content_length = len;
    safe_snprintf(first_line, sizeof(first_line)-1, "HTTP/1.1 %d %s", 200, DESC_200);
    c->rsp_header = cJSON_CreateObject();
    cJSON_AddStringToObject(c->rsp_header, "first_line", first_line);
    cJSON_AddStringToObject(c->rsp_header, "Content-Type", "application/json;charset=UTF-8");
    cJSON_AddStringToObject(c->rsp_header, "Server", C6_SERVER);
    if (c->is_keepalive)
        cJSON_AddStringToObject(c->rsp_header, "Connection", "keep-alive");
    else
        cJSON_AddStringToObject(c->rsp_header, "Connection", "close");
    cJSON_AddNumberToObject(c->rsp_header, "Content-Length", c->content_length);

    send_http_rsp(c, 200);
    return 0;
}

static int send_http_simple_rsp(c6_conn_pt c, int status, char* out) {
    if (c->sockfd < 0)
        return 0;
    dyn_buf buf;
    char first_line[256];
    init_buffer(&buf, 1024);

    char* desc = NULL;
    switch (status) {
        case 200:
            desc = DESC_200;
            break;
        case 206:
            desc = DESC_206;
            break;
        case 302:
            desc = DESC_302;
            break;
        case 304:
            desc = DESC_304;
            break;
        case 400:
            desc = DESC_400;
            break;
        case 403:
            desc = DESC_403;
            break;
        case 404:
            desc = DESC_404;
            break;
        case 408:
            desc = DESC_408;
            break;
        case 500:
            desc = DESC_500;
            break;
        case 501:
            desc = DESC_501;
            break;
        case 503:
            desc = DESC_503;
            break;
        default:
            desc = other_desc;
            break;
    }
    safe_snprintf(first_line, sizeof(first_line)-1, "HTTP/1.1 %d %s", status, desc);
    c->rsp_header = cJSON_CreateObject();
    cJSON_AddStringToObject(c->rsp_header, "first_line", first_line);
    cJSON_AddStringToObject(c->rsp_header, "Content-Type", "text/plain;charset=UTF-8");
    cJSON_AddStringToObject(c->rsp_header, "Server", C6_SERVER);
    if (c->is_keepalive)
        cJSON_AddStringToObject(c->rsp_header, "Connection", "keep-alive");
    else
        cJSON_AddStringToObject(c->rsp_header, "Connection", "close");
    if (NULL == out) {
        c->content_length = 0;
    }
    else {
        c->content_length = strlen(out);
        c->body_send_buf = (char*)malloc(c->content_length);
        if (NULL == c->body_send_buf) {
            Error("%s(%d): malloc %d bytes failed\n", 
                    __FUNCTION__, __LINE__, c->content_length);
            c->do_close(c);
            return -5;
        }
        memcpy(c->body_send_buf, out,  c->content_length);
    }
    if (c->content_length > 0)
        cJSON_AddNumberToObject(c->rsp_header, "Content-Length", c->content_length);
    http_create_rsponse_header(c->rsp_header, &buf);
    c->head_bytes_to_send = get_buffer_len(&buf);
    safe_memcpy(c->send_buf, sizeof(c->send_buf), get_buffer(&buf), c->head_bytes_to_send);
    c->body_bytes_to_send = c->content_length;
    c->bytes_sent = 0;
    c->status = status;
    
    ev_io_init(&c->write_ev, client_send_cb, c->sockfd, EV_WRITE);
    ev_io_start(glo.loop, &c->write_ev);
    return 0;
}

static bool is_complete_http_req_header(c6_conn_pt c) {
    cJSON* json = NULL;
    char* ip = NULL;
    char* debug = NULL;

    c->header = http_parse_request_header(c->recv_buf, c->bytes_recved);
    if (NULL == c->header)
        return false;
    // record real ip
    if (NULL != (json = cJSON_GetObjectItem_EX(c->header, "client_ip"))) {
        ip = json->valuestring;
        safe_memcpy_0(c->real_ip, sizeof(c->real_ip)-1, ip, strlen(ip));
    }
    else if (NULL != (json = cJSON_GetObjectItem_EX(c->header, "x-forwarded-for"))) {
        ip = json->valuestring;
        safe_memcpy_0(c->real_ip, sizeof(c->real_ip)-1, ip, strlen(ip));
    }
    else {
        ip = inet_ntoa(c->client_addr.sin_addr);
        safe_memcpy_0(c->real_ip, sizeof(c->real_ip)-1, ip, strlen(ip));
    }
    json = cJSON_GetObjectItem_EX(c->header, "Connection");
    if (NULL == json)
        c->is_keepalive = 0;
    else if (0 == memcmp(json->valuestring, "keep-alive", sizeof("keep-alive")-1))
        c->is_keepalive = 1;
    else
        c->is_keepalive = 0;
    
    json = cJSON_GetObjectItem_EX(c->header, "header-length");
    c->head_length = json->valueint;

    json = cJSON_GetObjectItem_EX(c->header, "Content-Length");
    if (NULL != json)
        c->content_length = atoi(json->valuestring);

    json = cJSON_GetObjectItem_EX(c->header, "method");
    safe_memcpy_0(c->method, sizeof(c->method)-1, json->valuestring, strlen(json->valuestring));

    debug = cJSON_Print(c->header);
    Info("%s(%d): \n%s\n", __FUNCTION__, __LINE__, debug);
    free(debug);
    return true;
}

static bool is_complete_http_rsp_header(c6_conn_pt c) {
    cJSON* json = NULL;
    char* ip = NULL;
    char* debug = NULL;

    c->rsp_header = http_parse_response_header(c->recv_buf, c->bytes_recved);
    if (NULL == c->rsp_header)
        return false;
    // record real ip
    if (NULL != (json = cJSON_GetObjectItem_EX(c->rsp_header, "client_ip"))) {
        ip = json->valuestring;
        safe_memcpy_0(c->real_ip, sizeof(c->real_ip)-1, ip, strlen(ip));
    }
    else if (NULL != (json = cJSON_GetObjectItem_EX(c->rsp_header, "x-forwarded-for"))) {
        ip = json->valuestring;
        safe_memcpy_0(c->real_ip, sizeof(c->real_ip)-1, ip, strlen(ip));
    }
    else {
        ip = inet_ntoa(c->client_addr.sin_addr);
        safe_memcpy_0(c->real_ip, sizeof(c->real_ip)-1, ip, strlen(ip));
    }
    json = cJSON_GetObjectItem_EX(c->rsp_header, "Connection");
    if (NULL == json)
        c->is_keepalive = 0;
    else if (0 == memcmp(json->valuestring, "keep-alive", sizeof("keep-alive")-1))
        c->is_keepalive = 1;
    else
        c->is_keepalive = 0;
    
    json = cJSON_GetObjectItem_EX(c->rsp_header, "header-length");
    c->head_length = json->valueint;

    json = cJSON_GetObjectItem_EX(c->rsp_header, "Content-Length");
    if (NULL != json)
        c->content_length = atoi(json->valuestring);

    debug = cJSON_Print(c->rsp_header);
    Info("%s(%d): \n%s\n", __FUNCTION__, __LINE__, debug);
    free(debug);
    return true;
}

static int do_proxy_recv_body(c6_conn_pt c) {
    int ret = 0;
    int left = 0;
    c6_conn_pt client = NULL;
    
    client = take_conn(c->e_sockfd, c->e_session_id);
    if (NULL == client) {
        Error("%s(%d): client(%d,%d) is changed, discard this response\n", 
                __FUNCTION__, __LINE__, c->e_sockfd, c->e_session_id);
        c->do_close(c);
        return -1;
    }
    left = default_proxy_buf_size - client->body_bytes_to_send;
    ret = recv(c->sockfd, client->body_send_buf+client->body_bytes_to_send, left, 0);
    if (ret < 0) {
        if (EAGAIN == errno || EINTR == errno) {
            Info("%s(%d): recv(%d,%d) not ready\n", __FUNCTION__, __LINE__, c->sockfd, left);
            return -2;
        }
        Error("%s(%d): recv(%d,%d) failed. error(%d): %s\n", 
                __FUNCTION__, __LINE__, c->sockfd, left, errno, strerror(errno));
        c->do_close(c);
        return -3 ;
    }
    else if (0 == ret) {
        // peer close
        // Error("%s(%d): recv(%d,%d) return 0, peer closed\n", __FUNCTION__, __LINE__, c->sockfd, left);
        c->do_close(c);
        return -4;
    }
    else {
        // ok get some data
        client->active_at = c->active_at = now();
        client->body_bytes_to_send += ret;
        c->bytes_recved += ret;
        if (c->bytes_recved == (c->head_length + c->content_length))
            c->do_close(c);
    }
    return 0;
}

static int do_proxy_recv_header(c6_conn_pt c) {
    int ret = 0;
    int left = 0;
    c6_conn_pt client = NULL;
    int more = 0;

    left = sizeof(c->recv_buf) - c->bytes_recved;
    ret = recv(c->sockfd, c->recv_buf+c->bytes_recved, left, 0);
    if (ret < 0) {
        if (EAGAIN == errno || EINTR == errno) {
            Info("%s(%d): recv(%d,%d) not ready\n", __FUNCTION__, __LINE__, c->sockfd, left);
            return -1;
        }
        Error("%s(%d): recv(%d,%d) failed. error(%d): %s\n", 
                __FUNCTION__, __LINE__, c->sockfd, left, errno, strerror(errno));
        c->do_close(c);
        return -2;
    }
    else if (0 == ret) {
        // peer close
        // Error("%s(%d): recv(%d,%d) return 0, peer closed\n", __FUNCTION__, __LINE__, c->sockfd, left);
        c->do_close(c);
        return -3;
    }
    else {
        // ok get some data
        c->active_at = now();
        c->bytes_recved += ret;

        // if a complete http package?
        if (is_complete_http_rsp_header(c)) {
            client = take_conn(c->e_sockfd, c->e_session_id);
            if (NULL == client) {
                Error("%s(%d): client(%d,%d) is changed, discard this response\n", 
                        __FUNCTION__, __LINE__, c->e_sockfd, c->e_session_id);
                c->do_close(c);
                return -4;
            }
            client->body_send_buf = (char*)malloc(default_proxy_buf_size);
            if (NULL == client->body_send_buf) {
                Error("%s(%d): malloc %d bytes failed\n", 
                        __FUNCTION__, __LINE__, default_proxy_buf_size);
                c->do_close(c);
                return -5;
            }
            c->is_recvd_header = 1;
            memcpy(client->send_buf, c->recv_buf, c->head_length);
            client->head_bytes_to_send = c->head_length;

            more = c->bytes_recved - c->head_length;
            memcpy(client->body_send_buf, c->recv_buf+c->head_length, more);
            client->content_length = c->content_length;
            client->body_bytes_to_send = more;
            client->bytes_sent = 0;
            client->is_sent_header = 0;
            ev_io_init(&client->write_ev, client_send_cb, client->sockfd, EV_WRITE);
            ev_io_start(glo.loop, &client->write_ev);
        }
        else if (ret == left) {
            // wrong requst
            Error("%s(%d): recv_buf(%d,%lu) is full, but not find http header ending, illegal request\n", 
                    __FUNCTION__, __LINE__, c->sockfd, sizeof(c->recv_buf));
            c->do_close(c);
            return -6;
        }
    }
    return 0;
}

static void proxy_recv_cb(EV_P_ ev_io *w, int revents) {
    c6_conn_pt c = &(glo.cs[w->fd]);
    if (0 == c->is_recvd_header)
        do_proxy_recv_header(c);
    else
        do_proxy_recv_body(c);
    return;
}

static void proxy_send_cb(EV_P_ ev_io *w, int revents) {
    c6_conn_pt c = &(glo.cs[w->fd]);
    if (0 == c->is_sent_header)
        do_proxy_send_header(c);
    else {
        ev_io_stop(glo.loop, &c->write_ev);
        ev_io_init(&c->read_ev, proxy_recv_cb, c->sockfd, EV_READ);
        ev_io_start(glo.loop, &c->read_ev);
    }
    return;
}

static int do_proxy_send_header(c6_conn_pt c)
{
    int ret = 0;
    long long need_send = 0;

    need_send = c->head_bytes_to_send - c->bytes_sent;
    ret = send(c->sockfd, c->send_buf+c->bytes_sent, need_send, 0);
    if (ret < 0) {
        if (EAGAIN == errno || EINTR == errno) {
            Info("%s(%d): send(%d,%lld) not ready\n", __FUNCTION__, __LINE__, c->sockfd, need_send);
            return 0;
        }
        Error("%s(%d): send(%d,%lld) failed. error(%d): %s\n", 
                __FUNCTION__, __LINE__, c->sockfd, need_send, errno, strerror(errno));
        c->do_close(c);
        return -1;
    }
    else {
        // ok get some data
        c->active_at = now();
        c->bytes_sent += ret;
        if (c->bytes_sent == c->head_bytes_to_send) {
            Info("%s(%d): %s+%d, http header is sent\n", 
                    __FUNCTION__, __LINE__, c->access_time, now()/1000 - c->begin_ms);
            // head over, now body
            c->bytes_sent = 0;
            c->is_sent_header = 1;
        }
    }
    return 0;
}

static void do_proxy_close(c6_conn_pt c) {
    free_conn(c);
    return;
}

static int do_subreq_recv_body(c6_conn_pt c) {
    int ret = 0;
    int left = 0;
    c6_conn_pt client = NULL;
    
    left = c->content_length - c->bytes_recved;
    ret = recv(c->sockfd, c->body_recv_buf+c->bytes_recved, left, 0);
    if (ret < 0) {
        if (EAGAIN == errno || EINTR == errno) {
            Info("%s(%d): recv(%d,%d) not ready\n", __FUNCTION__, __LINE__, c->sockfd, left);
            return -2;
        }
        Error("%s(%d): recv(%d,%d) failed. error(%d): %s\n", 
                __FUNCTION__, __LINE__, c->sockfd, left, errno, strerror(errno));
        c->do_close(c);
        return -3 ;
    }
    else if (0 == ret) {
        // peer close
        // Error("%s(%d): recv(%d,%d) return 0, peer closed\n", __FUNCTION__, __LINE__, c->sockfd, left);
        c->do_close(c);
        return -4;
    }
    else {
        // ok get some data
        c->active_at = now();
        c->bytes_recved += ret;
        if (c->bytes_recved == c->content_length) {
            // finish subreq, we handle the response from subreq, and prepare response for client
            // here, we just send `ok`, you may replace it by your code
            client = take_conn(c->e_sockfd, c->e_session_id);
            if (NULL == client) {
                Error("%s(%d): client(%d,%d) is changed, discard this response\n", 
                        __FUNCTION__, __LINE__, c->e_sockfd, c->e_session_id);
                c->do_close(c);
                return -1;
            }
            send_http_simple_rsp(client, 200, c->body_recv_buf);
        }
    }
    return 0;
}

static int do_subreq_recv_header(c6_conn_pt c) {
    int ret = 0;
    int left = 0;
    int more = 0;

    left = sizeof(c->recv_buf) - c->bytes_recved;
    ret = recv(c->sockfd, c->recv_buf+c->bytes_recved, left, 0);
    if (ret < 0) {
        if (EAGAIN == errno || EINTR == errno) {
            Info("%s(%d): recv(%d,%d) not ready\n", __FUNCTION__, __LINE__, c->sockfd, left);
            return -1;
        }
        Error("%s(%d): recv(%d,%d) failed. error(%d): %s\n", 
                __FUNCTION__, __LINE__, c->sockfd, left, errno, strerror(errno));
        c->do_close(c);
        return -2;
    }
    else if (0 == ret) {
        // peer close
        // Error("%s(%d): recv(%d,%d) return 0, peer closed\n", __FUNCTION__, __LINE__, c->sockfd, left);
        c->do_close(c);
        return -3;
    }
    else {
        // ok get some data
        c->active_at = now();
        c->bytes_recved += ret;

        // if a complete http package?
        if (is_complete_http_rsp_header(c)) {
            c->body_recv_buf = (char*)malloc(c->content_length);
            if (NULL == c->body_recv_buf) {
                Error("%s(%d): malloc %d bytes failed\n", 
                        __FUNCTION__, __LINE__, c->content_length);
                c->do_close(c);
                return -5;
            }
            c->is_recvd_header = 1;
            more = c->bytes_recved - c->head_length;
            memcpy(c->body_recv_buf, c->recv_buf+c->head_length, more);
            c->bytes_recved = more;
        }
        else if (ret == left) {
            // wrong requst
            Error("%s(%d): recv_buf(%d,%lu) is full, but not find http header ending, illegal request\n", 
                    __FUNCTION__, __LINE__, c->sockfd, sizeof(c->recv_buf));
            c->do_close(c);
            return -6;
        }
    }
    return 0;
}

static void subreq_recv_cb(EV_P_ ev_io *w, int revents) {
    c6_conn_pt c = &(glo.cs[w->fd]);
    if (0 == c->is_recvd_header)
        do_subreq_recv_header(c);
    else
        do_subreq_recv_body(c);
    return;
}

static void subreq_send_cb(EV_P_ ev_io *w, int revents) {
    c6_conn_pt c = &(glo.cs[w->fd]);
    if (0 == c->is_sent_header)
        do_subreq_send_header(c);
    else {
        ev_io_stop(glo.loop, &c->write_ev);
        ev_io_init(&c->read_ev, subreq_recv_cb, c->sockfd, EV_READ);
        ev_io_start(glo.loop, &c->read_ev);
    }
    return;
}

static int do_subreq_send_header(c6_conn_pt c)
{
    int ret = 0;
    long long need_send = 0;

    need_send = c->head_bytes_to_send - c->bytes_sent;
    ret = send(c->sockfd, c->send_buf+c->bytes_sent, need_send, 0);
    if (ret < 0) {
        if (EAGAIN == errno || EINTR == errno) {
            Info("%s(%d): send(%d,%lld) not ready\n", __FUNCTION__, __LINE__, c->sockfd, need_send);
            return 0;
        }
        Error("%s(%d): send(%d,%lld) failed. error(%d): %s\n", 
                __FUNCTION__, __LINE__, c->sockfd, need_send, errno, strerror(errno));
        c->do_close(c);
        return -1;
    }
    else {
        // ok get some data
        c->active_at = now();
        c->bytes_sent += ret;
        if (c->bytes_sent == c->head_bytes_to_send) {
            Info("%s(%d): %s+%d, http header is sent\n", 
                    __FUNCTION__, __LINE__, c->access_time, now()/1000 - c->begin_ms);
            // head over, now body
            c->bytes_sent = 0;
            c->is_sent_header = 1;
        }
    }
    return 0;
}

static void do_subreq_close(c6_conn_pt c) {
    free_conn(c);
    return;
}

static void client_recv_cb(EV_P_ ev_io *w, int revents) {
    c6_conn_pt c = &(glo.cs[w->fd]);
    if (0 == c->is_recvd_header)
        do_client_recv_header(c);
    else
        do_client_recv_body(c);
    return;
}

static int do_client_recv_body(c6_conn_pt c) {
    int ret = 0;
    int left = 0;
    int status = 0;
    
    left = c->content_length - c->bytes_recved;
    ret = recv(c->sockfd, c->body_recv_buf+c->bytes_recved, left, 0);
    if (ret < 0) {
        if (EAGAIN == errno || EINTR == errno) {
            Info("%s(%d): recv(%d,%d) not ready\n", __FUNCTION__, __LINE__, c->sockfd, left);
            return -2;
        }
        Error("%s(%d): recv(%d,%d) failed. error(%d): %s\n", 
                __FUNCTION__, __LINE__, c->sockfd, left, errno, strerror(errno));
        c->do_close(c);
        return -3 ;
    }
    else if (0 == ret) {
        // peer close
        // Error("%s(%d): recv(%d,%d) return 0, peer closed\n", __FUNCTION__, __LINE__, c->sockfd, left);
        c->do_close(c);
        return -4;
    }
    else {
        // ok get some data
        c->active_at = now();
        c->bytes_recved += ret;
        if (c->bytes_recved == c->content_length) {
            status = do_work(c);
            if (status != 200) {
                Error("%s(%d): ret %d, failed\n", __FUNCTION__, __LINE__, status);
                send_http_simple_rsp(c, status, NULL);
            }
        }
    }
    return 0;
}

static int do_client_recv_header(c6_conn_pt c) {
    int ret = 0;
    int left = 0;
    int status = 0;
    int more = 0;

    left = sizeof(c->recv_buf) - c->bytes_recved;
    ret = recv(c->sockfd, c->recv_buf+c->bytes_recved, left, 0);
    if (ret < 0) {
        if (EAGAIN == errno || EINTR == errno) {
            Info("%s(%d): recv(%d,%d) not ready\n", __FUNCTION__, __LINE__, c->sockfd, left);
            return 0;
        }
        Error("%s(%d): recv(%d,%d) failed. error(%d): %s\n", 
                __FUNCTION__, __LINE__, c->sockfd, left, errno, strerror(errno));
        c->do_close(c);
        return -1;
    }
    else if (0 == ret) {
        // peer close
        // Error("%s(%d): recv(%d,%d) return 0, peer closed\n", __FUNCTION__, __LINE__, c->sockfd, left);
        c->do_close(c);
        return -2;
    }
    else {
        // ok get some data
        c->active_at = now();
        c->bytes_recved += ret;

        // if a complete http package?
        if (is_complete_http_req_header(c)) {
            c->is_recvd_header = 1;
            if (0 == memcmp(c->method, "GET", sizeof("GET")-1)) {
                status = do_work(c);
                if (status != 200) {
                    Error("%s(%d): ret %d, failed\n", __FUNCTION__, __LINE__, status);
                    send_http_simple_rsp(c, status, NULL);
                    return -3;
                }
            }
            else if (0 == memcmp(c->method, "POST", sizeof("POST")-1)) {
                c->body_recv_buf = (char*)malloc(c->content_length);
                if (NULL == c->body_recv_buf) {
                    Error("%s(%d): malloc %d bytes failed\n", 
                            __FUNCTION__, __LINE__, c->content_length);
                    c->do_close(c);
                    return -4;
                }
                more = c->bytes_recved - c->head_length;
                memcpy(c->body_recv_buf, c->recv_buf+c->head_length, more);
                c->bytes_recved = more;
                if (c->bytes_recved == c->content_length) {
                    status = do_work(c);
                    if (status != 200) {
                        Error("%s(%d): ret %d, failed\n", __FUNCTION__, __LINE__, status);
                        send_http_simple_rsp(c, status, NULL);
                        return -5;
                    }
                }
            }
            else {
                send_http_simple_rsp(c, 501, c->method);
                return -6;
            }
        }
        else if (ret == left) {
            // wrong requst
            Error("%s(%d): recv_buf(%d,%lu) is full, but not find http header ending, illegal request\n", 
                    __FUNCTION__, __LINE__, c->sockfd, sizeof(c->recv_buf));
            c->do_close(c);
        }
    }
    return 0;
}

static void do_client_close(c6_conn_pt c) {
    free_conn(c);
    return;
}

static int do_client_send_body(c6_conn_pt c) {
    int ret = 0;
    unsigned int need_send = 0;
    unsigned int bs = 0;
    ssize_t ssize;

    // send static file
    if (NULL == c->body_send_buf && c->content_length > 0) {
        need_send = c->content_length - c->bytes_sent;
        if (need_send > 0) {
            if (c->static_file_fd <= 0) {
                c->static_file_fd = open(c->static_file, O_RDONLY);
                if (-1 == c->static_file_fd) {
                    Error("%s(%d): open(%s) failed, error(%d):%s\n", 
                            __FUNCTION__, __LINE__, c->static_file, errno, strerror(errno));
                    return -1;
                }
            }
            ssize = sendfile(c->sockfd, c->static_file_fd, &c->offset, c->content_length);
            if (-1 == ssize) {
                if (EAGAIN == errno || EINTR == errno) {
                    Info("%s(%d): send(%d,%u) not ready\n", __FUNCTION__, __LINE__, c->sockfd, need_send);
                    return 0;
                }
                c->do_close(c);
                return -1;
            }
            else {
                c->active_at = now();
                c->bytes_sent = c->offset;
                if (c->bytes_sent == c->content_length) {
                    Info("%s(%d): %s+%d, http body is sent\n", 
                            __FUNCTION__, __LINE__, c->access_time, now()/1000 - c->begin_ms);
                    // sent all
                    if (c->is_keepalive) {
                        reset_conn(c);
                        ev_io_stop(glo.loop, &c->write_ev);
                        ev_io_init(&c->read_ev, client_recv_cb, c->sockfd, EV_READ);
                        ev_io_start(glo.loop, &c->read_ev);
                    }
                    else{
                        c->do_close(c);
                    }
                }
            }
        }
        return 0;
    }

    // send memory buffer
    need_send = c->content_length - c->bytes_sent;
    bs = c->body_bytes_to_send;
    need_send = need_send > bs ? bs : need_send;
    ret = send(c->sockfd, c->body_send_buf, need_send, 0);
    if (ret < 0) {
        if (EAGAIN == errno || EINTR == errno) {
            Info("%s(%d): send(%d,%u) not ready\n", __FUNCTION__, __LINE__, c->sockfd, need_send);
            return 0;
        }
        Error("%s(%d): send(%d,%u) failed. error(%d): %s\n", 
                __FUNCTION__, __LINE__, c->sockfd, need_send, errno, strerror(errno));
        c->do_close(c);
        return -1;
    }
    else {
        // ok get some data
        c->active_at = now();
        c->bytes_sent += ret;
        c->body_bytes_to_send -= ret;
        memmove(c->body_send_buf, c->body_send_buf+ret, c->body_bytes_to_send);
        if (c->bytes_sent == c->content_length) {
            Info("%s(%d): %s+%d, http body is sent\n", 
                    __FUNCTION__, __LINE__, c->access_time, now()/1000 - c->begin_ms);
            // sent all
            if (c->is_keepalive) {
                reset_conn(c);
                ev_io_stop(glo.loop, &c->write_ev);
            }
            else {
                c->do_close(c);
            }
        }
    }
    return 0;
}

static int do_client_send_header(c6_conn_pt c)
{
    int ret = 0;
    long long need_send = 0;

    need_send = c->head_bytes_to_send - c->bytes_sent;
    ret = send(c->sockfd, c->send_buf+c->bytes_sent, need_send, 0);
    if (ret < 0) {
        if (EAGAIN == errno || EINTR == errno) {
            Info("%s(%d): send(%d,%lld) not ready\n", __FUNCTION__, __LINE__, c->sockfd, need_send);
            return 0;
        }
        Error("%s(%d): send(%d,%lld) failed. error(%d): %s\n", 
                __FUNCTION__, __LINE__, c->sockfd, need_send, errno, strerror(errno));
        c->do_close(c);
        return -1;
    }
    else {
        // ok get some data
        c->active_at = now();
        c->bytes_sent += ret;
        if (c->bytes_sent == c->head_bytes_to_send) {
            Info("%s(%d): %s+%d, http header is sent\n", 
                    __FUNCTION__, __LINE__, c->access_time, now()/1000 - c->begin_ms);
            // head over, now body
            c->bytes_sent = 0;
            c->is_sent_header = 1;
        }
    }
    return 0;
}

static void client_send_cb(EV_P_ ev_io *w, int revents) {
    c6_conn_pt c = &(glo.cs[w->fd]);
    if (0 == c->is_sent_header)
        do_client_send_header(c);
    else
        do_client_send_body(c);
    return;
}

static void accept_cb(EV_P_ ev_io *w, int revents)
{
    int sockfd = 0;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    c6_conn_pt c = NULL;

    sockfd = accept(w->fd, (struct sockaddr*)&addr, &addr_len);
    if (sockfd < 0) {
        Error("%s(%d): accept() failed. error(%d): %s\n", 
                __FUNCTION__, __LINE__,  errno, strerror(errno));
        return;
    }
    if (sockfd >= MAX_SOCKET) {
        Error("%s(%d): socket(%d) is bigger than MAX_SOCKET(%d), close it.\n",
                __FUNCTION__, __LINE__, sockfd, MAX_SOCKET);
        close(sockfd);
        return;
    }
    c = make_conn(sockfd, sock_type_client);
    memcpy(&c->client_addr, &addr, sizeof(struct sockaddr_in));
    return;
}

static int create_listener(struct sockaddr_in* a) {
    int sockfd = -1;
    int nb = 1;

    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (-1 == sockfd) {
        Error("%s(%d): socket() failed. error(%d): %s\n", __FUNCTION__, __LINE__, errno, strerror(errno));
        return -1;
    }
    if (ioctl(sockfd, FIONBIO, &nb)) {
        Error("%s(%d): ioctl(FIONBIO) failed. error(%d): %s\n", __FUNCTION__, __LINE__, errno, strerror(errno));
        close(sockfd);
        return -2;
    }
    if (-1 == setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &nb, sizeof(nb))) {
        Error("%s(%d): setsockopt(SO_REUSEADDR) failed. error(%d): %s\n", __FUNCTION__, __LINE__, errno, strerror(errno));
        close(sockfd);
        return -3;
    }
    if (-1 == bind(sockfd, (struct sockaddr*)a, sizeof(struct sockaddr_in))) {
        Error("%s(%d): bind(%s:%hu) failed. error(%d): %s\n", 
                __FUNCTION__, __LINE__, inet_ntoa(a->sin_addr), ntohs(a->sin_port), errno, strerror(errno));
        close(sockfd);
        return -4;
    }
    if (-1 == listen(sockfd, SOMAXCONN)) {
        Error("%s(%d): listen(%d) failed. error(%d): %s\n", __FUNCTION__, __LINE__, SOMAXCONN, errno, strerror(errno));
        close(sockfd);
        return -5;
    }
    return sockfd;
}

static int get_cpu_num(void) {
    FILE* f = NULL;
    char buf[64];
    int cpu_num = 0;

    const char* cmd = "cat /proc/cpuinfo | grep processor | wc -l";
    memset(buf, 0x00, sizeof(buf));
    f = popen(cmd, "r");
    if (NULL == f) {
        Error("%s(%d): popen(%s) failed. error(%d): %s\n", __FUNCTION__, __LINE__, cmd, errno, strerror(errno));
        return cpu_num;
    }
    if (NULL != fgets(buf, sizeof(buf)-1, f)) {
        cpu_num = atoi(buf);
    }
    if (NULL != f) {
        pclose(f);
        f = NULL;
    }
    Info("%s(%d): the num of cpu: %d\n", __FUNCTION__, __LINE__, cpu_num);
    return cpu_num;
}

static MYSQL* connect_mysql(db_info_s* di) {
    MYSQL* db = NULL;
    char value = 1;

    if (NULL == (db = mysql_init(NULL))) {
        Error("%s(%d): mysql is NULL, mysql_init() failed\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    if (!mysql_real_connect(db, di->db_host, di->db_user, di->db_passwd, di->db_name, 0, NULL, 0)) {
        Error("%s(%d): Couldn't cect to mysql(host:%s,user:%s,passwd:%s,dbname:%s)!\nerror: %s\n",
                __FUNCTION__, __LINE__, di->db_host, di->db_user, di->db_passwd, di->db_name, mysql_error(db));
        mysql_close(db);
        return NULL;
    }
    // set auto-recect
    mysql_options(db, MYSQL_OPT_RECONNECT, (char*)&value);

    if (0 != mysql_query(db, "set names utf8")) {
        Error("%s(%d): Query set names gbk failed. error: %s\n", __FUNCTION__, __LINE__, mysql_error(db));
        mysql_close(db);
        return NULL;
    }
    return db;
}


static int init(int argc, char* argv[]) {
    FILE* fp = NULL;
    char line[1024];
    char name[128];
    char value[128];
    char path[256] = {0};
    int cn = 0;
    int lightn = 0;
    int tcn = 0;

    safe_snprintf(path, sizeof(path)-1, "%s.conf", argv[0]);
    fp = fopen(path, "r");
    if (NULL == fp) {
        printf("%s(%d): fopen(%s) failed. error(%d): %s\n", __FUNCTION__, __LINE__, path, errno, strerror(errno));  
        return -1;
    }
    while (NULL != fgets(line, 1024, fp)) {
        if ('#' == line[0] || 0 == strcmp(line, ""))
            continue;
        memset(name, 0x00, sizeof(name));
        memset(value, 0x00, sizeof(value));

        sscanf(line, "%s %s", name, value);
        if (0 == strcmp(name, "LISTEN"))
            strcpy(glo.listen_ip, value);
        else if (0 == strcmp(name, "PORT"))
            glo.listen_port = atoi(value);
        else if (0 == strcmp(name, "TC_PORT"))
            glo.tc_worker_port = atoi(value);
        else if (0 == strcmp(name, "LOG"))
            strcpy(glo.log_path, value);
        else if (0 == strcmp(name, "ACCESS_LOG"))
            strcpy(glo.access_log_path, value);
        else if (0 == strcmp(name, "LIGHT_WORKER_NUM"))
            lightn = atoi(value);
        else if (0 == strcmp(name, "TC_WORKER_NUM"))
            tcn = atoi(value);
        else if (0 == strcmp(name, "DB_HOST"))
            strcpy(glo.db_info.db_host, value);
        else if (0 == strcmp(name, "DB_USER"))
            strcpy(glo.db_info.db_user, value);
        else if (0 == strcmp(name, "DB_PASSWD"))
            strcpy(glo.db_info.db_passwd, value);
        else if (0 == strcmp(name, "DB_NAME"))
            strcpy(glo.db_info.db_name, value);
        else 
            continue;
    }
    fclose(fp);

    cn = get_cpu_num();
    glo.light_worker_num = lightn > 0 ? (lightn > cn ? cn : lightn) : cn;
    glo.tc_worker_num = tcn > 0 ? (tcn > cn ? cn : tcn) : cn;
    printf("the cpu count:%d, LIGHT_WORKER_NUM:%d, TC_WORKER_NUM:%d, "
            "finally, light_worker_num=%d, tc_worker_num=%d\n", 
            cn, lightn, tcn, glo.light_worker_num, glo.tc_worker_num);

    // set listener
    glo.listen_addr.sin_family = AF_INET;
    glo.listen_addr.sin_addr.s_addr = inet_addr(glo.listen_ip);
    glo.listen_addr.sin_port = htons(glo.listen_port);

    set_rlimit(MAX_SOCKET);
    return 0;
}

static void timer_cb(EV_P_ ev_timer *w, int revents) {
    int i;
    static int sec_time = 0;
    // static int prev_sec = 0;
    static int idx = 0;
    int now = 0;
    c6_conn_pt p = NULL;

    now = time(NULL);
    if (now != sec_time) {   
        sec_time = now;
        for (i=0; i<MAX_SOCKET/100; ++i) {
            idx = (idx + 1) % MAX_SOCKET;
            p = &glo.cs[idx];
            if (NULL != p->do_timer) {
                p->do_timer(p);
            }
        }
    }
    return;
}

static int business_worker() {
    size_t sz = 0;
    struct ev_loop* loop = EV_DEFAULT;
    c6_conn_pt c = NULL;
    char lpath[256];

    glo.pid = getpid();
    
    // init log file
    safe_snprintf(lpath, sizeof(lpath)-1, "%s.%u", glo.log_path, glo.listen_port);
    xlog_init(lpath);

    // malloc cections
    sz = sizeof(c6_conn_t) * MAX_SOCKET;
    glo.cs = (c6_conn_pt)malloc(sz);
    if (NULL == glo.cs) {
        Error("%s(%d): malloc(%lu,%d) failed. error(%d): %s\n", 
                __FUNCTION__, __LINE__, sz, MAX_SOCKET, errno, strerror(errno));    
        return -1;
    }
    glo.conn_cnt = 0;
    Info("%s(%d): malloc(%lu) memory for %d cections\n", __FUNCTION__, __LINE__, sz, MAX_SOCKET);

    glo.loop = loop;

    c = make_conn(glo.listen_sockfd, sock_type_listen);
    Info("%s(%d): %d - %s:%d is listening...\n", __FUNCTION__, __LINE__, glo.pid, glo.listen_ip, glo.listen_port);

    // timer
    ev_timer_init(&glo.timer, timer_cb, 60, 60);
    ev_timer_start(glo.loop, &glo.timer);

    // connect db
    glo.db = connect_mysql(&glo.db_info);

    // now wait for events to arrive
    ev_run(glo.loop, 0);

    // break was called, so exit
    return 0;
}

int main(int argc, char* argv[]) {
    int ret = 0;
    int i;

    ret = init(argc, argv);
    if (ret < 0) {
        printf("%s(%d): init() failed\n", __FUNCTION__, __LINE__);
        return -1;
    }

    // daemon it
    daemon(1, 1);

    glo.role = light_worker;
    glo.listen_sockfd = create_listener(&glo.listen_addr);
    if (glo.listen_sockfd < 0) {
        printf("%s(%d): create_listener(%s:%u) failed\n", 
                __FUNCTION__, __LINE__, glo.listen_ip, glo.listen_port);
        return -2;
    }
    for (i=0; i<glo.light_worker_num; ++i) {
        ret = fork();
        if (ret < 0) {
            // failed
            return -3;
        }
        else if (ret > 0) {
            // parent
            continue;
        }
        else {
            // child
            business_worker();
            return 0;
        }
    }
    glo.role = tc_worker;
    glo.listen_port = glo.tc_worker_port;
    glo.listen_addr.sin_port = htons(glo.listen_port);
    close(glo.listen_sockfd);
    glo.listen_sockfd = socket_unused;
    glo.listen_sockfd = create_listener(&glo.listen_addr);
    if (glo.listen_sockfd < 0) {
        printf("%s(%d): create_listener(%s:%u) failed\n", 
                __FUNCTION__, __LINE__, glo.listen_ip, glo.listen_port);
        return -2;
    }
    for (i=0; i<glo.tc_worker_num; ++i) {
        ret = fork();
        if (ret < 0) {
            // failed
            return -3;
        }
        else if (ret > 0) {
            // parent
            continue;
        }
        else {
            // child
            business_worker();
            return 0;
        }
    }
    while (1)
        wait(NULL);
}
