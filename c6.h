/*
 * c6.h: a http server
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

#ifndef __C6_H_YUE_XIAOCHENG_2013_05_30_
#define __C6_H_YUE_XIAOCHENG_2013_05_30_

#ifdef __cplusplus
extern "C" 
{
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <sys/shm.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <unistd.h>
#include <time.h>
#include <sys/vfs.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <iconv.h>
#include <sys/msg.h>
#include <assert.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <stdbool.h>
#include <sys/sendfile.h>
#include <wait.h>

#include "http_protocol.h"
#include "cJSON.h"
#include "ev.h"

#define MAX_SOCKET (10000)
#define header_recv_buf_size (2*1024)
#define header_send_buf_size (2*1024)

#define default_proxy_buf_size (64*1024)

#define C6_VERSION "1.0.0"
#define C6_NAME "c6"
#define C6_SERVER C6_NAME "-" C6_VERSION

#pragma pack(1)

enum {
    socket_unused = -1,
};

typedef enum {
    sock_type_noused = 0,
    sock_type_listen,
    sock_type_client,
    sock_type_subreq,
    sock_type_proxy,
} conn_type_t;

typedef struct c6_conn_s {
    conn_type_t st;
    int sockfd;
    int session_id;
    struct sockaddr_in client_addr;

    // subreq or proxy socket 
    int e_sockfd;
    int e_session_id;

    // timestamp
    long long start_at;
    long long active_at;
    long begin_ms;
    char access_time[32]; // 20120704 16:35:00.297

    // buffer bytes
    unsigned int bytes_sent;
    unsigned int bytes_recved;

    unsigned int head_bytes_to_send;
    unsigned int body_bytes_to_send;
    unsigned int bytes_to_recv;

    // buffer for header part
    char recv_buf[header_recv_buf_size];
    char send_buf[header_send_buf_size];

    // buffer for body part
    char* body_recv_buf;
    char* body_send_buf;
    
    // for sendfile
    char static_file[256];
    int static_file_fd;
    off_t offset;

    // http protocol part
    cJSON* header;
    cJSON* rsp_header;
    int head_length;
    unsigned int content_length;
    int is_sent_header;
    int is_recvd_header;
    int status;
    bool is_keepalive;
    char real_ip[32];

    ev_io read_ev;
    ev_io write_ev;

    void (*do_timer)(struct c6_conn_s* conn);
    void (*do_close)(struct c6_conn_s* conn);
} c6_conn_t;

typedef c6_conn_t* c6_conn_pt;

#pragma pack()

#ifdef __cplusplus
}
#endif

#endif // __C6_H_YUE_XIAOCHENG_2013_05_30_

