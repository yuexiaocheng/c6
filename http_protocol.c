/*
 * http_protocol.c: http protocol parser implementation
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

#include "http_protocol.h"

// HTTP/1.1 302 Found\r\n
// version: HTTP/1.1
// code: 302
// desc: Found
// const char* p = "HTTP/1.1 302 Found\r\n"
static cJSON* http_response_first_line(const char* line, unsigned int len) {
    cJSON* header = NULL;
    char* p1 =NULL, *p2 = NULL;
    char longest[1024];
    char* e = (char*)line + len;

    p1 = (char*)line;
    header = cJSON_CreateObject();
    // parse http version
    p2 = memchr(p1, ' ', e-p1);
    if (NULL == p2)
        goto parse_failed;
    safe_memcpy_0(longest, sizeof(longest)-1, p1, p2-p1);
    cJSON_AddStringToObject(header, "version", longest);
    p1 = p2 + 1; // ` `
    // parse ret code
    p2 = memchr(p1, ' ', e-p1);
    if (NULL == p2)
        goto parse_failed;
    safe_memcpy_0(longest, sizeof(longest)-1, p1, p2-p1);
    cJSON_AddStringToObject(header, "code", longest);
    p1 = p2 + 1; // ` `
    // parse http version
    p2 = memstr(p1, e-p1, "\r\n", 2);
    if (NULL == p2)
        goto parse_failed;
    safe_memcpy_0(longest, sizeof(longest)-1, p1, p2-p1);
    cJSON_AddStringToObject(header, "desc", longest);
    
    safe_memcpy_0(longest, sizeof(longest)-1, (char*)line, p2-(char*)line);
    cJSON_AddStringToObject(header, "first_line", longest);
    return header;
parse_failed:
    cJSON_Delete(header);
    return NULL;
}

void http_parse_cookie(cJSON* header, const char* line, unsigned int len) {
    char* p3 = NULL;
    char* e2 = NULL;
    char* p4 = NULL, *p5 = NULL;
    cJSON* cookie_kv = NULL;
    char* p = NULL;
    char key[256];
    char value[2048];

    char* l = (char*)malloc(len+1);
    p = l;
    p = xcpymem(p, line, len);
    *p++ = '\0';

    p3 = l;
    e2 = p3 + len;

    cJSON_AddItemToObject(header, "cookie_kv", cookie_kv = cJSON_CreateObject());
    do {
        p4 = memchr(p3, ';', e2-p3);
        if (NULL == p4) {
            // just one
            p4 = memchr(p3, '=', e2-p3);
            if (NULL == p4) {
                // only a single string, we take it as a key without value
                // cJSON_AddStringToObject(cookie_kv, p3, "");
            }
            else {
                while(isspace(*p3))
                    p3++;
                safe_memcpy_0(key, sizeof(key)-1, p3, p4-p3);
                p4 += 1; // `=`
                cJSON_AddStringToObject(cookie_kv, key, p4);
            }
            break;
        }
        else {
            // find `;`
            p5 = memchr(p3, '=', p4-p3);
            if (NULL == p5) {
                p3 = p4 + 1;
                continue;
            }
            while(isspace(*p3))
                p3++;
            safe_memcpy_0(key, sizeof(key)-1, p3, p5-p3);
            safe_memcpy_0(value, sizeof(value)-1, p5+1, p4-p5-1);
            cJSON_AddStringToObject(cookie_kv, key, value);
            p3 = p4 + 1;
        }
    } while(1);
    free(l);
    l = NULL;
}

void http_post_req_param(cJSON* header, const char* line, unsigned int len) {
    char* p3 = NULL;
    char* e2 = NULL;
    char* p4 = NULL, *p5 = NULL;
    cJSON* param = NULL, *param_kv = NULL;
    char* p = NULL;
    char key[256];
    char value[2048];

    char* l = (char*)malloc(len+1);
    p = l;
    p = xcpymem(p, line, len);
    *p++ = '\0';

    p3 = l;
    e2 = p3 + len;

    if (NULL == (param = cJSON_GetObjectItem_EX(header, "param"))) {
        cJSON_AddStringToObject(header, "param", l);
        cJSON_AddItemToObject(header, "param_kv", param_kv=cJSON_CreateObject());
    }
    else {
        if (NULL == (param_kv = cJSON_GetObjectItem_EX(header, "param_kv")))
            cJSON_AddItemToObject(header, "param_kv", param_kv=cJSON_CreateObject());
    }
    do {
        p4 = memchr(p3, '&', e2-p3);
        if (NULL == p4) {
            // just one parameter
            p4 = memchr(p3, '=', e2-p3);
            if (NULL == p4) {
                // only a single string, we take it as a key without value
                // cJSON_AddStringToObject(param_kv, p3, "");
            }
            else {
                safe_memcpy_0(key, sizeof(key)-1, p3, p4-p3);
                p4 += 1; // `=`
                cJSON_AddStringToObject(param_kv, key, p4);
            }
            break;
        }
        else {
            // find `&`
            p5 = memchr(p3, '=', p4-p3);
            if (NULL == p5) {
                p3 = p4 + 1;
                continue;
            }
            safe_memcpy_0(key, sizeof(key)-1, p3, p5-p3);
            safe_memcpy_0(value, sizeof(value)-1, p5+1, p4-p5-1);
            cJSON_AddStringToObject(param_kv, key, value);
            p3 = p4 + 1;
        }
    } while(1);
    free(l);
    l = NULL;
}

// GET /m/cskz_61445663.html?rec=4&tt=2 HTTP/1.1\r\n
// method: GET
// uri: /m/cskz_61445663.html?rec=4&tt=2
// version: HTTP/1.1
// cmd: /m/cskz_61445663.html
// param: rec=4&tt=2
// const char* p = "GET /m/cskz_61445663.html?rec=4&tt=2 HTTP/1.1\r\n";
static cJSON* http_request_first_line(const char* line, unsigned int len) {
    cJSON* header = NULL;
    cJSON* param_kv = NULL;
    char* e = (char*)line + len;
    char* e2 = NULL, *p1 = NULL, *p2 = NULL, *p3 = NULL, *p4 = NULL, *p5 = NULL;
    char longest[1024];
    char key[256];
    char value[2048];

    xurl_decode((char*)line, len);

    p1 = (char*)line;
    header = cJSON_CreateObject();
    // parse method
    p2 = memchr(p1, ' ', e-p1);
    if (NULL == p2)
        goto parse_failed;
    safe_memcpy_0(longest, sizeof(longest)-1, p1, p2-p1);
    cJSON_AddStringToObject(header, "method", longest);
    p1 = p2 + 1; // ` `
    // parse cmd
    p2 = memchr(p1, '?', e-p1);
    if (NULL == p2) {
        p2 = memrchr(p1, ' ', e-p1); // ` `
        if (NULL == p2)
            goto parse_failed;
        safe_memcpy_0(longest, sizeof(longest)-1, p1, p2-p1);
        cJSON_AddStringToObject(header, "cmd", longest);
    }
    else {
        safe_memcpy_0(longest, sizeof(longest)-1, p1, p2-p1);
        cJSON_AddStringToObject(header, "cmd", longest);
        p1 = p2 + 1; // `?`
        // parse parameters
        p2 = memrchr(p1, ' ', e-p1);
        if (NULL == p2)
            goto parse_failed;
        safe_memcpy_0(longest, sizeof(longest)-1, p1, p2-p1);
        cJSON_AddStringToObject(header, "param", longest);
        cJSON_AddItemToObject(header, "param_kv", param_kv=cJSON_CreateObject());
        e2 = longest + strlen(longest);
        p3 = longest;
        do {
            p4 = memchr(p3, '&', e2-p3);
            if (NULL == p4) {
                // just one parameter
                p4 = memchr(p3, '=', e2-p3);
                if (NULL == p4) {
                    // only a single string, we take it as a key without value
                    // cJSON_AddStringToObject(param_kv, p3, "");
                }
                else {
                    safe_memcpy_0(key, sizeof(key)-1, p3, p4-p3);
                    p4 += 1; // `=`
                    cJSON_AddStringToObject(param_kv, key, p4);
                }
                break;
            }
            else {
                // find `&`
                p5 = memchr(p3, '=', p4-p3);
                if (NULL == p5) {
                    p3 = p4 + 1;
                    continue;
                }
                safe_memcpy_0(key, sizeof(key)-1, p3, p5-p3);
                safe_memcpy_0(value, sizeof(value)-1, p5+1, p4-p5-1);
                cJSON_AddStringToObject(param_kv, key, value);
                p3 = p4 + 1;
            }
        } while(1);
    }
    p1 = p2 + 1; // ` `
    // parse http version
    p2 = memstr(p1, e-p1, "\r\n", 2);
    if (NULL == p2)
        goto parse_failed;
    safe_memcpy_0(longest, sizeof(longest)-1, p1, p2-p1);
    cJSON_AddStringToObject(header, "version", longest);

    safe_memcpy_0(longest, sizeof(longest)-1, (char*)line, p2-(char*)line);
    cJSON_AddStringToObject(header, "first_line", longest);
    return header;
parse_failed:
    cJSON_Delete(header);
    return NULL;
}

// Host: video.sina.com.cn\r\n
// User-Agent: Mozilla/5.0 (Windows NT 5.1; rv:13.0) Gecko/20100101 Firefox/13.0.1\r\n
// Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n
// Accept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3\r\n
// Accept-Encoding: gzip, deflate\r\n
// Connection: keep-alive\r\n
// Referer: http://video.sina.com.cn/p/news/s/v/2012-06-26/124361789049.html?opsubject_id=top1\r\n
// \r\n
// const char* p = "Host: video.sina.com.cn\r\nUser-Agent: Mozilla/5.0 (Windows NT 5.1; rv:13.0) Gecko/20100101 Firefox/13.0.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nReferer: http://video.sina.com.cn/p/news/s/v/2012-06-26/124361789049.html?opsubject_id=top1\r\n\r\n"
static void http_other_lines(cJSON* header, const char* other_lines, unsigned int len) {
    char* p1 = (char*)other_lines;
    char* p2 = NULL;
    char* p3 = NULL;
    char* e = (char*)other_lines + len;
    char key[256];
    char value[2048];

    do {
        p2 = memstr(p1, e-p1, "\r\n", 2);
        if (NULL == p2)
            return;
        p3 = memchr(p1, ':', p2-p1);
        if (NULL == p3) {
            // last `\r\n`
            return;
        }
        safe_memcpy_0(key, sizeof(key)-1, p1, p3-p1);
        p3 += 1; // `:`
        while(isspace(*p3))
            p3++;
        safe_memcpy_0(value, sizeof(value)-1, p3, p2-p3);
        cJSON_AddStringToObject(header, key, value);
        p1 = p2 + 2; // `\r\n`
    } while(1);
    return;
}

// root.level1.level2.key
cJSON* cJSON_GetObjectItem_EX(cJSON* json, const char* format)
{
    char key[256];
    char* e = NULL, *p1 = NULL, *p2 = NULL;
    cJSON* d = json;
    p1 = (char*)format;
    e = (char*) format + strlen(format);
    do {
        p2 = strchr(p1, '.');
        if (NULL == p2) {
            safe_memcpy_0(key, sizeof(key)-1, p1, e-p1);
            d = cJSON_GetObjectItem(d, key);
            return d;
        }
        else {
            safe_memcpy_0(key, sizeof(key)-1, p1, p2-p1);
            p1 = p2 + 1;
            d = cJSON_GetObjectItem(d, key);
            if (NULL == d)
                return NULL;
        }
    } while(1);
}

cJSON* http_parse_request_header(const char* req, unsigned int req_len) {
    char* p1 = NULL, *p2 = NULL;
    cJSON* header = NULL;
    p1 = memstr(req, req_len, "\r\n\r\n", 4);
    if (NULL == p1)
       return NULL;
    p1 += 4; // `\r\n\r\n`
    p2 = memstr(req, req_len, "\r\n", 2);
    p2 += 2; // `\r\n`
    header = http_request_first_line(req, p2-req);
    http_other_lines(header, p2, p1-p2);
    cJSON_AddNumberToObject(header, "header-length", (int)(p1-req));
    return header;
}

cJSON* http_parse_response_header(const char* rsp, unsigned int rsp_len) {
    char* p1 = NULL, *p2 = NULL;
    cJSON* header = NULL;
    p1 = memstr(rsp, rsp_len, "\r\n\r\n", 4);
    if (NULL == p1)
       return NULL;
    p1 += 4; // `\r\n\r\n`
    p2 = memstr(rsp, rsp_len, "\r\n", 2);
    p2 += 2; // `\r\n`
    header = http_response_first_line(rsp, p2-rsp);
    http_other_lines(header, p2, p1-p2);
    cJSON_AddNumberToObject(header, "header-length", (int)(p1-rsp));
    return header;
}

void http_create_request_header(cJSON* req, dyn_buf* buff) {
    char* o = NULL;
    cJSON* c = NULL;
    char o2[256];

    // first line
    c = cJSON_GetObjectItem_EX(req, "first_line");
    o = c->valuestring;
    copy_buffer(buff, o, strlen(o)); // `remove the symbol " in the begin and the end`
    copy_buffer(buff, "\r\n", 2);
    o = NULL;

    c = req->child;
    while (NULL != c) {
        if ((0 == memcmp(c->string, "cmd", 3)) 
                || (0 == memcmp(c->string, "method", 6))
                || (0 == memcmp(c->string, "param", 5))
                || (0 == memcmp(c->string, "param_kv", 8))
                || (0 == memcmp(c->string, "version", 7))
                || (0 == memcmp(c->string, "first_line", 10))
                || (0 == memcmp(c->string, "header-length", 13))) {
            c = c->next;
            continue;
        }
        if (cJSON_Number == c->type) {
            safe_snprintf(o2, sizeof(o2)-1, "%d", c->valueint);
            o = o2;
        }
        else {
            o = c->valuestring;
        }
        copy_buffer(buff, c->string, strlen(c->string));
        copy_buffer(buff, ":", 1);
        copy_buffer(buff, o, strlen(o)); // `remove the symbol " in the begin and the end`
        copy_buffer(buff, "\r\n", 2);
        o = NULL;
        c = c->next;
    }
    copy_buffer(buff, "\r\n", 2); // the last `\r\n`
    return;
}

void http_create_rsponse_header(cJSON* rsp, dyn_buf* buff) {
    char* o = NULL;
    cJSON* c = NULL;
    char o2[256];

    // first line
    c = cJSON_GetObjectItem_EX(rsp, "first_line");
    o = c->valuestring;
    copy_buffer(buff, o, strlen(o)); // `remove the symbol " in the begin and the end`
    copy_buffer(buff, "\r\n", 2);
    o = NULL;

    c = rsp->child;
    while (NULL != c) {
        if ((0 == memcmp(c->string, "code", 4)) 
                || (0 == memcmp(c->string, "desc", 4))
                || (0 == memcmp(c->string, "version", 7))
                || (0 == memcmp(c->string, "first_line", 10))) {
            c = c->next;
            continue;
        }
        if (cJSON_Number == c->type) {
            safe_snprintf(o2, sizeof(o2)-1, "%d", c->valueint);
            o = o2;
        }
        else {
            o = c->valuestring;
        }
        copy_buffer(buff, c->string, strlen(c->string));
        copy_buffer(buff, ":", 1);
        copy_buffer(buff, o, strlen(o)); // `remove the symbol " in the begin and the end`
        copy_buffer(buff, "\r\n", 2);
        o = NULL;
        c = c->next;
    }
    copy_buffer(buff, "\r\n", 2); // the last `\r\n`
    return;
}

