/*
 * http_protocol.h: http protocol parser
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

#ifndef __HTTP_PROTOCOL_H_YUE_XIAOCHENG_2013_05_26_
#define __HTTP_PROTOCOL_H_YUE_XIAOCHENG_2013_05_26_

#ifdef __cplusplus
extern "C" 
{
#endif

#define _GNU_SOURCE
#include <string.h>
#include <sys/types.h>
#include <ctype.h>
#include "xlog.h"
#include "cJSON.h"
#include "dyn_buf.h"

#define DESC_501                    "Not Implemented"
#define DESC_404                    "Not Found"
#define DESC_408                    "Request Timeout"
#define DESC_500                    "Internal Error"
#define DESC_503                    "Overload"
#define DESC_200                    "OK"
#define DESC_206                    "Partial Content"
#define DESC_302                    "Found"
#define DESC_304                    "Not Modified"
#define DESC_400                    "Bad Request"
#define DESC_403                    "Forbidden"
#define other_desc                  "internal error"

// INTERFACES
cJSON* http_parse_request_header(const char* req, unsigned int req_len);
cJSON* http_parse_response_header(const char* rsp, unsigned int rsp_len);

void http_create_request_header(cJSON* req, dyn_buf* buff);
void http_create_rsponse_header(cJSON* rsp, dyn_buf* buff);
cJSON* cJSON_GetObjectItem_EX(cJSON* json, const char* format); // root.level1.level2.key
#ifdef __cplusplus
}
#endif

#endif // __HTTP_PROTOCOL_H_YUE_XIAOCHENG_2013_05_26_

