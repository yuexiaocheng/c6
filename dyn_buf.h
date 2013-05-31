/*
 * dyn_buf.h: a buffer like std::string
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

#ifndef __DYN_BUF_H_YUE_XIAOCHENG_2010_06_09_
#define __DYN_BUF_H_YUE_XIAOCHENG_2010_06_09_

#ifdef __cplusplus
extern "C"
{
#endif

#define MAX_COPY_LEN (10*1024*1024)
typedef struct {
    unsigned int maxlen;
    unsigned int usedlen;
    char* buffer;
} dyn_buf;

int init_buffer(dyn_buf* it, unsigned int len);
int copy_buffer(dyn_buf* it, const char* in, int inlen);
char* get_buffer(dyn_buf* it);
unsigned int get_buffer_len(dyn_buf* it);
void reset_buffer(dyn_buf* it);
int is_buffer_empty(dyn_buf* it);
void free_buffer(dyn_buf* it);

#ifdef __cplusplus
}
#endif

#endif // __DYN_BUF_H_YUE_XIAOCHENG_2010_06_09_

