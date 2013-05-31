/*
 * xlog.h: log and util defines
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

#ifndef __X_LOG_H_YUE_XIAOCHENG_2013_03_25_
#define __X_LOG_H_YUE_XIAOCHENG_2013_03_25_

#ifdef __cplusplus
extern "C" 
{
#endif

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include "zlib.h"

int xlog_init(const char* filename);
void xlog_fini(void);
void Error(const char* format, ... );
void Info(const char* format, ... );
void Warn(const char* format, ... );
void Debug(const char* format, ... );
void flush_log();

#define MAX_LOG_LINE 40960

int md5_32(const unsigned char* byte_array, int array_len, char* md5_str);
void* memstr(const void* str, size_t n, char* r, size_t rn);
size_t memncpy(void *dest, size_t max, const void *src, size_t n, const char* function, int line, int append0);
int urldecode(char* from, int fromlen, char* to, int maxtolen);
int safe_snprintf(char *str, size_t size, const char *format, ...);
int mkdir_r(char* path);
int replace_str(char* in, char* out, char* rr, char* pp);
char* get_realip(char* domain, char* realip, int maxrealiplen);

char* xurl_encode(char const *s, int len, int *new_length);
int xurl_decode(char* str, int len);

int parse_by_mark(char* src, char* o[], int maxc, int* onum, char mark);

int set_rlimit(size_t limit);

int def(FILE *source, FILE *dest, int level);
void zerr(int ret);

#define safe_memcpy(dest, dest_sz, src, src_sz) \
    memncpy(dest, dest_sz, src, src_sz, __FUNCTION__, __LINE__, 0)
#define safe_memcpy_0(dest, dest_sz, src, src_sz) \
    memncpy(dest, dest_sz, src, src_sz, __FUNCTION__, __LINE__, 1)

#define xcpymem(dst, src, n)   (((char *) memcpy(dst, src, n)) + (n))

#ifdef __cplusplus
}
#endif

#endif // __X_LOG_H_YUE_XIAOCHENG_2013_03_25_
