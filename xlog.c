/*
 * xlog.c: log and util
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

#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <sys/time.h>
#include <netdb.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "zlib.h"
#include "xlog.h"

static int log_fd = -1;
static char fn_format[256];

int xlog_init(const char* filename) {
    size_t len = sizeof(filename) - 1;
    if (len >= sizeof(fn_format))
        return 0;
    strcpy(fn_format, filename);
    return 1;
}

void xlog_fini() {
    close(log_fd);
    return;
}

static inline int open_log_file() {
    struct timeval tv;
    struct tm gmt;

    static char buff[MAX_LOG_LINE];
    if (log_fd >= 0)
        close(log_fd);
    gettimeofday(&tv, 0);   
    localtime_r(&tv.tv_sec, &gmt);

    strftime(buff, MAX_LOG_LINE, fn_format, &gmt);
    mkdir_r(buff);
    return log_fd = open(buff, O_WRONLY|O_APPEND|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
}

static inline void _mwrite(const char* s, int n, int day) {
    static int lastDay = -1;

    if (log_fd < 0)
        open_log_file();

    if (lastDay == day)
        write(log_fd, s, n);
    else {
        open_log_file();
        lastDay = day;
        write(log_fd, s, n);
    }
    return;
}

inline void xout(const char* format, va_list arg, const char * err_msg) {
    static char buff[MAX_LOG_LINE];
    struct timeval tv;
    int ret, len;
    struct tm gmt;

    gettimeofday(&tv, 0);   
    localtime_r(&tv.tv_sec, &gmt);

    ret = safe_snprintf(buff, MAX_LOG_LINE - 1, "%04d%02d%02d %02d:%02d:%02d.%03ld %s - ",
            gmt.tm_year + 1900, gmt.tm_mon + 1, gmt.tm_mday, gmt.tm_hour, 
            gmt.tm_min, gmt.tm_sec, tv.tv_usec/1000, err_msg);
    if (ret > 0) {
        len = ret;
        ret = vsnprintf(buff+len, MAX_LOG_LINE-len, format, arg);
        if (ret > 0 && ret < MAX_LOG_LINE-len)
            _mwrite(buff, len+ret, gmt.tm_mday);
        else
            _mwrite("!Too Long Line\n", sizeof("!Too Long Line\n")-1, gmt.tm_mday);
    } 
    else
        _mwrite( "!!!Too Long Line\n", sizeof("!!!Too Long Line\n")-1, gmt.tm_mday);
}

void Error(const char* format, ...) {
    va_list arg;
    va_start(arg, format);
    xout(format, arg, "ERR");
    va_end(arg);
    return;
}

void Warn(const char* format, ...) {
    va_list arg;
    va_start(arg, format);
    xout(format, arg, "WRN");
    va_end(arg);
    return;
}

void Info(const char* format, ...) {
    va_list arg;
    va_start(arg, format);
    xout(format, arg, "INF");
    va_end(arg);
    return;
}

void Debug(const char* format, ...) {   
    va_list arg;
    va_start(arg, format);
    xout(format, arg, "DBG");
    va_end(arg);
    return;
}

void flush_log() {
    fsync(log_fd);
    return;
}

int md5_32(const unsigned char* byte_array, int array_len, char* md5_str) {
    if( byte_array == NULL || array_len < 16 || md5_str == NULL )
        return -1;

    int i;
    int len = 0;
    for( i = 0; i < 16; ++i ) {
        len = sprintf(md5_str, "%02x", byte_array[i]);
        md5_str += len;
    }
    return 0;
}

void* memstr(const void* str, size_t n, char* r, size_t rn) {
    unsigned const char* s = str;
    while (n >= rn) {
        if (0 == memcmp(s, r, rn)) 
            return (void*)s;
        s++;
        n--;
    }
    return (void*)0;
}

size_t memncpy(void *dest, size_t max, const void *src, size_t n, const char* function, int line, int append0) {
    size_t ret = n;
    if (0 == n) {
        if (append0 > 0)
            ((char*)dest)[0] = '\0';
        return 0;
    }
    if (max < n) {
        ret = max;
        printf("%s(%d): max=%lu, n=%lu, accurate copy=%lu", function, line, max, n, ret);
    }
    memcpy(dest, src, ret);
    if (append0 > 0)
        ((char*)dest)[ret] = '\0';
    return ret;
}

int safe_snprintf(char *str, size_t size, const char *format, ...) {
    int ret = 0;
    va_list arg;

    va_start(arg, format);
    ret = vsnprintf(str, size, format, arg);
    if (ret < 0 || (size_t)ret > size) {
        str[0] = '\0';
        ret = -1;
    }
    else {
        str[ret] = '\0';
    }
    va_end(arg);
    return ret;
}

int mkdir_r(char* path) {
    char dir[256] = {0};
    char* p = NULL;
    char* cur = NULL;
    int ret = 0;

    cur = path;
    if ('/' != *cur)
        return -1;

    if (0 == access(path, F_OK))
        return 0;
    cur++;
    p = strchr(cur, '/');
    while(NULL != p) {
        memcpy(dir, path, p-path+1);
        if (0 != access(dir, F_OK)) {
            // not exist, create it
            ret = mkdir(dir, 0777);
            if (ret < 0) {
                printf("%s(%d): mkdir %s failed\n", __FUNCTION__,
                        __LINE__, dir);
                return -2;
            }
        }
        cur = p + 1;
        if ((cur - path) > (int)strlen(path))
            break;
        p = strchr(cur, '/');
    }
    return 0;
}

int replace_str(char* in, char* out, char* rr, char* pp) {
    char* p1 = NULL;
    char* p2 = NULL;
    char* po = NULL;
    char* pe = NULL;
    int len = 0;
    int rr_len = 0;
    int pp_len = 0;
    int o_len = 0;

    if (NULL == in || NULL == out || NULL == rr || NULL == pp)
        return -1;

    rr_len = strlen(rr);
    pp_len = strlen(pp);

    po = out;
    pe = in + strlen(in);
    p1 = in;
    p2 = strstr(p1, rr);
    while (p2) {
        len = p2 - p1;
        memcpy(po, p1, len); po += len; o_len += len;
        p1 += len; p1 += rr_len;
        memcpy(po, pp, pp_len); po += pp_len; o_len += pp_len;
        p2 = strstr(p1, rr);
    }
    if (p1 < pe) {
        len = pe - p1 + 1;
        memcpy(po, p1, len); o_len += len;
    }
    out[o_len] = '\0';
    return 0;
}

char* get_realip(char* domain, char* realip, int maxrealiplen) {
    struct hostent* phost = NULL;
    char** pptr = NULL;
    int i;

    memset(realip, 0x00, maxrealiplen);
    strncpy(realip, domain, maxrealiplen);

    // get ip from domain
    for (i=0; i<10; ++i) {
        phost = gethostbyname(domain);
        if (NULL != phost)
            break;
    }
    if (NULL == phost) {
        printf("%s(%d): gethostbyname(%s) failed. ERRORS(%d), return %s\n", 
                __FUNCTION__, __LINE__, domain, h_errno, realip);
        return realip;
    }
    else {
        switch(phost->h_addrtype) {
            case AF_INET:
            case AF_INET6:
                pptr = phost->h_addr_list;
                for(; NULL!=*pptr; ++pptr) {
                    memset(realip, 0x00, maxrealiplen);
                    inet_ntop(phost->h_addrtype, *pptr, realip, maxrealiplen);
                    if (0 != strcmp(realip, "")) {
                        printf("%s(%d): domain(%s): %s, return %s\n", __FUNCTION__, __LINE__, domain, realip, realip);
                        return realip;
                    }
                }
                break;
            default:
                printf("%s(%d): phost->h_addrtype(%d) is illegal!\n", 
                        __FUNCTION__, __LINE__, phost->h_addrtype);
                break;
        }
    }
    printf("%s(%d): domain(%s)'s ip: %s, can't get the ip, return %s", 
            __FUNCTION__, __LINE__, domain, realip, realip);
    return realip;
}

/* Compress from file source to file dest until EOF on source.
   def() returns Z_OK on success, Z_MEM_ERROR if memory could not be
   allocated for processing, Z_STREAM_ERROR if an invalid compression
   level is supplied, Z_VERSION_ERROR if the version of zlib.h and the
   version of the library linked do not match, or Z_ERRNO if there is
   an error reading or writing the files. 
   */
#define CHUNK 16384
int def(FILE *source, FILE *dest, int level) {
    int ret, flush;
    unsigned have;
    z_stream strm;
    static unsigned char in[CHUNK];
    static unsigned char out[CHUNK];
    /* allocate deflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    ret = deflateInit2(&strm, level, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK)
        return ret;
    /* compress until end of file */
    do {
        strm.avail_in = fread(in, 1, CHUNK, source);
        if (ferror(source)) {
            (void)deflateEnd(&strm);
            return Z_ERRNO;
        }
        flush = feof(source) ? Z_FINISH : Z_NO_FLUSH;
        strm.next_in = in;
        /* run deflate() on input until output buffer not full, finish
         *            compression if all of source has been read in */
        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = deflate(&strm, flush);    /* no bad return value */
            assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
            have = CHUNK - strm.avail_out;
            if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
                (void)deflateEnd(&strm);
                return Z_ERRNO;
            }
        } while (strm.avail_out == 0);
        assert(strm.avail_in == 0);     /* all input will be used */
        /* done when last data in file processed */
    } while (flush != Z_FINISH);
    assert(ret == Z_STREAM_END);        /* stream will be complete */
    /* clean up and return */
    (void)deflateEnd(&strm);
    return Z_OK;
}

/* report a zlib or i/o error */
void zerr(int ret) {
    fputs("zpipe: ", stderr);
    switch (ret) {
        case Z_ERRNO:
            if (ferror(stdin))
                fputs("error reading stdin\n", stderr);
            if (ferror(stdout))
                fputs("error writing stdout\n", stderr);
            break;
        case Z_STREAM_ERROR:
            fputs("invalid compression level\n", stderr);
            break;
        case Z_DATA_ERROR:
            fputs("invalid or incomplete deflate data\n", stderr);
            break;
        case Z_MEM_ERROR:
            fputs("out of memory\n", stderr);
            break;
        case Z_VERSION_ERROR:
            fputs("zlib version mismatch!\n", stderr);
    }
}

char* xurl_encode(char const *s, int len, int *new_length) {
#define safe_emalloc(nmemb, size, offset)   malloc((nmemb) * (size) + (offset))
    static unsigned char hexchars[] = "0123456789ABCDEF";
    register unsigned char c;
    unsigned char *to, *start;
    unsigned char const *from, *end;

    from = (unsigned char *)s;
    end = (unsigned char *)s + len;
    start = to = (unsigned char *) safe_emalloc(3, len, 1);

    while (from < end) {
        c = *from++;
        if (c == ' ') 
            *to++ = '+';
        else if (!isalnum(c) && strchr("_-.:/", c) == NULL) {
            /* Allow only alphanumeric chars and '_', '-', '.', ':', '/'; escape the rest */
            to[0] = '%';
            to[1] = hexchars[c >> 4];
            to[2] = hexchars[c & 15];
            to += 3;
        } 
        else 
            *to++ = c;
    }
    *to = 0;
    if (new_length) 
        *new_length = to - start;
    return (char *) start;
}

static int xhtoi(char* s) {
    int value;
    int c;

    c = ((unsigned char *)s)[0];
    if (isupper(c))
        c = tolower(c);
    value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16;

    c = ((unsigned char *)s)[1];
    if (isupper(c))
        c = tolower(c);
    value += c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;
    return (value);
}

int xurl_decode(char* str, int len) {
    char* dest = str;
    char* data = str;

    while (len--) {
        if (*data == '+') 
            *dest = ' ';
        else if (*data == '%' && len >= 2 && isxdigit((int) *(data + 1)) 
                && isxdigit((int) *(data + 2))) {
            *dest = (char) xhtoi(data + 1);
            data += 2;
            len -= 2;
        } 
        else 
            *dest = *data;
        data++;
        dest++;
    }
    // *dest = '\0';
    return dest - str;
}

int parse_by_mark(char* src, char* o[], int maxc, int* onum, char mark) {
    if( !src || !o || maxc < 1 )
        return -1;

    char* value = src;
    int lastpos = strlen(value) - 1;
    char* pos = NULL;
    char* begin = value;
    char* last = NULL;
    int i = 0;

    // set init value
    *onum = 0;
    // erase useless `mark` at head and tail 
    while (lastpos >= 0) {
        if (mark == value[lastpos]) {
            value[lastpos] = '\0';
            lastpos--;
        }
        else
            break;
    }
    while (lastpos >= 0) {
        if (mark == *begin) {
            ++begin;
            lastpos--;
        }
        else
            break;
    }

    // :-( 
    // all chars are erased...
    if (strlen(begin) < 1)
        return -2;
    // now: parsing
    last = begin + strlen(begin);
    pos = strchr(begin, mark);
    i = 0;
    size_t str_len;
    while (NULL != pos && begin < last - 1 && i < maxc) {
        str_len = pos - begin;
        o[i] = (char*)malloc(str_len + 1);
        if( o[i] == NULL)
            return -3;
        safe_memcpy(o[i], str_len, begin, str_len); o[i][str_len] = '\0'; ++i;
        begin = pos + 1;
        pos = strchr(begin, mark);
    }
    if (begin < last) {
        str_len = last - begin;
        o[i] = (char*)malloc(str_len + 1);
        if(o[i] == NULL)
            return -3;
        safe_memcpy(o[i], str_len, begin, str_len); o[i][str_len] = '\0'; ++i;
    }
    // set num after parsed
    *onum = i;
    return 0;
}

int set_rlimit(size_t limit) {
    //ulimit -n xxxx
    struct rlimit rlim;

    if (getrlimit(RLIMIT_CORE, &rlim) == 0) {
        rlim.rlim_cur = rlim.rlim_max;
        setrlimit(RLIMIT_CORE, &rlim);
    }
    if (getrlimit(RLIMIT_NOFILE, &rlim) < 0) {
        printf("%s(%d): getrlimit() failed. error(%d): %s\n", __FUNCTION__, __LINE__, errno, strerror(errno));
        return -1;
    }
    rlim.rlim_max = rlim.rlim_cur = limit;
    if (setrlimit(RLIMIT_NOFILE, &rlim) < 0)
        printf("%s(%d): setrlimit() failed. error(%d): %s\n", __FUNCTION__, __LINE__, errno, strerror(errno));
    if (0 == getrlimit(RLIMIT_NOFILE, &rlim))
        printf("%s(%d): getrlimit() %lu %lu %lu\n", 
                __FUNCTION__, __LINE__, rlim.rlim_max, rlim.rlim_cur, limit);
    return 0;
}

