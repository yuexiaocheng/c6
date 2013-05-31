/*
 * dyn_buf.c: a buffer like std::string
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

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "dyn_buf.h"

int init_buffer(dyn_buf* it, unsigned int len) {
    assert(NULL != it);
    it->buffer = (char*)malloc(len);
    if (NULL == it->buffer) {
        it->maxlen = it->usedlen = 0;
        return -1;
    }
    else {
        // memset(it->buffer, 0x00, len);
        it->maxlen = len;
        it->usedlen = 0;
        it->buffer[it->usedlen] = '\0';
    }
    return 0;
};

int copy_buffer(dyn_buf* it, const char* in, int inlen) {
    char* pTmp = NULL;
    unsigned int needlen = 0;
    
    assert(NULL != it);
    assert(NULL != in);

    assert(inlen < MAX_COPY_LEN);

    if (inlen >= (it->maxlen - it->usedlen)) {
        needlen = it->maxlen * 2;
        needlen = (needlen - it->usedlen) > inlen ? needlen : (needlen + inlen);
        pTmp = realloc(it->buffer, needlen);
        if (NULL == pTmp) {
            return -1;
        }
        else {
            it->buffer = pTmp;
            // memset(it->buffer+it->maxlen, 0x00, needlen - it->maxlen);
            it->maxlen = needlen;
        }
    }
    assert(inlen < (it->maxlen - it->usedlen));
    memcpy(it->buffer+it->usedlen, in, inlen);
    it->usedlen += inlen;
    it->buffer[it->usedlen] = '\0';
    return 0;
};

char* get_buffer(dyn_buf* it) {
    assert(NULL != it);
    return it->buffer;
}

unsigned int get_buffer_len(dyn_buf* it) {
    assert(NULL != it);
    return it->usedlen;
}

void reset_buffer(dyn_buf* it) {
    assert(NULL != it);
    it->usedlen = 0;
    it->buffer[it->usedlen] = '\0';
}

int is_buffer_empty(dyn_buf* it) {
    assert(NULL != it);
    return (0 == it->usedlen);
}

void free_buffer(dyn_buf* it) {
    assert(NULL != it);
    if (NULL == it)
        return;
    if (NULL != it->buffer) {
        free(it->buffer);
        it->buffer = NULL;
    }
    it->maxlen = it->usedlen = 0;
};

