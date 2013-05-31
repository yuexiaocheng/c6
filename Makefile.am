AUTOMAKE_OPTIONS=foreign
INCLUDES=-I./ -I./include -I/usr/include/mysql

EXTRA_DIST = config.h.in config.h

bin_PROGRAMS=c6
c6_SOURCES=c6.c \
			  http_protocol.c \
			  xlog.c \
			  cJSON.c \
			  dyn_buf.c

c6_LDFLAGS=-L./ -L./lib -L/usr/lib64/mysql/
c6_LDADD= -lev -lmysqlclient -lm -lz -lssl 

CFLAGS=-Wall -Wpointer-arith -Wno-unused-parameter -Werror -g -Wunreachable-code -finline-functions  

include_HEADERS = c6.h \
				  http_protocol.h \
				  xlog.h \
				  cJSON.h \
				  dyn_buf.h

EXTRA_DIST += c6.conf
