# Makefile.am for linxdisc

LINXROOT = ..
INCLUDES = -I ../include/

LIBLINX = $(LINXROOT)/lib/liblinx.a
LIBCFG  = $(LINXROOT)/lib/libcfg.a

bin_PROGRAMS    = $(LINXROOT)/bin/linxdisc
__LINXROOT__bin_linxdisc_SOURCES = config.c \
		   debug.c \
		   linxdisc.h \
		   linxdisc.c \
		   util.c

__LINXROOT__bin_linxdisc_LDADD = $(LIBCFG) $(LIBLINX)
__LINXROOT__bin_linxdisc_CFLAGS = -O2 -Wall -pedantic -std=gnu99 -D_GNU_SOURCE

if !DEBUG
__LINXROOT__bin_linxdisc_CFLAGS += -DNDEBUG
endif



