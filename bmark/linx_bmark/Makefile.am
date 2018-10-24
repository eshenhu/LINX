# Makefile.am for linx_bmark

AM_CPPFLAGS = $(DEPS_CFLAGS)

__BMARK__bin_linx_bmark_LDADD = $(LINXROOT)/lib/liblinx.a -lpthread

LINXROOT = ../..
BMARK = ..

include $(LINXROOT)/flags.am

bin_PROGRAMS    = $(BMARK)/bin/linx_bmark

__BMARK__bin_linx_bmark_SOURCES = linx_bmark_attach.c \
		     linx_bmark_latency.c \
		     linx_bmark_burst.c \
		     linx_bmark_throughput.c \
		     linx_bmark.c \
		     linx_bmark.h

INCLUDES = -I $(LINXROOT)/include/
