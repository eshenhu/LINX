# Makefile.am for liblinx

LIB   = ../lib
LINXROOT = ..
INCLUDES = -I $(LINXROOT)/include/

include $(LINXROOT)/flags.am

lib_LTLIBRARIES = $(LIB)/liblinx.la
noinst_LIBRARIES = $(LIB)/liblinx.a

__LIB__liblinx_la_SOURCES = linx.c
__LIB__liblinx_la_LDFLAGS = $(all_libraries)
__LIB__liblinx_la_CFLAGS = -c -Wall -pedantic -std=gnu99 -O2

__LIB__liblinx_a_SOURCES = linx.c
__LIB__liblinx_a_CFLAGS = -c -Wall -pedantic -std=gnu99 -O2

if !DEBUG
__LIB__liblinx_la_CFLAGS += -DNDEBUG
__LIB__liblinx_a_CFLAGS += -DNDEBUG
endif