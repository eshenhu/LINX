# Makefile.am for linx_basic


AM_CPPFLAGS = $(DEPS_CFLAGS)

__EXAMPLE__bin_linx_basic_client_LDADD = $(LINXROOT)/lib/liblinx.a
__EXAMPLE__bin_linx_basic_server_LDADD = $(LINXROOT)/lib/liblinx.a

include $(LINXROOT)/flags.am

EXAMPLE = ..
LINXROOT = ../..

bin_PROGRAMS    = $(EXAMPLE)/bin/linx_basic_server $(EXAMPLE)/bin/linx_basic_client

__EXAMPLE__bin_linx_basic_client_SOURCES = linx_basic_client.c \
                                           linx_basic.sig \
					   linx_basic.h	

__EXAMPLE__bin_linx_basic_server_SOURCES = linx_basic_server.c \
                                           linx_basic.sig \
					   linx_basic.h	

INCLUDES = -I $(LINXROOT)/include/
