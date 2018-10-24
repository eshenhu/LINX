# Makefile.am for linxgwcmd

LIBGW = $(LINXROOT)/lib/libgw.a

AM_CPPFLAGS = $(DEPS_CFLAGS)

__LINXROOT__bin_linxgwcmd_LDADD = $(LIBGW)
__LINXROOT__bin_linxgwcmd_SOURCES = linxgwcmd.c

LINXROOT = ../..
include $(LINXROOT)/flags.am

bin_PROGRAMS    = $(LINXROOT)/bin/linxgwcmd

INCLUDES = -I ../include/

