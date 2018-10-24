# Makefile.am for linxgws

#SUBDIRS = ../libgw \
#	  ../../liblinx

LIBGW = $(LINXROOT)/lib/libgw.a
LIBLINX = $(LINXROOT)/lib/liblinx.a
LINXROOT = ../..

include $(LINXROOT)/flags.am

bin_PROGRAMS    = $(LINXROOT)/bin/linxgws

__LINXROOT__bin_linxgws_SOURCES = linxgws.c \
		  linxgws_main.c \
		  linxgws_msghandler.c \
		  linxgws.h \
		  linxgws_msghandler.h
__LINXROOT__bin_linxgws_LDADD = $(LIBLINX) $(LIBGW)

INCLUDES = -I ../include/ -I ../../include/

