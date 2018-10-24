# Makefile.am for libgw
# Install config.guess so that we can figure
# out what machine we are running on.
#libexecdir = $(pkgdatadir)/libexec
#libexec_SCRIPTS = config.guess

LINXROOT = ../..
LIB = ../../lib

include $(LINXROOT)/flags.am

lib_LTLIBRARIES = $(LIB)/libgw.la
noinst_LIBRARIES = $(LIB)/libgw.a

__LIB__libgw_la_SOURCES = ose_gw.c
__LIB__libgw_a_SOURCES = ose_gw.c

INCLUDES = -I $(LINXROOT)/include/ \
	-I ../include/

__LIB__libgw_la_LDFLAGS = $(all_libraries)

__LIB__libgw_la_CFLAGS = -c -Wall -pedantic -std=gnu99 -O2
__LIB__libgw_a_CFLAGS = -c -Wall -pedantic -std=gnu99 -O2
