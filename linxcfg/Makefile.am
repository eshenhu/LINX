# Makefile.am for linxcfg

LIBLINX = ../lib/liblinx.a
LIBCFG  = ../lib/libcfg.a
LDADD = ../lib/libcfg.a

LIB = ../lib
LINXROOT = ..

include $(LINXROOT)/flags.am

AM_CPPFLAGS = $(DEPS_CFLAGS)

bin_PROGRAMS =  $(LINXROOT)/bin/mkethcon \
		$(LINXROOT)/bin/linxcfg  \
		$(LINXROOT)/bin/mklink   \
		$(LINXROOT)/bin/rmlink   \
		$(LINXROOT)/bin/rmethcon \
		$(LINXROOT)/bin/mktcpcon \
		$(LINXROOT)/bin/rmtcpcon \
		$(LINXROOT)/bin/mkshmcon \
		$(LINXROOT)/bin/rmshmcon \
		$(LINXROOT)/bin/mkriocon \
		$(LINXROOT)/bin/rmriocon \
		$(LINXROOT)/bin/mkcmclcon \
		$(LINXROOT)/bin/rmcmclcon

__LINXROOT__bin_mkethcon_SOURCES =  mkethcon.c
__LINXROOT__bin_mkethcon_LDADD   = $(LIBLINX) $(LIBCFG)

__LINXROOT__bin_linxcfg_SOURCES = linx_cfg_eth.c \
		  linx_cfg_rio.c \
		  linx_cfg_tcp.c \
                  linx_cfg_cmcl.c \
                  linx_cfg_cm.h \
		  linxcfg.c \
                  linx_cfg.h \
		  config.c \
                  config.h
__LINXROOT__bin_linxcfg_LDADD =  $(LIBLINX) $(LIBCFG)

__LINXROOT__bin_rmethcon_SOURCES =  rmethcon.c

__LINXROOT__bin_mkriocon_SOURCES =  mkriocon.c
__LINXROOT__bin_mkriocon_LDADD   =  $(LIBLINX) $(LIBCFG)

__LINXROOT__bin_rmriocon_SOURCES =  rmriocon.c

__LINXROOT__bin_mktcpcon_SOURCES =  mktcpcon.c

__LINXROOT__bin_rmtcpcon_SOURCES =  rmtcpcon.c

__LINXROOT__bin_mkshmcon_SOURCES =  mkshmcon.c

__LINXROOT__bin_rmshmcon_SOURCES = rmshmcon.c

__LINXROOT__bin_mkcmclcon_SOURCES =  mkcmclcon.c

__LINXROOT__bin_rmcmclcon_SOURCES = rmcmclcon.c

__LINXROOT__bin_mklink_SOURCES =  mklink.c

__LINXROOT__bin_rmlink_SOURCES =  rmlink.c

lib_LTLIBRARIES = $(LIB)/libcfg.la
noinst_LIBRARIES = $(LIB)/libcfg.a

__LIB__libcfg_la_SOURCES = db_utils.c \
		  cmcl_utils.c \
		  ethcm_utils.c \
		  riocm_utils.c \
		  shmcm_utils.c \
		  tcpcm_utils.c \
		  rlnh_utils.c \
		  libcfg.c \
		  riocm_utils.h \
		  rlnh_utils.h \
		  shmcm_utils.h\
		  ethcm_utils.h \
		  tcpcm_utils.h \
		  cmcl_utils.h \
		  linx_cfg.h \
		  db_utils.h

__LIB__libcfg_a_SOURCES = $(__LIB__libcfg_la_SOURCES)

INCLUDES = -I $(LINXROOT)/include/
__LIB__libcfg_la_LDFLAGS = $(all_libraries)

__LIB__libcfg_la_CFLAGS = -c -Wall -pedantic -std=gnu99 -O2
__LIB__libcfg_a_CFLAGS = -c -Wall -pedantic -std=gnu99 -O2

AM_CFLAGS = -I../include
AM_CFLAGS += -I../net/linx/include
AM_CFLAGS += -I../linxcfg
AM_CFLAGS += -O2 -std=gnu99
AM_CFLAGS += -DUSER_SPACE_COMMAND
AM_CFLAGS += -Wall
LINX ?= $(PWD)/..

