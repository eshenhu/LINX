# SHMCM Makefile

all: modules

LINX ?= $(CURDIR)/../../..
include $(LINX)/net/linx/config.mk

KERNEL_CODE := $(shell awk '/LINUX_VERSION_CODE/ {print $$3}' $(KERNEL)/include/linux/version.h)
VENDOR_VERSION := $(shell awk '/UTS_RELEASE/ {print $$3}' $(KERNEL)/include/linux/version.h)

ifneq ($(VENDOR_VERSION), "")
	EXTRA_CFLAGS += -DGFP_IS_INT
endif

# Kernel version codes
2_6_13 := 132621

# 'gt_or_eq'
gt_or_eq = $(findstring $(1),$(word 2,$(sort $(2) $(1))))

ifeq ($(call gt_or_eq,$(KERNEL_CODE),$(2_6_13)),$(KERNEL_CODE))
	EXTRA_CFLAGS += -DSHMCM_COMPAT
else
   ifeq ($(findstring 2.6.10_mvlcge401,$(VENDOR_VERSION)),2.6.10_mvlcge401)
      EXTRA_CFLAGS += -DSHMCM_COMPAT
   else
      EXTRA_CFLAGS += -DSHMCM_KZALLOC
   endif
endif

ifeq ($(TRACE),yes)
	EXTRA_CFLAGS += -DSHMCM_TRACE
else
	ifeq ($(SHMCM_TRACE),yes)
		EXTRA_CFLAGS += -DSHMCM_TRACE
	endif
endif

ifeq ($(VERBOSE),yes)
VERB         =
XMAKE_SILENT =
V            = 1
else
VERB         = @
ifneq ($(NEED_KERNEL),yes)
XMAKE_SILENT = -s
else
XMAKE_SILENT =
endif
V            = 0
endif

XMAKE := $(VERB)$(MAKE) $(XMAKE_SILENT)

EXTRA_CFLAGS += -Wall
ifeq ($(EXTRA_WARNINGS),yes)
EXTRA_CFLAGS += -Wextra #  -Wno-unused-parameter -Wno-sign-compare
endif
EXTRA_CFLAGS += -I$(LINX)/include -I$(LINX)/net/linx \
		-I$(LINX)/net/linx/include \
                -I$(LINX)/net/linx/shmcm

INSTALLDIR = /lib/modules/`uname -r`/kernel/net/linx
MODULES = linx_shm_cm.ko

obj-m := linx_shm_cm.o

linx_shm_cm-y += shmcm.o
linx_shm_cm-y += shmcm_rx.o
linx_shm_cm-y += shmcm_tx.o
linx_shm_cm-y += shmcm_kutils.o

modules:
	$(XMAKE) ARCH=$(ARCH) V=$(V) -C $(KERNEL) M=`pwd` modules
	$(CP) linx_shm_cm.ko ..

clean:
	$(XMAKE) ARCH=$(ARCH) V=$(V) -C $(KERNEL) M=`pwd` clean
	$(LINXRM) Module.symvers Module.markers modules.order ../linx_shm_cm.ko

install: modules
	$(XMAKE) ARCH=$(ARCH) V=$(V) -C $(KERNEL) M=`pwd` modules_install
	depmod

