all: modules

LINX ?= $(PWD)/../..

include $(LINX)/net/linx/config.mk

EXTRA_CFLAGS += -Wall

obj-m := linxtrace.o

linxtrace-y += linxtracedrv.o

ifeq ($(LINXTRACE_DBG),yes)
EXTRA_CFLAGS += -DLINXTRACE_DBG
endif

ifeq ($(EXTRA_WARNINGS),yes)
EXTRA_CFLAGS += -Wextra # -Wno-unused-parameter -Wno-sign-compare
endif

modules:
	$(XMAKE) ARCH=$(ARCH) V=$(V) -C $(KERNEL) M=`pwd` modules

clean:
	$(XMAKE) ARCH=$(ARCH) V=$(V) -C $(KERNEL) M=`pwd` clean
	$(LINXRM) Module.symvers Module.markers modules.order

install: modules
	$(XMAKE) ARCH=$(ARCH) V=$(V) -C $(KERNEL) M=`pwd` modules_install
	depmod

