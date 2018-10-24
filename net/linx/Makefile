all: echo_config modules

LINX ?= $(CURDIR)/../..
NEED_KERNEL=yes
include $(LINX)/net/linx/config.mk

ifeq ($(DEBUGINFO),yes)
EXTRA_CFLAGS += -g
endif

ifeq ($(TRACE),yes)
EXTRA_CFLAGS += -DTRACE -DDEBUG
endif

ifeq ($(ERRORCHECKS),yes)
EXTRA_CFLAGS += -DERRORCHECKS -DASSERT
ifneq ($(ERRORCHECKS_MEM),no)
EXTRA_CFLAGS += -DERRORCHECKS_MEM
endif
endif

ifeq ($(ERRORCHECKS_MEM),yes)
EXTRA_CFLAGS += -DERRORCHECKS_MEM
endif

ifeq ($(COVERAGE_ANALYSIS),yes)
EXTRA_CFLAGS += -DCOVERAGE_ANALYSIS
endif

ifeq ($(LINXTRACE_DBG),yes)
EXTRA_CFLAGS += -DLINXTRACE_DBG
endif

ifeq ($(LINX_MESSAGE_TRACE),yes)
EXTRA_CFLAGS += -DLINX_MESSAGE_TRACE
endif

ifeq ($(LINX_RBLOG),yes)
EXTRA_CFLAGS += -DLINX_RBLOG
endif

ifeq ($(LINX_KERNEL_WORKAROUND_1),yes)
EXTRA_CFLAGS += -DLINX_KERNEL_WORKAROUND_1
endif

ifeq ($(SOCK_STAT),yes)
EXTRA_CFLAGS += -DSOCK_STAT
endif

ifneq ($(RLNH_VERSION),)
EXTRA_CFLAGS += -DRLNH_VERSION=$(RLNH_VERSION)
endif

ifeq ($(EXTRA_WARNINGS),yes)
EXTRA_CFLAGS += -Wextra #  -Wno-unused-parameter -Wno-sign-compare
endif

# Kernel version codes
2_6_34 := 132640
2_6_15 := 132623
2_6_14 := 132622
2_6_13 := 132621
2_6_11 := 132619

# Vendors version of kernel, needed to catch certain back patches
VENDOR_VERSION := $(shell awk '/UTS_RELEASE/ {print $$3}' $(KERNEL)/include/linux/version.h)
# Main line kernel version
KERNEL_CODE    := $(shell awk '/LINUX_VERSION_CODE/ {print $$3}' $(KERNEL)/include/linux/version.h)

#
# 'gt_or_eq'
#
# Test if first argument is greater than or equal to second argument
#
gt_or_eq = $(findstring $(1),$(word 2,$(sort $(2) $(1))))

ifeq ($(call gt_or_eq,$(KERNEL_CODE),$(2_6_11)),$(KERNEL_CODE))
  EXTRA_CFLAGS += -DSK_ALLOC_COMPAT
else
  ifeq ($(findstring 2.6.11-1.1369_FC4,$(VENDOR_VERSION)),2.6.11-1.1369_FC4)
    EXTRA_CFLAGS += -DSK_ALLOC_COMPAT
  endif
endif

ifeq ($(call gt_or_eq,$(KERNEL_CODE),$(2_6_13)),$(KERNEL_CODE))
  EXTRA_CFLAGS += -DETHER_RX_COMPAT
else
  ifeq ($(findstring 2.6.10_mvlcge401-pc_target-x86_pentium4,$(VENDOR_VERSION)),2.6.10_mvlcge401-pc_target-x86_pentium4)
    EXTRA_CFLAGS += -DETHER_RX_COMPAT
  endif
endif

ifeq ($(call gt_or_eq,$(KERNEL_CODE),$(2_6_15)),$(KERNEL_CODE))
  ifeq ($(call gt_or_eq,$(KERNEL_CODE),$(2_6_34)),$(KERNEL_CODE))
    EXTRA_CFLAGS += -imacros generated/autoconf.h
  else
    EXTRA_CFLAGS += -imacros linux/autoconf.h
  endif
endif

EXTRA_CFLAGS += -DENDIAN_CONVERT
EXTRA_CFLAGS += -Wall
EXTRA_CFLAGS += -I$(LINX)/include -I$(LINX)/net/linx -I$(LINX)/net/linx/include

obj-m := linx.o #linx_tcp_cm.o

linx-y += af_linx.o
linx-y += linx_ioctl_info.o
linx-y += linx_module.o
linx-y += linx_message_trace.o

linx-y += ipc/attach_detach.o
linx-y += ipc/hunt.o
linx-y += ipc/rlnh.o
linx-y += ipc/mem.o
linx-y += ipc/stat.o
linx-y += ipc/tmo.o
linx-y += ipc/new_link.o

linx-y += trace/trace.o

ifeq ($(LINX_RBLOG),yes)
linx-y += rblog/pagebuffer.o
linx-y += rblog/rblog.o
endif

linx-y += rlnh/rlnh_linux.o
linx-y += rlnh/rlnh_queue.o

linx-y += cfg/db.o
linx-y += cfg/db_format.o
linx-y += cfg/db_ioctl.o
linx-y += cfg/db_proc.o

#other modules
obj-y += ecm/
obj-y += tcp_cm/
obj-y += shmcm/
obj-y += riocm/
obj-y += cmcl/

modules:
	$(XMAKE) ARCH=$(ARCH) V=$(V) -C $(KERNEL) M=`pwd` modules
	$(CP) */*.ko .
clean:
	$(XMAKE) ARCH=$(ARCH) V=$(V) -C $(KERNEL) M=`pwd` clean
	$(LINXRM) Module.symvers Module.markers modules.order

install: modules
	$(XMAKE) ARCH=$(ARCH) V=$(V) -C $(KERNEL) M=`pwd` modules_install
	depmod

