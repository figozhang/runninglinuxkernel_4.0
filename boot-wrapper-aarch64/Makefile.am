#
# Makefile.am - build a kernel+filesystem image for stand-alone Linux
# booting
#
# Copyright (C) 2012 ARM Limited. All rights reserved.
#
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE.txt file.

# VE
PHYS_OFFSET	:= $(shell perl -I $(top_srcdir) $(top_srcdir)/findmem.pl $(KERNEL_DTB))
UART_BASE	:= $(shell perl -I $(top_srcdir) $(top_srcdir)/findbase.pl $(KERNEL_DTB) 0 'arm,pl011')
SYSREGS_BASE	:= $(shell perl -I $(top_srcdir) $(top_srcdir)/findbase.pl $(KERNEL_DTB) 0 'arm,vexpress-sysreg')
CNTFRQ		:= 0x01800000	# 24Mhz

CPU_IDS		:= $(shell perl -I $(top_srcdir) $(top_srcdir)/findcpuids.pl $(KERNEL_DTB))
NR_CPUS         := $(shell echo $(CPU_IDS) | tr ',' ' ' | wc -w)

DEFINES		= -DCNTFRQ=$(CNTFRQ)
DEFINES		+= -DCPU_IDS=$(CPU_IDS)
DEFINES		+= -DNR_CPUS=$(NR_CPUS)
DEFINES		+= -DSYSREGS_BASE=$(SYSREGS_BASE)
DEFINES		+= -DUART_BASE=$(UART_BASE)
DEFINES		+= -DSTACK_SIZE=256

if KERNEL_32
DEFINES		+= -DKERNEL_32
PSCI_CPU_ON	:= 0x84000003
else
PSCI_CPU_ON	:= 0xc4000003
endif
PSCI_CPU_OFF	:= 0x84000002

OFILES		=

if BOOTWRAPPER_32
CPPFLAGS	+= -DBOOTWRAPPER_32
CFLAGS		+= -marm -mno-unaligned-access
ARCH_SRC	:= arch/aarch32/
else
CFLAGS		+= -mgeneral-regs-only -mstrict-align
ARCH_SRC	:= arch/aarch64/
endif

if PSCI
BOOTMETHOD	:= psci.o
OFILES		+= psci.o
PSCI_NODE	:= psci {				\
			compatible = \"arm,psci\";	\
			method = \"smc\";		\
			cpu_on = <$(PSCI_CPU_ON)>;	\
			cpu_off = <$(PSCI_CPU_OFF)>;	\
		   };
CPU_NODES	:= $(shell perl -I $(top_srcdir) $(top_srcdir)/addpsci.pl $(KERNEL_DTB))
else
BOOTMETHOD	:= spin.o
PSCI_NODE	:=
CPU_NODES	:=
endif

if GICV3
GIC_DIST_BASE	:= $(shell perl -I $(top_srcdir) $(top_srcdir)/findbase.pl $(KERNEL_DTB) 0 'arm,gic-v3')
GIC_RDIST_BASE	:= $(shell perl -I $(top_srcdir) $(top_srcdir)/findbase.pl $(KERNEL_DTB) 1 'arm,gic-v3')
DEFINES		+= -DGIC_DIST_BASE=$(GIC_DIST_BASE)
DEFINES		+= -DGIC_RDIST_BASE=$(GIC_RDIST_BASE)
GIC		:= gic-v3.o
else
GIC_DIST_BASE	:= $(shell perl -I $(top_srcdir) $(top_srcdir)/findbase.pl $(KERNEL_DTB) 0 'arm,cortex-a15-gic')
GIC_CPU_BASE	:= $(shell perl -I $(top_srcdir) $(top_srcdir)/findbase.pl $(KERNEL_DTB) 1 'arm,cortex-a15-gic')
DEFINES		+= -DGIC_CPU_BASE=$(GIC_CPU_BASE)
DEFINES		+= -DGIC_DIST_BASE=$(GIC_DIST_BASE)
GIC		:= gic.o
endif

if KERNEL_32
MBOX_OFFSET	:= 0x7ff8
KERNEL_OFFSET	:= 0x8000
TEXT_LIMIT	:= 0x3000
else
MBOX_OFFSET	:= 0xfff8
KERNEL_OFFSET	:= 0x80000
TEXT_LIMIT	:= 0x80000
endif

LD_SCRIPT	:= model.lds.S

FS_OFFSET	:= 0x10000000
FILESYSTEM_START:= $(shell echo $$(($(PHYS_OFFSET) + $(FS_OFFSET))))
FILESYSTEM_SIZE	:= $(shell stat -Lc %s $(FILESYSTEM) 2>/dev/null || echo 0)
FILESYSTEM_END	:= $(shell echo $$(($(FILESYSTEM_START) + $(FILESYSTEM_SIZE))))

FDT_OFFSET	:= 0x08000000

if XEN
XEN		:= -DXEN=$(XEN_IMAGE)
XEN_OFFSET	:= 0x08200000
KERNEL_SIZE	:= $(shell stat -Lc %s $(KERNEL_IMAGE) 2>/dev/null || echo 0)
DOM0_OFFSET	:= $(shell echo $$(($(PHYS_OFFSET) + $(KERNEL_OFFSET))))
XEN_CHOSEN	:= xen,xen-bootargs = \"$(XEN_CMDLINE)\";		\
		   \#address-cells = <2>;				\
		   \#size-cells = <2>;					\
		   module@1 {						\
			compatible = \"xen,linux-zimage\", \"xen,multiboot-module\"; \
			reg = <0x0 $(DOM0_OFFSET) 0x0 $(KERNEL_SIZE)>;	\
		   };
endif

if INITRD
INITRD_FLAGS	:= -DUSE_INITRD
INITRD_CHOSEN   := linux,initrd-start = <$(FILESYSTEM_START)>;	\
		   linux,initrd-end = <$(FILESYSTEM_END)>;
endif

CHOSEN_NODE	:= chosen {						\
			bootargs = \"$(CMDLINE)\";			\
			$(INITRD_CHOSEN)				\
			$(XEN_CHOSEN)					\
		   };

CPPFLAGS	+= $(INITRD_FLAGS)
CFLAGS		+= -I$(top_srcdir)/include/ -I$(top_srcdir)/$(ARCH_SRC)/include/
CFLAGS		+= -Wall -fomit-frame-pointer
CFLAGS		+= -ffunction-sections -fdata-sections
LDFLAGS		+= --gc-sections

OFILES		+= boot_common.o bakery_lock.o platform.o $(GIC) cache.o lib.o
OFILES		+= $(addprefix $(ARCH_SRC),boot.o stack.o $(BOOTMETHOD) utils.o)

# Don't lookup all prerequisites in $(top_srcdir), only the source files. When
# building outside the source tree $(ARCH_SRC) needs to be created.
VPATH		=
vpath %.c $(top_srcdir)
vpath %.S $(top_srcdir)

all: $(IMAGE)

CLEANFILES = $(IMAGE) linux-system.axf xen-system.axf $(OFILES) model.lds fdt.dtb

$(IMAGE): $(OFILES) model.lds fdt.dtb $(KERNEL_IMAGE) $(FILESYSTEM) $(XEN_IMAGE)
	$(LD) $(LDFLAGS) $(OFILES) -o $@ --script=model.lds

$(ARCH_SRC):
	$(MKDIR_P) $@

%.o: %.S Makefile | $(ARCH_SRC)
	$(CC) $(CPPFLAGS) -D__ASSEMBLY__ $(CFLAGS) $(DEFINES) -c -o $@ $<

%.o: %.c Makefile
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DEFINES) -c -o $@ $<

model.lds: $(LD_SCRIPT) Makefile
	$(CPP) $(CPPFLAGS) -ansi -DPHYS_OFFSET=$(PHYS_OFFSET) -DMBOX_OFFSET=$(MBOX_OFFSET) -DKERNEL_OFFSET=$(KERNEL_OFFSET) -DFDT_OFFSET=$(FDT_OFFSET) -DFS_OFFSET=$(FS_OFFSET) $(XEN) -DXEN_OFFSET=$(XEN_OFFSET) -DKERNEL=$(KERNEL_IMAGE) -DFILESYSTEM=$(FILESYSTEM) -DTEXT_LIMIT=$(TEXT_LIMIT) -P -C -o $@ $<

fdt.dtb: $(KERNEL_DTB) Makefile
	( $(DTC) -O dts -I dtb $(KERNEL_DTB) ; echo "/ { $(CHOSEN_NODE) $(PSCI_NODE) }; $(CPU_NODES)" ) | $(DTC) -O dtb -o $@ -

# The filesystem archive might not exist if INITRD is not being used
.PHONY: all clean $(FILESYSTEM)

MAINTAINERCLEANFILES = aclocal.m4 compile config.* configure install-sh \
	Makefile.in missing
