#BASEINCLUDE ?= /lib/modules/$(shell uname -r)/build
BASEINCLUDE ?= /home/rlk/rlk_basic/runninglinuxkernel_4.0

oops-objs := ramdisk-driver.o 
KBUILD_CFLAGS +=-g -O0


obj-m	:=   ramdisk_driver.o
all : 
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) modules;

install:
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) modules_install;
	
	

clean:
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) clean;
	rm -f *.ko;


