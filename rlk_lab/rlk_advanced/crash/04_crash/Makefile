BASEINCLUDE ?= /lib/modules/$(shell uname -r)/build

crash-objs := crash_test.o 
KBUILD_CFLAGS +=-g


obj-m	:=   crash.o
all : 
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) modules;

clean:
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) clean;
	rm -f *.ko;


