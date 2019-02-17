BASEINCLUDE ?= /lib/modules/$(shell uname -r)/build

oops-objs := oops_test.o 
KBUILD_CFLAGS +=-g


obj-m	:=   oops.o
all : 
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) modules;

clean:
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) clean;
	rm -f *.ko;


