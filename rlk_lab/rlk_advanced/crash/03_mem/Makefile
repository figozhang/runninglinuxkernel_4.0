BASEINCLUDE ?= /lib/modules/$(shell uname -r)/build

mem-objs := mem_test.o 
KBUILD_CFLAGS +=-g


obj-m	:=   mem.o
all : 
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) modules;

clean:
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) clean;
	rm -f *.ko;


