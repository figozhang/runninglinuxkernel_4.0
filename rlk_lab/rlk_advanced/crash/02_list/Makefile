BASEINCLUDE ?= /lib/modules/$(shell uname -r)/build

list-crash-objs := list_crash.o 
KBUILD_CFLAGS +=-g


obj-m	:=   list-crash.o
all : 
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) modules;

clean:
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) clean;
	rm -f *.ko;


