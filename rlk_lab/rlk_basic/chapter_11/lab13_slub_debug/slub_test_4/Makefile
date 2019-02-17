
BASEINCLUDE ?= /home/rlk/rlk_basic/runninglinuxkernel_4.0
slub4-objs := slub_test.o 

obj-m	:=   slub4.o
all : 
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) modules;

clean:
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) clean;
	rm -f *.ko;


