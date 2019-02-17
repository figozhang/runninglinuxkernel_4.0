
BASEINCLUDE ?= /home/rlk/rlk_basic/runninglinuxkernel_4.0
slub1-objs := slub_test.o 

obj-m	:=   slub1.o
all : 
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) modules;

clean:
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) clean;
	rm -f *.ko;


