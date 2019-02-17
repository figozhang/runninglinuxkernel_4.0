ccflags-y :=-g
BASEINCLUDE ?= /home/rlk/rlk_basic/runninglinuxkernel_4.0
kmemleak-objs := kmemleak_test.o 

obj-m	:=   kmemleak.o
all : 
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) modules;

clean:
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) clean;
	rm -f *.ko;


