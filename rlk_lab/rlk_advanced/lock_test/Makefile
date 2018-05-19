#ARCH = arm
#CROSS_COMPILE = arm-linux-gnueabi-

ccflags-y :=-g
BASEINCLUDE ?= /home/figo/work/test1/runninglinuxkernel/runninglinuxkernel_4.0
lock-objs := lock_test.o 

obj-m	:=   lock.o
all : 
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) modules;

clean:
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) clean;
	rm -f *.ko;


