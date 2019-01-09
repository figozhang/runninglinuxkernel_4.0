#ARCH = arm
#CROSS_COMPILE = arm-linux-gnueabi-

ccflags-y :=-g
BASEINCLUDE ?= /home/figo/work/test1/runninglinuxkernel/runninglinuxkernel_4.0
mutexlock-objs := mutexlock_test.o 

obj-m	:=   mutexlock.o
all : 
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) modules;

clean:
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) clean;
	rm -f *.ko;


