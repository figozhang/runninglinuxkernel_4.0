#ARCH = arm
#CROSS_COMPILE = arm-linux-gnueabi-

BASEINCLUDE ?= /home/figo/work/test1/runninglinuxkernel/runninglinuxkernel_4.0
oops-objs := oops_test.o 

obj-m	:=   oops.o
all : 
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) modules;

clean:
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) clean;
	rm -f *.ko;


