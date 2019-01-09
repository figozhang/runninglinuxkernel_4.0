#ARCH = arm
#CROSS_COMPILE = arm-linux-gnueabi-

BASEINCLUDE ?= /home/ben/work/runninglinuxkernel_4.0
#BASEINCLUDE ?= /lib/modules/`uname -r`/build

mymodule-objs := module_parm.o 

obj-m	:=   mymodule.o
all : 
	$(MAKE) -C $(BASEINCLUDE) M=$(PWD) modules;

clean:
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) clean;
	rm -f *.ko;


