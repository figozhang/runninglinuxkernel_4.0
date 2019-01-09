
BASEINCLUDE ?= /home/ben/work/runninglinuxkernel_4.0
#BASEINCLUDE ?= /lib/modules/`uname -r`/build

mydemo-objs := simple_char.o 

obj-m	:=   mydemo.o
all : 
	$(MAKE) -C $(BASEINCLUDE) M=$(PWD) modules;

clean:
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) clean;
	rm -f *.ko;


