
BASEINCLUDE ?= /home/ben/work/runninglinuxkernel_4.0
#BASEINCLUDE ?= /lib/modules/`uname -r`/build

mydemo_poll-objs := mydemodrv_poll.o 

obj-m	:=   mydemo_poll.o
all : 
	$(MAKE) -C $(BASEINCLUDE) M=$(PWD) modules;

clean:
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) clean;
	rm -f *.ko;


