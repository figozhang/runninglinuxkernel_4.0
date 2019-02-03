BASEINCLUDE ?= /home/figo/work/runninglinuxkernel/runninglinuxkernel_4.0
#BASEINCLUDE ?= /lib/modules/`uname -r`/build

debugfs-test-objs := debugfs_test.o 

obj-m	:=   debugfs-test.o
all : 
	$(MAKE) -C $(BASEINCLUDE) M=$(PWD) modules;

clean:
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) clean;
	rm -f *.ko;


