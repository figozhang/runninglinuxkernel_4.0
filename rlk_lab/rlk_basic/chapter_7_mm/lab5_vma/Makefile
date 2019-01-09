
# modify right kernel PATH for your system
BASEINCLUDE ?= /home/figo/work/runninglinuxkernel/runninglinuxkernel_4.0
#BASEINCLUDE ?= /lib/modules/`uname -r`/build

vma_test-objs := vma.o

obj-m	:= vma_test.o
all :
	$(MAKE) -C $(BASEINCLUDE) M=$(PWD) modules;

clean:
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) clean;
	rm -f *.ko;


