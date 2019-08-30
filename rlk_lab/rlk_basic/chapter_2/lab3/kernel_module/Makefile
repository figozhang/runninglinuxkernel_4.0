BASEINCLUDE ?= /home/rlk/rlk_basic/runninglinuxkernel_4.0

rb_test-objs := rbtree_test.o 

obj-m	:=   rb_test.o
all : 
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) modules;

clean:
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) clean;
	rm -f *.ko;


