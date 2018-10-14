obj-m := uprobes.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
DEPENDENCIES := $(shell echo uprobes.[ch] uprobes_*.[ch])
DEPENDENCIES += $(shell echo ../uprobes2/uprobes.[ch] ../uprobes2/uprobes_*.[ch])
DEPENDENCIES += Makefile

CLEAN_FILES := $(shell echo *.mod.c *.ko *.o .*.cmd *~ *.sgn)
CLEAN_FILES += Module.markers modules.order Module.symvers
CLEAN_DIRS  := .tmp_versions

LIBEXECDIR = ../../../../libexec/systemtap
CERTDB = ../../../../etc/systemtap/staprun

# Build the module and, if we are root or stap-server, sign it.
# Make sure that all the required tools and resources are available
# before attempting to sign the module. 
# Ensure that the generated files are writable by the group which
# owns this build directory. This is so that the stap-server service
# can rebuild the module, if necessary.
default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
	if test `id -u` = 0 -o `id -un` = stap-server; then \
		if test -x $(LIBEXECDIR)/stap-sign-module; then \
			stap_dir=${SYSTEMTAP_DIR}; \
			if test -z "$$stap_dir"; then \
				stap_dir=~/.systemtap; \
			fi; \
			certfile=$$stap_dir/ssl/server/stap.cert; \
			if test ! -f $$certfile -o -f $$stap_dir/ssl/server/pw; then \
				$(LIBEXECDIR)/stap-gen-cert > /dev/null; \
			fi; \
			if test `id -u` = 0; then \
				$(LIBEXECDIR)/stap-authorize-cert $$certfile $(CERTDB) > /dev/null; \
			fi; \
			for f in *.ko; do \
				if test ! -e $$f.sgn -o $$f.sgn -ot $$f; then \
					$(LIBEXECDIR)/stap-sign-module $$f > /dev/null; \
				fi \
			done \
		fi \
	fi
	group=`stat -c %G $(PWD)`; \
	for f in $(CLEAN_FILES); do \
		test ! -f $$f && continue; \
		chgrp -f $$group $$f; \
		chmod -f 664 $$f; \
	done; \
	for d in $(CLEAN_DIRS); do \
		test ! -d $$d && continue; \
		chgrp -f $$group $$d; \
		chmod -f 775 $$d; \
		for dd in `find $$d -type d`; do \
			chgrp -f $$group $$dd; \
			chmod -f 775 $$dd; \
		done; \
		for f in `find $$d -type f`; do \
			chgrp -f $$group $$f; \
			chmod -f 664 $$f; \
		done; \
	done

# This target is used with "make -q" to see whether a "real" build is needed.
uprobes.ko: $(DEPENDENCIES)
	@echo uprobes.ko is not a valid target.  See Makefile.

clean:
	rm -f $(CLEAN_FILES)
	rm -rf $(CLEAN_DIRS)
