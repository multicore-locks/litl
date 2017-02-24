# Note:
# - the compile flags for the locks are inside src/Makefile
# - we need special version of CLHT and ssmem (to compile them for shared library)
include Makefile.config

LDFLAGS=-LCLHT/external/lib -LCLHT -lsspfd -lssmem -lclht -lrt -lm -m64 -pthread
CFLAGS=-Iinclude/

TARGETS=$(addprefix lib, $(ALGORITHMS))
DIR=$(addprefix obj/, $(ALGORITHMS))
SOS=$(TARGETS:=.so)
SHS=$(TARGETS:=.sh)
export COND_VAR=1

.PRECIOUS: %.o
.SECONDARY: $(OBJS)
.PHONY: all clean format

all: $(DIR) include/topology.h $(SOS) $(SHS)

no_cond_var: COND_VAR=0
no_cond_var: all

%.so: obj/CLHT/libclht.a obj/
	mkdir -p lib/
	$(MAKE) -C src/ ../lib/$@

obj/:
	mkdir -p $@

$(DIR):
	mkdir -p $@

obj/CLHT:
	cd obj/ && ([ -d CLHT ] || git clone https://github.com/HugoGuiroux/CLHT.git)
	mkdir -p obj/CLHT/external/lib/

obj/CLHT/libclht.a: obj/CLHT obj/CLHT/external/lib/libssmem.a obj/CLHT/external/lib/libsspfd.a
	cd obj/CLHT/ && make libclht_lb_res.a

obj/CLHT/external/lib/libssmem.a: obj/CLHT
	cd obj/CLHT/ && \
	([ -d ssmem ] || git clone https://github.com/HugoGuiroux/ssmem.git) && \
	cd ssmem && \
	make libssmem.a && \
	cp libssmem.a ../external/lib/ && \
	cp include/ssmem.h ../external/include

obj/CLHT/external/lib/libsspfd.a: obj/CLHT
	cd obj/CLHT/ && \
	([ -d sspfd ] || git clone https://github.com/HugoGuiroux/sspfd.git  && sed -i 's/CFLAGS = -O3 -Wall$$/CFLAGS = -O3 -Wall -fPIC/g' sspfd/Makefile) && \
	cd sspfd && \
	make libsspfd.a && \
	cp libsspfd.a ../external/lib/ && \
	cp sspfd.h ../external/include

$(SHS): src/liblock.in
	cat $< | sed -e "s/@abs_top_srcdir@/$$(echo $$(cd .; pwd) | sed -e 's/\([\/&]\)/\\\1/g')/g" > $@
	sed -i "s/@lib@/$$(basename $@ .sh).so/g" $@
	chmod a+x $@

include/topology.h: include/topology.in
	cat $< | sed -e "s/@nodes@/$$(numactl -H | head -1 | cut -f 2 -d' ')/g" > $@
	sed -i "s/@cpus@/$$(nproc)/g" $@
	sed -i "s/@cachelinesize@/128/g" $@  # 128 bytes is advised by intel documentation to avoid false-sharing with the HW prefetcher
	sed -i "s/@pagesize@/$$(getconf PAGESIZE)/g" $@
	sed -i 's#@cpufreq@#'$$(cat /proc/cpuinfo | grep MHz | head -1 | awk '{ x = $$4/1000; printf("%0.2g", x); }')'#g' $@
	chmod a+x $@


clean:
	rm -rf lib/ obj/ $(SHS) include/topology.h

format:
	for i in `find . | egrep "\.c$$|\.cc$$|\.cxx$$|\.cpp$$|\.h$$"`; do clang-format  -i "$$i"; done
