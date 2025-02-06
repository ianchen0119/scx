OUTPUT = output
LIBBPF_SRC = $(abspath libbpf/src)
LIBBPF_OBJ = $(abspath $(OUTPUT)/libbpf.a)
LIBBPF_OBJDIR = $(abspath ./$(OUTPUT)/libbpf)
LIBBPF_DESTDIR = $(abspath ./$(OUTPUT))


TARGET = main
BPF_TARGET = ${TARGET:=.bpf}
BPF_C = ${BPF_TARGET:=.c}
BPF_OBJ = ${BPF_C:.c=.o}

BASEDIR = $(abspath .)
OUTPUT = output
LIBBPF_INCLUDE_UAPI = $(abspath ./libbpf/include/uapi)
LIBBPF_SRC = $(abspath libbpf/src)
LIBBPF_OBJ = $(abspath $(OUTPUT)/libbpf.a)
LIBBPF_OBJDIR = $(abspath ./$(OUTPUT)/libbpf)
LIBBPF_DESTDIR = $(abspath ./$(OUTPUT))
CLANG_BPF_SYS_INCLUDES := `shell $(CLANG) -v -E - </dev/null 2>&1 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }'`
CGOFLAG = CC=clang CGO_CFLAGS="-I$(BASEDIR)/$(OUTPUT)" CGO_LDFLAGS="-lelf -lz $(LIBBPF_OBJ)"
STATIC=-extldflags -static

.PHONY: build
build: $(BPF_OBJ) libbpf libbpf-uapi
	$(CGOFLAG) go build -ldflags "-w -s $(STATIC)" main.go

test: build
	vng -r v6.12.2 -- ./main

.PHONY: libbpf-uapi
libbpf-uapi: $(LIBBPF_SRC)
	UAPIDIR=$(LIBBPF_DESTDIR) \
		$(MAKE) -C $(LIBBPF_SRC) install_uapi_headers

.PHONY: libbpf
libbpf: $(LIBBPF_SRC) $(wildcard $(LIBBPF_SRC)/*.[ch])
	CC="gcc" CFLAGS="-g -O2 -Wall -fpie" \
	   $(MAKE) -C $(LIBBPF_SRC) \
		BUILD_STATIC_ONLY=1 \
		OBJDIR=$(LIBBPF_OBJDIR) \
		DESTDIR=$(LIBBPF_DESTDIR) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install
	$(eval STATIC=-extldflags -static)

dep:
	git clone https://github.com/libbpf/libbpf.git && \
	cd libbpf && \
	git checkout 09b9e83 && \
	cd src && \
	make

$(BPF_OBJ): %.o: %.c
	clang-17 \
		-O2 -g -Wall -target bpf \
		-D__TARGET_ARCH_x86 -mcpu=v3 -mlittle-endian \
		'-idirafter$ /usr/lib/llvm-17/lib/clang/17/include' '-idirafter$ /usr/local/include' '-idirafter$ /usr/include/x86_64-linux-gnu' '-idirafter$ /usr/include' \
		-I ../../build/libbpf/src/usr/include -I ../../build/libbpf/include/uapi -I ../../scheds/include -I ../../scheds/include/arch/x86 -I ../../scheds/include/bpf-compat -I ../../scheds/include/lib \
		-Wno-compare-distinct-pointer-types \
		-c $< -o $@
	bpftool gen skeleton main.bpf.o > main.skeleton.h

clean:
	rm *.skeleton.h
	rm *.ll *.o