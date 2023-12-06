LIBBPF := $(PWD)/libbpf/src

export CGO_CFLAGS  = -I$(LIBBPF)
export CGO_LDFLAGS = -L$(LIBBPF)

FLOW_STATE_TYPE ?= BPF_MAP_TYPE_LRU_PERCPU_HASH
FLOW_STATE_SIZE ?= 1000000  # 1M
FLOW_SHARE_SIZE ?= 1000000  # 1M
FLOW_QUEUE_SIZE ?= 10000

cmd/balancer: cmd/balancer.go libbpf/src/libbpf.a bpf/bpf.o 
	go build -o $@ cmd/balancer.go


%.o: %.c libbpf/src
	clang -S \
	    -target bpf \
	    -D FLOW_STATE_TYPE=$(FLOW_STATE_TYPE) \
	    -D FLOW_STATE_SIZE=$(FLOW_STATE_SIZE) \
	    -D FLOW_SHARE_SIZE=$(FLOW_SHARE_SIZE) \
	    -D FLOW_QUEUE_SIZE=$(FLOW_QUEUE_SIZE) \
	    -D __BPF_TRACING__ \
	    -I$(LIBBPF) \
	    -Wall \
	    -Werror \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -g -O2 -emit-llvm -c -o $*.ll $*.c
	llc -march=bpf -filetype=obj -o $@ $*.ll
	rm $*.ll

libbpf:
	git clone -b v0.6.1 https://github.com/libbpf/libbpf

libbpf/src/libbpf.a: libbpf
	cd libbpf/src && $(MAKE)

clean:
	rm -f bpf/bpf.o cmd/balancer

distclean: clean
	rm -rf libbpf

ubuntu-dependencies:
	apt-get install git build-essential libelf-dev clang libc6-dev libc6-dev-i386 llvm golang-1.20 libyaml-perl libjson-perl ethtool
	ln -s /usr/lib/go-1.20/bin/go /usr/local/bin/go
