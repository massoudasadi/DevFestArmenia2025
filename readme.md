On Ubuntu 24.04, you need the following dependencies:

-clang and llvm

-libbpf-dev

-linux-tools-common and linux-tools-$(uname -r)



how to run program inside process file:

Generate vmlinux.h: bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
Compile BPF: clang -g -O2 -target bpf -c notify.bpf.c -o notify.bpf.o
Generate Skeleton: bpftool gen skeleton notify.bpf.o > notify.skel.h
Compile Userspace: clang -g -O2 notify.c -lbpf -lelf -lz -o notify
Run: sudo ./notify



how to run program inside xdp file:

Compile BPF: clang -g -O2 -target bpf -c xdp_drop_ip.c -o xdp_drop_ip.o
Compile Userspace: clang -g -O2 user.c -lbpf -lelf -lz -o user
Run: sudo ./user ens33 104.21.75.194