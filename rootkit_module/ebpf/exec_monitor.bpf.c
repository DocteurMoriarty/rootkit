/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Moniteur d'execution — enregistre chaque appel execve dans un ring buffer.
 *
 * Se branche sur le tracepoint sched:sched_process_exec pour capturer
 * le PID, UID, PPID, comm et nom de fichier de chaque nouveau processus.
 * Les evenements sont envoyes au userspace via un ring buffer BPF.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "rk_bpf_common.h"

/* Ring buffer pour envoyer les evenements au userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RK_RINGBUF_SIZE);
} exec_events SEC(".maps");

/* Flag pour activer/desactiver le moniteur */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} exec_enabled SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    __u32 zero = 0;
    __u8 *enabled = bpf_map_lookup_elem(&exec_enabled, &zero);
    if (!enabled || *enabled == 0)
        return 0;

    struct exec_event *evt;
    evt = bpf_ringbuf_reserve(&exec_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    evt->pid  = bpf_get_current_pid_tgid() >> 32;
    evt->uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    /* Lire le nom du fichier execute depuis le contexte du tracepoint */
    unsigned int fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&evt->filename, sizeof(evt->filename),
                       (void *)ctx + fname_off);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
