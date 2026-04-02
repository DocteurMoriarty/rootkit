/*
 * obfs.c — XOR string decode runtime
 *
 * obfs_decode(dst, enc, len)
 *   XOR each byte of enc[] with OBFS_KEY, write to dst, null-terminate.
 *   dst must be at least len+1 bytes (caller allocates via DEOBFS macro).
 */

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stddef.h>
#endif

#include "obfs.h"

void obfs_decode(char *dst, const unsigned char *enc, int len)
{
    int i;
    for (i = 0; i < len; i++)
        dst[i] = (char)(enc[i] ^ OBFS_KEY);
    dst[len] = '\0';
}
