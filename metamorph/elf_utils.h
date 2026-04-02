/**
 * @file elf_utils.h
 * @brief ELF64 little-endian parsing and writing utilities.
 *
 * Provides a context-based API to load, inspect, modify and write back
 * ELF64 LE binaries.  All pointers stored in elf_ctx_t are offsets into
 * the single heap-allocated buffer ctx->buf, so realloc(ctx->buf) must
 * be followed by a call to elf_parse() to refresh derived pointers.
 */

#ifndef ELF_UTILS_H
#define ELF_UTILS_H

#include <elf.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief ELF parsing context.
 *
 * All pointer fields are aliases into buf and become invalid if buf is
 * reallocated without a subsequent elf_parse() call.
 */
typedef struct {
    uint8_t    *buf;
    size_t      size;
    Elf64_Ehdr *ehdr;
    Elf64_Shdr *shdrs;
    const char *shstrtab;
} elf_ctx_t;

/**
 * @brief Load an ELF64 LE file into a newly allocated context.
 *
 * Reads the file at @p path into a heap buffer, validates the ELF magic,
 * class (ELF64) and data encoding (little-endian), then calls elf_parse().
 *
 * @param path  Filesystem path of the ELF binary to load.
 * @return      Pointer to a heap-allocated elf_ctx_t on success,
 *              NULL on I/O error or invalid ELF format.
 */
elf_ctx_t  *elf_load(const char *path);

/**
 * @brief Refresh all derived pointers inside an existing context.
 *
 * Must be called after any reallocation of ctx->buf to keep ehdr,
 * shdrs and shstrtab valid.
 *
 * @param ctx  Initialised ELF context.  Must not be NULL.
 */
void        elf_parse(elf_ctx_t *ctx);

/**
 * @brief Find a section header by name.
 *
 * Performs a linear search through the section header table using
 * shstrtab.
 *
 * @param ctx   Initialised ELF context.
 * @param name  Null-terminated section name (e.g. ".text").
 * @return      Pointer to the matching Elf64_Shdr inside ctx->buf,
 *              or NULL if not found or shstrtab is unavailable.
 */
Elf64_Shdr *elf_find_section(elf_ctx_t *ctx, const char *name);

/**
 * @brief Find a program header by type.
 *
 * Performs a linear search through the program header table.
 *
 * @param ctx     Initialised ELF context.
 * @param p_type  Program header type to search for (e.g. PT_NOTE).
 * @return        Pointer to the matching Elf64_Phdr inside ctx->buf,
 *                or NULL if not found or no program header table exists.
 */
Elf64_Phdr *elf_find_phdr(elf_ctx_t *ctx, uint32_t p_type);

/**
 * @brief Write the ELF buffer to disk.
 *
 * Creates or truncates the file at @p dst_path and writes ctx->buf
 * in full with permissions 0755.
 *
 * @param ctx       Initialised ELF context.
 * @param dst_path  Destination file path.
 * @return          0 on success, -1 on I/O error.
 */
int         elf_write(elf_ctx_t *ctx, const char *dst_path);

/**
 * @brief Release all resources held by an ELF context.
 *
 * Frees ctx->buf and ctx itself.  Safe to call with NULL.
 *
 * @param ctx  ELF context to free.  May be NULL.
 */
void        elf_free(elf_ctx_t *ctx);

#endif /* ELF_UTILS_H */
