/**
 * @file elf_utils.c
 * @brief ELF64 little-endian parsing and writing utilities — implementation.
 */

#include "elf_utils.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/**
 * @brief Load an ELF64 LE file into a newly allocated context.
 *
 * Opens @p path, reads its content into a heap buffer, validates the ELF
 * magic bytes, class (ELFCLASS64) and data encoding (ELFDATA2LSB), then
 * delegates pointer initialisation to elf_parse().
 *
 * @param path  Filesystem path of the ELF binary to load.
 * @return      Heap-allocated elf_ctx_t on success, NULL on error.
 */
elf_ctx_t *elf_load(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror(path);
        return NULL;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return NULL;
    }

    elf_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        close(fd);
        return NULL;
    }

    ctx->size = (size_t)st.st_size;
    ctx->buf  = malloc(ctx->size);
    if (!ctx->buf) {
        perror("malloc");
        free(ctx);
        close(fd);
        return NULL;
    }

    if (read(fd, ctx->buf, ctx->size) != (ssize_t)ctx->size) {
        perror("read");
        free(ctx->buf);
        free(ctx);
        close(fd);
        return NULL;
    }
    close(fd);

    if (ctx->size < sizeof(Elf64_Ehdr)
        || memcmp(ctx->buf, ELFMAG, SELFMAG) != 0
        || ctx->buf[EI_CLASS] != ELFCLASS64
        || ctx->buf[EI_DATA]  != ELFDATA2LSB) {
        fprintf(stderr, "%s: not a valid ELF64 LE file\n", path);
        free(ctx->buf);
        free(ctx);
        return NULL;
    }

    elf_parse(ctx);
    return ctx;
}

/**
 * @brief Refresh all derived pointers inside an existing context.
 *
 * Recomputes ehdr, shdrs and shstrtab as offsets into ctx->buf.
 * Must be called after any reallocation of ctx->buf.
 *
 * @param ctx  Initialised ELF context.  Must not be NULL.
 */
void elf_parse(elf_ctx_t *ctx)
{
    ctx->ehdr  = (Elf64_Ehdr *)ctx->buf;
    ctx->shdrs = (Elf64_Shdr *)(ctx->buf + ctx->ehdr->e_shoff);

    if (ctx->ehdr->e_shstrndx != SHN_UNDEF
        && ctx->ehdr->e_shstrndx < ctx->ehdr->e_shnum) {
        Elf64_Shdr *strsec = &ctx->shdrs[ctx->ehdr->e_shstrndx];
        ctx->shstrtab = (const char *)(ctx->buf + strsec->sh_offset);
    } else {
        ctx->shstrtab = NULL;
    }
}

/**
 * @brief Find a section header by name.
 *
 * Iterates over all section headers and compares their names against
 * @p name using shstrtab.
 *
 * @param ctx   Initialised ELF context.
 * @param name  Null-terminated section name to look up (e.g. ".text").
 * @return      Pointer to the matching Elf64_Shdr, or NULL if not found.
 */
Elf64_Shdr *elf_find_section(elf_ctx_t *ctx, const char *name)
{
    if (!ctx->shstrtab)
        return NULL;

    for (int i = 0; i < ctx->ehdr->e_shnum; i++) {
        Elf64_Shdr *s = &ctx->shdrs[i];
        const char *sname = ctx->shstrtab + s->sh_name;
        if (strcmp(sname, name) == 0)
            return s;
    }
    return NULL;
}

/**
 * @brief Find a program header by type.
 *
 * Iterates over the program header table and returns the first entry
 * whose p_type matches @p p_type.
 *
 * @param ctx     Initialised ELF context.
 * @param p_type  Program header type (e.g. PT_NOTE, PT_LOAD).
 * @return        Pointer to the matching Elf64_Phdr, or NULL if not found.
 */
Elf64_Phdr *elf_find_phdr(elf_ctx_t *ctx, uint32_t p_type)
{
    if (ctx->ehdr->e_phoff == 0 || ctx->ehdr->e_phnum == 0)
        return NULL;

    Elf64_Phdr *phdrs = (Elf64_Phdr *)(ctx->buf + ctx->ehdr->e_phoff);
    for (int i = 0; i < ctx->ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == p_type)
            return &phdrs[i];
    }
    return NULL;
}

/**
 * @brief Write the ELF buffer to disk.
 *
 * Creates or truncates @p dst_path, writes ctx->buf in full and sets
 * file permissions to 0755.
 *
 * @param ctx       Initialised ELF context.
 * @param dst_path  Destination file path.
 * @return          0 on success, -1 on I/O error.
 */
int elf_write(elf_ctx_t *ctx, const char *dst_path)
{
    int fd = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) {
        perror(dst_path);
        return -1;
    }
    if (write(fd, ctx->buf, ctx->size) != (ssize_t)ctx->size) {
        perror("write");
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

/**
 * @brief Release all resources held by an ELF context.
 *
 * Frees ctx->buf then ctx.  Safe to call with NULL.
 *
 * @param ctx  ELF context to free.  May be NULL.
 */
void elf_free(elf_ctx_t *ctx)
{
    if (!ctx)
        return;
    free(ctx->buf);
    free(ctx);
}
