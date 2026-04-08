#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf_utils.h"
#include "transforms.h"

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s <input> <output> [--ko]\n"
        "\n"
        "  input   ELF binaire ou module kernel (.ko)\n"
        "  output  fichier de sortie\n"
        "  --ko    active le mode module kernel (transforms prudentes uniquement)\n"
        "\n"
        "Transforms appliquées :\n"
        "  tous    : strip, build-id, bss-pad, .comment, rename-syms\n"
        "  binaire : + dead-code, nuke-shdrs\n",
        prog);
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    const char *input  = argv[1];
    const char *output = argv[2];
    int         is_ko  = (argc >= 4 && strcmp(argv[3], "--ko") == 0);

    printf("[*] metamorph — input: %s  output: %s  mode: %s\n",
           input, output, is_ko ? "kernel module" : "userspace binary");

    char tmp_path[256];
    snprintf(tmp_path, sizeof(tmp_path), "%s.strip_tmp", output);

    printf("\n[1] strip\n");
    if (transform_strip(input, tmp_path, is_ko) < 0) {
        fprintf(stderr, "    strip ignoré, copie directe\n");
        snprintf(tmp_path, sizeof(tmp_path), "%s", input);
    }

    elf_ctx_t *ctx = elf_load(tmp_path);
    if (!ctx) {
        fprintf(stderr, "[!] elf_load échoué\n");
        return 1;
    }
    printf("\n[2] transformations\n");
    transform_build_id(ctx);
    transform_bss_pad(ctx);
    transform_comment(ctx);
    transform_rename_symbols(ctx, is_ko);

    if (!is_ko) {
        transform_dead_code(ctx);
        transform_nuke_section_headers(ctx);
    }

    printf("\n[3] écriture\n");
    if (elf_write(ctx, output) < 0) {
        fprintf(stderr, "[!] elf_write échoué\n");
        elf_free(ctx);
        return 1;
    }
    printf("  [+] écrit → %s\n", output);

    elf_free(ctx);

    printf("\n[4] timestamps\n");
    transform_forge_timestamps(output);

    if (strcmp(tmp_path, input) != 0)
        remove(tmp_path);

    printf("\n[✓] terminé.\n");
    return 0;
}
