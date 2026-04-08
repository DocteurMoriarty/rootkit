#ifndef TRANSFORMS_H
#define TRANSFORMS_H

#include "elf_utils.h"

int transform_build_id(elf_ctx_t *ctx);
int transform_bss_pad(elf_ctx_t *ctx);
int transform_comment(elf_ctx_t *ctx);
int transform_strip(const char *src, const char *dst, int is_ko);
int transform_rename_symbols(elf_ctx_t *ctx, int is_ko);
int transform_dead_code(elf_ctx_t *ctx);
int transform_nuke_section_headers(elf_ctx_t *ctx);
int transform_forge_timestamps(const char *path);

#endif
