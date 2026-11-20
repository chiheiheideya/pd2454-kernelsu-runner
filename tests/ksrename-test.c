/*
 * Host harness for ksrename.h (reviewed: gpt-6.2-sol/high, 2026-11).
 * Applies the rename pass to a copy of a real module image and
 * re-verifies every invariant independently:
 *
 *  1. the pass must succeed and rewrite BOTH identity fields;
 *  2. no case-insensitive "ksu" token may survive in .modinfo,
 *     .gnu.linkonce.this_module, the symtab-linked .strtab, or the
 *     .BTF string region (rodata is exempt by design);
 *  3. SHN_UNDEF symbol names must be byte-identical (kernel
 *     resolution cannot change);
 *  4. bytes outside the four target sections must be byte-identical
 *     to the input.
 * The patched image is written only after every assertion passed.
 * Usage: ksrename-test <module.ko> [out.ko]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "ksrename.h"

static unsigned char *slurp(const char *p, uint64_t *n)
{
    FILE *f = fopen(p, "rb");
    unsigned char *b = NULL;
    uint64_t cap = 1u << 20, sz = 0;

    if (!f)
        return NULL;
    b = malloc(cap);
    if (!b)
        exit(2);
    for (;;)
    {
        size_t got;

        if (sz == cap)
        {
            unsigned char *grown;

            if (cap > SIZE_MAX / 2)
                exit(2);
            cap *= 2;
            grown = realloc(b, cap);
            if (!grown)
                exit(2);
            b = grown;
        }
        got = fread(b + sz, 1, cap - sz, f);
        if (!got)
            break;
        sz += got;
    }
    if (ferror(f))
    {
        fclose(f);
        free(b);
        return NULL;
    }
    fclose(f);
    *n = sz;
    return b;
}

static uint64_t count_ci(const unsigned char *b, uint64_t n,
                         const char *needle)
{
    uint64_t hits = 0;
    size_t l = strlen(needle);

    for (uint64_t i = 0; l && i + l <= n; i++)
    {
        size_t k;

        for (k = 0; k < l; k++)
        {
            unsigned char x = b[i + k], y = (unsigned char)needle[k];

            if (x >= 'A' && x <= 'Z')
                x += 32;
            if (y >= 'A' && y <= 'Z')
                y += 32;
            if (x != y)
                break;
        }
        if (k == l)
            hits++;
    }
    return hits;
}

/* strict section walker: ELF64/LSB/ET_REL, bounded names, NOBITS and
 * NULL skipped; invokes cb for every file-backed section */
static int walk_sections(const unsigned char *img, uint64_t size,
                         int (*cb)(const char *nm, uint32_t typ,
                                   const unsigned char *img,
                                   uint64_t off, uint64_t sz, int *fails),
                         int *fails)
{
    uint64_t shoff, shstr_off, shstr_size;
    uint16_t shentsize, shnum, shstrndx;

    memcpy(&shoff, img + 0x28, 8);
    memcpy(&shentsize, img + 0x3a, 2);
    memcpy(&shnum, img + 0x3c, 2);
    memcpy(&shstrndx, img + 0x3e, 2);
    memcpy(&shstr_off, img + shoff + (uint64_t)shstrndx * shentsize + 0x18,
           8);
    memcpy(&shstr_size, img + shoff + (uint64_t)shstrndx * shentsize + 0x20,
           8);
    if (shstr_off > size || shstr_size > size - shstr_off)
        return -1;
    for (uint32_t i = 0; i < shnum; i++)
    {
        uint64_t off = shoff + (uint64_t)i * shentsize;
        uint32_t name_off, typ;
        uint64_t soff, ssz;
        const char *nm;

        memcpy(&name_off, img + off, 4);
        memcpy(&typ, img + off + 4, 4);
        memcpy(&soff, img + off + 0x18, 8);
        memcpy(&ssz, img + off + 0x20, 8);
        if (typ == 0 || typ == 8)
            continue;
        if (name_off >= shstr_size)
            return -1;
        nm = (const char *)img + shstr_off + name_off;
        if (!memchr(nm, 0, shstr_size - name_off))
            return -1;
        if (soff > size || ssz > size - soff)
            return -1;
        if (cb(nm, typ, img, soff, ssz, fails))
            return -1;
    }
    return 0;
}

static int check_section(const char *nm, uint32_t typ,
                         const unsigned char *img, uint64_t off,
                         uint64_t sz, int *fails)
{
    uint64_t ci = count_ci(img + off, sz, "ksu");

    (void)typ;
    if (!strncmp(nm, ".rodata", 7))
    {
        printf("INFO %-26s rodata: ksu_ci=%llu (unpatched by design)\n",
               nm, (unsigned long long)ci);
        return 0;
    }
    if (strcmp(nm, ".modinfo") && strcmp(nm, ".gnu.linkonce.this_module") &&
        strcmp(nm, ".strtab") && strcmp(nm, ".BTF"))
        return 0; /* non-target sections are covered by the byte-diff */
    if (ci)
    {
        fprintf(stderr, "FAIL %-26s %llu case-insensitive 'ksu' tokens "
                        "remain\n",
                nm, (unsigned long long)ci);
        (*fails)++;
    }
    return 0;
}

int main(int argc, char **argv)
{
    uint64_t n;
    unsigned char *orig, *img;
    struct ks_rename_stats st;
    int fails = 0;
    const char *out = argc > 2 ? argv[2] : "/tmp/ksrename-out.ko";

    if (argc < 2)
    {
        fprintf(stderr, "usage: %s <module.ko> [out.ko]\n", argv[0]);
        return 2;
    }
    orig = slurp(argv[1], &n);
    if (!orig)
    {
        perror("open module");
        return 2;
    }
    img = malloc(n);
    if (!img)
        return 2;
    memcpy(img, orig, n);

    if (ks_rename_module(img, n, &st) != 0)
    {
        fprintf(stderr, "FAIL: ks_rename_module rejected the image "
                        "(validation or identity-field failure)\n");
        return 1;
    }
    printf("stats: modinfo=%u/%u this_module=%u strtab(exact=%u pfx=%u "
           "tok=%u upfx=%u protected=%u) btf(%u/%u/%u/%u)\n",
           st.modinfo_name, st.modinfo_other, st.this_module_name,
           st.strtab_exact, st.strtab_prefix, st.strtab_token,
           st.strtab_upfx, st.strtab_protected, st.btf_exact,
           st.btf_prefix, st.btf_token, st.btf_upfx);
    if (st.modinfo_name != 1 || st.this_module_name != 1)
    {
        fprintf(stderr, "FAIL: identity fields not both rewritten\n");
        fails++;
    }

    /* per-section token assertions (strict walker, NOBITS skipped) */
    if (walk_sections(img, n, check_section, &fails) != 0)
    {
        fprintf(stderr, "FAIL: patched image failed strict section walk\n");
        fails++;
    }

    /* SHN_UNDEF symbol names must be byte-identical to the input */
    {
        uint64_t shoff, shstr_off, shstr_size, sym_off = 0, sym_sz = 0,
                                                    stroff = 0;
        uint16_t shentsize, shnum, shstrndx;
        uint32_t link = 0;
        int seen = 0, und = 0, bad = 0;

        memcpy(&shoff, img + 0x28, 8);
        memcpy(&shentsize, img + 0x3a, 2);
        memcpy(&shnum, img + 0x3c, 2);
        memcpy(&shstrndx, img + 0x3e, 2);
        memcpy(&shstr_off,
               img + shoff + (uint64_t)shstrndx * shentsize + 0x18, 8);
        memcpy(&shstr_size,
               img + shoff + (uint64_t)shstrndx * shentsize + 0x20, 8);
        for (uint32_t s = 0; s < shnum; s++)
        {
            uint64_t off = shoff + (uint64_t)s * shentsize;
            uint32_t typ;

            memcpy(&typ, img + off + 4, 4);
            if (typ == 2)
            {
                memcpy(&sym_off, img + off + 0x18, 8);
                memcpy(&sym_sz, img + off + 0x20, 8);
                memcpy(&link, img + off + 0x28, 4);
                seen = 1;
                break;
            }
        }
        if (!seen || link >= shnum)
        {
            fprintf(stderr, "FAIL: no symtab in output\n");
            fails++;
        }
        else
        {
            memcpy(&stroff, img + shoff + (uint64_t)link * shentsize + 0x18,
                   8);
            for (uint64_t j = 1; j < sym_sz / 24; j++)
            {
                const uint8_t *so = img + sym_off + j * 24;
                uint32_t sn;
                uint16_t shn;

                memcpy(&sn, so, 4);
                memcpy(&shn, so + 6, 2);
                if (shn != 0)
                    continue;
                und++;
                if (strcmp((const char *)img + stroff + sn,
                           (const char *)orig + stroff + sn))
                    bad++;
            }
            printf("und_names=%d unchanged=%d\n", und, und - bad);
            if (bad)
            {
                fprintf(stderr, "FAIL: %d SHN_UNDEF names changed\n", bad);
                fails++;
            }
        }
    }

    /* everything outside the four target sections must be unchanged */
    {
        uint64_t shoff, shstr_off, shstr_size, changed = 0;
        uint16_t shentsize, shnum, shstrndx;

        memcpy(&shoff, img + 0x28, 8);
        memcpy(&shentsize, img + 0x3a, 2);
        memcpy(&shnum, img + 0x3c, 2);
        memcpy(&shstrndx, img + 0x3e, 2);
        memcpy(&shstr_off,
               img + shoff + (uint64_t)shstrndx * shentsize + 0x18, 8);
        memcpy(&shstr_size,
               img + shoff + (uint64_t)shstrndx * shentsize + 0x20, 8);
        if (shstr_off > n || shstr_size > n - shstr_off)
        {
            fprintf(stderr, "FAIL: bad section-name table in output\n");
            fails++;
        }
        else
            for (uint64_t i = 0; i < n; i++)
            {
                int in_target = 0;

                for (uint32_t s = 0; s < shnum && !in_target; s++)
                {
                    uint64_t off = shoff + (uint64_t)s * shentsize;
                    uint32_t name_off, typ;
                    uint64_t soff, ssz;
                    const char *nm;

                    memcpy(&name_off, img + off, 4);
                    memcpy(&typ, img + off + 4, 4);
                    memcpy(&soff, img + off + 0x18, 8);
                    memcpy(&ssz, img + off + 0x20, 8);
                    if (typ == 0 || typ == 8)
                        continue;
                    if (name_off >= shstr_size ||
                        soff > n || ssz > n - soff)
                    {
                        fprintf(stderr, "FAIL: corrupt section header "
                                        "%u in output\n",
                                s);
                        fails++;
                        in_target = 1; /* stop scanning */
                        break;
                    }
                    nm = (const char *)img + shstr_off + name_off;
                    if (i >= soff && i < soff + ssz &&
                        (!strcmp(nm, ".modinfo") ||
                         !strcmp(nm, ".gnu.linkonce.this_module") ||
                         !strcmp(nm, ".BTF") || !strcmp(nm, ".strtab")))
                        in_target = 1;
                }
                if (!in_target && img[i] != orig[i])
                    changed++;
            }
        if (changed)
        {
            fprintf(stderr, "FAIL: %llu bytes changed outside the target "
                            "sections\n",
                    (unsigned long long)changed);
            fails++;
        }
    }

    if (fails)
    {
        fprintf(stderr, "%d FAILURES\n", fails);
        return 1;
    }
    {
        FILE *f = fopen(out, "wb");

        if (!f || fwrite(img, 1, n, f) != n || fclose(f) != 0)
        {
            perror("write out.ko");
            return 2;
        }
    }
    printf("wrote %s (%llu bytes) -- verify: llvm-nm/readelf/objdump\n",
           out, (unsigned long long)n);
    printf("PASS: module renamed %s -> %s\n", KS_RENAME_OLD,
           KS_RENAME_MODULE);
    free(orig);
    free(img);
    return 0;
}
