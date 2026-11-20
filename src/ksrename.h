#ifndef KSRENAME_H
#define KSRENAME_H

/*
 * Module-image name hardening pass (reviewed: gpt-6.2-sol/high, 2026-11).
 *
 * Rewrites, IN PLACE and strictly equal-length (no section size, offset,
 * relocation or string-table index ever changes):
 *   .modinfo                    the "name=<old>" value, plus any other
 *                               <old> substring in other entries
 *   .gnu.linkonce.this_module   struct module.name[56] (found by a bounded
 *                               scan constrained to the name field)
 *   .strtab (via symtab sh_link) every NUL-terminated string EXCEPT the
 *                               name spans of SHN_UNDEF symbols, whose
 *                               names resolve against the kernel and must
 *                               stay stable
 *   .BTF                        the same swaps, confined to the BTF string
 *                               table located through the BTF header
 *
 * Safety model (hardened after review):
 *   - EVERYTHING is validated before the first byte is written: ELF64
 *     LSB ET_REL header, 64-byte section entries, table bounds via
 *     subtraction, section-name strings bounded inside the section-name
 *     string table, exactly one symtab whose sh_link names a real strtab,
 *     strtab NUL-terminated at both ends, target sections extent-checked,
 *     non-overlapping and outside the ELF/section-header regions, and a
 *     fully parsed BTF header with disjoint in-bounds type/string spans.
 *   - Both identity fields (modinfo name=, struct module.name) MUST be
 *     found and rewritten or the whole pass fails; a caller never
 *     publishes a half-renamed image.
 *   - Undefined-symbol name spans are computed from the symtab and are
 *     never touched, so kernel-side name resolution cannot change.
 *   - Duplicate-name collisions at load time would fail closed at
 *     insmod; KS_RENAME_MODULE is verified not loaded on PD2454 but a
 *     collision is an error, not an impossibility.
 *
 * Standalone: the host harness (tests/ksrename-test.c) includes this
 * file directly and re-verifies every invariant against the patched
 * image.  Run after every name-keyed pass in the caller (the binder
 * resolves UNDEFINED symbols by name; defined module-internal names are
 * only ever bound by index).
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define KS_RENAME_OLD "kernelsu"
#define KS_RENAME_MODULE "vfcs_sec"
#define KS_RENAME_PFX_OLD "ksu_"
#define KS_RENAME_PFX_NEW "vvs_"
/* bare daemon token: "ksud" contains the "ksu" scan token and survives
 * the prefix rule; swap it too (strtab/BTF only -- the /data/adb/ksud
 * PATH string in rodata is runtime-critical and stays). */
#define KS_RENAME_TOKEN_OLD "ksud"
#define KS_RENAME_TOKEN_NEW "kdmd"
/* BTF enum constants use an uppercase prefix (KSU_FEATURE_*) */
#define KS_RENAME_UPFX_OLD "KSU_"
#define KS_RENAME_UPFX_NEW "VVS_"

/* All swaps must be exactly length-preserving. */
_Static_assert(sizeof(KS_RENAME_OLD) == sizeof(KS_RENAME_MODULE),
               "module name swap must be equal length");
_Static_assert(sizeof(KS_RENAME_PFX_OLD) == sizeof(KS_RENAME_PFX_NEW),
               "prefix swap must be equal length");
_Static_assert(sizeof(KS_RENAME_TOKEN_OLD) == sizeof(KS_RENAME_TOKEN_NEW),
               "token swap must be equal length");
_Static_assert(sizeof(KS_RENAME_UPFX_OLD) == sizeof(KS_RENAME_UPFX_NEW),
               "uppercase prefix swap must be equal length");

struct ks_rename_stats
{
    unsigned modinfo_name;     /* the name= entry (must be 1) */
    unsigned modinfo_other;    /* other old-name substrings replaced */
    unsigned this_module_name; /* struct module.name (must be 1) */
    unsigned strtab_exact;
    unsigned strtab_prefix;
    unsigned strtab_token;
    unsigned strtab_upfx;
    unsigned strtab_protected; /* UND-symbol spans left untouched */
    unsigned btf_exact;
    unsigned btf_prefix;
    unsigned btf_token;
    unsigned btf_upfx;
};

/* Equal-length in-place swaps of needle -> replacement across
 * [s, s+len). Returns the swap count; 0 for any argument mismatch. */
static unsigned ks_swap_all(char *s, size_t len, const char *old,
                            const char *nw)
{
    size_t lo = strlen(old);
    unsigned n = 0;

    if (lo == 0 || lo > len || strlen(nw) != lo)
        return 0;
    for (size_t i = 0; i + lo <= len; i++)
    {
        if (!memcmp(s + i, old, lo))
        {
            memcpy(s + i, nw, lo);
            n++;
            i += lo - 1;
        }
    }
    return n;
}

/* section-name lookup bounded inside the section-name string table */
static const char *ks_sh_name(const uint8_t *img, uint64_t shstr_off,
                              uint64_t shstr_size, uint32_t name_off)
{
    const uint8_t *p;

    if (name_off >= shstr_size)
        return NULL;
    p = img + shstr_off + name_off;
    if (!memchr(p, 0, (size_t)(shstr_size - name_off)))
        return NULL;
    return (const char *)p;
}

static int ks_extent_ok(uint64_t off, uint64_t sz, uint64_t img)
{
    return off <= img && sz <= img - off;
}

static int ks_rename_module(uint8_t *image, uint64_t size,
                            struct ks_rename_stats *st)
{
    static const char old_name[] = KS_RENAME_OLD;
    static const char new_name[] = KS_RENAME_MODULE;
    static const char pfx_old[] = KS_RENAME_PFX_OLD;
    static const char pfx_new[] = KS_RENAME_PFX_NEW;
    static const char tok_old[] = KS_RENAME_TOKEN_OLD;
    static const char tok_new[] = KS_RENAME_TOKEN_NEW;
    static const char upfx_old[] = KS_RENAME_UPFX_OLD;
    static const char upfx_new[] = KS_RENAME_UPFX_NEW;
    const size_t old_len = sizeof(old_name) - 1;
    uint64_t shoff, shstr_off = 0, shstr_size = 0;
    uint64_t modinfo_off = 0, modinfo_size = 0;
    uint64_t thismod_off = 0, thismod_size = 0;
    uint64_t strtab_off = 0, strtab_size = 0;
    uint64_t symtab_off = 0;
    uint64_t btf_off = 0, btf_size = 0, btf_str_off = 0, btf_str_len = 0;
    uint32_t symtab_link = 0;
    unsigned symtab_count = 0, symtabs = 0, shstrtabs = 0;
    uint16_t shentsize, shnum, shstrndx;
    struct span
    {
        uint64_t off;
        uint64_t len;
    } *spans = NULL;
    unsigned nspans = 0;

    memset(st, 0, sizeof(*st));
    if (size < 64 || image[0] != 0x7f || memcmp(image + 1, "ELF", 3))
        return -1;
    if (image[4] != 2 /* ELFCLASS64 */ || image[5] != 1 /* ELFDATA2LSB */ ||
        image[6] != 1 /* EV_CURRENT */)
        return -1;
    memcpy(&shoff, image + 0x28, 8);
    memcpy(&shentsize, image + 0x3a, 2);
    memcpy(&shnum, image + 0x3c, 2);
    memcpy(&shstrndx, image + 0x3e, 2);
    if (image[0x10] != 1 /* ET_REL */)
        return -1;
    if (shentsize != 64 || shnum == 0 || shstrndx >= shnum)
        return -1;
    if (shoff < 64 || !ks_extent_ok(shoff, (uint64_t)shnum * shentsize,
                                    size))
        return -1;

    /* ---- validation pass: no writes before every check passed ---- */
    {
        uint64_t hdr_lo = shoff, hdr_hi = shoff + (uint64_t)shnum * shentsize;

        for (uint32_t i = 0; i < shnum; i++)
        {
            uint64_t off = shoff + (uint64_t)i * shentsize;
            uint32_t name_off, typ, link;
            uint64_t soff, ssz;

            memcpy(&name_off, image + off, 4);
            memcpy(&typ, image + off + 4, 4);
            memcpy(&soff, image + off + 0x18, 8);
            memcpy(&ssz, image + off + 0x20, 8);
            memcpy(&link, image + off + 0x28, 4);
            if (typ == 0 /* SHT_NULL */ || typ == 8 /* SHT_NOBITS */)
                continue;
            if (!ks_extent_ok(soff, ssz, size))
                return -1;
            /* the section-name table itself */
            if (i == shstrndx)
            {
                if (typ != 3 || ssz == 0 || image[soff] != 0 ||
                    image[soff + ssz - 1] != 0)
                    return -1;
                shstr_off = soff;
                shstr_size = ssz;
                shstrtabs++;
            }
            if (typ == 2) /* SHT_SYMTAB */
            {
                if (symtabs || ssz % 24 != 0)
                    return -1;
                symtabs++;
                symtab_off = soff;
                symtab_link = link;
                symtab_count = (unsigned)(ssz / 24);
            }
        }
        if (shstrtabs != 1 || symtabs != 1)
            return -1;
        if (symtab_link >= shnum)
            return -1;
        for (uint32_t i = 0; i < shnum; i++)
        {
            uint64_t off = shoff + (uint64_t)i * shentsize;
            uint32_t name_off, typ;
            uint64_t soff, ssz;
            const char *nm;

            memcpy(&name_off, image + off, 4);
            memcpy(&typ, image + off + 4, 4);
            memcpy(&soff, image + off + 0x18, 8);
            memcpy(&ssz, image + off + 0x20, 8);
            if (typ == 0 || typ == 8)
                continue;
            nm = ks_sh_name(image, shstr_off, shstr_size, name_off);
            if (!nm)
                return -1;
            if (i == symtab_link)
            {
                if (typ != 3 || ssz == 0 || image[soff] != 0 ||
                    image[soff + ssz - 1] != 0 || strcmp(nm, ".strtab"))
                    return -1;
                strtab_off = soff;
                strtab_size = ssz;
            }
            else if (typ == 1 && !strcmp(nm, ".modinfo"))
            {
                if (modinfo_size)
                    return -1; /* duplicate */
                modinfo_off = soff;
                modinfo_size = ssz;
            }
            else if (typ == 1 &&
                     !strcmp(nm, ".gnu.linkonce.this_module"))
            {
                if (thismod_size)
                    return -1;
                thismod_off = soff;
                thismod_size = ssz;
            }
            else if (typ == 1 && !strcmp(nm, ".BTF"))
            {
                if (btf_size)
                    return -1;
                btf_off = soff;
                btf_size = ssz;
            }
        }
        if (!strtab_size || !modinfo_size || !thismod_size || !btf_size)
            return -1;
        /* targets must stay clear of the ELF header, the section table
         * and each other (paranoia: equal-length swaps make overlap
         * harmless, but reject it so the counts stay meaningful). */
        {
            const struct
            {
                const char *what;
                uint64_t off, sz;
            } t[4] = {
                {"modinfo", modinfo_off, modinfo_size},
                {"this_module", thismod_off, thismod_size},
                {"strtab", strtab_off, strtab_size},
                {"btf", btf_off, btf_size},
            };
            for (int i = 0; i < 4; i++)
            {
                if (t[i].off < hdr_hi && t[i].off + t[i].sz > hdr_lo)
                    return -1; /* overlaps the section-header table */
                if (t[i].off < 64)
                    return -1; /* overlaps the ELF header */
                for (int j = i + 1; j < 4; j++)
                    if (t[i].off < t[j].off + t[j].sz &&
                        t[j].off < t[i].off + t[i].sz)
                        return -1;
            }
        }
        /* BTF header: fully parsed before any write */
        {
            const uint8_t *b = image + btf_off;
            uint32_t magic16, hdr_len = 0, type_off, type_len, str_off = 0,
                               str_len = 0;

            if (btf_size < 0x18)
                return -1;
            memcpy(&magic16, b, 2);
            memcpy(&hdr_len, b + 4, 4);
            memcpy(&type_off, b + 8, 4);
            memcpy(&type_len, b + 0xc, 4);
            memcpy(&str_off, b + 0x10, 4);
            memcpy(&str_len, b + 0x14, 4);
            if (magic16 != 0xeb9f || b[2] < 1 || b[2] > 5 || b[3] != 0 ||
                (hdr_len != 0x18 && hdr_len != 0x1c && hdr_len != 0x20) ||
                hdr_len > btf_size)
                return -1;
            if ((uint64_t)type_off + type_len > str_off ||
                (uint64_t)hdr_len + str_off + str_len > btf_size ||
                (uint64_t)hdr_len + type_off + type_len > btf_size)
                return -1;
            btf_str_off = (uint64_t)hdr_len + str_off;
            btf_str_len = str_len;
        }
        /* UND-symbol name spans inside the strtab (never rewritten) */
        spans = calloc(symtab_count ? symtab_count : 1, sizeof(*spans));
        if (!spans)
            return -1;
        for (unsigned j = 1; j < symtab_count; j++)
        {
            const uint8_t *sym = image + symtab_off + (uint64_t)j * 24;
            uint32_t st_name;
            uint16_t st_shndx;

            memcpy(&st_name, sym, 4);
            memcpy(&st_shndx, sym + 6, 2);
            if (st_shndx != 0 /* SHN_UNDEF */ || st_name == 0 ||
                st_name >= strtab_size)
                continue;
            {
                const uint8_t *p = image + strtab_off + st_name;
                const uint8_t *nul =
                    memchr(p, 0, (size_t)(strtab_size - st_name));

                if (!nul)
                    return -1; /* strtab validated NUL-terminated */
                spans[nspans].off = st_name;
                spans[nspans].len = (uint64_t)(nul - p) + 1;
                nspans++;
            }
        }
    }

    /* ---- mutation pass (only reached when everything validated) ---- */

    /* .modinfo: bounded entries; the name= value must be present. */
    {
        const size_t key_len = 5; /* "name=" */
        uint64_t i = 0;

        while (i < modinfo_size)
        {
            uint64_t j = i;
            char *e;

            while (j < modinfo_size && image[modinfo_off + j])
                j++;
            e = (char *)image + modinfo_off + i;
            if (j > i)
            {
                size_t len = (size_t)(j - i);

                if (!st->modinfo_name && len == key_len + old_len &&
                    !memcmp(e, "name=", key_len) &&
                    !memcmp(e + key_len, old_name, old_len))
                {
                    memcpy(e + key_len, new_name, old_len);
                    st->modinfo_name = 1;
                }
                else
                {
                    st->modinfo_other += ks_swap_all(e, len, old_name,
                                                     new_name);
                }
            }
            i = j + 1;
        }
        if (!st->modinfo_name)
        {
            free(spans);
            return -1; /* refuse to publish an unnamed/renamed-less image */
        }
    }

    /* struct module.name: bounded scan inside the name field region. */
    {
        char *base = (char *)image + thismod_off;
        int found = 0;

        for (uint64_t i = 0; i + old_len < thismod_size && i < 56; i++)
        {
            if ((i == 0 || base[i - 1] == 0) &&
                !memcmp(base + i, old_name, old_len) &&
                base[i + old_len] == 0)
            {
                memcpy(base + i, new_name, old_len);
                st->this_module_name = 1;
                found = 1;
                break;
            }
        }
        if (!found)
        {
            free(spans);
            return -1;
        }
    }

    /* .strtab: swap every string outside UND spans. */
    {
        char *base = (char *)image + strtab_off;
        uint64_t i = 0;

        while (i < strtab_size)
        {
            uint64_t j = i;

            while (j < strtab_size && base[j])
                j++;
            if (j > i)
            {
                size_t len = (size_t)(j - i);
                int protected_span = 0;

                for (unsigned k = 0; k < nspans; k++)
                    if (i < spans[k].off + spans[k].len &&
                        spans[k].off < i + len)
                    {
                        protected_span = 1;
                        break;
                    }
                if (protected_span)
                    st->strtab_protected++;
                else
                {
                    st->strtab_exact += ks_swap_all(base + i, len,
                                                    old_name, new_name);
                    st->strtab_prefix += ks_swap_all(base + i, len,
                                                     pfx_old, pfx_new);
                    st->strtab_token += ks_swap_all(base + i, len,
                                                    tok_old, tok_new);
                    st->strtab_upfx += ks_swap_all(base + i, len,
                                                   upfx_old, upfx_new);
                }
            }
            i = j + 1;
        }
    }

    /* .BTF string table. */
    {
        char *sbase = (char *)image + btf_off + btf_str_off;

        st->btf_exact = ks_swap_all(sbase, (size_t)btf_str_len, old_name,
                                    new_name);
        st->btf_prefix = ks_swap_all(sbase, (size_t)btf_str_len, pfx_old,
                                     pfx_new);
        st->btf_token = ks_swap_all(sbase, (size_t)btf_str_len, tok_old,
                                    tok_new);
        st->btf_upfx = ks_swap_all(sbase, (size_t)btf_str_len, upfx_old,
                                   upfx_new);
    }
    free(spans);
    return 0;
}

#endif /* KSRENAME_H */
