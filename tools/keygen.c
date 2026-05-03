#include "speer.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <ctype.h>
#include <string.h>

#define PROGRAM_NAME "speer-keygen"
#define VERSION      "0.2.0"

typedef enum {
    FORMAT_HEX,
    FORMAT_BINARY,
    FORMAT_HEADER,
    FORMAT_DOTENV,
} output_format_t;

static void print_usage(const char *prog) {
    printf("Usage: %s [options]\n", prog);
    printf("\nGenerate Ed25519 keypairs for speer.\n\n");
    printf("Options:\n");
    printf("  -f, --format FORMAT   Output: hex, binary, header, dotenv (default: hex)\n");
    printf("  -o, --output FILE     Output file (default: stdout)\n");
    printf("  -s, --seed HEX        Use specific seed (64 hex chars, testing only)\n");
    printf("  -h, --help            Show help\n");
    printf("  -v, --version         Show version\n");
}

static void print_version(void) {
    printf("%s version %s\n", PROGRAM_NAME, VERSION);
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return -1;

    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return 0;
}

static void print_hex(FILE *f, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) { fprintf(f, "%02x", data[i]); }
}

/* constrain -o to a cwd-relative base name; avoids odd fopen paths */
static int output_file_safe(const char *p) {
    if (!p || !p[0]) return -1;
    if (strstr(p, "..")) return -1;
#if defined(_WIN32)
    if (strpbrk(p, "/\\:?*\"<>|")) return -1;
#else
    if (*p == '/' || strchr(p, '/') != NULL) return -1;
#endif
    for (const char *q = p; *q; q++) {
        unsigned char c = (unsigned char)*q;
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.')) return -1;
    }
    if ((size_t)strlen(p) >= 260) return -1;
    return 0;
}

int main(int argc, char **argv) {
    output_format_t format = FORMAT_HEX;
    const char *output_file = NULL;
    const char *seed_hex = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            print_version();
            return 0;
        }
        if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--format") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: -f requires an argument\n");
                return 1;
            }
            const char *fmt = argv[++i];
            if (strcmp(fmt, "hex") == 0)
                format = FORMAT_HEX;
            else if (strcmp(fmt, "binary") == 0)
                format = FORMAT_BINARY;
            else if (strcmp(fmt, "header") == 0)
                format = FORMAT_HEADER;
            else if (strcmp(fmt, "dotenv") == 0)
                format = FORMAT_DOTENV;
            else {
                fprintf(stderr, "Error: Unknown format '%s'\n", fmt);
                return 1;
            }
        } else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: -o requires an argument\n");
                return 1;
            }
            output_file = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--seed") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: -s requires an argument\n");
                return 1;
            }
            seed_hex = argv[++i];
        } else {
            fprintf(stderr, "Error: Unknown option '%s'\n", argv[i]);
            return 1;
        }
    }

    uint8_t seed[32];
    if (seed_hex) {
        if (hex_to_bytes(seed_hex, seed, 32) != 0) {
            fprintf(stderr, "Error: Invalid seed hex (expected 64 chars)\n");
            return 1;
        }
        fprintf(stderr, "Warning: Using provided seed\n");
    } else {
        speer_random_bytes(seed, 32);
    }

    uint8_t public_key[SPEER_PUBLIC_KEY_SIZE];
    uint8_t private_key[SPEER_PRIVATE_KEY_SIZE];

    int ret = speer_generate_keypair(public_key, private_key, seed);
    if (ret != SPEER_OK) {
        fprintf(stderr, "Error: Failed to generate keypair\n");
        return 1;
    }

    FILE *out = stdout;
    if (output_file) {
        if (output_file_safe(output_file) != 0) {
            fprintf(stderr, "Error: refusing unsafe output path (use simple file name paths)\n");
            return 1;
        }
        const char *mode = (format == FORMAT_BINARY) ? "wb" : "w";
        out = fopen(output_file, mode);
        if (!out) {
            fprintf(stderr, "Error: Cannot open '%s'\n", output_file);
            return 1;
        }
    }

    switch (format) {
    case FORMAT_HEX:
        fprintf(out, "PUBLIC_KEY=");
        print_hex(out, public_key, SPEER_PUBLIC_KEY_SIZE);
        fprintf(out, "\nPRIVATE_KEY=");
        print_hex(out, private_key, SPEER_PRIVATE_KEY_SIZE);
        fprintf(out, "\n");
        break;

    case FORMAT_BINARY:
        fwrite(public_key, 1, SPEER_PUBLIC_KEY_SIZE, out);
        fwrite(private_key, 1, SPEER_PRIVATE_KEY_SIZE, out);
        break;

    case FORMAT_HEADER:
        fprintf(out, "#ifndef SPEER_KEYS_H\n#define SPEER_KEYS_H\n\n");
        fprintf(out, "static const uint8_t SPEER_PUBLIC_KEY[32] = {\n    ");
        for (int i = 0; i < 32; i++) {
            fprintf(out, "0x%02x%s", public_key[i], (i < 31) ? ", " : "");
            if ((i + 1) % 8 == 0 && i < 31) fprintf(out, "\n    ");
        }
        fprintf(out, "\n};\n\n");
        fprintf(out, "static const uint8_t SPEER_PRIVATE_KEY[32] = {\n    ");
        for (int i = 0; i < 32; i++) {
            fprintf(out, "0x%02x%s", private_key[i], (i < 31) ? ", " : "");
            if ((i + 1) % 8 == 0 && i < 31) fprintf(out, "\n    ");
        }
        fprintf(out, "\n};\n\n#endif\n");
        break;

    case FORMAT_DOTENV:
        fprintf(out, "SPEER_PUBLIC_KEY=");
        print_hex(out, public_key, SPEER_PUBLIC_KEY_SIZE);
        fprintf(out, "\nSPEER_PRIVATE_KEY=");
        print_hex(out, private_key, SPEER_PRIVATE_KEY_SIZE);
        fprintf(out, "\n");
        break;
    }

    if (out != stdout) fclose(out);

    memset(seed, 0, sizeof(seed));
    memset(private_key, 0, sizeof(private_key));

    return 0;
}
