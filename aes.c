#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

#include "block.h"
#include "modes.h"

static void usage(char *);
static void readKey(uint32_t *, size_t, char *);

static void (*cipherFuncs[2][2])(FILE *, FILE *, uint8_t *, size_t) = {
    {encryptCBC, encryptECB},
    {decryptCBC, decryptECB}
};

int main(int argc, char **argv) {
    if (argc < 7)
        usage(argv[0]);
    emode_t type = ENC_M;
    rmode_t mode = CBC_M;
    size_t klen = 128;
    char *input = NULL;
    char *output = NULL;
    char *key = NULL;

    // Get input values
    for (size_t i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-e"))
            type = ENC_M;
        else if (!strcmp(argv[i], "-d"))
            type = DEC_M;
        else if (!strcmp(argv[i], "-i"))
            input = argv[++i];
        else if (!strcmp(argv[i], "-o"))
            output = argv[++i];
        else if (!strcmp(argv[i], "-cbc"))
            mode = CBC_M;
        else if (!strcmp(argv[i], "-ecb"))
            mode = ECB_M;
        else if (!strncmp(argv[i], "-k", 2)) {
            size_t val = atoi(argv[i] + 2);
            if (val == 128 || val == 192 || val == 256) {
                klen = val;
                key = argv[++i];
            } else {
                fprintf(stderr, "Key length must be 128, 192, or 256.\n");
                exit(1);
            }
        } else
            usage(argv[0]);
    }
    if (!input || !output || !key)
        usage(argv[0]);
    if (!strcmp(input, output)) {
        fprintf(stderr, "Input and output names identical.\n");
        exit(1);
    }

    // Derive keys
    klen /= 32;
    size_t nrounds = 3;
    uint32_t *keys = calloc(4 * (nrounds + 1), sizeof (uint32_t));
    readKey(keys, klen, key);
    deriveKeys(keys, nrounds + 1, klen);

    // Open input/output files
    FILE *inputFile = fopen(input, "rb");
    if (!inputFile) {
        fprintf(stderr, "Failed to open input file.\n");
        exit(1);
    }
    FILE *outputFile = fopen(output, "wb");
    if (!outputFile) {
        fprintf(stderr, "Failed to open output file.\n");
        exit(1);
    }

    // Transform key blocks into byte array
    uint8_t *keyBytes = calloc(16 * (nrounds + 1), sizeof (uint8_t));
    for (size_t i = 0; i < 4 * (nrounds + 1); i++)
        for (size_t j = 0; j < 4; j++)
            keyBytes[4 * i + (3 - j)] = (keys[i] & (0xFF << j)) >> j;
    
    // Run AES
    cipherFuncs[type][mode](inputFile, outputFile, keyBytes, nrounds);
    
    // Cleanup
    fclose(inputFile);
    fclose(outputFile);
    free(keys);
    return 0;
}

static void usage(char *name) {
    fprintf(stderr, "Usage: %s [-e | -d] <-i inputFile> <-o outputFile> <-k(len) keyFile>\n", name);
    exit(1);
}

static void readKey(uint32_t *key, size_t klen, char *filename) {
    FILE *keyFile = fopen(filename, "rb");
    if (!keyFile) {
        fprintf(stderr, "Failed to open key file.\n");
        exit(1);
    }
    uint32_t block = 0;
    size_t read = 0;
    while (fread(&block, sizeof (uint32_t), 1, keyFile)) {
        if (read == klen)
            break;
        key[read++] = block;
    }
    fclose(keyFile);
    if (read < klen) {
        fprintf(stderr, "Insufficient data in key file.\n");
        exit(1);
    }
    return;
}