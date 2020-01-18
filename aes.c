#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

typedef enum {
    ENC_M,
    DEC_M
} emode_t;

void usage(char *);
void readKey(uint32_t *, size_t, char *);
void deriveKeys(uint32_t *, size_t, size_t, uint8_t[256]);
uint32_t keyWreck(uint32_t, uint32_t *, uint8_t[256]);
void subBox(uint8_t[256]);
void invSBox(uint8_t[256]);
void encrypt(FILE *, FILE *, uint8_t *, uint8_t *, size_t);
void decrypt(FILE *, FILE *, uint8_t *, uint8_t *, size_t);
void shiftRows(uint8_t *);
void invShiftRows(uint8_t *);
void mixCols(uint8_t *);
void invMixCols(uint8_t *);
void mixKey(uint8_t *, uint8_t *);
void makeSub(uint8_t *, uint8_t *);

#define ROTL8(x, shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))

void tests(uint8_t *kBox, uint8_t *iBox) {
    uint8_t s[16] = {0};
    uint8_t a[16] = {0};
    for (size_t i = 0; i < 16; i++) {
        s[i] = i << 1;
        a[i] = i << 1;
    }
    mixCols(a);
    invMixCols(a);
    for (size_t i = 0; i < 16; i++)
        assert(a[i] == s[i]);
    printf("A\n");
    exit(0);
}

int main(int argc, char **argv) {
    if (argc < 7)
        usage(argv[0]);
    emode_t mode = ENC_M;
    size_t klen = 128;
    char *input = NULL;
    char *output = NULL;
    char *key = NULL;
    char force = 0;
    for (size_t i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-e"))
            mode = ENC_M;
        else if (!strcmp(argv[i], "-d"))
            mode = DEC_M;
        else if (!strcmp(argv[i], "-i"))
            input = argv[++i];
        else if (!strcmp(argv[i], "-o"))
            output = argv[++i];
        else if (!strcmp(argv[i], "-f"))
            force = 1;
        else if (!strncmp(argv[i], "-k", 2)) {
            size_t val = atoi(argv[i] + 2);
            if (val >= 128 && !(val % 64))
                klen = val;
                key = argv[++i];
        } else
            usage(argv[0]);
    }
    if (!input || !output || !key)
        usage(argv[0]);
    if (!force && !strcmp(input, output)) {
        fprintf(stderr, "Input and output names identical. Use -f to force overwriting.\n");
        exit(1);
    }
    klen /= 32;
    size_t nrounds = 3;
    uint32_t *keys = calloc(4 * (nrounds + 1), sizeof (uint32_t));
    uint8_t invBox[256];
    uint8_t keyBox[256];
    subBox(keyBox);
    if (mode == DEC_M)
        invSBox(invBox);
    readKey(keys, klen, key);
    deriveKeys(keys, nrounds + 1, klen, keyBox);
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
    uint8_t *keyBytes = calloc(16 * (nrounds + 1), sizeof (uint8_t));
    for (size_t i = 0; i < 4 * (nrounds + 1); i++)
        for (size_t j = 0; j < 4; j++)
            keyBytes[4 * i + (3 - j)] = (keys[i] & (0xFF << j)) >> j;
    //tests(keyBox, invBox);
    if (mode == ENC_M)
        encrypt(inputFile, outputFile, keyBox, keyBytes, nrounds);
    else
        decrypt(inputFile, outputFile, invBox, keyBytes, nrounds);
    fclose(inputFile);
    fclose(outputFile);
    free(keys);
    return 0;
}

void usage(char *name) {
    fprintf(stderr, "Usage: %s [-e | -d] <-i inputFile> <-o outputFile> <-k(len) keyFile> [-f]\n", name);
    exit(1);
}

void readKey(uint32_t *key, size_t klen, char *filename) {
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

void deriveKeys(uint32_t *subkeys, size_t nrounds, size_t msize, uint8_t *sBox) {
    size_t nblocks = 4 * nrounds;
    size_t filled = msize;
    uint32_t conn = 0x01000000;
    uint32_t specBlock = keyWreck(subkeys[msize - 1], &conn, sBox);
    while (filled < nblocks) {
        for (size_t nkey = 0; nkey < msize; nkey++, filled++) {
            if (!nkey) {
                subkeys[filled] = specBlock ^ subkeys[filled - msize];
                continue;
            }
            if (msize > 6 && nkey % msize == 4) {
                uint32_t sub = 0;
                for (size_t i = 0; i < 4; i++)
                    sub |= sBox[(subkeys[filled - 1] & (0xFF << i)) >> i] << i;
                subkeys[filled] = sub ^ subkeys[filled - msize];
                continue;
            }
            subkeys[filled] = subkeys[filled - 1] ^ subkeys[filled - msize];
        }
        specBlock = keyWreck(subkeys[filled - 1], &conn, sBox);
    }
    return;
}

uint32_t keyWreck(uint32_t block, uint32_t *conn, uint8_t *sbox) {
    block = ROTL8(block, 8);
    uint32_t result = 0;
    for (size_t i = 0; i < 32; i += 8)
        result |= sbox[(block & (0xFF << i)) >> i] << i;
    result ^ *conn;
    if (*conn >= 0x80)
        *conn = (*conn << 1) ^ 0x80;
    else
        *conn <<= 1;
    return result;
}

void subBox(uint8_t *sbox) {
	uint8_t p = 1, q = 1;
	do {
		p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);
		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q ^= q & 0x80 ? 0x09 : 0;
		uint8_t xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);
		sbox[p] = xformed ^ 0x63;
	} while (p != 1);
	sbox[0] = 0x63;
    return;
}

void invSBox(uint8_t *invbox) {
    uint8_t sbox[256];
    subBox(sbox);
    for (size_t i = 0; i < 256; i++)
        invbox[sbox[i]] = i;
    return;
}

void encrypt(FILE *inF, FILE *outF, uint8_t *sBox, uint8_t *keys, size_t nrounds) {
    uint8_t state[16] = {0};
    uint8_t temp[16] = {0};
    FILE *urand = fopen("/dev/urandom", "rb");
    if (!urand) {
        fprintf(stderr, "Unable to seed cipher.\n");
        exit(1);
    }
    fread(state, sizeof (uint8_t), 16, urand);
    fwrite(state, sizeof (uint8_t), 16, outF);
    size_t nr = 0;
    while ((nr = fread(temp, sizeof (uint8_t), 16, inF))) {
        if (nr < 16)
            for (size_t i = nr; i < 16; i++)
                temp[i] = 0;
        mixKey(state, temp);
        mixKey(state, keys);
        for (size_t i = 1; i < nrounds; i++) {
            makeSub(state, sBox);
            shiftRows(state);
            mixCols(state);
            mixKey(state, keys + 16 * i);
        }
        makeSub(state, sBox);
        shiftRows(state);
        mixKey(state, keys + 16 * nrounds);
        fwrite(state, sizeof (uint8_t), 16, outF);
    }
}

void decrypt(FILE *inF, FILE *outF, uint8_t *sBox, uint8_t *keys, size_t nrounds) {
    uint8_t state[16] = {0};
    uint8_t temp[16] = {0};
    uint8_t temp2[16] = {0};
    fread(temp2, sizeof (uint8_t), 16, inF);
    char run = fread(temp, sizeof (uint8_t), 16, inF);
    for (size_t i = 0; i < 16; i++)
        state[i] = temp[i];
    while (run) {
        mixKey(state, keys + 16 * nrounds);
        invShiftRows(state);
        makeSub(state, sBox);
        mixKey(state, keys + 16 * (nrounds - 1));
        for (size_t i = nrounds - 1; i > 0; i--) {
            invMixCols(state);
            invShiftRows(state);
            makeSub(state, sBox);
            mixKey(state, keys + 16 * (i - 1));
        }
        mixKey(state, temp2);
        for (size_t i = 0; i < 16; i++)
            temp2[i] = temp[i];
        run = fread(temp, sizeof (uint8_t), 16, inF);
        if (run)
            fwrite(state, sizeof (uint8_t), 16, outF);
        else {
            size_t i = 15;
            for (; i > 0; i--)
                if (state[i])
                    break;
            fwrite(state, sizeof (uint8_t), i + 1, outF);
        }
        for (size_t i = 0; i < 16; i++)
            state[i] = temp[i];
    }
}

void mixKey(uint8_t *state, uint8_t *key) {
    for (size_t i = 0; i < 16; i++)
        state[i] ^= key[i];
    return;
}

void makeSub(uint8_t *state, uint8_t *sBox) {
    for (size_t i = 0; i < 16; i++)
        state[i] = sBox[state[i]];
    return;
}

void shiftRows(uint8_t *state) {
    uint8_t temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
    return;
}

void invShiftRows(uint8_t * state) {
    uint8_t temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
    return;
}

void mixCols(uint8_t *state) {
    uint8_t state1[16];
    uint8_t state2[16];
    for (size_t i = 0; i < 16; i++) {
        uint8_t xor = (state[i] & 0x80 ? 0x1B : 0);
        state1[i] = state[i];
        state2[i] = (state[i] << 1) ^ xor;
    }
    for (size_t i = 0; i < 4; i++) {
        state[4 * i + 0] = state2[4 * i + 0] ^ state1[4 * i + 1] ^ state2[4 * i + 1] ^ state1[4 * i + 2] ^ state1[4 * i + 3];
        state[4 * i + 1] = state2[4 * i + 1] ^ state1[4 * i + 2] ^ state2[4 * i + 2] ^ state1[4 * i + 3] ^ state1[4 * i + 0];
        state[4 * i + 2] = state2[4 * i + 2] ^ state1[4 * i + 3] ^ state2[4 * i + 3] ^ state1[4 * i + 0] ^ state1[4 * i + 1];
        state[4 * i + 3] = state2[4 * i + 3] ^ state1[4 * i + 0] ^ state2[4 * i + 0] ^ state1[4 * i + 1] ^ state1[4 * i + 2];
    }
}

void invMixCols(uint8_t *state) {
    uint8_t state1[16];
    uint8_t state2[16];
    uint8_t state4[16];
    uint8_t state8[16];
    for (size_t i = 0; i < 16; i++) {
        uint8_t xor = (state[i] & 0x80 ? 0x1B : 0);
        state1[i] = state[i];
        state2[i] = (state[i] << 1) ^ xor;
        xor = (state2[i] & 0x80 ? 0x1B : 0);
        state4[i] = (state2[i] << 1) ^ xor;
        xor = (state4[i] & 0x80 ? 0x1B : 0);
        state8[i] = (state4[i] << 1) ^ xor;
        state2[i] ^= state1[i] ^ state8[i];
        state4[i] ^= state1[i] ^ state8[i];
        state1[i] ^= state8[i];
        state8[i] ^= state2[i] ^ state4[i];
    }
    for (size_t i = 0; i < 4; i++) {
        state[4 * i + 0] = state8[4 * i + 0] ^ state2[4 * i + 1] ^ state4[4 * i + 2] ^ state1[4 * i + 3];
        state[4 * i + 1] = state8[4 * i + 1] ^ state2[4 * i + 2] ^ state4[4 * i + 3] ^ state1[4 * i + 0];
        state[4 * i + 2] = state8[4 * i + 2] ^ state2[4 * i + 3] ^ state4[4 * i + 0] ^ state1[4 * i + 1];
        state[4 * i + 3] = state8[4 * i + 3] ^ state2[4 * i + 0] ^ state4[4 * i + 1] ^ state1[4 * i + 2];
    }
}
