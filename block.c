#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "block.h"

#define ROTL8(x, shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))

static uint8_t subBox[256] = {0};
static uint8_t invBox[256] = {0};

static void initialiseSubbox(void);
static uint32_t keyWreck(uint32_t, uint32_t *);
static void makeSub(uint8_t *, uint8_t *);
static void shiftRows(uint8_t *);
static void invShiftRows(uint8_t *);
static void mixCols(uint8_t *);
static void invMixCols(uint8_t *);

void deriveKeys(uint32_t *subkeys, size_t nrounds, size_t msize) {
    if (!subBox[0])
        initialiseSubbox();
    size_t nblocks = 4 * nrounds;
    size_t filled = msize;
    uint32_t conn = 0x01000000;
    uint32_t specBlock = keyWreck(subkeys[msize - 1], &conn);
    while (filled < nblocks) {
        for (size_t nkey = 0; nkey < msize; nkey++, filled++) {
            if (!nkey) {
                subkeys[filled] = specBlock ^ subkeys[filled - msize];
                continue;
            }
            if (msize > 6 && nkey % msize == 4) {
                uint32_t sub = 0;
                for (size_t i = 0; i < 4; i++)
                    sub |= subBox[(subkeys[filled - 1] & (0xFF << i)) >> i] << i;
                subkeys[filled] = sub ^ subkeys[filled - msize];
                continue;
            }
            subkeys[filled] = subkeys[filled - 1] ^ subkeys[filled - msize];
        }
        specBlock = keyWreck(subkeys[filled - 1], &conn);
    }
    return;
}

static uint32_t keyWreck(uint32_t block, uint32_t *conn) {
    if (!subBox[0])
        initialiseSubbox();
    block = ROTL8(block, 8);
    uint32_t result = 0;
    for (size_t i = 0; i < 32; i += 8)
        result |= subBox[(block & (0xFF << i)) >> i] << i;
    result ^ *conn;
    if (*conn >= 0x80)
        *conn = (*conn << 1) ^ 0x80;
    else
        *conn <<= 1;
    return result;
}

static void initialiseSubbox(void) {
	uint8_t p = 1, q = 1;
	do {
		p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);
		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q ^= q & 0x80 ? 0x09 : 0;
		uint8_t xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4) ^ 0x63;
		subBox[p] = xformed;
        invBox[xformed] = p;
	} while (p != 1);
	subBox[0] = 0x63;
    return;
}

void encryptBlock(uint8_t *inData, uint8_t *outData, uint8_t *keys, size_t nrounds) {
    if (outData != inData)
        memcpy(outData, inData, 16 * sizeof (uint8_t));
    mixKey(outData, keys);
    for (size_t i = 1; i < nrounds; i++) {
        makeSub(outData, subBox);
        shiftRows(outData);
        mixCols(outData);
        mixKey(outData, keys + 16 * i * sizeof (uint8_t));
    }
    makeSub(outData, subBox);
    shiftRows(outData);
    mixKey(outData, keys + 16 * nrounds * sizeof (uint8_t));
    return;
}

void decryptBlock(uint8_t *inData, uint8_t *outData, uint8_t *keys, size_t nrounds) {
    if (outData != inData)
        memcpy(outData, inData, 16 * sizeof (uint8_t));
    mixKey(outData, keys + 16 * nrounds * sizeof (uint8_t));
    invShiftRows(outData);
    makeSub(outData, invBox);
    for (size_t i = nrounds - 1; i > 0; i--) {
        mixKey(outData, keys + 16 * i * sizeof (uint8_t));
        invMixCols(outData);
        invShiftRows(outData);
        makeSub(outData, invBox);
    }
    mixKey(outData, keys);
    return;
}

void mixKey(uint8_t *state, uint8_t *key) {
    for (size_t i = 0; i < 16; i++)
        state[i] ^= key[i];
    return;
}

static void makeSub(uint8_t *state, uint8_t *sBox) {
    for (size_t i = 0; i < 16; i++)
        state[i] = sBox[state[i]];
    return;
}

static void shiftRows(uint8_t *state) {
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

static void invShiftRows(uint8_t * state) {
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

static void mixCols(uint8_t *state) {
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

static void invMixCols(uint8_t *state) {
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
