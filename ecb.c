#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "block.h"
#include "modes.h"

void encryptECB(FILE *inF, FILE *outF, uint8_t *keys, size_t nrounds) {
    uint8_t state[16] = {0};
    uint8_t nr = 0;
    while ((nr = fread(state, sizeof (uint8_t), 16, inF))) {
        if (nr < 16)
            for (uint8_t i = nr; i < 16; i++)
                state[i] = 0;
        encryptBlock(state, state, keys, nrounds);
        fwrite(state, sizeof (uint8_t), 16, outF);
        if (nr < 16)
            break;
    }
    fwrite(&nr, sizeof (uint8_t), 1, outF);
    return;
}

void decryptECB(FILE *inF, FILE *outF, uint8_t *keys, size_t nrounds) {
    uint8_t state[3][16] = {{0}};
    size_t len[2] = {0};
    size_t active = 0;
    for (size_t i = 0; i < 2; i++)
        len[i] = fread(state[i], sizeof (uint8_t), 16, inF);
    while (1) {
        decryptBlock(state[active], state[2], keys, nrounds);
        len[active] = fread(state[active], sizeof (uint8_t), 16, inF);
        active = !active;
        if (len[active] == 16)
            fwrite(state[2], sizeof (uint8_t), 16, outF);
        else {
            fwrite(state[2], sizeof (uint8_t), state[active][0], outF);
            break;
        }
    }
    return;
}