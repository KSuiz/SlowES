#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "block.h"
#include "modes.h"

void encryptCBC(FILE *inF, FILE *outF, uint8_t *keys, size_t nrounds) {
    uint8_t state[2][16] = {{0}};
    FILE *urand = fopen("/dev/urandom", "rb");
    if (!urand) {
        fprintf(stderr, "Unable to seed cipher.\n");
        exit(1);
    }
    fread(state[0], sizeof (uint8_t), 16, urand);
    fwrite(state[0], sizeof (uint8_t), 16, outF);

    uint8_t nr = 0;
    while ((nr = fread(state[1], sizeof (uint8_t), 16, inF))) {
        if (nr < 16)
            for (uint8_t i = nr; i < 16; i++)
                state[1][i] = 0;
        mixKey(state[0], state[1]);
        encryptBlock(state[0], state[0], keys, nrounds);
        fwrite(state[0], sizeof (uint8_t), 16, outF);
        if (nr < 16)
            break;
    }
    fwrite(&nr, sizeof (uint8_t), 1, outF);
    return;
}

void decryptCBC(FILE *inF, FILE *outF, uint8_t *keys, size_t nrounds) {
    uint8_t state[4][16] = {0};
    size_t len[3] = {0};
    size_t active[2] = {0, 1};
    for (size_t i = 0; i < 3; i++)
        len[i] = fread(state[i], sizeof (uint8_t), 16, inF);
    while (1) {
        decryptBlock(state[active[1]], state[3], keys, nrounds);
        mixKey(state[3], state[active[0]]);
        len[active[0]] = fread(state[active[0]], sizeof (uint8_t), 16, inF);
        active[1] = ((active[0] = active[1]) + 1) % 3;
        if (len[active[1]] == 16)
            fwrite(state[3], sizeof (uint8_t), 16, outF);
        else {
            fwrite(state[3], sizeof (uint8_t), state[active[1]][0], outF);
            break;
        }
    }
    return;
}