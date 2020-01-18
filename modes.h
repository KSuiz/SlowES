#ifndef MODES_H
#define MODES_H

void encryptCBC(FILE *, FILE *, uint8_t *, size_t);
void decryptCBC(FILE *, FILE *, uint8_t *, size_t);

typedef enum {
    ENC_M = 0,
    DEC_M = 1
} emode_t;

typedef enum {
    CBC_M = 0
} rmode_t;

static void (*cipherFuncs[2][1])(FILE *, FILE *, uint8_t *, size_t) = {
    {encryptCBC},
    {decryptCBC}
};

#endif