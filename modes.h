#ifndef MODES_H
#define MODES_H

void encryptCBC(FILE *, FILE *, uint8_t *, size_t);
void decryptCBC(FILE *, FILE *, uint8_t *, size_t);
void encryptECB(FILE *, FILE *, uint8_t *, size_t);
void decryptECB(FILE *, FILE *, uint8_t *, size_t);

typedef enum {
    ENC_M = 0,
    DEC_M = 1
} emode_t;

typedef enum {
    CBC_M = 0,
    ECB_M = 1
} rmode_t;

#endif