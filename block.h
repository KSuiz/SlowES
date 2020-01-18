#ifndef BLOCK_H
#define BLOCK_H

void deriveKeys(uint32_t *, size_t, size_t);
void encryptBlock(uint8_t *, uint8_t *, uint8_t *, size_t);
void decryptBlock(uint8_t *, uint8_t *, uint8_t *, size_t);
void mixKey(uint8_t *, uint8_t *);

#endif