#ifndef _TEA_H_
#define _TEA_H_
#include <stdint.h>
#include <cstring>

class TEA{

private:
    uint32_t key[4];

    void EncryptBlock(uint32_t v[2]);
    void DecryptBlock(uint32_t v[2]);
public:
    TEA(uint8_t key[16]);
    TEA(uint32_t key[4]);

    void TEAEncrypt(uint8_t *dest, uint8_t *src, int n);

    void TEADecrypt(uint8_t *dest, uint8_t *src, int n);

};
#endif