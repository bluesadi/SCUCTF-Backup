#ifndef _RC4_H_
#define _RC4_H_
#include <algorithm>
#include <stdint.h>

class RC4{
private:
    uint8_t *S;
    uint8_t *T;

public:
    RC4(void *key, int keylen);

    void RC4Encrypt(void *dest, void *src, int n);

};
#endif