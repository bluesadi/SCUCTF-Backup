#include "TEA.h"

void TEA::EncryptBlock(uint32_t v[2]) {
    uint32_t *k = this->key;
    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
    uint32_t delta=0x9E3779B9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

void TEA::DecryptBlock(uint32_t v[2]) {
    uint32_t *k = this->key;
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  /* set up; sum is 32*delta */
    uint32_t delta=0x9E3779B9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

TEA::TEA(uint8_t key[16]){
    memcpy(this->key, key, 16);
}

TEA::TEA(uint32_t key[4]){
    memcpy(this->key, key, 16);
}

void TEA::TEAEncrypt(uint8_t *dest, uint8_t *src, int n){
    memcpy(dest, src, n);
    for(int i = 0;i < n;i += 8){
        EncryptBlock((uint32_t*)(dest + i));
    }
}

void TEA::TEADecrypt(uint8_t *dest, uint8_t *src, int n){
    memcpy(dest, src, n);
    for(int i = 0;i < n;i += 8){
        DecryptBlock((uint32_t*)(dest + i));
    }
}