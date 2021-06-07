#include "RC4.h"

#include <cstdio>
RC4::RC4(void *key, int keylen){
    this->S = new uint8_t[256];
    this->T = new uint8_t[256];
    for(int i = 0;i < 256;i ++) S[i] = i, T[i] = ((uint8_t*)key)[i % keylen];
    int j = 0;
    for(int i = 0;i < 256;i ++){
        j = (j + S[i] + T[i]) % 256; 
        std::swap(S[i], S[j]);
    }
}
void RC4::RC4Encrypt(void *dest, void *src, int n){
    int i = 0, j = 0;
    for(int k = 0;k < n;k ++){
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        std::swap(S[i], S[j]);
        ((uint8_t*)dest)[k] = ((uint8_t*)src)[k] ^ S[(S[i] + S[j]) % 256];
    }
}