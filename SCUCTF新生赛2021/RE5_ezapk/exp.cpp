#include <cstdio>

// scuctf{6eb6906c4cd197b69c50f70b3ee4c9dd}
/*int main(){
    char input[] = "you_are_android_genius";
    unsigned char buf[23] = {0};
    int ptr = 0;
    for(int i = 0;i < 2;i += 1){
        for(int j = 0;j < 22;j += 2){
            buf[i + j] = input[ptr++];
        }
    }
    printf("%s\n", buf);
    for(int i = 0;i < 22;i ++){
        buf[i] += i;
        buf[i] ^= i;
    }
    for(int i = 0;i < 22;i ++){
        printf("\\x%02x", buf[i]);
    }
}*/

int main(){
    unsigned char enc[23] = "\x79\x72\x73\x71\x7d\x6b\x63\x6c\x61\x61\x76\x79\x7d\x7f\x63\x72\x61\x6b\x92\x9b\x6c\x9d";
    for(int i = 0;i < 22;i ++){
        enc[i] ^= i;
        enc[i] -= i;
    }
    int ptr = 0;
    unsigned char passwd[23] = {0};
    for(int i = 0;i < 2;i += 1){
        for(int j = 0;j < 22;j += 2){
            passwd[ptr++] = enc[i + j];
        }
    }
    printf("%s\n", passwd);
}