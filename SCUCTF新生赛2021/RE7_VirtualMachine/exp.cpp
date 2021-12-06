#include <cstdio>

char flag[100] = "Ez_Vqzz\x85qp_My{v\x89\x90\x89";

int main(){
    for(int i = 1;flag[i - 1];i ++){
        flag[i - 1] = (flag[i - 1] - i) ^ i;
    }
    printf("scuctf{%s}", flag);
}