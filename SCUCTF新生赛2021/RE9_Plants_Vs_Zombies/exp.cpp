#include <cstdio>
#include <cstdint>

// scuctf{knockin_on_heavens_gate}
// \x6e\x6d\xb0\x6f\x92\xd1\x11\x74\xd5\xf6\x76\x78\x39\xda\xf9\xfc\xdd\xfc\x1f\xbf\x40\xe3\xc2\xe4\x86\x04\x06\x47\xaa\xc9\xcd
int main(){
    uint8_t flag[] = "\x6e\x6d\xb0\x6f\x92\xd1\x11\x74\xd5\xf6\x76\x78\x39\xda\xf9\xfc\xdd\xfc\x1f\xbf\x40\xe3\xc2\xe4\x86\x04\x06\x47\xaa\xc9\xcd";
    for(int i = 0;i < 31;i ++){
        if(i == 6){
            flag[i] ^= 0x64;
        }
        flag[i] -= i;
        flag[i] = (flag[i] << 3) | (flag[i] >> 5);
    }
    printf("%s\n", flag);
}