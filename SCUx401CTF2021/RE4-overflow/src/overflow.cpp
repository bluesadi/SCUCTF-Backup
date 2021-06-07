#include "RC4.h"
#include "TEA.h"
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>

char input[100] = {0};
uint32_t t;

void encrypt2(){
    uint8_t key[16];
    //retn 402181
    memcpy(key, "\x26\x14\x8D\x62\x1E\xF7\x48\x44\x91\x8A\xF1\x82\xD6\x39\x76\xB6\xD7\xA8\x79\x4C\xE5\x47\x35\x1C\x81\x21\x40\x00\x00\x00\x00\x00", 32);
    char buf[100] = {0};
    memcpy(buf, input, 100);
    RC4 rc4(key, 16);
    rc4.RC4Encrypt(input, buf, 32);
    t=input[15];input[15]=input[4];input[4]=t;
    t=input[1];input[1]=input[21];input[21]=t;
    t=input[4];input[4]=input[8];input[8]=t;
    t=input[31];input[31]=input[3];input[3]=t;
    t=input[21];input[21]=input[5];input[5]=t;
    t=input[12];input[12]=input[7];input[7]=t;
    t=input[6];input[6]=input[12];input[12]=t;
    t=input[17];input[17]=input[29];input[29]=t;
    t=input[6];input[6]=input[11];input[11]=t;
    t=input[15];input[15]=input[20];input[20]=t;
    t=input[27];input[27]=input[4];input[4]=t;
    t=input[19];input[19]=input[22];input[22]=t;
    t=input[28];input[28]=input[19];input[19]=t;
    t=input[26];input[26]=input[15];input[15]=t;
    t=input[27];input[27]=input[6];input[6]=t;
    t=input[5];input[5]=input[17];input[17]=t;
    t=input[29];input[29]=input[23];input[23]=t;
    t=input[8];input[8]=input[14];input[14]=t;
    t=input[22];input[22]=input[15];input[15]=t;
    t=input[28];input[28]=input[24];input[24]=t;
    t=input[14];input[14]=input[14];input[14]=t;
    t=input[10];input[10]=input[27];input[27]=t;
    t=input[7];input[7]=input[7];input[7]=t;
    t=input[25];input[25]=input[0];input[0]=t;
    t=input[1];input[1]=input[18];input[18]=t;
    t=input[16];input[16]=input[16];input[16]=t;
    t=input[24];input[24]=input[20];input[20]=t;
    t=input[9];input[9]=input[5];input[5]=t;
    t=input[9];input[9]=input[25];input[25]=t;
    t=input[6];input[6]=input[20];input[20]=t;
    t=input[8];input[8]=input[5];input[5]=t;
    t=input[30];input[30]=input[22];input[22]=t;
    t=input[6];input[6]=input[31];input[31]=t;
    t=input[8];input[8]=input[1];input[1]=t;
    t=input[11];input[11]=input[6];input[6]=t;
    t=input[20];input[20]=input[20];input[20]=t;
    t=input[11];input[11]=input[8];input[8]=t;
    t=input[20];input[20]=input[3];input[3]=t;
    t=input[30];input[30]=input[31];input[31]=t;
    t=input[31];input[31]=input[30];input[30]=t;
    t=input[31];input[31]=input[3];input[3]=t;
    t=input[31];input[31]=input[12];input[12]=t;
    t=input[14];input[14]=input[18];input[18]=t;
    t=input[15];input[15]=input[4];input[4]=t;
    t=input[28];input[28]=input[1];input[1]=t;
    t=input[14];input[14]=input[1];input[1]=t;
    t=input[0];input[0]=input[19];input[19]=t;
    t=input[7];input[7]=input[25];input[25]=t;
    t=input[13];input[13]=input[18];input[18]=t;
    t=input[11];input[11]=input[19];input[19]=t;
    t=input[29];input[29]=input[10];input[10]=t;
    t=input[20];input[20]=input[30];input[30]=t;
    t=input[20];input[20]=input[11];input[11]=t;
    t=input[27];input[27]=input[22];input[22]=t;
    t=input[4];input[4]=input[9];input[9]=t;
    t=input[30];input[30]=input[15];input[15]=t;
    t=input[6];input[6]=input[15];input[15]=t;
    t=input[23];input[23]=input[8];input[8]=t;
    t=input[2];input[2]=input[17];input[17]=t;
    t=input[26];input[26]=input[5];input[5]=t;
    t=input[28];input[28]=input[25];input[25]=t;
    t=input[8];input[8]=input[23];input[23]=t;
    t=input[27];input[27]=input[22];input[22]=t;
    t=input[13];input[13]=input[8];input[8]=t;
    t=input[13];input[13]=input[5];input[5]=t;
    t=input[3];input[3]=input[15];input[15]=t;
    t=input[9];input[9]=input[1];input[1]=t;
    t=input[19];input[19]=input[28];input[28]=t;
    t=input[16];input[16]=input[3];input[3]=t;
    t=input[3];input[3]=input[8];input[8]=t;
    t=input[0];input[0]=input[26];input[26]=t;
    t=input[5];input[5]=input[6];input[6]=t;
    t=input[2];input[2]=input[18];input[18]=t;
    t=input[31];input[31]=input[14];input[14]=t;
    t=input[7];input[7]=input[18];input[18]=t;
    t=input[12];input[12]=input[15];input[15]=t;
    t=input[5];input[5]=input[19];input[19]=t;
    t=input[5];input[5]=input[28];input[28]=t;
    t=input[19];input[19]=input[23];input[23]=t;
    t=input[5];input[5]=input[18];input[18]=t;
    t=input[9];input[9]=input[19];input[19]=t;
    t=input[31];input[31]=input[0];input[0]=t;
    t=input[18];input[18]=input[2];input[2]=t;
    t=input[30];input[30]=input[17];input[17]=t;
    t=input[4];input[4]=input[29];input[29]=t;
    t=input[1];input[1]=input[8];input[8]=t;
    t=input[7];input[7]=input[7];input[7]=t;
    t=input[1];input[1]=input[30];input[30]=t;
    t=input[26];input[26]=input[26];input[26]=t;
    t=input[25];input[25]=input[9];input[9]=t;
    t=input[16];input[16]=input[11];input[11]=t;
    t=input[31];input[31]=input[19];input[19]=t;
    t=input[29];input[29]=input[5];input[5]=t;
    t=input[17];input[17]=input[6];input[6]=t;
    t=input[24];input[24]=input[15];input[15]=t;
    t=input[11];input[11]=input[26];input[26]=t;
    t=input[23];input[23]=input[18];input[18]=t;
    t=input[14];input[14]=input[15];input[15]=t;
    t=input[1];input[1]=input[28];input[28]=t;
    t=input[22];input[22]=input[5];input[5]=t;
}

void encrypt(){
    //retn 400DE3
    uint8_t key[16];
    memcpy(key, "\x94\xfa\x3e\x55\x38\xd5\x7f\x71\x93\x7a\x85\x07\x6e\x96\xfb\xc5\xc0\x0f\x8f\xdd\xbb\xcb\xb8\xb4\xE3\x0D\x40\x00\x00\x00\x00\x00", 32);
    char buf[100] = {0};
    memcpy(buf, input, 100);
    TEA tea(key);
    tea.TEAEncrypt((uint8_t*)input, (uint8_t*)buf, 32);
}

int get_name_by_pid(pid_t pid, char* name){
    int fd;
    char buf[1024] = {0};
    snprintf(buf, 1024, "/proc/%d/cmdline", pid);
    if ((fd = open(buf, O_RDONLY)) == -1)
        return -1;
    read(fd, buf, 1024);
    strncpy(name, buf, 1023);
    return 0;
}

int nodebugger(){
    pid_t ppid = getppid();
    char name[1024] = {0};
    get_name_by_pid(ppid, name);
    if(strcmp(name, "/bin/bash") && strcmp(name, "bash")){
        exit(0);
    }
}

int no = nodebugger();

//scuctf{y0u_4r3_r34l_pwn_y3y3!!!}
int main(){
    scanf("%s", input);
    if(strlen(input) != 32){
        printf("?\n");
        exit(0);
    }
    encrypt();
    if(!memcmp(input, "\x7D\xB9\x37\xE4\x3F\xF1\x0A\x83\xF5\x55\xCA\x5C\x32\xD4\x7D\x47\x18\x0C\x21\x13\x0D\x15\xF1\x5B\x13\x8B\x35\x7B\x72\x5D\x62\x37", 32)){
        printf("Right!\n");
    }else{
        printf("??\n");
    }
}