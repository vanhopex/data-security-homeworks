#include <string.h>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include <stdlib.h>

#define SET_BIT(x, bit) (x |= ((unsigned long long)1 << bit))
#define UNSET_BIT(x, bit) (x &= ~((unsigned long long)1 << bit))
#define GET_BIT(x, bit) ((x & ((unsigned long long)1 << bit)) >> bit)

unsigned char digest[1024];
unsigned long long A[5][5];

unsigned long long left_shift(unsigned long long x, int shift){
    return (x << shift) | (x >> (64 - shift));
}

void theta(){
    unsigned long long C[5], D[5];

    memset(C, 0, sizeof(C));
    memset(D, 0, sizeof(D));

    for(int x = 0;x < 5;x ++){
        C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4];
    }

    for(int x = 0;x < 5;x ++){
        D[x] = C[(((x - 1) % 5) + 5 ) % 5] ^ left_shift(C[(x + 1) % 5], 1);
    }

    for(int x = 0;x < 5;x ++){
        for(int y = 0;y < 5;y ++){
            A[x][y] = A[x][y] ^ D[x];
        }
    }
}

void rho(){
    int x, y, m;
    x = 1;
    y = 0;
    for(int t = 0; t < 24; t ++){
        A[x][y] = left_shift(A[x][y], ((t + 1)*(t + 2) / 2) % 64);
        m = x;
        x = y;
        y = (2 * m + 3 * y) % 5;
    }
}

void pi(){
    unsigned long long Ax[5][5];
    memcpy(Ax, A, sizeof(A));

    for(int x = 0;x < 5;x ++){
        for(int y = 0;y < 5;y ++){
            A[x][y] = Ax[(x + 3 * y) % 5][x];
            // printf("%d %d <- %d %d\n", x, y, (x + 3 * y) % 5, x);
        }
    }
}

void chi(){
    unsigned long long Ax[5][5];
    memcpy(Ax, A, sizeof(A));

    for(int x = 0;x < 5;x ++){
        for(int y = 0;y < 5;y ++){
            A[x][y] = Ax[x][y] ^ ((Ax[(x + 1) % 5][y] ^ 0xffffffffffffffffull) & Ax[(x + 2) % 5][y]);
        }
    }
}

int rc(int t){
    if(t % 255 == 0)return 1;
    int R[10];R[0] = 1;
    for(int i = 1;i < 8;i ++)R[i] = 0;
    for(int i = 0;i < t % 255;i ++){
        int Rx[10];
        for(int i = 0;i < 8;i ++)Rx[i] = R[i];
        R[0] = Rx[7];
        for(int i = 1;i < 4;i ++)R[i] = Rx[i - 1];
        R[4] = Rx[3] ^ Rx[7];
        R[5] = Rx[4] ^ Rx[7];
        R[6] = Rx[5] ^ Rx[7];
        R[7] = Rx[6];
    }
    return R[0];
}

void iota(int round){
    unsigned long long RC = 0;
    for(int j = 0;j <= 6;j ++){
        if(rc(j + 7 * round) == 1){
            SET_BIT(RC, (1 << j) - 1);
        }
    }
    // printf("%016llx\n", RC);
    A[0][0] ^= RC;
}

void keccak_p(){
    for(int round = 0;round < 24;round ++){
        // printf("Round %d\n", round);
        theta();
        rho();
        pi();
        chi();
        iota(round);
    }
}

void sponge(int r, unsigned char* message, int message_len, int d){
    
    int j = (((-2 - message_len) % r) + r) % r;
    // printf("%d\n", j);
    SET_BIT(message[message_len / 8], message_len % 8);
    SET_BIT(message[(message_len + j + 1)/ 8], (message_len + j + 1) % 8);
    for(int i = 0;i < ((message_len + j + 1) % 8);i ++)UNSET_BIT(message[(message_len + j + 1)/ 8], i);
    for(int i = (message_len / 8) + 1; i < (message_len + j + 1)/ 8;i ++)message[i] = 0;
    for(int i = (message_len % 8) + 1;i < 8;i ++)UNSET_BIT(message[message_len / 8], i);
    message_len += 2 + j;


    int n = message_len / r;
    int c = 1600 - r;

    for(int i = 0; i < n; i ++){
        unsigned long long temp_S[5][5];
        for(int y = 0;y < 5;y ++){
            for(int x = 0;x < 5;x ++){
                temp_S[x][y] = 0;
                for(int j = 0;j < 8;j ++){
                    temp_S[x][y] |= ((40 * y + 8 * x + j) < (r / 8) ? ((unsigned long long)message[(i * r / 8) + 40 * y + 8 * x + j]) : 0) << (j * 8);
                }
            }
        }
        for(int y = 0;y < 5;y ++){
            for(int x = 0;x < 5;x ++){
                A[x][y] ^= temp_S[x][y];
            }
        }

        keccak_p();
    }


    int x = 0;
    int y = 0;
    int z = 0;
    for(int i = 0;i < d / 8;i ++){
        digest[i] = (A[x][y] & (0xFFllu << z)) >> z;
        z += 8;
        if(z >= 64){
            z = 0;
            x = x + 1;
            if(x >= 5){
                x = 0;
                y = y + 1;
            }
        }
    }
}

void keccak(int c, unsigned char* message, int message_len, int d){
    sponge(1600 - c, message, message_len, d);
}

void sha3_256(unsigned char* message, int message_len){
    UNSET_BIT(message[message_len / 8], message_len % 8);
    SET_BIT(message[(message_len + 1)/ 8], (message_len + 1) % 8);
    message_len += 2;
    keccak(512, message, message_len, 256);
    return ;
}

void sha3_512(unsigned char* message, int message_len){
    UNSET_BIT(message[message_len / 8], message_len % 8);
    SET_BIT(message[(message_len + 1)/ 8], (message_len + 1) % 8);
    message_len += 2;
    keccak(1024, message, message_len, 512);
    return ;
}

int main(int argc, char ** argv){

    FILE *fp;
    unsigned char *buffer;
    long file_size;

    char*  inputFileName = argv[2];
    fp = fopen(inputFileName, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Error opening file.\n");
        exit(1);
    }

    fseek(fp, 0L, SEEK_END);  // 移动文件指针到文件末尾
    file_size = ftell(fp) * 8;    // 获取文件大小
    rewind(fp);               // 重置文件指针到文件开头

    buffer = (unsigned char*) malloc(file_size);  // 分配缓冲区内存
    if (buffer == NULL) {
        fprintf(stderr, "Error allocating memory.\n");
        exit(1);
    }

    fread(buffer, file_size, 1, fp);  // 读取文件内容到缓冲区
  
    fclose(fp);  // 关闭文件

    clock_t start;
    clock_t end;
 
    uint32_t type = atoi(argv[1]);
    if (256 == type) {
        start = clock();
        sha3_256(buffer, file_size);
        end = clock();
        // printf("digest:\n");
        for(int i = 0;i < 256 / 8;i ++)printf("%02x", digest[i]);
        printf("\nTime Cost of SHA3-256 encrypt: %f\n", ((double)end - start) / CLOCKS_PER_SEC);

    }
    else if (512 == type) {
        start = clock();
        sha3_512(buffer, file_size);
        end = clock();
        // printf("digest:\n");
        for(int i = 0;i < 512 / 8;i ++)printf("%02x", digest[i]);
        printf("\nTime Cost of SHA3-512 encrypt: %f\n", ((double)end - start) / CLOCKS_PER_SEC);

    }
    else printf("Only suport 256 & 512\n");

    free(buffer);

    return 0;
}