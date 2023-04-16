#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "SM4.h"

void char2uint8(const char* input, uint8_t* output, size_t length) {
  for (size_t i = 0; i < length; i++) {
    output[i] = (uint8_t)input[i];
  }
}

sm4_ctx ctx;
// uint8_t gkey[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};

void printHex(const uint8_t *ptr, int len) { // byte length

    for (int i = 0; i < len; ++i) {
        printf("%.2x", *ptr++);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {

   size_t length = strlen(argv[1]);
   uint8_t* key2 = malloc(length * sizeof(uint8_t));
   char2uint8(argv[1], key2, length);

    char*  inputFileName = argv[2];
    char*  cEncryptFileName = argv[3];
    
    /*读入参数，打开输入文件，并调用并调用aesEncrypt()加密*/
    FILE* input_file = fopen(inputFileName, "rb");
    FILE* output_file = fopen(cEncryptFileName, "wb");

    clock_t startTime, endTime;

    if (!input_file) {
        printf("无法打开输入文件\n");
        return 1;
    }

    if (!output_file) {
        printf("无法打开输出文件\n");
        fclose(input_file);
        return 1;
    }
    sm4_set_key(key2, &ctx);

    unsigned char buffer[16];
    size_t bytes_read;

    startTime = clock();
    int  i = 0;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), input_file)) > 0) {
        uint8_t ct[16] = {0};        
        sm4_encrypt(buffer, ct, &ctx);
        fwrite(ct, 1, bytes_read, output_file);
        i++;
    }

    endTime = clock();
    
    printf("Time cost of SM4 Encrypt: %f s", ((double)endTime - startTime) / CLOCKS_PER_SEC);

    fclose(input_file);
    fclose(output_file);

    return 0;

}
