#include "AES.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void char2uint8(const char* input, uint8_t* output, size_t length) {
  for (size_t i = 0; i < length; i++) {
    output[i] = (uint8_t)input[i];
  }
}

int main(int argc, char* argv[]) {
    // uint8_t *key2 = (uint8_t *)argv[1];
   size_t length = strlen(argv[1]);
   uint8_t* key2 = malloc(length * sizeof(uint8_t));
   char2uint8(argv[1], key2, length);

    char*  inputFileName = argv[2];
    char*  cEncryptFileName = argv[3];
    // printf("size of key2 : %lu \n", sizeof(key2));
    
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

    unsigned char buffer[16];
    size_t bytes_read;

    startTime = clock();
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), input_file)) > 0) {

        uint8_t ct[16] = {0};
        aesEncrypt(key2, length, buffer, ct, sizeof(buffer));
        // printHex(ct, 16, "after encryption:");
        fwrite(ct, 1, bytes_read, output_file);
        // printf("\n");
    }
    endTime = clock();
    
    printf("\nTime cost of AES Encrypt: %f s", ((double)endTime - startTime) / CLOCKS_PER_SEC);

    fclose(input_file);
    fclose(output_file);

    return 0;
}