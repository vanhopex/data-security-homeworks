#include "AES.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


void printHex(const uint8_t *ptr, int len, char *tag) {
    printf("%s\ndata[%d]: ", tag, len);
    for (int i = 0; i < len; ++i) {
        printf("%.2x", *ptr++);
    }
    printf("\n");
}

void printState(uint8_t (*state)[4], char *tag) {
    printf("%s\n", tag);
    for (int i = 0; i < 4; ++i) {
        printf("%.2X %.2X %.2X %.2X\n", state[i][0], state[i][1], state[i][2], state[i][3]);
    }
    printf("\n");
}

void char2uint8(const char* input, uint8_t* output, size_t length) {
  for (size_t i = 0; i < length; i++) {
    output[i] = (uint8_t)input[i];
  }
}

int main(int argc, char* argv[]) {

    // for (int x = 0; x < argc; x++) {
    //     printf("第%d个参数是 %s\n", x, argv[x]);
    // }


    // case 1
    // const uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    // const uint8_t pt[16]={0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    // uint8_t ct[16] = {0};
    // uint8_t plain[16] = {0};

    // aesEncrypt(key, 16, pt, ct, 16);
    // printHex(pt, 16, "plain data:");
    // printf("expect cipher:\n39 25 84 1D 02 DC 09 FB DC 11 85 97 19 6A 0B 32\n");

    // printHex(ct, 16, "after encryption:");

    // aesDecrypt(key, 16, ct, plain, 16);
    // printHex(plain, 16, "after decryption:");

    // case 2
    // clock_t startTime, endTime;
    // const uint8_t key2[]="123456789012345678901234";
    // const uint8_t *data = (uint8_t*)"abcdefghijklmnopqrstuvwxyz123456";
    // uint8_t ct2[32] = {0};
    // uint8_t plain2[32] = {0};
    // // printf("%ld %ld\n", sizeof(key2), sizeof(*data) * strlen((char*)data));
    // startTime = clock();
    // aesEncrypt(key2, sizeof(key2) - 1, data, ct2, sizeof(*data) * strlen((char*)data));
    // endTime = clock();
    
    // printf("\nplain text:\n%s\n", data);
    // printf("expect ciphertext:\nfcad715bd73b5cb0488f840f3bad7889\n");
    // printHex(ct2, sizeof(*data) * strlen((char*)data), "after encryption:");

    // printf("\n Time cost of AES Encrypt: %f ms\n", ((double)endTime - startTime));
    

    // aesDecrypt(key2, sizeof(key2) - 1, ct2, plain2, sizeof(*data) * strlen((char*)data));
    // printHex(plain2, sizeof(*data) * strlen((char*)data), "after decryption:");

    // printf("output plain text: ");
    // for (int i = 0; i < sizeof(*data) * strlen((char*)data); ++i) {
    //     printf("%c", plain2[i]);
    // }


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
        // fwrite(buffer, 1, bytes_read, output_file);
        // printf("\n%zu 个字节：", bytes_read);
        // for (int i = 0; i < bytes_read; i++) {
        //     printf("%02x ", buffer[i]);
        // }
        uint8_t ct[16] = {0};
        aesEncrypt(key2, length, buffer, ct, sizeof(buffer));
        // printHex(ct, 16, "after encryption:");
        fwrite(ct, 1, bytes_read, output_file);
        // printf("\n");
    }
    endTime = clock();
    // for (int x = 0; x < argc; x++) {
    //     printf("第%d个参数是 %s\n", x, argv[x]);
    // }
    // printf("argv[1] length %zd\n", length);
    // printf("size of key2 : %lu \n", sizeof(key2));
    printf("\nTime cost of AES Encrypt: %f s", ((double)endTime - startTime) / CLOCKS_PER_SEC);
    // printf("\nfinished the AES encrypt.\n");

    fclose(input_file);
    fclose(output_file);

    return 0;
}