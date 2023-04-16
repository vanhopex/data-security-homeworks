#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "SM4.h"

// void char2uint8(const char* input, uint8_t* output, size_t length) {
//    for (size_t i = 0; i < length / 2; i++) {
//         char temp[3];
//         strncpy(temp, input + i * 2, 2); // Copy 2 characters at a time
//         temp[2] = '\0'; // Null-terminate the string
//         output[i] = (uint8_t)strtoul(temp, NULL, 16); // Convert to uint8_t
//     }
// }

void char2uint8(const char* input, uint8_t* output, size_t length) {
  for (size_t i = 0; i < length; i++) {
    output[i] = (uint8_t)input[i];
  }
}

sm4_ctx ctx;
// uint8_t gkey[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
// uint8_t *gkey = "0123456789abcdeffedcba9876543210";

void printHex(const uint8_t *ptr, int len) { // byte length

    for (int i = 0; i < len; ++i) {
        printf("%.2x", *ptr++);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    // printf("hello\n");

    // size_t length = strlen("0123456789abcdef");
    // uint8_t* gkey = malloc(length * sizeof(uint8_t));
    // char2uint8("0123456789abcdef", gkey, length);
	
	// //}
	// sm4_set_key(gkey, &ctx);
    // // uint8_t input[] = "0123456789abcdeffedcba9876543210";
    // printf("set down\n");
    // uint8_t* input = malloc(length * sizeof(uint8_t));
    // char2uint8("0123456789abcdef", input, length);
    // uint8_t *out = malloc(length  * sizeof(uint8_t));
    // printf("begin\n");
    // // printHex(input, 16);
    // printHex(input, 16);
    // sm4_encrypt(input, out, &ctx);
    // printHex(out, 16);
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
    sm4_set_key(key2, &ctx);

    unsigned char buffer[16];
    size_t bytes_read;

    startTime = clock();
    int  i = 0;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), input_file)) > 0) {
        uint8_t ct[16] = {0};        
        sm4_encrypt(buffer, ct, &ctx);
        // if (i == 0) {
        //     printHex(buffer, 16);
        //     printHex(ct, 16);
        //     printf("\n");
        // }
        
        fwrite(ct, 1, bytes_read, output_file);
        i++;
    }


    endTime = clock();
    
    printf("Time cost of SM4 Encrypt: %f s", ((double)endTime - startTime) / CLOCKS_PER_SEC);

    fclose(input_file);
    fclose(output_file);

    return 0;

}
