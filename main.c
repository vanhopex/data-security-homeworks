#include "AES.h"
#include <stdio.h>
#include <string.h>


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


int main() {

    // case 1
    const uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    const uint8_t pt[16]={0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    uint8_t ct[16] = {0};
    uint8_t plain[16] = {0};

    aesEncrypt(key, 16, pt, ct, 16);
    printHex(pt, 16, "plain data:");
    printf("expect cipher:\n39 25 84 1D 02 DC 09 FB DC 11 85 97 19 6A 0B 32\n");

    printHex(ct, 16, "after encryption:");

    aesDecrypt(key, 16, ct, plain, 16);
    printHex(plain, 16, "after decryption:");

    // case 2
    const uint8_t key2[]="1234567890123456";
    const uint8_t *data = (uint8_t*)"abcdefghijklmnopqrstuvwxyz123456";
    uint8_t ct2[32] = {0};
    uint8_t plain2[32] = {0};
    // printf("%ld %ld\n", sizeof(key2), sizeof(*data) * strlen((char*)data));
    aesEncrypt(key2, sizeof(key2) - 1, data, ct2, sizeof(*data) * strlen((char*)data));

    printf("\nplain text:\n%s\n", data);
    printf("expect ciphertext:\nfcad715bd73b5cb0488f840f3bad7889\n");
    printHex(ct2, sizeof(*data) * strlen((char*)data), "after encryption:");

    aesDecrypt(key2, sizeof(key2) - 1, ct2, plain2, sizeof(*data) * strlen((char*)data));
    printHex(plain2, sizeof(*data) * strlen((char*)data), "after decryption:");

    printf("output plain text: ");
    for (int i = 0; i < sizeof(*data) * strlen((char*)data); ++i) {
        printf("%c", plain2[i]);
    }

    printf("\n finished the AES");
    return 0;
}