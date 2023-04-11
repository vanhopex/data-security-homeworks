#ifndef AES_H
#define AES_H

#include<stdint.h>

/**
 * @brief AES加密算法
 * 
 * @param key ：密钥
 * @param keyLen ：密钥长度
 * @param pt ： plaintext, 明文
 * @param ct ： ciphertext 密文
 * @param len ： 明文长度
 * @return int ：加密状态，0为成功，-1失败
 */
int aesEncrypt(const uint8_t *key, uint32_t keyLen, const uint8_t *pt, uint8_t *ct, uint32_t len);


/**
 * @brief AES解密算法
 * 
 * @param key 密钥
 * @param keyLen 密钥长度
 * @param ct 密文
 * @param pt 明文
 * @param len 密文长度
 * @return int 解密状态，0为成功，-1失败
 */
int aesDecrypt(const uint8_t *key, uint32_t keyLen, const uint8_t *ct, uint8_t *pt, uint32_t len);

#endif 