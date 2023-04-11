from Crypto.Cipher import AES

password = b'123456789012345678901234' #秘钥，b就是表示为bytes类型
text = b'abcdefghijklmnopqrstuvwxyz123456' #需要加密的内容，bytes类型
aes = AES.new(password,AES.MODE_ECB) #创建一个aes对象
# AES.MODE_ECB 表示模式是ECB模式
en_text = aes.encrypt(text) #加密明文
print("密文：",en_text) #加密明文，bytes类型
hex_text = en_text.hex()
print(type(hex_text))
print(hex_text)
den_text = aes.decrypt(en_text) # 解密密文
print("明文：",den_text)
