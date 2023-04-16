import subprocess
from Crypto.Cipher import AES

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class SM4Utils:
    secret_key = b''

    def __init__(self, secret_key):
        self.secret_key = secret_key

    # 加密方法
    def encryptData_ECB(self, plain_text):
        # 创建 SM4对象
        crypt_sm4 = CryptSM4()
        # 定义key值
        # secret_key = b"nXVeb/hgPKFLPA=="
        # 设置key
        crypt_sm4.set_key(self.secret_key, SM4_ENCRYPT)
        # 调用加密方法加密(十六进制的bytes类型)
        encrypt_value = crypt_sm4.crypt_ecb(plain_text)
        # 用base64.b64encode转码（编码后的bytes）
        cipher_text = base64.b64encode(encrypt_value)
        # 返回加密后的字符串
        # return cipher_text.decode('utf-8', 'ignore')
        return encrypt_value.hex()
    
   
# 定义加密函数
def test_aes(aes_key, input_file):

    c_encrypted_file = str(len(aes_key)) + "bytes_c_encrypt_file.txt"
    # 可执行程序
    aes_executable = "./AES"
    # 传入参数
    args = [aes_key, input_file, c_encrypted_file]
    # 使用subprocess模块执行命令，并获取标准输出和标准错误输出
    result = subprocess.run([aes_executable] + args, capture_output=True)
    # 输出标准输出和标准错误输出
    print(result.stdout.decode(), end='')
    print(result.stderr.decode())
    # 创建AES加密器对象
    cipher = AES.new(aes_key, AES.MODE_ECB)
    # 逐块读取并加密文件内容
    with open(input_file, "rb") as fin, open(c_encrypted_file, "rb") as fcin:
        while True:
            # 读取16字节的块
            block = fin.read(16)
            c_block = fcin.read(16)
            if not block and not c_block: 
                break
            # 对块进行加密，并写入输出文件
            encrypted_block = cipher.encrypt(block)
            if encrypted_block != c_block:
                print("Test AES-"+str(len(aes_key)*8)+ " for the " + input_file + " encrypt failed, check out your AES implemention!")
                return 
    print("Test AES-"+str(len(aes_key)*8)+ " for the " + input_file + " encrypt succeeded!\n")   

def test_sm4(sm4_key, input_file):
    
    
    c_encrypted_file = "sm4_encrypt_file.txt"
    # 可执行程序
    aes_executable = "./SM4"
    # 传入参数
    args = [sm4_key, input_file, c_encrypted_file]
    # 使用subprocess模块执行命令，并获取标准输出和标准错误输出
    result = subprocess.run([aes_executable] + args, capture_output=True)
    # 输出标准输出和标准错误输出
    print(result.stdout.decode(), end='')
    print(result.stderr.decode())
    
    cipher = Cipher(algorithms.SM4(sm4_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # 逐块读取并加密文件内容
    with open(input_file, "rb") as fin, open(c_encrypted_file, "rb") as fcin:
        while True:
            # 读取16字节的块
            block = fin.read(16)
            c_block = fcin.read(16)
            if not block and not c_block: 
                break

            encrypted_block = encryptor.update(block)

            if encrypted_block != c_block:
                print(block.hex())
                print(encrypted_block)
                print("Test SM4-" + " for the " + input_file + " encrypt failed, check out your AES implemention!")
                return 
    print("Test SM4"+  " for the " + input_file + " encrypt succeeded!\n")   
    
    return

def test_sha2(type, input_file):
    
    # 可执行程序
    sha2_executable = "./SHA2"
    # 传入参数
    args = [str(type), input_file]
    # 使用subprocess模块执行命令，并获取标准输出和标准错误输出
    result = subprocess.run([sha2_executable] + args, capture_output=True)
    # 输出标准输出和标准错误输出
    # print(result.stdout.decode())
    # print(result.stderr.decode())
    
    hash_result = result.stdout.decode()
    print(hash_result)
    
    return 

def test_sha3():
    print("#####  testing sha3  ####")
    return 




if __name__ == "__main__":
    
    input_file_16K = "16K.txt"
    input_file_4M = "4M.txt"
 
    
    print("#####  testing AES  ####")
    aes_key128 = b'1234567890123456'
    aes_key192 = b'123456789012345678901234'
    aes_key256 = b"12345678901234567890123456789012"  # 定义AES加密密钥,只能是16 24 或者 32位的
    test_aes(aes_key128, input_file_16K)
    test_aes(aes_key192, input_file_16K)
    test_aes(aes_key256, input_file_16K)
    test_aes(aes_key128, input_file_4M)
    test_aes(aes_key192, input_file_4M)
    test_aes(aes_key256, input_file_4M)
    
    print("#####  testing sm4  ####")
    sm4_key = b'0123456789abcdef'
    test_sm4(sm4_key, input_file_16K)
    test_sm4(sm4_key, input_file_4M)

    print("#####  testing sha2  ####")
    test_sha2(256, input_file_16K)
    test_sha2(512, input_file_16K)
    test_sha2(256, input_file_4M)
    test_sha2(512, input_file_4M)

    test_sha3()

    
