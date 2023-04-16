import subprocess
from Crypto.Cipher import AES

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os 

import hashlib

def sha256_file(file_path):
    with open(file_path, 'rb') as f:
        sha256 = hashlib.sha256()
        while True:
            data = f.read(1024)
            if not data:
                break
            sha256.update(data)
    return str(sha256.hexdigest())

def sha512_file(file_path):
    with open(file_path, 'rb') as f:
        sha512 = hashlib.sha512()
        while True:
            data = f.read(1024)
            if not data:
                break
            sha512.update(data)
    return str(sha512.hexdigest())

# 使用python3.8及以上可以用此方法，写法更简洁。
def file_hash(file_path: str, hash_method) -> str:
    if not os.path.isfile(file_path):
        print('文件不存在。')
        return ''
    h = hash_method()
    with open(file_path, 'rb') as f:
        while b := f.read(1024):
            h.update(b)
    return str(h.hexdigest())


# 定义加密函数
def test_aes(aes_key, input_file):

    c_encrypted_file = str(len(aes_key)) + "bytes_AES_encrypt_file.txt"
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
    print(result.stderr.decode())
    
    my_result = result.stdout.decode().split('\n')
    if type == 256 :
        # py_result = sha256_file(input_file)
        py_result = file_hash(input_file, hashlib.sha256)
    else :
        # py_result = sha512_file(input_file)
        py_result = file_hash(input_file, hashlib.sha512)
    # print(my_result)
    # print("my: " + my_result[0])
    # print("py: " + py_result)
    # print("\n\n")
    print(my_result[1])
    if(my_result[0] != py_result):
        print("Test SHA" + str(type) +  " for " + input_file  + " encrypt failed!")
    else:
        print("Test SHA" + str(type) + " for " + input_file  + " encrypt succeeded!")

def test_sha3(type, input_file):
    # 可执行程序
    sha2_executable = "./SHA3"
    # 传入参数
    args = [str(type), input_file]
    # 使用subprocess模块执行命令，并获取标准输出和标准错误输出
    result = subprocess.run([sha2_executable] + args, capture_output=True)
    # 输出标准输出和标准错误输出
    # print(result.stdout.decode())
    print(result.stderr.decode())
    
    my_result = result.stdout.decode().split('\n')
    if type == 256 :
        # py_result = sha256_file(input_file)
        py_result = file_hash(input_file, hashlib.sha3_256)
    else :
        # py_result = sha512_file(input_file)
        py_result = file_hash(input_file, hashlib.sha3_512)

    print(my_result[1])
    if(my_result[0] != py_result):
        print("Test SHA3-" + str(type) +  " for " + input_file  + " encrypt failed!")
    else:
        print("Test SHA3-" + str(type) + " for " + input_file  + " encrypt succeeded!")
    
    return 




if __name__ == "__main__":
    
    input_file_16K = "16K.txt"
    input_file_4M = "4M.txt"
 
    
    # print("#####  testing AES  ####")
    # aes_key128 = b'1234567890123456'
    # aes_key192 = b'123456789012345678901234'
    # aes_key256 = b"12345678901234567890123456789012"  # 定义AES加密密钥,只能是16 24 或者 32位的
    # test_aes(aes_key128, input_file_16K)
    # test_aes(aes_key192, input_file_16K)
    # test_aes(aes_key256, input_file_16K)
    # test_aes(aes_key128, input_file_4M)
    # test_aes(aes_key192, input_file_4M)
    # test_aes(aes_key256, input_file_4M)
    
    # print("#####  testing sm4  ####")
    # sm4_key = b'0123456789abcdef'
    # test_sm4(sm4_key, input_file_16K)
    # test_sm4(sm4_key, input_file_4M)

    # print("#####  testing sha2  ####")
    # test_sha2(256, input_file_16K)
    # test_sha2(512, input_file_16K)
    # test_sha2(256, input_file_4M)
    # test_sha2(512, input_file_4M)

    print("#####  testing sha3  ####")
    test_sha3(256, input_file_16K)
    test_sha3(512, input_file_16K)
    test_sha3(256, input_file_4M)
    test_sha3(512, input_file_4M)

    
