import subprocess
from Crypto.Cipher import AES

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

def test_sm4():
    print("#####  testing sm4  ####")
    return

def test_sha2():
    print("#####  testing sha2  ####")
    return 

def test_sha3():
    print("#####  testing sha3  ####")
    return 




if __name__ == "__main__":
    # 打开输入文件并加密
    aes_key128 = b'1234567890123456'
    aes_key192 = b'123456789012345678901234'
    aes_key256 = b"12345678901234567890123456789012"  # 定义AES加密密钥,只能是16 24 或者 32位的
    input_file_16K = "16K.txt"
    input_file_4M = "4M.txt"
    # 测试加密结果是否正确
    print("#####  testing AES  ####")
    test_aes(aes_key128, input_file_16K)
    test_aes(aes_key192, input_file_16K)
    test_aes(aes_key256, input_file_16K)
    test_aes(aes_key128, input_file_4M)
    test_aes(aes_key192, input_file_4M)
    test_aes(aes_key256, input_file_4M)
    
    
    test_sm4()

    # 
    test_sha2()

    test_sha3()

    
