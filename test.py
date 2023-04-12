import subprocess
from Crypto.Cipher import AES

# 定义加密函数
def encrypt_file_test(input_file, c_encrypted_file, key):
    # 创建AES加密器对象
    cipher = AES.new(key, AES.MODE_ECB)
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
            # fout.write(encrypted_block)

            if encrypted_block != c_block:
                print(encrypted_block.hex())
                print(c_block.hex())
                print("test fail, check out your AES implemention!")
                return 
    print("test success!!!")   
    
 
# 打开输入文件并加密
key = b"12345678901234567890123456789012"  # 定义加密密钥
input_file = "4M.txt"
c_encrypted_file = str(len(key)) + "bytes_c_encrypt_file.txt"
# 可执行程序
executable = "./AES"
# 传入参数
args = [key, input_file, c_encrypted_file]
# 使用subprocess模块执行命令，并获取标准输出和标准错误输出
result = subprocess.run([executable] + args, capture_output=True)

# 输出标准输出和标准错误输出
print(result.stdout.decode())
print(result.stderr.decode())

encrypt_file_test(input_file, c_encrypted_file, key)
