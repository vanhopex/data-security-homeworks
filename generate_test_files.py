import random 
def testcase_generate():
    f = open("16k.txt", "w")
    for i in range(16 * 1024):
        c = chr(random.randint(32, 126))
        f.write(c)
    f = open("4M.txt", "w")
    for i in range(4 * 1024 * 1024):
        c = chr(random.randint(32, 126))
        f.write(c)
# 生成测试用例
testcase_generate() 