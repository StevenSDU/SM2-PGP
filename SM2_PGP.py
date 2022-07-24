import random
from Crypto.Cipher import AES
from gmssl import sm2

#SM2加密：
def SM2_enc(plaintext):
    ciphertext = sm2_crypt.encrypt(plaintext)
    return ciphertext

#SM2解密：
def SM2_dec(ciphertext):
    plaintext = sm2_crypt.decrypt(ciphertext)
    return plaintext

#PGP加密过程：
def PGP_Encrypt(message, key):
    #选择OFB加密模式
    mode = AES.MODE_OFB
    #偏移向量为0
    iv = b'0000000000000000'
    cryptor = AES.new(key.encode('utf-8'), mode, iv)
    #AES加密的每一块为16字节
    length = 16
    count = len(message)
    #计算填充量，如果不虚填充则add=0
    if count % length != 0:
        add = length - (count % length)
    else:
        add = 0
    message = message + ('\0' * add)
    #先对消息进行加密后再利用AES加密
    ciphertext1 = cryptor.encrypt(message.encode('utf-8'))
    plaintext = key.encode('utf-8')
    ciphertext2 = SM2_enc(plaintext)
    print("用会话密钥k，AES对称加密算法加密的消息值：", ciphertext1)
    print("用SM2公钥得到会话密钥k的加密结果：", ciphertext2)
    return ciphertext1, ciphertext2

def PGP_Decrypt(mes1, mes2):
    #利用OFB模式解密
    mode = AES.MODE_OFB
    iv = b'0000000000000000'
    get_key = SM2_dec(mes2)
    print("用SM2私钥得到会话密钥：", get_key.decode('utf-8'))
    cryptor = AES.new(get_key, mode, iv)
    #先得到会话密钥，再利用密钥和AES解密算法将明文解密出来
    plain_text = cryptor.decrypt(mes1)
    print("原消息值", plain_text.decode('utf-8'))

if __name__ == '__main__':
    #根据SM2国家标准进行参数选取
    p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
    b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
    n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
    Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
    Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
    G = [Gx, Gy]
    #详见SM2任务，在此不赘述，仅使用该函数生成公私钥
    [sk, pk] = key_gen(a, p, n, Gx, Gy)
    #生成公钥和私钥，由于用16进制表示，结果前两位为0x，因此需要舍去，从字符串第二位开始保留。
    sk1 = hex(sk)[2:]
    pk1 = hex(pk[0])[2:] + hex(pk[1])[2:]
    sm2_crypt = sm2.CryptSM2(public_key=pk1, private_key=sk1)
    message = "shandongdaxue"
    print("消息为：", message)
    #随机生成会话秘钥
    key = hex(random.randint(2 ** 127, 2 ** 128))[2:]
    print("随机生成的对称加密密钥：", key)
    result1, result2 = PGP_Encrypt(message, key)
    PGP_Decrypt(result1, result2)
