from random import randint
from operator import xor


# IDEA算法的Python实现代码来自：Bo Zhu 2015
# https://github.com/bozhu/IDEA-Python
class IDEA_Crypto:
    modulo = 0xffff

    def __init__(self, key=None):
        if key is None:
            self.master_key = randint(1 << 127, (1 << 128) - 1)
        else:
            self.master_key = key
        self.subkeys = self.__generate_subkeys()
        self.decrypt_keys = self.__generate_decrypt_keys()

    def __generate_subkeys(self) -> list:
        """
        Compute all the 52 subkeys of the system
        """
        key = self.master_key
        L = []
        filt = 0xffff0000000000000000000000000000
        offset = 112

        for i in range(52):
            L.append((key & filt) >> offset)
            filt = filt // 0x10000
            offset = offset - 16
            if offset < 0:
                # 25 bits left rotation
                msb = (key & 0xffffff80000000000000000000000000) >> 103  # msb = the 25 most significant bit
                key = ((key << 25) | msb) & 0xffffffffffffffffffffffffffffffff
                filt = 0xffff0000000000000000000000000000
                offset = 112
        return L

    def __generate_decrypt_keys(self) -> list:
        K = [self.multinv(self.subkeys[48]), (-(self.subkeys[49])) % (1 << 16), (-(self.subkeys[50])) % (1 << 16),
             self.multinv(self.subkeys[51])]

        i = 7
        while i >= 1:
            K.append(self.subkeys[i * 6 + 4])
            K.append(self.subkeys[i * 6 + 5])

            K.append(self.multinv(self.subkeys[i * 6]))
            K.append((-(self.subkeys[i * 6 + 2])) % (1 << 16))
            K.append((-(self.subkeys[i * 6 + 1])) % (1 << 16))
            K.append(self.multinv(self.subkeys[i * 6 + 3]))

            i = i - 1

        K.append(self.subkeys[i * 6 + 4])
        K.append(self.subkeys[i * 6 + 5])

        K.append(self.multinv(self.subkeys[i * 6]))
        K.append((-(self.subkeys[i * 6 + 1])) % (1 << 16))
        K.append((-(self.subkeys[i * 6 + 2])) % (1 << 16))
        K.append(self.multinv(self.subkeys[i * 6 + 3]))

        return K

    def encrypt_block(self, message: int) -> int:
        """
        encrypt one bloc of 64 bits
        """

        if message >= 1 << 64:
            print("WARNING : the message is too large for a bloc, it has been truncated ")
            message = message & 0xffffffffffffffff

        X = self.__split_block(message)

        for i in range(8):
            X = self.__round(X, i, self.subkeys)

        X1, X3, X2, X4 = X

        X1 = self.mul(X1, self.subkeys[48])  # & self.modulo
        X2 = X2 + self.subkeys[49] & self.modulo
        X3 = X3 + self.subkeys[50] & self.modulo
        X4 = self.mul(X4, self.subkeys[51])  # & self.modulo

        res = self.join_subblocks((X1, X2, X3, X4))

        return res

    def decrypt_block(self, cipher: int) -> int:
        """
        decrypt one bloc of 64 bits
        """
        if cipher >= 1 << 64:
            print("ERROR : not valid cipher ")
            return -1

        X = self.__split_block(cipher)

        for i in range(8):
            X = self.__round(X, i, self.decrypt_keys)

        X1, X3, X2, X4 = X

        X1 = self.mul(X1, self.decrypt_keys[48])  # & self.modulo
        X2 = X2 + self.decrypt_keys[49] & self.modulo
        X3 = X3 + self.decrypt_keys[50] & self.modulo
        X4 = self.mul(X4, self.decrypt_keys[51])  # & self.modulo

        res = self.join_subblocks((X1, X2, X3, X4))

        return res

    def __round(self, X: tuple, n: int, key: list) -> tuple:
        """
        A round of IDEA
        Entry : * n : the round number (0 to 7)
            * X : the 4 quarter of the message
        Return : the 4 quarter of the message after the round
        """

        X1, X2, X3, X4 = X

        X1 = self.mul(X1, key[n * 6])  # & self.modulo #1
        X2 = X2 + key[n * 6 + 1] & self.modulo  # 2
        X3 = X3 + key[n * 6 + 2] & self.modulo  # 3
        X4 = self.mul(X4, key[n * 6 + 3])  # & self.modulo #4

        A = xor(X1, X3)  # 5
        B = xor(X2, X4)  # 6

        A = self.mul(A, key[n * 6 + 4])  # & self.modulo #7
        B = A + B & self.modulo  # 8

        B = self.mul(B, key[n * 6 + 5])  # & self.modulo #9
        A = A + B & self.modulo  # 10

        X1 = xor(X1, B)  # 11
        X3 = xor(X3, B)  # 12
        X2 = xor(X2, A)  # 13
        X4 = xor(X4, A)  # 14

        return (X1, X3, X2, X4)  # 15 swap

    @staticmethod
    def __split_block(message: int) -> tuple:
        X4 = message & 0xffff
        X3 = (message & 0xffff0000) >> 16
        X2 = (message & 0xffff00000000) >> 32
        X1 = (message & 0xffff000000000000) >> 48
        return (X1, X2, X3, X4)

    @staticmethod
    def join_subblocks(X: tuple) -> int:
        """
        gathers all the 4 subblocks of 16 bits to one of 64bits
        """
        X1, X2, X3, X4 = X
        res = X4 | (X3 << 16) | (X2 << 32) | (X1 << 48)

        return res

    def print_keys(self):
        print("master key : ", hex(self.master_key))

        print("ENCRYPT KEYS")
        for i in range(len(self.subkeys)):
            print("key ", i, " : ", hex(self.subkeys[i]))

        print("DECRYPT KEYS")
        for i in range(len(self.decrypt_keys)):
            print("dec key ", i, " : ", hex(self.decrypt_keys[i]))

    def mul(self, a: int, b: int) -> int:
        a = a & self.modulo
        b = b & self.modulo
        p = a * b
        if p != 0:
            b = p & self.modulo
            a = p >> 16
            res = b - a
            if b < a:
                res = res + 1
            return res & self.modulo
        elif a != 0:
            return 1 - b & self.modulo
        else:
            return 1 - a & self.modulo

    def multinv(self, x: int) -> int:

        if x <= 1:
            return x

        t1 = 0x10001 // x
        y = 0x10001 % x

        if y == 1:
            return (1 - t1) & self.modulo

        t0 = 1

        while y != 1:
            q = x // y
            x = x % y
            t0 = t0 + (q * t1)
            if x == 1:
                return t0
            q = y // x
            y = y % x
            t1 = t1 + q * t0

        return (1 - t1) & self.modulo


def getSuffix(ipv6_addr: str):
    """
    获取IPv6地址的后64位
    :param ipv6_addr:IPV6地址
    :return:IPv6地址后缀,冒号间不足4位补前导0,例如:0200:0000:feb0:0000
    """
    ipv6_addr_list = ipv6_addr.split(":")
    ipv6_addr_suffix = ""
    for i in range(4, 8):
        ipv6_addr_suffix = ipv6_addr_suffix + ipv6_addr_list[i].zfill(4)
    return ipv6_addr_suffix[1:]


def getIdeaDecrypt(cipher_str, key):
    """
    根据密钥和密文解密出明文
    :param cipher_str: 密文字符串
    :param key: 密钥
    :return: 明文字符串
    """
    cipher_int = int(cipher_str, 16)
    idea_object = IDEA_Crypto(int(key, 16))
    plain_int = idea_object.decrypt_block(cipher_int)
    return hex(plain_int)[2:]


def getIdeaEncrypt(plain_str):
    """
    随机生成密钥并加密出密文
    :param plain_str: 明文字符串
    :return: 随机的128位密钥,密文字符串
    """
    plain_int = int(plain_str, 16)
    idea_object = IDEA_Crypto()
    cipher_int = idea_object.encrypt_block(plain_int)
    return idea_object.master_key, hex(cipher_int)[2:]


if __name__ == '__main__':
    ip_addr = "2001:da8:24d:0:321f:7cd:e:ef56"
    idea_key = IDEA_Crypto().master_key
    suffix = getSuffix(ipv6_addr=ip_addr)

    result = getIdeaDecrypt(suffix, idea_key)
    print(suffix)
    print(hex(idea_key))
    print(result)
    print(hex(IDEA_Crypto(idea_key).encrypt_block(int(result, 16))))
