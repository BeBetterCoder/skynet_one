
from Crypto.Hash import SHA256
from Crypto.Random import random
from lib.helpers import read_hex

# Project TODO: Is this the best choice of prime? Why? Why not? Feel free to replacasddsae!

# 选取RFC3526中D-H密钥交换的3072位长度的模数，这个模数用于传输128位的密钥比较合适
# obtained from RFC 3526
raw_prime = """FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
      E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
      DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
      15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
      ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
      ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
      F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
      BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
      43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF"""
prime = read_hex(raw_prime)

# Project TODO: write the appropriate code to perform DH key exchange

# 本函数用于生成D-H的公私密钥,返回值就是用于加密的公私钥
def create_dh_key():

    # a就是私钥，D-H体制要求a介于1~P-2之间
    a = random.randint(2, prime - 2)
    # generator value g 是参考的 RFC3526,选取2
    g = 2
    Public_key = pow(g,a,prime)
    return (Public_key, a)


# 本函数用于计算通信双方用于块加密算法的共享密钥，并且使用md5哈希计算共享密钥的哈希值
def calculate_dh_secret(their_public, my_private):

    shared_secret = pow(their_public, my_private, prime)
    shared_hash = SHA256.new(bytes(str(shared_secret), "ascii")).hexdigest()
    return shared_hash
