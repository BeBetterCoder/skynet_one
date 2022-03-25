import struct
from Crypto.Hash import MD5
from dh import create_dh_key, calculate_dh_secret
from .xor import XOR
import time


class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.client = client
        self.cipher = None
        self.server = server
        self.verbose = verbose
        self.session_id = None
        self.initiate_session()


    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the clientasdsad
        if self.server or self.client:
            # 利用D-H算法选择公私钥
            my_public_key, my_private_key = create_dh_key()
            # 公钥发送给对方
            self.send(bytes(str(my_public_key), "ascii"))
            # 接收私钥
            their_public_key = int(self.recv())
            # 这里是在计算共享密钥的哈希值
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            # 输出哈希值的hex格式，一共64个字符
            print("Shared hash: {}".format(shared_hash))
            # 使用默认的异或加密算法来new一个对象，其作用是加解密数据段
            self.cipher = XOR.new(bytes(shared_hash[:32],encoding="ascii"))

            # 这里的会话id是用16进制哈希值的后十位来代替，当作hmac的密钥，当然这里也可以抗重放
            self.session_id = bytes(shared_hash[-10:],"ascii")

    def send(self, data):
        #时间戳，抗重放攻击
        time_num = str(int(time.time()))
        #这里是用session_id作为hmac的密钥，哈希函数选取的是md5
        if self.cipher:
            msg = self.session_id + data
            mac_data  = MD5.new(msg).hexdigest()
            encrypted_data = self.cipher.encrypt(bytes(mac_data,"ascii")+msg)
            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data
        #pkt_len是2字节长度的无符号整数
        pkt_len = struct.pack('H', len(encrypted_data))

        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)
        self.conn.sendall(bytes(time_num,encoding="ascii"))
    def recv(self):
        # 先接收对方第一次发送的内容，为数据段的长度
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]
        # 接收第二次发送的内容，即mac和数据段
        encrypted_data = self.conn.recv(pkt_len)
        # 验证时间戳，设置的是三分钟以内有效
        if (int(time.time()) - int(self.conn.recv(10)) < 180):
            if self.cipher:
                data = self.cipher.decrypt(encrypted_data)
                mac_data = data[:32]
        # 前32位bytes是mac，后边为数据
                msg = data[32:]
        # 验证mac
                integrity = self.hmac_check(mac_data,msg)
                if integrity:
                    session_id = msg[:10]
                    data = msg[10:]
                    if session_id == self.session_id:
                        # if self.verbose:
                        if True:
                            print("Receiving packet of length {}".format(pkt_len))
                            print("Encrypted data: {}".format(repr(encrypted_data)))
                            print("Original data: {}".format(data))
                    else:
                        print('[Warning] Replay attack detected')
                        data = encrypted_data
                else:
                    print('[Warning] MAC check failed, received data has been modified.')
                    data = encrypted_data
            else:
                data = encrypted_data

        else:
            # 如果超时则数据无效,返回一个None
            print('[Warning] Time out!')
            data = None
        return data


    def hmac_check(self, h_msg,msg):
        # 核对mac
        print(MD5.new(msg).hexdigest())
        print(h_msg)
        if h_msg == bytes(MD5.new(msg).hexdigest(),"ascii"):
            print("Mac is right!")
            return True
        else:
            return False

    def close(self):
        self.conn.close()
