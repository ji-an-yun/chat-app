import sys
import socket
import threading
import json
import time
import hashlib
import struct
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome import Random
from Cryptodome.Util.Padding import pad, unpad

class CLIClient:
    def __init__(self):
        self.client = None
        self.connected = False
        self.aes_key = None
        self.username = ""
        self.server_host = ""
        self.server_port = 0
        
        # 初始化加密配置为默认值
        self.encryption_config = {
            "algorithm": "AES-256-CBC",
            "block_size": 16,
            "key_length": 32
        }
        
    def connect_to_server(self, host, port, username):
        try:
            # 根据主机名判断使用IPv4还是IPv6
            try:
                socket.inet_pton(socket.AF_INET6, host)
                family = socket.AF_INET6
            except socket.error:
                family = socket.AF_INET
                
            self.client = socket.socket(family, socket.SOCK_STREAM)
            self.client.connect((host, port))
            self.server_host = host
            self.server_port = port
            self.username = username
            self.connected = True
            
            # 接收服务器公钥
            server_public_key_data = self.client.recv(2048)
            server_public_key = RSA.import_key(server_public_key_data)
            
            # 发送准备好的信号
            self.client.send("READY_FOR_CONFIG".encode())
            
            # 生成临时RSA密钥对用于加密配置
            temp_rsa_key = RSA.generate(2048)
            temp_public_key = temp_rsa_key.publickey().export_key()
            
            # 发送临时公钥
            self.client.send(temp_public_key)
            
            # 接收加密的配置和AES密钥
            config_len_data = self.client.recv(4)
            config_len = struct.unpack('>I', config_len_data)[0]
            encrypted_config = self.client.recv(config_len)
            
            # 解密配置和AES密钥
            cipher_rsa = PKCS1_OAEP.new(temp_rsa_key)
            config_json = cipher_rsa.decrypt(encrypted_config)
            config_data = json.loads(config_json.decode())
            
            self.encryption_config = config_data["config"]
            self.aes_key = bytes.fromhex(config_data["aes_key"])
            
            # 确认密钥交换成功
            response = self.client.recv(1024).decode()
            if response == "KEY_EXCHANGE_SUCCESS":
                print("与服务器的密钥交换完成")
                threading.Thread(target=self.receive_messages, daemon=True).start()
                return True
            else:
                print(f"密钥交换失败: {response}")
                return False
                
        except Exception as e:
            print(f"连接服务器失败: {str(e)}")
            return False
            
    def receive_messages(self):
        buffer = b''
        while self.connected:
            try:
                data = self.client.recv(4096)
                if not data:
                    break
                buffer += data
                while len(buffer) >= 4:
                    msg_len = struct.unpack('>I', buffer[:4])[0]
                    if len(buffer) < 4 + msg_len:
                        break
                    encrypted_msg = buffer[4:4+msg_len]
                    buffer = buffer[4+msg_len:]
                    try:
                        decrypted_data = self.decrypt_message(encrypted_msg)
                        message = json.loads(decrypted_data)
                        sender = message['sender']
                        content = message['content']
                        timestamp = message['timestamp']
                        print(f"\n[{timestamp}] {sender}: {content}")
                        print("请输入消息: ", end="", flush=True)  # 重新显示输入提示
                    except Exception as e:
                        print(f"\n消息解密失败: {str(e)}")
                        print("请输入消息: ", end="", flush=True)
            except ConnectionResetError:
                print("\n服务器断开连接")
                self.connected = False
                break
            except Exception as e:
                if self.connected:
                    print(f"\n接收消息时出错: {str(e)}")
                    print("请输入消息: ", end="", flush=True)
                break
        self.connected = False
        
    def send_message(self, content):
        if not self.connected:
            return False
            
        try:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            message = {
                "sender": self.username,
                "content": content,
                "timestamp": timestamp,
                "hash": hashlib.md5(f"{self.username}{timestamp}{content}".encode()).hexdigest()
            }
            
            encrypted_msg = self.encrypt_message(json.dumps(message))
            msg_len = struct.pack('>I', len(encrypted_msg))
            self.client.sendall(msg_len + encrypted_msg)
            return True
        except Exception as e:
            print(f"发送消息失败: {str(e)}")
            return False
            
    def encrypt_message(self, message):
        # 使用预设的块大小进行填充
        block_size = self.encryption_config.get("block_size", AES.block_size)
        data = pad(message.encode('utf-8'), block_size)
        iv = Random.get_random_bytes(16)  # IV固定为16字节
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(data)
        return iv + encrypted

    def decrypt_message(self, data):
        try:
            # 使用预设的加密配置
            block_size = self.encryption_config.get("block_size", AES.block_size)
            
            # 验证数据长度足够提取IV和至少一个块的数据
            if len(data) < 16 + block_size:
                raise ValueError(f"数据长度不足 ({len(data)}字节)，需要至少{16 + block_size}字节")
            
            iv = data[:16]
            encrypted = data[16:]
            
            # 验证加密数据长度是否为块大小的整数倍
            if len(encrypted) % block_size != 0:
                raise ValueError(f"加密数据长度 ({len(encrypted)}字节) 不是块大小({block_size}字节)的整数倍")
            
            cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted)
            
            # 尝试去填充，处理padding错误
            try:
                unpadded = unpad(decrypted, block_size)
                return unpadded.decode('utf-8')
            except ValueError as e:
                # 如果padding错误，尝试检测数据是否已损坏
                if b'{' in decrypted and b'}' in decrypted:
                    # 尝试直接提取JSON结构（作为最后的尝试）
                    start_idx = decrypted.find(b'{')
                    end_idx = decrypted.rfind(b'}') + 1
                    if start_idx >= 0 and end_idx > start_idx:
                        try:
                            return decrypted[start_idx:end_idx].decode('utf-8', errors='replace')
                        except:
                            pass
                raise Exception(f"Padding错误: {str(e)}, 可能是数据损坏或密钥不匹配")
        except UnicodeDecodeError as e:
            raise Exception(f"UTF-8解码失败")
        except Exception as e:
            raise Exception(f"解密失败")

    def disconnect(self):
        self.connected = False
        if self.client:
            try:
                self.client.close()
            except:
                pass
        print("已断开连接")

def main():
    print("CLI聊天客户端")
    
    host = input("请输入服务器地址 (默认 localhost): ").strip()
    if not host:
        host = "localhost"
        
    port_input = input("请输入服务器端口 (默认 12345): ").strip()
    try:
        port = int(port_input) if port_input else 12345
    except ValueError:
        print("无效端口号，使用默认 12345")
        port = 12345
        
    username = input("请输入用户名: ").strip()
    if not username:
        print("用户名不能为空")
        return
        
    client = CLIClient()
    if not client.connect_to_server(host, port, username):
        return
        
    print("连接成功! 输入消息并按回车发送，输入 'quit' 退出")
    
    try:
        while client.connected:
            message = input("请输入消息: ").strip()
            if message.lower() == 'quit':
                client.disconnect()
                break
            elif message:
                if not client.send_message(message):
                    print("发送消息失败")
    except KeyboardInterrupt:
        client.disconnect()
    except Exception as e:
        print(f"发生错误: {str(e)}")
        client.disconnect()

if __name__ == "__main__":
    main()