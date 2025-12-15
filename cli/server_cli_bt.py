import sys
import socket
import threading
import json
import hashlib
import os
import struct
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome import Random
from Cryptodome.Util.Padding import pad, unpad

class CLIServer:
    def __init__(self):
        self.clients = {}
        self.running = False
        self.server = None
        
        # 生成RSA密钥用于传输加密配置
        self.rsa_key = RSA.generate(2048)
        self.public_key = self.rsa_key.publickey().export_key()
        self.private_key = self.rsa_key.export_key()
        
        # 预设加密方式和密钥
        self.encryption_config = {
            "algorithm": "AES-256-CBC",
            "block_size": 16,
            "key_length": 32
        }
        # 生成预设的AES密钥
        from Cryptodome.Random import get_random_bytes
        self.preset_aes_key = get_random_bytes(32)
        
    def start_server(self, ip_version, port):
        try:
            if ip_version == "IPv6":
                family = socket.AF_INET6
                address = '::'
            else:
                family = socket.AF_INET
                address = '0.0.0.0'
                
            self.server = socket.socket(family, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Linux特有设置，允许端口复用
            self.server.bind((address, port))
            self.server.listen(5)
            self.running = True
            
            print(f"CLI服务端已启动 ({ip_version}, 端口: {port})")
            print("输入 'quit' 或按 Ctrl+C 停止服务端")
            
            threading.Thread(target=self.accept_clients, daemon=True).start()
            
            # 主线程等待退出命令
            while self.running:
                try:
                    cmd = input()
                    if cmd.strip().lower() == 'quit':
                        self.stop_server()
                        break
                except KeyboardInterrupt:
                    self.stop_server()
                    break
                    
        except Exception as e:
            print(f"启动服务端失败: {str(e)}")
            
    def stop_server(self):
        self.running = False
        if self.server:
            self.server.close()
        for client in self.clients.values():
            try:
                client.close()
            except:
                pass
        self.clients.clear()
        print("服务端已停止")
            
    def accept_clients(self):
        while self.running:
            try:
                client_socket, addr = self.server.accept()
                client_id = f"{addr[0]}:{addr[1]}"
                print(f"新的客户端连接: {client_id}")
                client_thread = threading.Thread(
                    target=self.handle_client, 
                    args=(client_socket, addr),
                    daemon=True
                )
                client_thread.start()
            except socket.error as e:
                if self.running:
                    print(f"接受客户端连接时出现套接字错误: {str(e)}")
                    continue
            except Exception as e:
                if self.running:
                    print(f"接受客户端连接时出错: {str(e)}")
                    continue
                    
    def handle_client(self, client_socket, addr):
        client_id = f"{addr[0]}:{addr[1]}"
        self.clients[client_id] = client_socket
        try:
            # 发送服务器公钥
            bytes_sent = client_socket.send(self.public_key)
            print(f"已发送公钥给 {client_id}: {bytes_sent}字节")
            
            # 接收客户端准备好的信号
            ready_signal = client_socket.recv(1024).decode()
            if ready_signal != "READY_FOR_CONFIG":
                print(f"客户端 {client_id} 未准备好接收配置: {ready_signal}")
                return
                
            # 加密并发送预设的加密配置和AES密钥
            try:
                # 打包加密配置和密钥
                config_data = {
                    "config": self.encryption_config,
                    "aes_key": self.preset_aes_key.hex()
                }
                config_json = json.dumps(config_data).encode()
                
                # 接收客户端的临时公钥用于加密配置
                client_public_key_data = client_socket.recv(2048)
                if not client_public_key_data:
                    print(f"从 {client_id} 接收临时公钥失败")
                    return
                client_public_key = RSA.import_key(client_public_key_data)
                
                # 使用客户端临时公钥加密配置数据
                cipher_rsa = PKCS1_OAEP.new(client_public_key)
                encrypted_config = cipher_rsa.encrypt(config_json)
                
                # 发送加密配置的长度和配置数据
                config_len = struct.pack('>I', len(encrypted_config))
                client_socket.sendall(config_len + encrypted_config)
                
                # 使用预设的AES密钥进行后续通信
                aes_key = self.preset_aes_key
                
            except Exception as e:
                print(f"发送加密配置失败 for {client_id}: {str(e)}")
                return
            
            # 确认密钥交换成功
            client_socket.send("KEY_EXCHANGE_SUCCESS".encode())
            print(f"与 {client_id} 的密钥交换完成")
            
            buffer = b''
            while self.running:
                try:
                    data = client_socket.recv(4096)
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
                            decrypted_data = self.decrypt_message(encrypted_msg, aes_key)
                            message = json.loads(decrypted_data)
                        except Exception as e:
                            print(f"处理客户端 {client_id} 消息解密失败: {str(e)}")
                            continue
                            
                        if self.verify_message(message):
                            sender = message['sender']
                            content = message['content']
                            timestamp = message['timestamp']
                            print(f"[{timestamp}] 来自 {sender} 的加密消息: {content}")
                            self.broadcast(encrypted_msg, exclude=client_socket)
                        else:
                            print(f"来自 {client_id} 的消息完整性验证失败")
                except ConnectionResetError:
                    print(f"客户端 {client_id} 强制断开连接")
                    break
                except socket.error as e:
                    print(f"处理客户端 {client_id} 套接字时出错: {str(e)}")
                    break
                except Exception as e:
                    print(f"处理客户端 {client_id} 消息时出错: {str(e)}")
                    break
        except ConnectionResetError:
            print(f"客户端 {client_id} 在连接初始化时强制断开")
        except socket.error as e:
            print(f"处理客户端 {client_id} 套接字连接时出错: {str(e)}")
        except Exception as e:
            print(f"处理客户端 {client_id} 时出错: {str(e)}")
        finally:
            print(f"客户端 {client_id} 断开连接")
            try:
                client_socket.close()
            except:
                pass
            if client_id in self.clients:
                del self.clients[client_id]

    def decrypt_message(self, data, aes_key):
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
            
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
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

    def verify_message(self, message):
        content = message['content']
        timestamp = message['timestamp']
        sender = message['sender']
        received_hash = message['hash']
        message_str = f"{sender}{timestamp}{content}"
        calculated_hash = hashlib.md5(message_str.encode()).hexdigest()
        return received_hash == calculated_hash
    
    def broadcast(self, encrypted_msg, exclude=None):
        msg_len = struct.pack('>I', len(encrypted_msg))
        data = msg_len + encrypted_msg
        for client_id, client_socket in list(self.clients.items()):
            if client_socket != exclude:
                try:
                    client_socket.sendall(data)
                except Exception as e:
                    print(f"广播消息到 {client_id} 失败: {str(e)}")
                    try:
                        client_socket.close()
                    except:
                        pass
                    del self.clients[client_id]

def main():
    # print("选择IP版本:")
    # print("1. IPv4")
    # print("2. IPv6")
    
    # ip_choice = input("请输入选项 (1 或 2): ").strip()
    ip_choice = "1"
    if ip_choice == "1":
        ip_version = "IPv4"
    elif ip_choice == "2":
        ip_version = "IPv6"
    else:
        print("无效选项，使用默认 IPv4")
        ip_version = "IPv4"
    
    # port_input = input("请输入端口号 (默认 12345): ").strip()
    port_input = "12345"
    try:
        port = int(port_input) if port_input else 12345
    except ValueError:
        print("无效端口号，使用默认 12345")
        port = 12345
    
    server = CLIServer()
    server.start_server(ip_version, port)

if __name__ == "__main__":
    main()