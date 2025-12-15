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
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTextEdit, QVBoxLayout, 
                            QWidget, QLabel, QPushButton, QLineEdit, QComboBox,
                            QHBoxLayout, QMessageBox)
from PyQt5.QtCore import Qt, QCoreApplication
from PyQt5.QtGui import QPalette, QColor, QFont

class ChatServer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.clients = {}
        self.setup_ui()
        self.setup_server()
        
    def setup_ui(self):
        self.setWindowTitle("安全聊天服务端 (IPv6支持) - Linux版本")
        self.setGeometry(300, 300, 800, 600)
        self.set_dark_theme()
        central_widget = QWidget()
        layout = QVBoxLayout()
        config_layout = QVBoxLayout()
        config_layout.setSpacing(10)
        config_label = QLabel("服务器配置")
        config_label.setFont(QFont("Arial", 12, QFont.Bold))
        config_label.setStyleSheet("color: #4EC9B0;")
        ip_version_layout = QHBoxLayout()
        ip_version_label = QLabel("IP版本:")
        ip_version_label.setStyleSheet("color: #D4D4D4;")
        self.ip_version_combo = QComboBox()
        self.ip_version_combo.addItems(["IPv4", "IPv6"])
        self.ip_version_combo.setCurrentIndex(0)
        self.ip_version_combo.setStyleSheet("""
            QComboBox {
                background-color: #2d2d30;
                color: #d4d4d4;
                border: 1px solid #3c3c40;
                padding: 5px;
            }
        """)
        ip_version_layout.addWidget(ip_version_label)
        ip_version_layout.addWidget(self.ip_version_combo)
        port_layout = QHBoxLayout()
        port_label = QLabel("端口号:")
        port_label.setStyleSheet("color: #D4D4D4;")
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("输入端口号 (默认: 12345)")
        self.port_input.setText("12345")
        self.port_input.setStyleSheet("""
            QLineEdit {
                background-color: #2d2d30;
                color: #d4d4d4;
                border: 1px solid #3c3c40;
                padding: 5px;
            }
        """)
        port_layout.addWidget(port_label)
        port_layout.addWidget(self.port_input)
        self.start_button = QPushButton("启动服务")
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: #0078d7;
                color: white;
                border: none;
                padding: 10px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #106ebe;
            }
            QPushButton:disabled {
                background-color: #505050;
                color: #a0a0a0;
            }
        """)
        self.start_button.clicked.connect(self.toggle_server)
        config_layout.addWidget(config_label)
        config_layout.addLayout(ip_version_layout)
        config_layout.addLayout(port_layout)
        config_layout.addWidget(self.start_button)
        log_layout = QVBoxLayout()
        log_label = QLabel("服务器日志")
        log_label.setFont(QFont("Arial", 12, QFont.Bold))
        log_label.setStyleSheet("color: #4EC9B0;")
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setStyleSheet("""
            background-color: #1e1e1e;
            color: #d4d4d4;
            font-family: Consolas, 'Courier New', monospace;
            font-size: 12px;
            border: 1px solid #3c3c40;
        """)
        log_layout.addWidget(log_label)
        log_layout.addWidget(self.log_area)
        self.status_label = QLabel("服务端状态: 未启动")
        self.status_label.setStyleSheet("color: #F44747; font-weight: bold; font-size: 12px;")
        layout.addLayout(config_layout)
        layout.addLayout(log_layout)
        layout.addWidget(self.status_label)
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)
        
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
        
    def set_dark_theme(self):
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(30, 30, 30))
        palette.setColor(QPalette.WindowText, QColor(212, 212, 212))
        palette.setColor(QPalette.Base, QColor(30, 30, 30))
        palette.setColor(QPalette.AlternateBase, QColor(45, 45, 45))
        palette.setColor(QPalette.ToolTipBase, QColor(53, 53, 53))
        palette.setColor(QPalette.ToolTipText, QColor(212, 212, 212))
        palette.setColor(QPalette.Text, QColor(212, 212, 212))
        palette.setColor(QPalette.Button, QColor(53, 53, 53))
        palette.setColor(QPalette.ButtonText, QColor(212, 212, 212))
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Highlight, QColor(142, 45, 197).lighter())
        palette.setColor(QPalette.HighlightedText, Qt.black)
        self.setPalette(palette)
        
    def setup_server(self):
        self.server = None
        self.running = False
        
    def toggle_server(self):
        if self.running:
            self.stop_server()
        else:
            self.start_server()
            
    def start_server(self):
        try:
            port = int(self.port_input.text() or "12345")
            ip_version = self.ip_version_combo.currentText()
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
            self.start_button.setText("停止服务")
            self.status_label.setText(f"服务端状态: 运行中 ({ip_version}, 端口: {port})")
            self.status_label.setStyleSheet("color: #4EC9B0; font-weight: bold; font-size: 12px;")
            self.log(f"服务端已启动 ({ip_version}, 端口: {port})")
            threading.Thread(target=self.accept_clients, daemon=True).start()
        except Exception as e:
            self.log(f"启动服务端失败: {str(e)}", error=True)
            
    def stop_server(self):
        self.running = False
        if self.server:
            self.server.close()
        for client in self.clients.values():
            client.close()
        self.clients.clear()
        self.start_button.setText("启动服务")
        self.status_label.setText("服务端状态: 已停止")
        self.status_label.setStyleSheet("color: #F44747; font-weight: bold; font-size: 12px;")
        self.log("服务端已停止")
            
    def accept_clients(self):
        while self.running:
            try:
                client_socket, addr = self.server.accept()
                client_id = f"{addr[0]}:{addr[1]}"
                self.log(f"新的客户端连接: {client_id}")
                client_thread = threading.Thread(
                    target=self.handle_client, 
                    args=(client_socket, addr),
                    daemon=True
                )
                client_thread.start()
            except socket.error as e:
                if self.running:
                    self.log(f"接受客户端连接时出现套接字错误: {str(e)}", error=True)
                    continue
            except Exception as e:
                if self.running:
                    self.log(f"接受客户端连接时出错: {str(e)}", error=True)
                    continue
                    
    def handle_client(self, client_socket, addr):
        client_id = f"{addr[0]}:{addr[1]}"
        self.clients[client_id] = client_socket
        try:
            # 发送服务器公钥
            bytes_sent = client_socket.send(self.public_key)
            self.log(f"已发送公钥给 {client_id}: {bytes_sent}字节")
            
            # 接收客户端准备好的信号
            ready_signal = client_socket.recv(1024).decode()
            if ready_signal != "READY_FOR_CONFIG":
                self.log(f"客户端 {client_id} 未准备好接收配置: {ready_signal}", error=True)
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
                    self.log(f"从 {client_id} 接收临时公钥失败", error=True)
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
                self.log(f"发送加密配置失败 for {client_id}: {str(e)}", error=True)
                return
            
            # 确认密钥交换成功
            client_socket.send("KEY_EXCHANGE_SUCCESS".encode())
            self.log(f"与 {client_id} 的密钥交换完成")
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
                            self.log(f"处理客户端 {client_id} 消息解密失败: {str(e)}", error=True)
                            continue
                        if self.verify_message(message):
                            sender = message['sender']
                            content = message['content']
                            timestamp = message['timestamp']
                            self.log(f"[{timestamp}] 来自 {sender} 的加密消息")
                            self.broadcast(encrypted_msg, exclude=client_socket)
                        else:
                            self.log(f"来自 {client_id} 的消息完整性验证失败", error=True)
                except ConnectionResetError:
                    self.log(f"客户端 {client_id} 强制断开连接", error=True)
                    break
                except socket.error as e:
                    self.log(f"处理客户端 {client_id} 套接字时出错: {str(e)}", error=True)
                    break
                except Exception as e:
                    self.log(f"处理客户端 {client_id} 消息时出错: {str(e)}", error=True)
                    break
        except ConnectionResetError:
            self.log(f"客户端 {client_id} 在连接初始化时强制断开", error=True)
        except socket.error as e:
            self.log(f"处理客户端 {client_id} 套接字连接时出错: {str(e)}", error=True)
        except Exception as e:
            self.log(f"处理客户端 {client_id} 时出错: {str(e)}", error=True)
        finally:
            self.log(f"客户端 {client_id} 断开连接")
            try:
                client_socket.close()
            except:
                pass
            if client_id in self.clients:
                del self.clients[client_id]                                 

    def encrypt_message(self, message, key):
        # 使用预设的块大小进行填充
        block_size = self.encryption_config.get("block_size", AES.block_size)
        data = pad(message.encode('utf-8'), block_size)
        iv = Random.get_random_bytes(16)  # IV固定为16字节
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(data)
        return iv + encrypted

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
                    self.log(f"广播消息到 {client_id} 失败: {str(e)}", error=True)
                    client_socket.close()
                    del self.clients[client_id]
    
    def log(self, message, error=False):
        color = "#F44747" if error else "#4EC9B0"
        html_message = f"<span style='color:{color}'>{message}</span>"
        self.log_area.append(html_message)
        QCoreApplication.processEvents()
        
    def closeEvent(self, event):
        self.stop_server()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    # 确保Linux下中文显示正常
    font = QFont("SimHei")
    app.setFont(font)
    server = ChatServer()
    server.show()
    sys.exit(app.exec_())