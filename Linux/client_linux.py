import sys
import socket
import threading
import json
import time
import hashlib
import os
import struct
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome import Random
from Cryptodome.Util.Padding import pad, unpad
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTextEdit, QLineEdit, 
                            QPushButton, QVBoxLayout, QHBoxLayout, QWidget,
                            QLabel, QComboBox, QMessageBox)
from PyQt5.QtCore import Qt, QCoreApplication, pyqtSignal
from PyQt5.QtGui import QPalette, QColor, QFont

class ChatClient(QMainWindow):
    message_received = pyqtSignal(str, str, str, bool)
    connection_status_changed = pyqtSignal(str, str)
    ui_state_changed = pyqtSignal(bool, bool)
    connect_button_text_changed = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.aes_key = None
        # 初始化加密配置为默认值
        self.encryption_config = {
            "algorithm": "AES-256-CBC",
            "block_size": 16,
            "key_length": 32
        }
        self.setup_ui()
        self.setup_client()
        self.message_received.connect(self._display_message)
        self.connection_status_changed.connect(self._update_connection_status)
        self.ui_state_changed.connect(self._update_ui_state)
        self.connect_button_text_changed.connect(self._update_connect_button_text)
        
    def setup_ui(self):
        self.setWindowTitle("安全聊天客户端 (IPv6支持) - Linux版本")
        self.setGeometry(300, 300, 800, 600)
        self.set_dark_theme()
        central_widget = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(10)
        connection_layout = QVBoxLayout()
        connection_label = QLabel("连接设置")
        connection_label.setFont(QFont("Arial", 12, QFont.Bold))
        connection_label.setStyleSheet("color: #4EC9B0;")
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
        server_layout = QHBoxLayout()
        server_label = QLabel("服务器地址:")
        server_label.setStyleSheet("color: #D4D4D4;")
        self.server_input = QLineEdit()
        self.server_input.setPlaceholderText("输入服务器地址")
        self.server_input.setText("127.0.0.1")
        self.server_input.setStyleSheet("""
            QLineEdit {
                background-color: #2d2d30;
                color: #d4d4d4;
                border: 1px solid #3c3c40;
                padding: 5px;
            }
        """)
        server_layout.addWidget(server_label)
        server_layout.addWidget(self.server_input)
        port_layout = QHBoxLayout()
        port_label = QLabel("端口号:")
        port_label.setStyleSheet("color: #D4D4D4;")
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("输入端口号")
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
        username_layout = QHBoxLayout()
        username_label = QLabel("用户名:")
        username_label.setStyleSheet("color: #D4D4D4;")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("输入用户名")
        self.username_input.setText("用户" + str(os.getpid())[-3:])
        self.username_input.setStyleSheet("""
            QLineEdit {
                background-color: #2d2d30;
                color: #d4d4d4;
                border: 1px solid #3c3c40;
                padding: 5px;
            }
        """)
        username_layout.addWidget(username_label)
        username_layout.addWidget(self.username_input)
        self.connect_button = QPushButton("连接")
        self.connect_button.setStyleSheet("""
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
        self.connect_button.clicked.connect(self.toggle_connection)
        connection_layout.addWidget(connection_label)
        connection_layout.addLayout(ip_version_layout)
        connection_layout.addLayout(server_layout)
        connection_layout.addLayout(port_layout)
        connection_layout.addLayout(username_layout)
        connection_layout.addWidget(self.connect_button)
        self.encryption_status = QLabel("加密状态: 未连接")
        self.encryption_status.setStyleSheet("color: #F44747; font-weight: bold; font-size: 12px;")
        chat_layout = QVBoxLayout()
        chat_label = QLabel("聊天区域")
        chat_label.setFont(QFont("Arial", 12, QFont.Bold))
        chat_label.setStyleSheet("color: #4EC9B0;")
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        self.chat_area.setStyleSheet("""
            background-color: #1e1e1e;
            color: #d4d4d4;
            font-family: Consolas, 'Courier New', monospace;
            font-size: 12px;
            border: 1px solid #3c3c40;
        """)
        chat_layout.addWidget(chat_label)
        chat_layout.addWidget(self.chat_area)
        message_layout = QHBoxLayout()
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("输入消息...")
        self.message_input.setStyleSheet("""
            QLineEdit {
                background-color: #2d2d30;
                color: #d4d4d4;
                border: 1px solid #3c3c40;
                padding: 8px;
            }
        """)
        self.message_input.setEnabled(False)
        self.message_input.returnPressed.connect(self.send_message)
        self.send_button = QPushButton("发送")
        self.send_button.setStyleSheet("""
            QPushButton {
                background-color: #388a34;
                color: white;
                border: none;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #2a6827;
            }
            QPushButton:disabled {
                background-color: #505050;
                color: #a0a0a0;
            }
        """)
        self.send_button.setEnabled(False)
        self.send_button.clicked.connect(self.send_message)
        message_layout.addWidget(self.message_input)
        message_layout.addWidget(self.send_button)
        layout.addLayout(connection_layout)
        layout.addWidget(self.encryption_status)
        layout.addLayout(chat_layout)
        layout.addLayout(message_layout)
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)
        self.rsa_key = RSA.generate(2048)
        self.public_key = self.rsa_key.publickey().export_key()
        self.private_key = self.rsa_key.export_key()
        
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
        
    def setup_client(self):
        self.client_socket = None
        self.connected = False
        
    def toggle_connection(self):
        if self.connected:
            self.disconnect()
        else:
            self.connect()
            
    def connect(self):
        server = self.server_input.text().strip()
        port_str = self.port_input.text().strip()
        username = self.username_input.text().strip()
        ip_version = self.ip_version_combo.currentText()
        if not server or not port_str or not username:
            self.display_message("错误", "请填写所有字段", error=True)
            return
        try:
            port = int(port_str)
        except ValueError:
            self.display_message("错误", "端口号必须是数字", error=True)
            return
        if ip_version == "IPv6":
            family = socket.AF_INET6
            if server.startswith('[') and server.endswith(']'):
                server = server[1:-1]
        else:
            family = socket.AF_INET
        threading.Thread(target=self._connect_thread, args=(family, server, port, username), daemon=True).start()

    def _connect_thread(self, family, server, port, username):
        try:
            self.client_socket = socket.socket(family, socket.SOCK_STREAM)
            self.client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Linux特有设置，允许端口复用
            self.client_socket.settimeout(5.0)
            self.client_socket.connect((server, port))
            self.client_socket.settimeout(None)
            self._update_ui_connecting()
            # 接收服务器公钥
            server_public_key = self.client_socket.recv(2048)
            if not server_public_key:
                raise Exception("未收到服务器公钥")
            
            # 生成临时RSA密钥对用于接收加密配置
            temp_rsa_key = RSA.generate(2048)
            temp_public_key = temp_rsa_key.publickey().export_key()
            temp_private_key = temp_rsa_key.export_key()
            
            # 发送准备好接收配置的信号
            self.client_socket.send("READY_FOR_CONFIG".encode())
            
            # 发送临时公钥给服务器
            self.client_socket.send(temp_public_key)
            
            # 接收加密配置的长度
            config_len_data = self.client_socket.recv(4)
            if not config_len_data:
                raise Exception("未收到配置长度")
            config_len = struct.unpack('>I', config_len_data)[0]
            
            # 接收加密配置
            encrypted_config = b''
            remaining = config_len
            while remaining > 0:
                chunk = self.client_socket.recv(min(4096, remaining))
                if not chunk:
                    raise Exception("配置接收中断")
                encrypted_config += chunk
                remaining -= len(chunk)
            
            # 解密配置
            try:
                private_key = RSA.import_key(temp_private_key)
                cipher_rsa = PKCS1_OAEP.new(private_key)
                config_json = cipher_rsa.decrypt(encrypted_config)
                config_data = json.loads(config_json)
                self.encryption_config = config_data["config"]
                self.aes_key = bytes.fromhex(config_data["aes_key"])
            except Exception as e:
                self.display_message("错误", f"配置解密失败: {str(e)}", error=True)
                raise
            
            # 等待服务器响应
            response = self.client_socket.recv(1024).decode()
            
            if response == "KEY_EXCHANGE_SUCCESS":
                self.connected = True
                self._update_ui_connected()
            else:
                self._update_ui_connection_failed(f"密钥交换失败: 服务器返回 '{response}'")
                self._disconnect()
        except socket.timeout:
            self._update_ui_connection_failed("连接超时，请检查服务器地址和端口")
            self._disconnect()
        except socket.gaierror:
            self._update_ui_connection_failed("地址解析失败，请检查服务器地址")
            self._disconnect()
        except ConnectionRefusedError:
            self._update_ui_connection_failed("连接被拒绝，服务器可能未启动或端口错误")
            self._disconnect()
        except Exception as e:
            self._update_ui_connection_failed(f"连接失败: {str(e)}")
            self._disconnect()

    def _update_ui_connecting(self):
        self.connect_button_text_changed.emit("断开")
        self.connection_status_changed.emit("加密状态: 连接中...", "color: #FFC107; font-weight: bold; font-size: 12px;")
        self.ui_state_changed.emit(True, True)
        self.display_message("系统", "正在连接到服务器...")

    def _update_ui_connected(self):
        self.connection_status_changed.emit("加密状态: 安全连接 (AES-256 + RSA + MD5)", "color: #4EC9B0; font-weight: bold; font-size: 12px;")
        self.display_message("系统", "安全连接已建立，可以开始聊天")
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def _update_ui_connection_failed(self, error_message):
        self.connect_button_text_changed.emit("连接")
        self.connection_status_changed.emit("加密状态: 未连接", "color: #F44747; font-weight: bold; font-size: 12px;")
        self.ui_state_changed.emit(False, False)
        self.display_message("错误", error_message, error=True)

    def _update_connect_button_text(self, text):
        self.connect_button.setText(text)
        
    def _disconnect(self):
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
        self.connected = False

    def disconnect(self):
        self._disconnect()
        self.connect_button.setText("连接")
        self.connect_button.setStyleSheet("""
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
        self.encryption_status.setText("加密状态: 未连接")
        self.encryption_status.setStyleSheet("color: #F44747; font-weight: bold; font-size: 12px;")
        self.message_input.setEnabled(False)
        self.send_button.setEnabled(False)
        self.display_message("系统", "已断开连接")

    def receive_messages(self):
        buffer = b''
        while self.connected:
            try:
                data = self.client_socket.recv(4096)
                if not data:
                    break
                buffer += data
                while len(buffer) >= 4:
                    msg_len = struct.unpack('>I', buffer[:4])[0]
                    if len(buffer) < 4 + msg_len:
                        break
                    encrypted_msg = buffer[4:4+msg_len]
                    buffer = buffer[4+msg_len:]
                    # Ensure we only process if the message is at least 16 bytes (IV) + 1
                    if len(encrypted_msg) < 17:
                        self.display_message("系统", "收到的加密消息长度异常", error=True)
                        continue
                    try:
                        decrypted_data = self.decrypt_message(encrypted_msg, self.aes_key)
                        message = json.loads(decrypted_data)
                    except Exception as e:
                        self.display_message("系统", f"消息解密失败: {str(e)}", error=True)
                        continue
                    if self.verify_message(message):
                        sender = message['sender']
                        content = message['content']
                        timestamp = message['timestamp']
                        self.display_message(sender, content, timestamp)
                    else:
                        self.display_message("系统", "收到无法验证的消息 (可能被篡改)", error=True)
            except (ConnectionResetError, OSError) as e:
                if self.connected:
                    self.display_message("错误", f"连接中断: {str(e)}", error=True)
                break
            except Exception as e:
                if self.connected:
                    self.display_message("错误", f"接收消息失败: {str(e)}", error=True)
                break
        self.disconnect()
        
    def send_message(self):
        if not self.connected or not self.aes_key:
            self.display_message("错误", "尚未连接到服务器", error=True)
            return
        message = self.message_input.text().strip()
        if not message:
            return
        self.message_input.clear()
        try:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            username = self.username_input.text()
            message_hash = hashlib.md5(f"{username}{timestamp}{message}".encode()).hexdigest()
            message_obj = {
                "sender": username,
                "content": message,
                "timestamp": timestamp,
                "hash": message_hash
            }
            encrypted = self.encrypt_message(json.dumps(message_obj), self.aes_key)
            msg_len = struct.pack('>I', len(encrypted))
            self.client_socket.sendall(msg_len + encrypted)
            self.display_message("我", message, timestamp)
        except Exception as e:
            self.display_message("错误", f"发送消息失败: {str(e)}", error=True)

    def encrypt_message(self, message, key):
        # 使用从服务端接收的块大小进行填充
        block_size = self.encryption_config.get("block_size", AES.block_size)
        data = pad(message.encode('utf-8'), block_size)
        iv = Random.get_random_bytes(16)  # IV固定为16字节
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(data)
        return iv + encrypted

    def decrypt_message(self, data, key):
        try:
            # 使用从服务端接收的配置
            block_size = self.encryption_config.get("block_size", AES.block_size)
            
            # 验证数据长度足够提取IV和至少一个块的数据
            if len(data) < 16 + block_size:
                raise ValueError(f"数据长度不足 ({len(data)}字节)，需要至少{16 + block_size}字节")
            
            iv = data[:16]
            encrypted = data[16:]
            
            # 验证加密数据长度是否为块大小的整数倍
            if len(encrypted) % block_size != 0:
                raise ValueError(f"加密数据长度 ({len(encrypted)}字节) 不是块大小({block_size}字节)的整数倍")
            
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted)
            
            # 尝试去填充，处理padding错误
            try:
                unpadded = unpad(decrypted, AES.block_size)
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
            
            return unpadded.decode('utf-8')
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

    def display_message(self, sender, message, timestamp=None, error=False):
        if not timestamp:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.message_received.emit(sender, message, timestamp, error)
        
    def _display_message(self, sender, message, timestamp, error):
        if error:
            color = "#F44747"
        elif sender == "我":
            color = "#4EC9B0"
        elif sender == "系统":
            color = "#C586C0"
        elif sender == "错误":
            color = "#F44747"
        else:
            color = "#DCDCAA"
        html_message = f"""
        <div style="margin-bottom: 10px;">
            <span style="color: #6A9955;">[{timestamp}]</span>
            <span style="color: {color}; font-weight: bold;">{sender}:</span>
            <span style="color: #D4D4D4;">{message}</span>
        </div>
        """
        self.chat_area.append(html_message)
        self.chat_area.moveCursor(self.chat_area.textCursor().End)
        QCoreApplication.processEvents()
        
    def _update_connection_status(self, status_text, status_style):
        self.encryption_status.setText(status_text)
        self.encryption_status.setStyleSheet(status_style)
        
    def _update_ui_state(self, message_input_enabled, send_button_enabled):
        self.message_input.setEnabled(message_input_enabled)
        self.send_button.setEnabled(send_button_enabled)
        
    def closeEvent(self, event):
        self.disconnect()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    # 确保Linux下中文显示正常
    font = QFont("SimHei")
    app.setFont(font)
    client = ChatClient()
    client.show()
    sys.exit(app.exec_())