# 安全聊天系统

## 项目简介

安全聊天系统是一个基于Python开发的加密聊天应用程序，支持多种平台和界面风格。该系统采用RSA和AES加密算法确保通信安全，支持IPv4和IPv6网络协议。

## 目录结构

```
├── Linux/               # Linux图形界面版本
│   ├── client_linux.py  # Linux客户端
│   └── server_linux.py  # Linux服务端
├── Windows/             # Windows图形界面版本
│   ├── client.py        # Windows客户端
│   └── server.py        # Windows服务端
├── cli/                 # 命令行版本
│   ├── client_cli.py    # CLI客户端
│   ├── server_cli.py    # CLI服务端
│   └── server_cli_bt.py # 宝塔Python站点专版服务端
```

## 功能特性

- 端到端加密通信（RSA + AES）
- 消息完整性校验（MD5）
- 跨平台支持（Linux、Windows）
- 多种界面风格（图形界面和命令行界面）
- 支持IPv4和IPv6
- 支持多客户端连接
- 自定义端口配置

## 技术架构

- 编程语言：Python 3.11.2
- 图形界面：PyQt5
- 加密库：pycryptodome（CLI版本）/ crypto（图形界面版本）
- 网络通信：TCP Socket
- 哈希算法：MD5（用于消息完整性校验）

## 加密机制

系统采用多层加密机制确保通信安全：

1. **传输加密**：
   - RSA算法用于密钥交换
   - AES-256-CBC算法用于消息内容加密

2. **消息完整性校验**：
   - MD5算法用于验证消息完整性，防止消息被篡改

## 安装和使用

请根据您要使用的版本查看对应目录下的说明文档：

- cli命令行版本  (文档待完善)
- Linux图形界面版本（文档待完善）
- Windows图形界面版本（文档待完善）