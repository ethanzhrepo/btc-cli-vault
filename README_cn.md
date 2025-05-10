# btc命令行钱包 (v0.1.2)

一个安全的btc命令行钱包，支持多种密钥存储的命令行程序，避免私钥丢失或者泄漏风险。

![GitHub commit activity](https://img.shields.io/github/commit-activity/w/ethanzhrepo/btc-cli-vault)
![GitHub Release](https://img.shields.io/github/v/release/ethanzhrepo/btc-cli-vault)
![GitHub Repo stars](https://img.shields.io/github/stars/ethanzhrepo/btc-cli-vault)
![GitHub License](https://img.shields.io/github/license/ethanzhrepo/btc-cli-vault)


<a href="https://t.me/ethanatca"><img alt="" src="https://img.shields.io/badge/Telegram-%40ethanatca-blue" /></a>
<a href="https://x.com/intent/follow?screen_name=0x99_Ethan">
<img alt="X (formerly Twitter) Follow" src="https://img.shields.io/twitter/follow/0x99_Ethan">
</a>

## 解决场景

助记词不知道该怎么备份更安全？抄在纸上？刻在钢板上？打乱顺序？第25个助记词？密码云存储器？硬件钱包？
- 物理备份容易丢失、损毁
- 存在云盘又怕被盗

安全实践：使用aes和passpharse双重保护后在多个云盘备份。只需要记住两个密码，一个用来解密24个助记词，一个用来结合24个助记词还原密钥。

[英文](./README.md) | [中文](./README_cn.md) | [Documentation](https://ethans-place.gitbook.io/btc-cli-vault)

## 重要安全提示

**所有数据文件和凭证始终完全由您自行控制。** 这个钱包通过自我托管让您完全控制您的资产：

- 钱包文件在存储前已用您的密码加密
- 私钥永远不会与任何第三方共享
- 云存储提供商无法访问您的未加密数据
- 您需要负责安全地存储您的钱包文件并记住您的密码
- 如果您丢失了加密文件或密码，没有任何恢复机制可用

始终保持多个加密钱包文件的备份，并确保您永远不会忘记密码。

## 安全特性

- BIP39 助记词生成（24个单词）
- 可选 BIP39 密码短语支持
- 使用 Argon2id 密钥派生的 AES-256-GCM 加密
- 通过 OAuth 支持云存储（Google Drive、Dropbox、Box、AWS S3）
- 本地钱包存储选项
- **无服务器组件** - 所有 OAuth 令牌交换、云存储对接和授权过程完全在您的本地计算机上进行，不涉及任何外部服务器。该程序完全是客户端的，将来也不会有任何服务器组件。

## 支持的地址类型

- [x] 传统地址 (P2PKH)
- [x] 隔离见证地址 (P2WPKH)
- [ ] 嵌套隔离见证地址 (P2SH-P2WPKH)
- [ ] Taproot地址 (P2TR)

> **TODO:** P2TR 和 P2SH 地址类型已计划但尚未在当前版本中完全实现。

## 支持的网络

- 比特币主网
- 比特币测试网

## 存储选项

- 本地文件系统
- Google Drive
- Dropbox
- Box
- AWS S3
- Apple Keychain (仅限macOS)

## 可用命令

### 核心钱包功能

- `create` - 创建新的比特币钱包，支持多种地址类型
- `get` - 从钱包文件中检索并显示比特币地址
- `list` - 列出云存储中可用的钱包
- `copy` - 在不同存储提供商之间复制钱包文件

### 交易操作

- `transfer` - 创建并广播比特币交易
- `sign-tx` - 签署原始比特币交易
- `sign-message` - 使用比特币私钥签署消息
- `utxo` - 列出地址的未花费交易输出
- `fee` - 获取当前推荐的比特币交易费用
- `consolidate-utxos` - 将多个小额UTXO合并为一个输出

### 配置

- `config` - 管理配置设置
  - `get` - 获取配置值
  - `set` - 设置配置值
  - `delete` - 删除配置值
  - `list` - 列出所有配置值

## 使用示例

### 创建新钱包

```bash
# 创建钱包并保存到本地文件
btc-cli create --output fs --path wallet.json

# 创建钱包并保存到Google Drive
btc-cli create --output google

# 创建钱包并保存到Apple Keychain（仅限macOS）
btc-cli create --output keychain
```

### 获取钱包地址

```bash
# 从本地文件
btc-cli get --input wallet.json

# 从云存储
btc-cli get --input google --name mywallet

# 从Apple Keychain
btc-cli get --input keychain --name mywallet
```

### 签署消息

```bash
# 使用钱包中的密钥签署消息
btc-cli sign-message --data "Hello, Bitcoin!" --file wallet.json
```

### 检查UTXO

```bash
# 列出特定地址的UTXO
btc-cli utxo --address bc1qexample...
```

### 转账比特币

```bash
# 从您的钱包向另一个地址转账资金
btc-cli transfer --from wallet.json --to bc1qexample... --amount 0.001
```

### 获取费用建议

```bash
# 获取当前费用建议
btc-cli fee
```

### 合并UTXO

```bash
# 将多个小额UTXO合并为一个输出
btc-cli consolidate-utxos --wallet wallet.json
```

## 安装

### 从二进制发布版

从[发布页面](https://github.com/ethanzhrepo/btc-cli-vault/releases)下载最新版本 (v0.1.2)。

#### Linux

```bash
# 下载二进制文件
wget https://github.com/ethanzhrepo/btc-cli-vault/releases/download/v0.1.2/btc-cli-0.1.2-linux-amd64

# 添加执行权限
chmod +x btc-cli-0.1.2-linux-amd64

# 移动到PATH目录（可选）
sudo mv btc-cli-0.1.2-linux-amd64 /usr/local/bin/btc-cli

# 运行
btc-cli --help
```

#### macOS (Apple Silicon)

```bash
# 下载二进制文件
curl -LO https://github.com/ethanzhrepo/btc-cli-vault/releases/download/v0.1.2/btc-cli-0.1.2-macos-arm64

# 添加执行权限
chmod +x btc-cli-0.1.2-macos-arm64

# 移动到PATH目录（可选）
sudo mv btc-cli-0.1.2-macos-arm64 /usr/local/bin/btc-cli

# 运行
btc-cli --help
```

> **注意**：使用Intel芯片的Mac用户应该从源码编译以获得最佳兼容性。

#### Windows

1. 从发布页面下载Windows可执行文件 (btc-cli-0.1.2-windows-amd64.exe)
2. 重命名为btc-cli.exe（可选）
3. 打开命令提示符或PowerShell，导航到下载位置
4. 运行可执行文件：`.\btc-cli.exe --help`

### 从源代码

为了获得最佳兼容性或如果您想修改代码，建议从源代码构建：

```bash
# 克隆仓库
git clone https://github.com/ethanzhrepo/btc-cli-vault.git
cd btc-cli-vault

# 复制示例.env文件并编辑您自己的API密钥
cp .env.example .env
nano .env  # 或使用任何文本编辑器更新密钥

# 构建二进制文件
go build -o btc-cli

# 运行
./btc-cli --help
```

#### 使用环境变量构建

如果您希望将API密钥嵌入到二进制文件中：

```bash
# 设置环境变量（替换为您的实际密钥）
export GOOGLE_OAUTH_CLIENT_ID=your_google_oauth_client_id
export GOOGLE_OAUTH_CLIENT_SECRET=your_google_oauth_client_secret
export DROPBOX_APP_KEY=your_dropbox_app_key
export BOX_CLIENT_ID=your_box_client_id
export BOX_CLIENT_SECRET=your_box_client_secret
export AWS_ACCESS_KEY_ID=your_aws_access_key_id
export AWS_SECRET_ACCESS_KEY=your_aws_secret_access_key
export AWS_S3_BUCKET=your_aws_s3_bucket
export AWS_REGION=your_aws_region

# 构建并嵌入这些变量
make build-macos  # 适用于macOS
# 或
make build-linux-amd64  # 适用于Linux
# 或
make build-windows  # 适用于Windows
```

## 许可证

[MIT许可证](LICENSE)

## 贡献

欢迎贡献！请随时提交拉取请求。

