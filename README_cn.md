# btc命令行钱包

一个安全的btc命令行钱包，支持多种密钥存储的命令行程序，避免私钥丢失或者泄漏风险。

![GitHub commit activity](https://img.shields.io/github/commit-activity/w/ethanzhrepo/eth-cli-vault)
![GitHub Release](https://img.shields.io/github/v/release/ethanzhrepo/eth-cli-vault)
![GitHub Repo stars](https://img.shields.io/github/stars/ethanzhrepo/eth-cli-vault)

<a href="https://t.me/ethanatca"><img alt="" src="https://img.shields.io/badge/Telegram-%40ethanatca-blue" /></a>
<a href="https://x.com/intent/follow?screen_name=0x99_Ethan">
<img alt="X (formerly Twitter) Follow" src="https://img.shields.io/twitter/follow/0x99_Ethan">
</a>


## 解决场景

助记词不知道该怎么备份更安全？抄在纸上？刻在钢板上？打乱顺序？第25个助记词？密码云存储器？硬件钱包？
- 物理备份容易丢失、损毁
- 存在云盘又怕被盗

安全实践：使用aes和passpharse双重保护后在多个云盘备份。只需要记住两个密码，一个用来解密24个助记词，一个用来结合24个助记词还原密钥。

[英文](./README.md) | [中文](./README_cn.md) 

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

