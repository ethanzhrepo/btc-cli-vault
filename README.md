# Bitcoin CLI Vault

A secure command-line wallet for Bitcoin that supports multiple key storage providers.


![GitHub commit activity](https://img.shields.io/github/commit-activity/w/ethanzhrepo/eth-cli-vault)
![GitHub Release](https://img.shields.io/github/v/release/ethanzhrepo/eth-cli-vault)
![GitHub Repo stars](https://img.shields.io/github/stars/ethanzhrepo/eth-cli-vault)
![GitHub License](https://img.shields.io/github/license/ethanzhrepo/eth-cli-vault)


<a href="https://t.me/ethanatca"><img alt="" src="https://img.shields.io/badge/Telegram-%40ethanatca-blue" /></a>
<a href="https://x.com/intent/follow?screen_name=0x99_Ethan">
<img alt="X (formerly Twitter) Follow" src="https://img.shields.io/twitter/follow/0x99_Ethan">
</a>


## Problem Solved

How to back up your mnemonic phrase more securely? Write it on paper? Engrave it on steel? Scramble the order? Use a 25th word? Password cloud storage? Hardware wallet?
- Physical backups can be lost or damaged 
- Cloud storage risks being hacked

Security practice: Use AES and passphrase dual protection to back up across multiple cloud drives. Only need to remember two passwords - one to decrypt the 24 word mnemonic, and one to combine with the 24 words to restore the key.

[英文](./README.md) | [中文](./README_cn.md) 

## Important Security Note

**All data files and credentials remain under your full control at all times.** This wallet puts you in complete control of your assets through self-custody:

- Wallet files are encrypted with your passwords before being stored
- Private keys are never shared with any third party
- Cloud storage providers cannot access your unencrypted data
- You are responsible for safely storing your wallet files and remembering your passwords
- No recovery mechanisms exist if you lose your encrypted files or passwords

Always keep multiple backups of your encrypted wallet files and ensure you never forget your passwords.

## Security Features

- BIP39 mnemonic phrase generation (24 words)
- Optional BIP39 passphrase support
- AES-256-GCM encryption with Argon2id key derivation
- Cloud storage support via OAuth (Google Drive, Dropbox, Box, AWS S3)
- Local wallet storage option
- **No server component** - all OAuth token exchanges, cloud storage connections, and authorization processes happen solely on your local machine without any external server involvement. This program is fully client-side and will never have any server component.

