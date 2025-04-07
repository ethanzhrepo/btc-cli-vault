# Bitcoin CLI Vault

A secure command-line wallet for Bitcoin that supports multiple key storage providers.


![GitHub commit activity](https://img.shields.io/github/commit-activity/w/ethanzhrepo/btc-cli-vault)
![GitHub Release](https://img.shields.io/github/v/release/ethanzhrepo/btc-cli-vault)
![GitHub Repo stars](https://img.shields.io/github/stars/ethanzhrepo/btc-cli-vault)
![GitHub License](https://img.shields.io/github/license/ethanzhrepo/btc-cli-vault)


<a href="https://t.me/ethanatca"><img alt="" src="https://img.shields.io/badge/Telegram-%40ethanatca-blue" /></a>
<a href="https://x.com/intent/follow?screen_name=0x99_Ethan">
<img alt="X (formerly Twitter) Follow" src="https://img.shields.io/twitter/follow/0x99_Ethan">
</a>


## Problem Solved

How to back up your mnemonic phrase more securely? Write it on paper? Engrave it on steel? Scramble the order? Use a 25th word? Password cloud storage? Hardware wallet?
- Physical backups can be lost or damaged 
- Cloud storage risks being hacked

Security practice: Use AES and passphrase dual protection to back up across multiple cloud drives. Only need to remember two passwords - one to decrypt the 24 word mnemonic, and one to combine with the 24 words to restore the key.

[English](./README.md) | [中文](./README_cn.md) 

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

## Supported Address Types

- Legacy addresses (P2PKH)
- SegWit addresses (P2WPKH)
- Nested SegWit addresses (P2SH-P2WPKH)
- Taproot addresses (P2TR)

## Supported Networks

- Bitcoin Mainnet
- Bitcoin Testnet

## Storage Options

- Local file system
- Google Drive
- Dropbox
- Box
- AWS S3
- Apple Keychain (macOS only)

## Available Commands

### Core Wallet Functions

- `create` - Create a new Bitcoin wallet with various address types
- `get` - Retrieve and display Bitcoin addresses from a wallet file
- `list` - List available wallets in cloud storage
- `copy` - Copy wallet between storage providers

### Transaction Operations

- `transfer` - Create and broadcast Bitcoin transactions
- `sign-tx` - Sign a raw Bitcoin transaction
- `sign-message` - Sign a message with a Bitcoin private key
- `utxo` - List unspent transaction outputs for an address
- `fee` - Get current recommended Bitcoin transaction fees
- `consolidate-utxos` - Consolidate multiple small UTXOs into a single output

### Configuration

- `config` - Manage configuration settings
  - `get` - Get a configuration value
  - `set` - Set a configuration value
  - `delete` - Delete a configuration value
  - `list` - List all configuration values

## Usage Examples

### Create a New Wallet

```bash
# Create wallet and save to local file
btc-cli create --output fs --path wallet.json

# Create wallet and save to Google Drive
btc-cli create --output google

# Create wallet and save to Apple Keychain (macOS only)
btc-cli create --output keychain
```

### Get Wallet Addresses

```bash
# From local file
btc-cli get --input wallet.json

# From cloud storage
btc-cli get --input google --name mywallet

# From Apple Keychain
btc-cli get --input keychain --name mywallet
```

### Sign a Message

```bash
# Sign a message with a key from your wallet
btc-cli sign-message --data "Hello, Bitcoin!" --file wallet.json
```

### Check UTXOs

```bash
# List UTXOs for a specific address
btc-cli utxo --address bc1qexample...
```

### Transfer Bitcoin

```bash
# Transfer funds from your wallet to another address
btc-cli transfer --from wallet.json --to bc1qexample... --amount 0.001
```

### Get Fee Recommendations

```bash
# Get current fee recommendations
btc-cli fee
```

### Consolidate UTXOs

```bash
# Consolidate many small UTXOs into a single output
btc-cli consolidate-utxos --wallet wallet.json
```

## Installation

### From Binary Releases

Download the latest release from the [Releases page](https://github.com/ethanzhrepo/btc-cli-vault/releases).

### From Source

```bash
git clone https://github.com/ethanzhrepo/btc-cli-vault.git
cd btc-cli-vault
go build
```

## License

[MIT License](LICENSE)

## Contribution

Contributions are welcome! Please feel free to submit a Pull Request.