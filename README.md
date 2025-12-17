# Bitcoin CLI Vault (v0.1.2)

A secure command-line wallet for Bitcoin that supports multiple key storage providers.


![GitHub commit activity](https://img.shields.io/github/commit-activity/w/ethanzhrepo/btc-cli-vault)
![GitHub Release](https://img.shields.io/github/v/release/ethanzhrepo/btc-cli-vault)
![GitHub Repo stars](https://img.shields.io/github/stars/ethanzhrepo/btc-cli-vault)
![GitHub License](https://img.shields.io/github/license/ethanzhrepo/btc-cli-vault)




## Problem Solved

How to back up your mnemonic phrase more securely? Write it on paper? Engrave it on steel? Scramble the order? Use a 25th word? Password cloud storage? Hardware wallet?
- Physical backups can be lost or damaged 
- Cloud storage risks being hacked

Security practice: Use AES and passphrase dual protection to back up across multiple cloud drives. Only need to remember two passwords - one to decrypt the 24 word mnemonic, and one to combine with the 24 words to restore the key.

[English](./README.md) | [中文](./README_cn.md) | [Documentation](https://ethans-place.gitbook.io/btc-cli-vault)

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

- [x] Legacy addresses (P2PKH)
- [x] SegWit addresses (P2WPKH)
- [ ] Nested SegWit addresses (P2SH-P2WPKH)
- [ ] Taproot addresses (P2TR)

> **TODO:** P2TR and P2SH address types are planned but not yet fully implemented in the current version.

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

Download the latest release (v0.1.2) from the [Releases page](https://github.com/ethanzhrepo/btc-cli-vault/releases).

#### Linux

```bash
# Download the binary
wget https://github.com/ethanzhrepo/btc-cli-vault/releases/download/v0.1.2/btc-cli-0.1.2-linux-amd64

# Make it executable
chmod +x btc-cli-0.1.2-linux-amd64

# Move to a directory in your PATH (optional)
sudo mv btc-cli-0.1.2-linux-amd64 /usr/local/bin/btc-cli

# Run the binary
btc-cli --help
```

#### macOS (Apple Silicon)

```bash
# Download the binary
curl -LO https://github.com/ethanzhrepo/btc-cli-vault/releases/download/v0.1.2/btc-cli-0.1.2-macos-arm64

# Make it executable
chmod +x btc-cli-0.1.2-macos-arm64

# Move to a directory in your PATH (optional)
sudo mv btc-cli-0.1.2-macos-arm64 /usr/local/bin/btc-cli

# Run the binary
btc-cli --help
```

> **Note for macOS Intel users**: Intel-based macOS users should compile from source for optimal compatibility.

#### Windows

1. Download the Windows executable (btc-cli-0.1.2-windows-amd64.exe) from the releases page
2. Rename it to btc-cli.exe (optional)
3. Open Command Prompt or PowerShell and navigate to the download location
4. Run the executable: `.\btc-cli.exe --help`

### From Source

For the best compatibility or if you want to modify the code, building from source is recommended:

```bash
# Clone the repository
git clone https://github.com/ethanzhrepo/btc-cli-vault.git
cd btc-cli-vault

# Copy the example .env file and edit it with your own API keys
cp .env.example .env
nano .env  # or use any text editor to update the keys

# Build the binary
go build -o btc-cli

# Run the binary
./btc-cli --help
```

#### Build with environment variables

If you prefer to embed the API keys in the binary:

```bash
# Set environment variables (replace with your actual keys)
export GOOGLE_OAUTH_CLIENT_ID=your_google_oauth_client_id
export GOOGLE_OAUTH_CLIENT_SECRET=your_google_oauth_client_secret
export DROPBOX_APP_KEY=your_dropbox_app_key
export BOX_CLIENT_ID=your_box_client_id
export BOX_CLIENT_SECRET=your_box_client_secret
export AWS_ACCESS_KEY_ID=your_aws_access_key_id
export AWS_SECRET_ACCESS_KEY=your_aws_secret_access_key
export AWS_S3_BUCKET=your_aws_s3_bucket
export AWS_REGION=your_aws_region

# Build with these variables embedded
make build-macos  # For macOS
# OR
make build-linux-amd64  # For Linux
# OR
make build-windows  # For Windows
```

## License

[MIT License](LICENSE)

## Contribution

Contributions are welcome! Please feel free to submit a Pull Request.

