package cmd

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/ethanzhrepo/btc-cli-vault/util"
	"github.com/spf13/viper"
	"golang.org/x/term"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip39"
)

// BIP 派生路径常量
const (
	BIP44Purpose = uint32(44) // Legacy addresses (P2PKH)
	BIP49Purpose = uint32(49) // Nested SegWit addresses (P2SH-P2WPKH)
	BIP84Purpose = uint32(84) // Native SegWit addresses (P2WPKH)
	BIP86Purpose = uint32(86) // Taproot addresses (P2TR)
)

// WalletFile 定义了钱包文件的通用结构
type WalletFile struct {
	Version           int                    `json:"version"`
	EncryptedMnemonic util.EncryptedMnemonic `json:"encrypted_mnemonic"`
	TestNet           bool                   `json:"testnet"`
	Accounts          []AccountInfo          `json:"accounts"`
}

// AccountInfo 存储不同类型账户的信息
type AccountInfo struct {
	Type           string `json:"type"`            // 账户类型：legacy, segwit, nested-segwit, taproot
	Purpose        uint32 `json:"purpose"`         // BIP用途：44, 49, 84, 86
	HDPath         string `json:"hd_path"`         // 完整HD路径
	DerivationPath string `json:"derivation_path"` // 默认派生路径
	Address        string `json:"address"`         // 生成的地址
}

// 从路径字符串派生密钥
func DeriveKeyFromPath(masterKey *hdkeychain.ExtendedKey, path string) (*hdkeychain.ExtendedKey, error) {
	// 移除 'm/' 前缀
	path = strings.TrimPrefix(path, "m/")
	parts := strings.Split(path, "/")

	currentKey := masterKey
	for _, part := range parts {
		// 处理硬化标记
		var childIdx uint32
		if strings.HasSuffix(part, "'") || strings.HasSuffix(part, "h") {
			// 硬化路径
			hardened := strings.TrimRight(strings.TrimRight(part, "'"), "h")
			idx, err := StringToUint32(hardened)
			if err != nil {
				return nil, fmt.Errorf("invalid path component: %v", err)
			}
			childIdx = hdkeychain.HardenedKeyStart + idx
		} else {
			// 非硬化路径
			idx, err := StringToUint32(part)
			if err != nil {
				return nil, fmt.Errorf("invalid path component: %v", err)
			}
			childIdx = idx
		}

		// 派生下一级密钥
		var err error
		currentKey, err = currentKey.Derive(childIdx)
		if err != nil {
			return nil, fmt.Errorf("error deriving key at %s: %v", part, err)
		}
	}

	return currentKey, nil
}

// 将字符串转换为 uint32
func StringToUint32(s string) (uint32, error) {
	var i uint32
	_, err := fmt.Sscanf(s, "%d", &i)
	return i, err
}

// initTxConfig initializes the configuration for transaction commands
func initTxConfig() (string, error) {
	// Initialize config
	initConfig()

	// Get RPC URL from config
	rpcURL := viper.GetString("rpc")
	if rpcURL == "" {
		return "", fmt.Errorf("RPC URL not configured. Please run 'eth-cli config set rpc YOUR_RPC_URL'")
	}

	return rpcURL, nil
}

// getPrivateKeyFromLocalFile retrieves a private key from a local wallet file
func getPrivateKeyFromLocalFile(filePath string) (string, string, error) {
	// Load from local file system
	walletData, err := util.Get(filePath, filePath)
	if err != nil {
		return "", "", fmt.Errorf("error loading wallet from local file: %v", err)
	}

	// Parse wallet file
	var wallet WalletFile
	if err := json.Unmarshal(walletData, &wallet); err != nil {
		return "", "", fmt.Errorf("error parsing wallet file: %v", err)
	}

	// Get password
	fmt.Print("Please Enter \033[1;31mAES\033[0m Password: ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", "", fmt.Errorf("error reading password: %v", err)
	}
	fmt.Println()
	password := string(passwordBytes)

	// Decrypt mnemonic
	mnemonic, err := util.DecryptMnemonic(wallet.EncryptedMnemonic, password)
	if err != nil {
		return "", "", fmt.Errorf("error decrypting mnemonic: %v", err)
	}

	// Ask if a passphrase was used
	fmt.Print("Did you use a BIP39 passphrase for this wallet? (y/n): ")
	var answer string
	fmt.Scanln(&answer)

	var passphrase string
	if strings.ToLower(answer) == "y" || strings.ToLower(answer) == "yes" {
		fmt.Print("Please Enter \033[1;31mBIP39\033[0m Passphrase: ")
		passphraseBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", "", fmt.Errorf("error reading passphrase: %v", err)
		}
		fmt.Println()
		passphrase = string(passphraseBytes)
	}

	// Generate seed from mnemonic
	seed := bip39.NewSeed(mnemonic, passphrase)

	// Derive private key from seed
	privateKey, err := crypto.ToECDSA(seed[:32]) // Use first 32 bytes of seed as private key
	if err != nil {
		return "", "", fmt.Errorf("error deriving private key: %v", err)
	}

	// Get hex representation of private key
	privateKeyHex := fmt.Sprintf("%x", crypto.FromECDSA(privateKey))

	// Get address
	address := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()

	return privateKeyHex, address, nil
}

// getPrivateKeyFromProvider retrieves a private key from a provider
func getPrivateKeyFromProvider(provider string, name string) (string, string, error) {
	// 判断输入是云存储还是本地文件
	var walletData []byte
	var err error
	isCloudProvider := false

	for _, p := range util.CLOUD_PROVIDERS {
		if provider == p {
			isCloudProvider = true
			// 从云存储获取钱包文件
			cloudPath := filepath.Join(util.DEFAULT_CLOUD_FILE_DIR, name+".json")
			walletData, err = util.Get(provider, cloudPath)
			if err != nil {
				return "", "", fmt.Errorf("error loading wallet from %s: %v", provider, err)
			}
			break
		}
	}

	if !isCloudProvider {
		// 从本地文件系统加载
		walletData, err = util.Get(provider, provider)
		if err != nil {
			return "", "", fmt.Errorf("error loading wallet from local file: %v", err)
		}
	}

	// 解析钱包文件
	var wallet WalletFile
	if err := json.Unmarshal(walletData, &wallet); err != nil {
		return "", "", fmt.Errorf("error parsing wallet file: %v", err)
	}

	// 获取密码
	fmt.Print("Please Enter \033[1;31mAES\033[0m Password: ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", "", fmt.Errorf("error reading password: %v", err)
	}
	fmt.Println()
	password := string(passwordBytes)

	// 解密助记词
	mnemonic, err := util.DecryptMnemonic(wallet.EncryptedMnemonic, password)
	if err != nil {
		return "", "", fmt.Errorf("error decrypting mnemonic: %v", err)
	}

	// 询问是否使用了passphrase
	fmt.Print("Did you use a BIP39 passphrase for this wallet? (y/n): ")
	var answer string
	fmt.Scanln(&answer)

	var passphrase string
	if strings.ToLower(answer) == "y" || strings.ToLower(answer) == "yes" {
		fmt.Print("Please Enter \033[1;31mBIP39\033[0m Passphrase: ")
		passphraseBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", "", fmt.Errorf("error reading passphrase: %v", err)
		}
		fmt.Println()
		passphrase = string(passphraseBytes)
	}

	// 从助记词生成种子
	seed := bip39.NewSeed(mnemonic, passphrase)

	// 从种子派生私钥
	privateKey, err := crypto.ToECDSA(seed[:32]) // 使用seed的前32字节作为私钥
	if err != nil {
		return "", "", fmt.Errorf("error deriving private key: %v", err)
	}

	// 获取私钥的十六进制字符串表示
	privateKeyHex := fmt.Sprintf("%x", crypto.FromECDSA(privateKey))

	// 获取地址
	address := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()

	return privateKeyHex, address, nil
}
