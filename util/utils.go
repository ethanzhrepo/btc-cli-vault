package util

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
)

// 钱包文件结构（用来存储钱包文件，来生成确定性的公钥）
// type WalletFile struct {
// 	Version           int    `json:"version"`
// 	EncryptedMnemonic string `json:"encrypted_mnemonic"`
// 	HDPath            string `json:"hd_path"`
// 	DerivationPath    string `json:"derivation_path"`
// 	TestNet           bool   `json:"testnet"`
// }

// 加密助记词的JSON结构
type EncryptedMnemonic struct {
	Version       int    `json:"version"`
	Algorithm     string `json:"algorithm"`
	Salt          string `json:"salt"`
	Nonce         string `json:"nonce"`
	Ciphertext    string `json:"ciphertext"`
	KeyDerivation string `json:"key_derivation"`
	Memory        uint32 `json:"memory_kb"`
	Iterations    uint32 `json:"iterations"`
	Parallelism   uint8  `json:"parallelism"`
	KeyLength     uint32 `json:"key_length"`
}

// 解密助记词
func DecryptMnemonic(encryptedMnemonic EncryptedMnemonic, password string) (string, error) {

	// 检查必要字段是否存在
	if encryptedMnemonic.Salt == "" || encryptedMnemonic.Nonce == "" || encryptedMnemonic.Ciphertext == "" {
		return "", fmt.Errorf("invalid encrypted mnemonic format: missing required fields")
	}

	// 检查加密算法
	if encryptedMnemonic.Algorithm != "AES-256-GCM" {
		return "", fmt.Errorf("unsupported encryption algorithm: %s", encryptedMnemonic.Algorithm)
	}

	// 检查密钥派生方法
	if strings.ToLower(encryptedMnemonic.KeyDerivation) != "argon2id" {
		return "", fmt.Errorf("unsupported key derivation method: %s", encryptedMnemonic.KeyDerivation)
	}

	// 解码盐值
	salt, err := base64.StdEncoding.DecodeString(encryptedMnemonic.Salt)
	if err != nil {
		return "", fmt.Errorf("decode salt failed: %v", err)
	}

	// 解码随机数
	nonce, err := base64.StdEncoding.DecodeString(encryptedMnemonic.Nonce)
	if err != nil {
		return "", fmt.Errorf("decode nonce failed: %v", err)
	}

	// 解码密文
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedMnemonic.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext failed: %v", err)
	}

	// 使用argon2id派生密钥
	key := argon2.IDKey([]byte(password), salt,
		encryptedMnemonic.Iterations,
		encryptedMnemonic.Memory,
		encryptedMnemonic.Parallelism,
		encryptedMnemonic.KeyLength)

	// 创建AES-GCM实例
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create AES cipher instance failed: %v", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM instance failed: %v", err)
	}

	// 解密
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt failed, maybe wrong password: %v", err)
	}

	return string(plaintext), nil
}

// parseStoragePath 解析存储路径为方法和文件路径
func ParseStoragePath(path string) (string, string, error) {
	parts := strings.SplitN(path, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid storage path format, should be 'method:path'")
	}

	method := strings.ToLower(parts[0])
	filePath := parts[1]

	// 验证方法
	switch method {
	case "fs":
		// 文件系统路径处理
		if strings.HasPrefix(filePath, "/") {
			// 绝对路径，保持不变
		} else {
			// 相对路径，转为绝对路径
			absPath, err := filepath.Abs(filePath)
			if err != nil {
				return "", "", fmt.Errorf("failed to convert to absolute path: %v", err)
			}
			filePath = absPath
		}
	case "googledrive", "dropbox", "s3":
		// 云存储路径，保持不变
	default:
		return "", "", fmt.Errorf("unsupported storage method: %s", method)
	}

	return method, filePath, nil
}
