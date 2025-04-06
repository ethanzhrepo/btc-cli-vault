package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

func EncryptMnemonic(mnemonic, password string) (EncryptedMnemonic, error) {
	// 初始化返回结构
	result := EncryptedMnemonic{
		Version:       1,
		Algorithm:     "AES-256-GCM",
		KeyDerivation: "Argon2id",
		Memory:        1024 * 1024,
		Iterations:    12,
		Parallelism:   4,
		KeyLength:     32,
	}

	// 生成随机salt (16字节)
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return result, fmt.Errorf("failed to generate random salt: %v", err)
	}
	result.Salt = base64.StdEncoding.EncodeToString(salt)

	// 使用 Argon2id 从密码派生密钥
	key := argon2.IDKey(
		[]byte(password),
		salt,
		result.Iterations,
		result.Memory,
		result.Parallelism,
		result.KeyLength,
	)

	// 创建cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return result, err
	}

	// 创建GCM模式
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return result, err
	}

	// 创建随机nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return result, err
	}
	result.Nonce = base64.StdEncoding.EncodeToString(nonce)

	// 加密数据
	ciphertext := gcm.Seal(nil, nonce, []byte(mnemonic), nil)
	result.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)

	return result, nil
}
