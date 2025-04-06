package cmd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/ethanzhrepo/btc-cli-vault/util"
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
	Type           string         `json:"type"`                      // 账户类型：p2pkh, p2wpkh, p2sh-p2wpkh, p2tr
	Purpose        uint32         `json:"purpose"`                   // BIP用途：44, 49, 84, 86
	HDPath         string         `json:"hd_path"`                   // 完整HD路径
	DerivationPath string         `json:"derivation_path"`           // 默认派生路径
	Address        string         `json:"address"`                   // 生成的地址
	RedeemScript   string         `json:"redeem_script,omitempty"`   // 赎回脚本 (用于P2SH)
	WitnessScript  string         `json:"witness_script,omitempty"`  // 见证脚本 (用于P2WSH)
	InternalPubKey string         `json:"internal_pubkey,omitempty"` // Taproot内部公钥 (x-only公钥)
	TapScriptInfo  *TapScriptInfo `json:"tap_script_info,omitempty"` // Taproot脚本信息 (用于脚本路径花费)
}

// TapScriptInfo 存储 Taproot 脚本路径信息
type TapScriptInfo struct {
	Leaves     []TapLeaf `json:"leaves"`                // 脚本叶子列表
	MerkleRoot string    `json:"merkle_root,omitempty"` // 可选: 预计算的默克尔根
}

// TapLeaf 表示 Taproot 脚本树中的一个叶子节点
type TapLeaf struct {
	Tag         string `json:"tag,omitempty"` // 可选: 脚本的人类可读标签
	Script      string `json:"script"`        // 十六进制编码的脚本
	LeafVersion uint8  `json:"leaf_version"`  // 叶子版本，通常为 0xc0 (192)
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
// StringToUint32 converts a string to a uint32 using strconv.ParseUint for robustness.
func StringToUint32(s string) (uint32, error) {
	// ParseUint parameters: string, base (10 for decimal), bitSize (32 for uint32)
	val, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		// Optionally wrap the error for more context
		return 0, fmt.Errorf("failed to parse '%s' as uint32: %w", s, err)
	}
	return uint32(val), nil
}
