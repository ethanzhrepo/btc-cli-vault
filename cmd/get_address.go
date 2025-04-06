package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethanzhrepo/btc-cli-vault/util"
	"github.com/spf13/cobra"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/term"
)

// GetAddressCmd 返回 get 命令
func GetAddressCmd() *cobra.Command {
	var inputLocation string
	var walletName string
	var showMnemonics bool
	var showPrivateKey bool

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get Bitcoin addresses from a wallet file",
		Long:  `Retrieve Bitcoin addresses from a local or cloud-stored wallet file.`,
		Run: func(cmd *cobra.Command, args []string) {
			// 初始化配置
			initConfig()

			// 检查必要参数
			if inputLocation == "" {
				fmt.Println("Error: --input parameter is required")
				cmd.Usage()
				os.Exit(1)
			}

			// 判断输入位置是云存储还是本地文件
			var walletData []byte
			var err error
			isCloudProvider := false

			for _, provider := range util.CLOUD_PROVIDERS {
				if inputLocation == provider {
					isCloudProvider = true
					// 从云存储获取钱包文件
					if walletName == "" {
						fmt.Println("Error: --name parameter is required when using cloud storage")
						cmd.Usage()
						os.Exit(1)
					}

					cloudPath := filepath.Join(util.DEFAULT_CLOUD_FILE_DIR, walletName+".json")
					walletData, err = util.Get(provider, cloudPath)
					if err != nil {
						fmt.Printf("Error loading wallet from %s: %v\n", provider, err)
						os.Exit(1)
					}
					break
				}
			}

			if !isCloudProvider {
				// 从本地文件系统加载
				walletData, err = util.Get(inputLocation, inputLocation)
				if err != nil {
					fmt.Printf("Error loading wallet from local file: %v\n", err)
					os.Exit(1)
				}
			}

			// 解析钱包文件
			var wallet WalletFile
			if err := json.Unmarshal(walletData, &wallet); err != nil {
				fmt.Printf("Error parsing wallet file: %v\n", err)
				os.Exit(1)
			}

			// 获取密码
			fmt.Print("Please Enter \033[1;31mEncryption Password\033[0m: ")
			passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				fmt.Printf("\nError reading password: %v\n", err)
				os.Exit(1)
			}
			fmt.Println()
			password := string(passwordBytes)

			// 解密助记词
			mnemonic, err := util.DecryptMnemonic(wallet.EncryptedMnemonic, password)
			if err != nil {
				fmt.Printf("Error decrypting mnemonic: %v\n", err)
				os.Exit(1)
			}

			// 显示助记词
			if showMnemonics {
				fmt.Printf("\nDecrypted Mnemonic: \033[1;32m%s\033[0m\n", mnemonic)
			}

			// 询问是否使用了passphrase
			fmt.Print("Did you use a BIP39 passphrase for this wallet? (y/n): ")
			var answer string
			fmt.Scanln(&answer)

			var passphrase string
			if strings.ToLower(answer) == "y" || strings.ToLower(answer) == "yes" {
				fmt.Print("Please Enter \033[1;31mBIP39 Passphrase\033[0m: ")
				passphraseBytes, err := term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					fmt.Printf("\nError reading passphrase: %v\n", err)
					os.Exit(1)
				}
				fmt.Println()
				passphrase = string(passphraseBytes)
			}

			// 从助记词生成种子
			seed := bip39.NewSeed(mnemonic, passphrase)

			// 确定网络参数
			var params *chaincfg.Params
			var networkName string

			if wallet.TestNet {
				params = &chaincfg.TestNet3Params
				networkName = "Testnet"
			} else {
				params = &chaincfg.MainNetParams
				networkName = "Mainnet"
			}

			// 创建主私钥
			masterKey, err := hdkeychain.NewMaster(seed, params)
			if err != nil {
				fmt.Printf("Error generating master key: %v\n", err)
				os.Exit(1)
			}

			// 输出钱包信息
			fmt.Printf("\nBitcoin Wallet Addresses (%s):\n", networkName)
			fmt.Println("========================================")

			// 检查新格式的钱包（包含Accounts数组）
			if len(wallet.Accounts) > 0 {
				// 使用新格式：通过派生路径生成每种类型的地址
				for _, account := range wallet.Accounts {
					// 显示账户类型
					var accountTypeName string
					switch account.Type {
					case "legacy":
						accountTypeName = "P2PKH (Legacy)"
					case "segwit":
						accountTypeName = "P2WPKH (SegWit)"
					case "nested-segwit":
						accountTypeName = "P2SH-P2WPKH (Nested SegWit)"
					case "taproot":
						accountTypeName = "P2TR (Taproot)"
					default:
						accountTypeName = account.Type
					}

					// 派生账户的私钥
					deriveKey, err := deriveKeyFromPath(masterKey, account.DerivationPath)
					if err != nil {
						fmt.Printf("Error deriving key for %s: %v\n", accountTypeName, err)
						continue
					}

					// 获取私钥和公钥
					privKey, err := deriveKey.ECPrivKey()
					if err != nil {
						fmt.Printf("Error getting private key for %s: %v\n", accountTypeName, err)
						continue
					}

					pubKey := privKey.PubKey()

					// 根据账户类型生成地址
					var addr string
					switch account.Type {
					case "legacy":
						addr, err = generateP2PKHAddress(pubKey, params)
					case "segwit":
						addr, err = generateP2WPKHAddress(pubKey, params)
					case "nested-segwit":
						addr, err = generateP2SHAddress(pubKey, params)
					case "taproot":
						addr, err = generateP2TRAddress(pubKey, params)
					default:
						fmt.Printf("Warning: Unknown account type: %s\n", account.Type)
						continue
					}

					if err != nil {
						fmt.Printf("Error generating address for %s: %v\n", accountTypeName, err)
						continue
					}

					// 显示地址信息
					fmt.Printf("%s address: \033[1;32m%s\033[0m\n", accountTypeName, addr)
					fmt.Printf("  Derivation path: %s\n", account.DerivationPath)

					// 如果显示私钥，则输出
					if showPrivateKey {
						privateKeyWIF, err := btcutil.NewWIF(privKey, params, true)
						if err == nil {
							fmt.Printf("  Private Key (WIF): \033[1;31m%s\033[0m\n", privateKeyWIF.String())
						}
					}
				}
			} else {
				// 兼容旧格式：使用单一路径派生所有地址类型
				// 旧钱包格式没有 DerivationPath 字段，使用默认派生路径
				var derivationPath string
				if wallet.TestNet {
					derivationPath = "m/44'/1'/0'/0/0"
				} else {
					derivationPath = "m/44'/0'/0'/0/0"
				}

				// 派生密钥
				deriveKey, err := deriveKeyFromPath(masterKey, derivationPath)
				if err != nil {
					fmt.Printf("Error deriving key: %v\n", err)
					os.Exit(1)
				}

				// 获取私钥和公钥
				privateKey, err := deriveKey.ECPrivKey()
				if err != nil {
					fmt.Printf("Error getting private key: %v\n", err)
					os.Exit(1)
				}

				publicKey := privateKey.PubKey()

				// P2PKH (传统地址)
				p2pkhAddr, err := generateP2PKHAddress(publicKey, params)
				if err != nil {
					fmt.Printf("Error generating P2PKH address: %v\n", err)
					os.Exit(1)
				}
				fmt.Printf("P2PKH address: \033[1;32m%s\033[0m\n", p2pkhAddr)

				// P2WPKH (原生隔离见证)
				p2wpkhAddr, err := generateP2WPKHAddress(publicKey, params)
				if err != nil {
					fmt.Printf("Error generating P2WPKH address: %v\n", err)
					os.Exit(1)
				}
				fmt.Printf("P2WPKH address: \033[1;32m%s\033[0m\n", p2wpkhAddr)

				// P2SH (脚本哈希 - 兼容格式的隔离见证地址)
				p2shAddr, err := generateP2SHAddress(publicKey, params)
				if err != nil {
					fmt.Printf("Error generating P2SH address: %v\n", err)
					os.Exit(1)
				}
				fmt.Printf("P2SH-P2WPKH address: \033[1;32m%s\033[0m\n", p2shAddr)

				// P2TR (Taproot)
				p2trAddr, err := generateP2TRAddress(publicKey, params)
				if err != nil {
					fmt.Printf("Error generating P2TR address: %v\n", err)
					os.Exit(1)
				}
				fmt.Printf("P2TR address: \033[1;32m%s\033[0m\n", p2trAddr)

				// 如果开启显示私钥参数，则输出私钥
				if showPrivateKey {
					fmt.Println("\n\033[1;31mWARNING: Never share your private key with anyone!\033[0m")
					privateKeyWIF, err := btcutil.NewWIF(privateKey, params, true)
					if err != nil {
						fmt.Printf("Error encoding private key: %v\n", err)
						os.Exit(1)
					}
					fmt.Printf("Private Key (WIF): \033[1;31m%s\033[0m\n", privateKeyWIF.String())
				}

				// 输出派生路径信息
				fmt.Printf("\nDerivation Path: %s\n", derivationPath)
			}
		},
	}

	// 添加命令参数
	cmd.Flags().StringVarP(&inputLocation, "input", "i", "", "Input location (local file path or cloud provider)")
	cmd.Flags().StringVarP(&walletName, "name", "n", "", "Name of the wallet file (required for cloud storage)")
	cmd.Flags().BoolVar(&showMnemonics, "show-mnemonics", false, "Display the decrypted mnemonic phrase")
	cmd.Flags().BoolVar(&showPrivateKey, "show-private-key", false, "Display the private key in WIF format")

	cmd.MarkFlagRequired("input")

	return cmd
}

// 从路径字符串派生密钥
func deriveKeyFromPath(masterKey *hdkeychain.ExtendedKey, path string) (*hdkeychain.ExtendedKey, error) {
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
			idx, err := strconv.ParseUint(hardened, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid path component: %v", err)
			}
			childIdx = hdkeychain.HardenedKeyStart + uint32(idx)
		} else {
			// 非硬化路径
			idx, err := strconv.ParseUint(part, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid path component: %v", err)
			}
			childIdx = uint32(idx)
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

// The address generation functions have been moved to a common location
// and are shared with the create.go implementation
