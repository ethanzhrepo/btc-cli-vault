package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/ethanzhrepo/btc-cli-vault/util"
	"github.com/spf13/cobra"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/term"
)

// 输出目标结构
type OutputTarget struct {
	Method string // "fs" 或 "googledrive" 或 "dropbox" 或 "onedrive"
	Path   string // 文件路径
}

// CreateCmd 返回 create 命令
func CreateCmd() *cobra.Command {
	var outputLocations string
	var walletName string
	var withPassphrase bool
	var force bool
	var useTestnet bool
	var showMnemonic bool

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new Bitcoin wallet",
		Long:  `Create a new Bitcoin wallet with BIP39 mnemonic and optional passphrase, save it to local filesystem or cloud storage.`,
		Run: func(cmd *cobra.Command, args []string) {
			// 初始化配置
			initConfig()

			// 检查必要参数
			if outputLocations == "" {
				fmt.Println("Error: --output parameter is required")
				cmd.Usage()
				os.Exit(1)
			}

			if walletName == "" {
				fmt.Println("Error: --name parameter is required")
				cmd.Usage()
				os.Exit(1)
			}

			// 解析输出位置
			outputs, err := parseOutputTargets(outputLocations)
			if err != nil {
				fmt.Printf("Error parsing output locations: %v\n", err)
				os.Exit(1)
			}

			// 检查是否已存在同名文件
			if !force {
				// 检查本地文件
				for _, output := range outputs {
					if output.Method == "fs" {
						fullPath := output.Path
						if !strings.HasSuffix(output.Path, ".json") {
							// 如果是目录，则添加钱包名和扩展名
							fullPath = filepath.Join(output.Path, walletName+".json")
						}
						if _, err := os.Stat(fullPath); err == nil {
							fmt.Printf("Error: Wallet file already exists at %s. Use -f or --force to overwrite.\n", fullPath)
							os.Exit(1)
						}
					}
				}
			}

			// 生成BIP39助记词
			entropy, err := bip39.NewEntropy(256) // 生成256位熵，对应24个单词
			if err != nil {
				fmt.Printf("Error generating entropy: %v\n", err)
				os.Exit(1)
			}
			mnemonic, err := bip39.NewMnemonic(entropy)
			if err != nil {
				fmt.Printf("Error generating mnemonic: %v\n", err)
				os.Exit(1)
			}

			// 显示原始助记词（如果showMnemonic为true）
			if showMnemonic {
				fmt.Println("Mnemonic (24 words):")
				fmt.Println("---------------------------------")
				fmt.Println(mnemonic)
				fmt.Println("---------------------------------")
				fmt.Println("IMPORTANT: Write these words down on paper and keep them safe!")
			}

			// 如果需要passphrase，则从用户那里获取
			var passphrase string
			if !withPassphrase {
				fmt.Println("\nPlease enter \033[1;31mBIP39 Passphrase\033[0m for extra security.")
				fmt.Println("This passphrase will be used to encrypt your \033[1;31mmnemonic\033[0m.")
				fmt.Println("If you forget it, you will not be able to recover your wallet.")
				fmt.Println("Please enter it carefully.")
				fmt.Println("It is recommended to use a strong passphrase: \033[1;31m8 characters or more, including uppercase, lowercase, numbers, and special characters\033[0m.")
				fmt.Println("Example: MyPassphrase123!")
				fmt.Println("If you don't want to use a passphrase, exit and run the command again with the \033[1;31m--without-passphrase\033[0m flag.")
				fmt.Println()

				fmt.Print("Please Enter BIP39 Passphrase: ")
				passphraseBytes, err := term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					fmt.Printf("\nError reading passphrase: %v\n", err)
					os.Exit(1)
				}
				fmt.Print("\nPlease ReEnter BIP39 Passphrase: ")
				confirmPassphraseBytes, err := term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					fmt.Printf("\nError reading passphrase confirmation: %v\n", err)
					os.Exit(1)
				}
				fmt.Println()

				if string(passphraseBytes) != string(confirmPassphraseBytes) {
					fmt.Println("Error: Passphrases do not match")
					os.Exit(1)
				}
				passphrase = string(passphraseBytes)

				// 检查密码强度
				if passphrase != "" && !isStrongPassword(passphrase) {
					fmt.Println("Error: Passphrase is not strong enough. It must be at least 8 characters and include uppercase, lowercase, numbers, and special characters.")
					os.Exit(1)
				}
			}

			// 获取加密密码
			password, err := readPasswordFromConsole()
			if err != nil {
				fmt.Printf("\nError: %v\n", err)
				os.Exit(1)
			}

			// 使用 Argon2id 加密助记词
			encryptedMnemonic, err := util.EncryptMnemonic(mnemonic, password)
			if err != nil {
				fmt.Printf("Error encrypting mnemonic: %v\n", err)
				os.Exit(1)
			}

			// 根据参数选择网络
			var params *chaincfg.Params
			var networkName string
			var coinType uint32

			if useTestnet {
				params = &chaincfg.TestNet3Params
				networkName = "Testnet"
				coinType = 1 // testnet
			} else {
				params = &chaincfg.MainNetParams
				networkName = "Mainnet"
				coinType = 0 // mainnet
			}

			// 从助记词生成BTC种子
			seed := bip39.NewSeed(mnemonic, passphrase)

			// 创建主私钥 (BIP32)
			masterKey, err := hdkeychain.NewMaster(seed, params)
			if err != nil {
				fmt.Printf("Error generating master key: %v\n", err)
				os.Exit(1)
			}

			// 生成各种标准的账户
			var accounts []AccountInfo

			// 1. 添加 BIP44 账户 (Legacy P2PKH)
			p2pkhAccount, err := createAccountInfo("legacy", BIP44Purpose, coinType, masterKey, params)
			if err != nil {
				fmt.Printf("Error creating legacy account: %v\n", err)
				os.Exit(1)
			}
			accounts = append(accounts, p2pkhAccount)

			// 2. 添加 BIP84 账户 (Native SegWit P2WPKH)
			p2wpkhAccount, err := createAccountInfo("segwit", BIP84Purpose, coinType, masterKey, params)
			if err != nil {
				fmt.Printf("Error creating segwit account: %v\n", err)
				os.Exit(1)
			}
			accounts = append(accounts, p2wpkhAccount)

			// 3. 添加 BIP49 账户 (Nested SegWit P2SH-P2WPKH)
			p2shAccount, err := createAccountInfo("nested-segwit", BIP49Purpose, coinType, masterKey, params)
			if err != nil {
				fmt.Printf("Error creating nested-segwit account: %v\n", err)
				os.Exit(1)
			}
			accounts = append(accounts, p2shAccount)

			// 4. 添加 BIP86 账户 (Taproot P2TR)
			p2trAccount, err := createAccountInfo("taproot", BIP86Purpose, coinType, masterKey, params)
			if err != nil {
				fmt.Printf("Error creating taproot account: %v\n", err)
				os.Exit(1)
			}
			accounts = append(accounts, p2trAccount)

			// 创建钱包文件对象
			wallet := WalletFile{
				Version:           1,
				EncryptedMnemonic: encryptedMnemonic,
				TestNet:           useTestnet,
				Accounts:          accounts,
			}

			// 序列化为JSON
			walletJSON, err := json.MarshalIndent(wallet, "", "  ")
			if err != nil {
				fmt.Printf("Error serializing wallet: %v\n", err)
				os.Exit(1)
			}

			// 保存到指定位置
			for _, output := range outputs {
				switch output.Method {
				case "fs":
					// 保存到本地文件系统
					fullPath := output.Path
					if !strings.HasSuffix(output.Path, ".json") {
						// 如果是目录，则添加钱包名和扩展名
						fullPath = filepath.Join(output.Path, walletName+".json")
					}

					// 确保目录存在
					dir := filepath.Dir(fullPath)
					if err := os.MkdirAll(dir, 0755); err != nil {
						fmt.Printf("Error creating directory %s: %v\n", dir, err)
						continue
					}

					// 写入文件
					if !force {
						// 检查文件是否存在
						if _, err := os.Stat(fullPath); err == nil {
							fmt.Printf("Error: Wallet file already exists at %s. Use -f or --force to overwrite.\n", fullPath)
							os.Exit(1)
						}
					}

					err := os.WriteFile(fullPath, walletJSON, 0600)
					if err != nil {
						fmt.Printf("Error saving wallet to %s: %v\n", fullPath, err)
					} else {
						fmt.Printf("Wallet saved to: %s\n", fullPath)
					}

				case "google", "dropbox", "s3", "box":
					// 保存到云存储
					cloudPath := filepath.Join(util.DEFAULT_CLOUD_FILE_DIR, walletName+".json")
					result, err := util.Put(output.Method, walletJSON, cloudPath, force)
					if err != nil {
						fmt.Printf("Error saving wallet to %s: %v\n", output.Method, err)
					} else {
						fmt.Println(result)
					}
				}
			}

			// 显示生成的地址信息
			fmt.Printf("\nGenerated Bitcoin Wallet Addresses (%s):\n", networkName)
			fmt.Println("========================================")

			for _, account := range accounts {
				var accountType string
				switch account.Type {
				case "legacy":
					accountType = "P2PKH (Legacy)"
				case "segwit":
					accountType = "P2WPKH (SegWit)"
				case "nested-segwit":
					accountType = "P2SH-P2WPKH (Nested SegWit)"
				case "taproot":
					accountType = "P2TR (Taproot)"
				}
				fmt.Printf("%s address: \033[1;32m%s\033[0m\n", accountType, account.Address)
				fmt.Printf("  Derivation path: %s\n", account.DerivationPath)
			}

			fmt.Println("\nBefore using this wallet, please test it with the get command:")

			// 示例命令
			for _, output := range outputs {
				if output.Method == "fs" {
					fullPath := output.Path
					if !strings.HasSuffix(output.Path, ".json") {
						fullPath = filepath.Join(output.Path, walletName+".json")
					}
					fmt.Printf("  btc-cli get -i %s\n", fullPath)
					break
				}
			}

			for _, output := range outputs {
				if output.Method != "fs" {
					fmt.Printf("  btc-cli get -i %s -n %s\n", output.Method, walletName)
					break
				}
			}

			// 安全提示
			fmt.Println("\n\033[1;31mIMPORTANT: Keep your passwords safe. If you lose them, you'll permanently lose access to your assets.\033[0m")
			fmt.Println("\033[1;31mBoth encryption steps use highly secure algorithms; current technology cannot recover lost passwords.\033[0m")

			// 成功提示
			fmt.Println("\n\033[1;32mSuccess: Bitcoin wallet created successfully.\033[0m")
		},
	}

	// 添加命令参数
	cmd.Flags().StringVarP(&outputLocations, "output", "o", "", "Comma-separated list of output locations (local path or cloud provider)")
	cmd.Flags().StringVarP(&walletName, "name", "n", "", "Name of the wallet file")
	cmd.Flags().BoolVar(&withPassphrase, "without-passphrase", false, "Skip the BIP39 passphrase step")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "Force overwrite if wallet file already exists")
	cmd.Flags().BoolVarP(&useTestnet, "testnet", "t", false, "Use Bitcoin testnet instead of mainnet")
	cmd.Flags().BoolVarP(&showMnemonic, "show-mnemonic", "s", false, "Show mnemonic phrase (use with caution!)")

	cmd.MarkFlagRequired("output")
	cmd.MarkFlagRequired("name")

	return cmd
}

// 读取并验证密码
func readPasswordFromConsole() (string, error) {
	fmt.Println("\nPlease enter \033[1;31mEncryption Password\033[0m for extra security.")
	fmt.Println("This password will be used to encrypt your \033[1;31mwallet file\033[0m.")
	fmt.Println("If you forget it, you will not be able to recover your wallet.")
	fmt.Println("It is recommended to use a strong password: \033[1;31m8 characters or more, including uppercase, lowercase, numbers, and special characters\033[0m.")
	fmt.Print("Enter password to encrypt mnemonic (input will be hidden): ")

	// 读取密码，不回显
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // 换行

	if err != nil {
		return "", fmt.Errorf("failed to read password: %v", err)
	}

	password := string(passwordBytes)
	if len(password) == 0 {
		return "", fmt.Errorf("password cannot be empty")
	}

	// 验证密码复杂度
	if !isStrongPassword(password) {
		return "", fmt.Errorf("password is not strong enough. It must be at least 8 characters and include uppercase, lowercase, numbers, and special characters")
	}

	// 确认密码
	fmt.Print("Confirm password (input will be hidden): ")
	confirmBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // 换行

	if err != nil {
		return "", fmt.Errorf("failed to read password confirmation: %v", err)
	}

	if string(confirmBytes) != password {
		return "", fmt.Errorf("passwords do not match")
	}

	return password, nil
}

// 检查密码强度
func isStrongPassword(password string) bool {
	if len(password) < 8 {
		return false
	}

	hasUpper := false
	hasLower := false
	hasNumber := false
	hasSpecial := false

	for _, c := range password {
		switch {
		case 'A' <= c && c <= 'Z':
			hasUpper = true
		case 'a' <= c && c <= 'z':
			hasLower = true
		case '0' <= c && c <= '9':
			hasNumber = true
		case c == '!' || c == '@' || c == '#' || c == '$' || c == '%' || c == '^' || c == '&' || c == '*' || c == '(' || c == ')' || c == '-' || c == '_' || c == '+' || c == '=' || c == '{' || c == '}' || c == '[' || c == ']' || c == '|' || c == ':' || c == ';' || c == '"' || c == '\'' || c == '<' || c == '>' || c == ',' || c == '.' || c == '?' || c == '/' || c == '\\' || c == '`' || c == '~':
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasNumber && hasSpecial
}

// 生成P2PKH地址 (Pay to Public Key Hash)
func generateP2PKHAddress(publicKey *btcec.PublicKey, params *chaincfg.Params) (string, error) {
	pubKeyHash := btcutil.Hash160(publicKey.SerializeCompressed())
	addr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, params)
	if err != nil {
		return "", err
	}
	return addr.EncodeAddress(), nil
}

// 生成P2WPKH地址 (Pay to Witness Public Key Hash)
func generateP2WPKHAddress(publicKey *btcec.PublicKey, params *chaincfg.Params) (string, error) {
	pubKeyHash := btcutil.Hash160(publicKey.SerializeCompressed())
	addr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, params)
	if err != nil {
		return "", err
	}
	return addr.EncodeAddress(), nil
}

// 生成P2SH地址 (Pay to Script Hash)
func generateP2SHAddress(publicKey *btcec.PublicKey, params *chaincfg.Params) (string, error) {
	// 创建P2WPKH脚本
	pubKeyHash := btcutil.Hash160(publicKey.SerializeCompressed())
	script, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_0).
		AddData(pubKeyHash).
		Script()
	if err != nil {
		return "", err
	}

	// 将P2WPKH脚本放入P2SH中 (P2SH-P2WPKH)
	scriptHash := btcutil.Hash160(script)
	addr, err := btcutil.NewAddressScriptHash(scriptHash, params)
	if err != nil {
		return "", err
	}
	return addr.EncodeAddress(), nil
}

// 生成P2TR地址 (Pay to Taproot)
func generateP2TRAddress(publicKey *btcec.PublicKey, params *chaincfg.Params) (string, error) {
	// 注意：在真实场景中，你可能需要考虑更多关于Taproot的细节
	// 这里我们使用一个简化的版本
	internalKey := publicKey

	// 创建Taproot输出密钥
	taprootKey := txscript.ComputeTaprootKeyNoScript(internalKey)
	addr, err := btcutil.NewAddressTaproot(taprootKey.SerializeCompressed()[1:], params)
	if err != nil {
		return "", err
	}
	return addr.EncodeAddress(), nil
}

// 创建不同类型的账户信息
func createAccountInfo(accountType string, purpose uint32, coinType uint32, masterKey *hdkeychain.ExtendedKey, params *chaincfg.Params) (AccountInfo, error) {
	// 创建基本账户信息
	account := AccountInfo{
		Type:    accountType,
		Purpose: purpose,
	}

	// 派生 purpose 层级
	purposeKey, err := masterKey.Derive(hdkeychain.HardenedKeyStart + purpose)
	if err != nil {
		return account, fmt.Errorf("error deriving purpose key: %v", err)
	}

	// 派生 coin type 层级
	coinTypeKey, err := purposeKey.Derive(hdkeychain.HardenedKeyStart + coinType)
	if err != nil {
		return account, fmt.Errorf("error deriving coin type key: %v", err)
	}

	// 派生 account 层级 (默认账户 0)
	accountKey, err := coinTypeKey.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return account, fmt.Errorf("error deriving account key: %v", err)
	}

	// 派生 change 层级 (外部链 0)
	changeKey, err := accountKey.Derive(0)
	if err != nil {
		return account, fmt.Errorf("error deriving change key: %v", err)
	}

	// 派生 address index 层级 (第一个地址 0)
	addressKey, err := changeKey.Derive(0)
	if err != nil {
		return account, fmt.Errorf("error deriving address key: %v", err)
	}

	// 获取私钥和公钥
	privateKey, err := addressKey.ECPrivKey()
	if err != nil {
		return account, fmt.Errorf("error getting private key: %v", err)
	}

	publicKey := privateKey.PubKey()

	// 设置HD路径和派生路径
	account.HDPath = fmt.Sprintf("m/%d'/%d'/%d'/0", purpose, coinType, 0)
	account.DerivationPath = fmt.Sprintf("m/%d'/%d'/%d'/0/0", purpose, coinType, 0)

	// 根据账户类型生成相应地址
	var address string
	var err2 error

	switch accountType {
	case "legacy":
		address, err2 = generateP2PKHAddress(publicKey, params)
	case "segwit":
		address, err2 = generateP2WPKHAddress(publicKey, params)
	case "nested-segwit":
		address, err2 = generateP2SHAddress(publicKey, params)
	case "taproot":
		address, err2 = generateP2TRAddress(publicKey, params)
	default:
		return account, fmt.Errorf("unsupported account type: %s", accountType)
	}

	if err2 != nil {
		return account, fmt.Errorf("error generating address for %s: %v", accountType, err2)
	}

	account.Address = address
	return account, nil
}

// 解析输出字符串
func parseOutputTargets(outputStr string) ([]OutputTarget, error) {
	if outputStr == "" {
		return nil, fmt.Errorf("output locations cannot be empty")
	}

	var targets []OutputTarget
	outputs := strings.Split(outputStr, ",")

	for _, out := range outputs {
		out = strings.TrimSpace(out)

		// 检查是否是云存储提供商
		isCloudProvider := false
		for _, provider := range util.CLOUD_PROVIDERS {
			if out == provider {
				targets = append(targets, OutputTarget{Method: out, Path: ""})
				isCloudProvider = true
				break
			}
		}

		// 如果不是云存储提供商，则视为本地文件路径
		if !isCloudProvider {
			targets = append(targets, OutputTarget{Method: "fs", Path: out})
		}
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid output targets found")
	}

	return targets, nil
}
