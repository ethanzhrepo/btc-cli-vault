package cmd

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethanzhrepo/btc-cli-vault/util"
	"github.com/spf13/cobra"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/term"
)

// SignMessageCmd creates the message signing command
func SignMessageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign-message",
		Short: "Sign a Bitcoin message",
		Long:  `Sign a text message using a private key from a Bitcoin wallet.`,
		RunE:  runSignMessage,
	}

	// Add flags
	cmd.Flags().StringP("data", "d", "", "Message to sign")
	cmd.Flags().String("data-file", "", "Path to file containing message to sign")
	cmd.Flags().StringP("provider", "p", "", "Key provider (e.g., google)")
	cmd.Flags().StringP("name", "n", "", "Name of the wallet file (for cloud storage)")
	cmd.Flags().StringP("file", "f", "", "Local wallet file path")
	cmd.Flags().Bool("schnorr", false, "Use Schnorr signature (BIP340) instead of ECDSA")

	return cmd
}

// formatBitcoinMessage formats a message according to the Bitcoin signed message format
// Implementation based on Bitcoin Core's approach
func formatBitcoinMessage(message string) []byte {
	var buf bytes.Buffer

	// Write the magic bytes
	buf.WriteString("\x18Bitcoin Signed Message:\n")

	// Write the message length as a varint
	writeVarInt(&buf, uint64(len(message)))

	// Write the message
	buf.WriteString(message)

	// Double SHA256 hash
	hash := sha256.Sum256(buf.Bytes())
	hash = sha256.Sum256(hash[:])

	return hash[:]
}

// writeVarInt writes a variable length integer to the buffer
func writeVarInt(w *bytes.Buffer, val uint64) {
	if val < 0xfd {
		// Single byte encoding
		w.WriteByte(byte(val))
	} else if val <= 0xffff {
		// 3-byte encoding (marker + 2 bytes)
		w.WriteByte(0xfd)
		binary.Write(w, binary.LittleEndian, uint16(val))
	} else if val <= 0xffffffff {
		// 5-byte encoding (marker + 4 bytes)
		w.WriteByte(0xfe)
		binary.Write(w, binary.LittleEndian, uint32(val))
	} else {
		// 9-byte encoding (marker + 8 bytes)
		w.WriteByte(0xff)
		binary.Write(w, binary.LittleEndian, val)
	}
}

// runSignMessage is the main function that handles the sign-message command execution
func runSignMessage(cmd *cobra.Command, args []string) error {
	// Get command flags
	message, _ := cmd.Flags().GetString("data")
	dataFile, _ := cmd.Flags().GetString("data-file")
	provider, _ := cmd.Flags().GetString("provider")
	name, _ := cmd.Flags().GetString("name")
	file, _ := cmd.Flags().GetString("file")
	useSchnorr, _ := cmd.Flags().GetBool("schnorr")

	// Check that we have a message to sign
	if message == "" && dataFile == "" {
		return fmt.Errorf("either --data or --data-file is required")
	}

	// If data-file is provided, read message from file
	if dataFile != "" {
		data, err := os.ReadFile(dataFile) // Using os.ReadFile instead of ioutil.ReadFile
		if err != nil {
			return fmt.Errorf("error reading data file: %v", err)
		}
		message = string(data)
	}

	// Check we have a wallet source
	if provider == "" && name == "" && file == "" {
		return fmt.Errorf("either --provider/--name or --file is required")
	}

	var privateKey *btcec.PrivateKey
	var address string
	var params *chaincfg.Params
	var wallet WalletFile

	// Get wallet data
	var walletData []byte
	var err error

	// Get wallet data from provider or file
	if file != "" {
		// Load from local file
		walletData, err = util.Get(file, file)
		if err != nil {
			return fmt.Errorf("error loading wallet from file: %v", err)
		}
	} else if provider != "" {
		// Check that name is provided for cloud storage
		if name == "" {
			return fmt.Errorf("--name is required when using cloud storage providers")
		}

		// Load from cloud provider
		isCloudProvider := false
		for _, p := range util.CLOUD_PROVIDERS {
			if provider == p {
				isCloudProvider = true
				break
			}
		}

		if !isCloudProvider {
			return fmt.Errorf("unsupported provider: %s", provider)
		}

		cloudPath := filepath.Join(util.GetCloudFileDir(), name+".json")
		walletData, err = util.Get(provider, cloudPath)
		if err != nil {
			return fmt.Errorf("error loading wallet from %s: %v", provider, err)
		}
	}

	// Parse wallet file
	if err := json.Unmarshal(walletData, &wallet); err != nil {
		return fmt.Errorf("error parsing wallet file: %v", err)
	}

	// Set network parameters
	if wallet.TestNet {
		params = &chaincfg.TestNet3Params
		fmt.Println("Using TESTNET")
	} else {
		params = &chaincfg.MainNetParams
		fmt.Println("Using MAINNET")
	}

	// Get password and decrypt mnemonic
	fmt.Print("Please Enter Wallet Password: ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("error reading password: %v", err)
	}
	fmt.Println()
	password := string(passwordBytes)

	// Decrypt mnemonic
	mnemonic, err := util.DecryptMnemonic(wallet.EncryptedMnemonic, password)
	if err != nil {
		return fmt.Errorf("error decrypting mnemonic: %v", err)
	}

	// Ask for BIP39 passphrase
	fmt.Print("Did you use a BIP39 passphrase for this wallet? (y/n): ")
	var answer string
	fmt.Scanln(&answer)

	var passphrase string
	if strings.ToLower(answer) == "y" || strings.ToLower(answer) == "yes" {
		fmt.Print("Please Enter BIP39 Passphrase: ")
		passphraseBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("error reading passphrase: %v", err)
		}
		fmt.Println()
		passphrase = string(passphraseBytes)
	}

	// Generate seed from mnemonic
	seed := bip39.NewSeed(mnemonic, passphrase)

	// Display available accounts for the user to choose from
	if len(wallet.Accounts) == 0 {
		return fmt.Errorf("no accounts found in the wallet")
	}

	// Filter accounts to only show supported types (legacy P2PKH and SegWit P2WPKH)
	var supportedAccounts []AccountInfo
	for _, account := range wallet.Accounts {
		if account.Type == "legacy" || account.Type == "segwit" || account.Type == "p2pkh" || account.Type == "p2wpkh" {
			supportedAccounts = append(supportedAccounts, account)
		}
	}

	if len(supportedAccounts) == 0 {
		return fmt.Errorf("no supported account types found in the wallet. Sign message only supports P2PKH (Legacy) and P2WPKH (SegWit) addresses")
	}

	fmt.Println("\nAvailable addresses to sign with:")
	fmt.Println("----------------------------------")

	// Create a map for account types to display names
	accountTypeNames := map[string]string{
		"legacy": "P2PKH (Legacy)",
		"segwit": "P2WPKH (SegWit)",
		"p2pkh":  "P2PKH (Legacy)",
		"p2wpkh": "P2WPKH (SegWit)",
	}

	// Display available accounts
	for i, account := range supportedAccounts {
		displayName, ok := accountTypeNames[account.Type]
		if !ok {
			displayName = account.Type
		}
		fmt.Printf("%d) %s: %s\n", i+1, displayName, account.Address)
	}

	// Ask the user to choose an account
	var selectedIndex int
	for {
		fmt.Print("\nSelect address to sign with (1-" + strconv.Itoa(len(supportedAccounts)) + "): ")
		reader := bufio.NewReader(os.Stdin)
		indexStr, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("error reading input: %v", err)
		}

		// Trim whitespace
		indexStr = strings.TrimSpace(indexStr)

		// Parse the index
		selectedIndex, err = strconv.Atoi(indexStr)
		if err != nil || selectedIndex < 1 || selectedIndex > len(supportedAccounts) {
			fmt.Println("Invalid selection. Please enter a number between 1 and", len(supportedAccounts))
			continue
		}

		// Adjust for 0-based indexing
		selectedIndex--
		break
	}

	// Get the selected account
	targetAccount := supportedAccounts[selectedIndex]
	address = targetAccount.Address
	accountType := targetAccount.Type

	// Check if selected account type supports Schnorr signatures
	if useSchnorr && accountType != "taproot" {
		fmt.Println("\nWarning: Schnorr signatures are only supported for Taproot (P2TR) addresses.")
		fmt.Println("Continuing with ECDSA signature instead.")
		useSchnorr = false
	}

	// Derive the private key using the path from the target account
	masterKey, err := hdkeychain.NewMaster(seed, params)
	if err != nil {
		return fmt.Errorf("error creating master key: %v", err)
	}

	// Derive the extended key using the derivation path
	extendedKey, err := DeriveKeyFromPath(masterKey, targetAccount.DerivationPath)
	if err != nil {
		return fmt.Errorf("error deriving key: %v", err)
	}

	// Get the EC private key from the extended key
	privateKey, err = extendedKey.ECPrivKey()
	if err != nil {
		return fmt.Errorf("error getting private key: %v", err)
	}

	// Modern Bitcoin wallets (BIP32/44/49/84/86) use compressed public keys by default
	compressed := true

	// Format the message according to the Bitcoin message format
	messageHash := formatBitcoinMessage(message)

	// Sign the message
	var signatureBase64 string
	if useSchnorr {
		// Schnorr signature (BIP340)
		sig, err := schnorr.Sign(privateKey, messageHash)
		if err != nil {
			return fmt.Errorf("error creating Schnorr signature: %v", err)
		}

		// Serialize the Schnorr signature
		signatureBase64 = base64.StdEncoding.EncodeToString(sig.Serialize())
	} else {
		// ECDSA signature using SignCompact which handles recovery ID correctly
		// SignCompact creates a signature in the proper Bitcoin format: [Header][R][S]
		// where header = 27 + recoveryID + (4 if compressed)
		sigBytes := ecdsa.SignCompact(privateKey, messageHash, compressed)

		// sigBytes is already in the format [Header (1 byte)][R (32 bytes)][S (32 bytes)]
		signatureBase64 = base64.StdEncoding.EncodeToString(sigBytes)
	}

	// Display the results
	fmt.Println("\nMessage Signing Result:")
	fmt.Println("----------------------------------------")
	fmt.Printf("Address: %s\n", address)
	fmt.Printf("Message: %s\n", message)
	fmt.Printf("Signature: %s\n", signatureBase64)
	fmt.Println("----------------------------------------")

	// Print verification command example
	fmt.Println("To verify this signature:")
	fmt.Println("  bitcoin-cli verifymessage", address, signatureBase64, "\""+message+"\"")
	fmt.Println("Or use a Bitcoin message verification tool online.")

	return nil
}
