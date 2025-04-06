package cmd

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/ethanzhrepo/btc-cli-vault/util"
	"github.com/spf13/cobra"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/term"
)

// TransferBTCCmd creates the BTC transfer command
func TransferBTCCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "transfer",
		Short: "Transfer BTC to another address",
		Long:  `Transfer Bitcoin to another Bitcoin address.`,
		RunE:  runTransferBTC,
	}

	cmd.Flags().StringP("amount", "a", "", "Amount of BTC to transfer (with unit e.g., 1.0btc, 10000sat)")
	cmd.Flags().StringP("to", "t", "", "Destination Bitcoin address")
	cmd.Flags().StringP("provider", "p", "", "Key provider (e.g., google)")
	cmd.Flags().StringP("name", "n", "", "Name of the wallet file (for cloud storage)")
	cmd.Flags().StringP("file", "f", "", "Local wallet file path")
	cmd.Flags().Bool("dry-run", false, "Only encode the transaction, do not broadcast")
	cmd.Flags().Bool("fee-only", false, "Only display fee estimation")
	cmd.Flags().BoolP("yes", "y", false, "Automatically confirm the transaction")
	cmd.Flags().Uint64("fee-rate", 0, "Fee rate in satoshis per byte (0 for auto-selection)")
	cmd.Flags().StringP("fee-preference", "", "normal", "Fee preference when auto-selecting (fastest, fast, normal, economic, minimum)")
	cmd.Flags().StringP("api", "R", "", "Bitcoin node RPC URL (overrides config)")
	cmd.Flags().Bool("testnet", false, "Use Bitcoin testnet instead of mainnet")

	cmd.MarkFlagRequired("amount")
	cmd.MarkFlagRequired("to")

	return cmd
}

func runTransferBTC(cmd *cobra.Command, args []string) error {
	// Parse basic flags
	toAddress, _ := cmd.Flags().GetString("to")
	amountStr, _ := cmd.Flags().GetString("amount")
	provider, _ := cmd.Flags().GetString("provider")
	name, _ := cmd.Flags().GetString("name")
	filePath, _ := cmd.Flags().GetString("file")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	feeOnly, _ := cmd.Flags().GetBool("fee-only")
	autoConfirm, _ := cmd.Flags().GetBool("yes")
	feeRate, _ := cmd.Flags().GetUint64("fee-rate")
	feePreference, _ := cmd.Flags().GetString("fee-preference")
	apiURL, _ := cmd.Flags().GetString("api")
	testnet, _ := cmd.Flags().GetBool("testnet")

	// Initialize config
	initConfig()

	// Set network parameters based on testnet flag
	params := &chaincfg.MainNetParams // Default to mainnet
	if testnet {
		params = &chaincfg.TestNet3Params
		fmt.Println("Using testnet network")
	}

	// Validate destination address with the appropriate network
	err := util.ValidateBitcoinAddress(toAddress, params == &chaincfg.TestNet3Params)
	if err != nil {
		return fmt.Errorf("invalid destination address: %v", err)
	}

	// Load wallet data
	var walletData []byte
	if provider != "" {
		// Cloud storage provider
		if name == "" {
			return fmt.Errorf("wallet name is required when using cloud storage")
		}
		cloudPath := filepath.Join(util.DEFAULT_CLOUD_FILE_DIR, name+".json")
		walletData, err = util.Get(provider, cloudPath)
		if err != nil {
			return fmt.Errorf("error loading wallet from %s: %v", provider, err)
		}
		fmt.Printf("Loaded wallet from %s cloud storage: %s\n", provider, name)
	} else if filePath != "" {
		// Local file
		walletData, err = util.Get(filePath, filePath)
		if err != nil {
			return fmt.Errorf("error loading wallet from local file: %v", err)
		}
		fmt.Printf("Loaded wallet from local file: %s\n", filePath)
	} else {
		return fmt.Errorf("either --provider and --name or --file must be specified")
	}

	// Parse wallet file
	var wallet WalletFile
	if err := json.Unmarshal(walletData, &wallet); err != nil {
		return fmt.Errorf("error parsing wallet file: %v", err)
	}

	// Check if we need to switch networks based on wallet settings
	// Only switch from mainnet to testnet, not the other way around
	if wallet.TestNet && params == &chaincfg.MainNetParams {
		params = &chaincfg.TestNet3Params
		fmt.Println("Wallet is configured for testnet, using testnet network")
	} else if !wallet.TestNet && params == &chaincfg.TestNet3Params {
		// Warn but don't automatically switch to mainnet
		fmt.Println("WARNING: Using testnet with a mainnet wallet. This is likely not what you want.")
		fmt.Println("If you meant to use mainnet, run without the --testnet flag.")
	}

	// Get password
	fmt.Print("Please Enter \033[1;31mEncryption Password\033[0m: ")
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
	fmt.Println("\033[1;32m✓ Wallet decrypted successfully\033[0m")

	// Ask if a passphrase was used
	fmt.Print("Did you use a BIP39 passphrase for this wallet? (y/n): ")
	var answer string
	fmt.Scanln(&answer)

	var passphrase string
	if strings.ToLower(answer) == "y" || strings.ToLower(answer) == "yes" {
		fmt.Print("Please Enter \033[1;31mBIP39 Passphrase\033[0m: ")
		passphraseBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("error reading passphrase: %v", err)
		}
		fmt.Println()
		passphrase = string(passphraseBytes)
	}

	// Generate seed from mnemonic
	seed := bip39.NewSeed(mnemonic, passphrase)

	// Display available addresses from the wallet
	if len(wallet.Accounts) == 0 {
		return fmt.Errorf("no accounts found in wallet")
	}

	fmt.Println("\n\033[1;36mAvailable addresses in wallet:\033[0m")
	for i, account := range wallet.Accounts {
		var accountType string
		switch account.Type {
		case "p2pkh", "legacy":
			accountType = "P2PKH (Legacy)"
		case "p2wpkh", "segwit":
			accountType = "P2WPKH (SegWit)"
		case "p2sh-p2wpkh", "nested-segwit":
			accountType = "P2SH-P2WPKH (Nested SegWit)"
		case "p2tr", "taproot":
			accountType = "P2TR (Taproot)"
		default:
			accountType = account.Type
		}
		fmt.Printf("%d. \033[1;32m%s\033[0m [%s]\n", i+1, account.Address, accountType)
	}

	// Let user select an address
	var selectedIdx int
	for {
		fmt.Print("\nSelect an address to send from (enter number): ")
		var idxStr string
		fmt.Scanln(&idxStr)
		idx, err := strconv.Atoi(idxStr)
		if err != nil || idx < 1 || idx > len(wallet.Accounts) {
			fmt.Println("Invalid selection. Please try again.")
			continue
		}
		selectedIdx = idx - 1
		break
	}

	selectedAccount := wallet.Accounts[selectedIdx]
	fmt.Printf("Selected address: \033[1;32m%s\033[0m\n", selectedAccount.Address)

	// Show additional account information
	fmt.Printf("Account type: \033[1;36m%s\033[0m\n", selectedAccount.Type)

	// 验证选择的账户包含必要的派生路径
	if selectedAccount.DerivationPath == "" && selectedAccount.HDPath == "" {
		return fmt.Errorf("\033[1;31mError: Selected account does not have a derivation path.\033[0m\nThis wallet cannot be used for transactions until a proper derivation path is added.")
	}

	// 显示派生路径
	derivationPath := selectedAccount.DerivationPath
	if derivationPath == "" {
		derivationPath = selectedAccount.HDPath
	}
	fmt.Printf("Derivation path: \033[1;36m%s\033[0m\n", derivationPath)

	// Safety check for P2SH-P2WPKH accounts - verify redeem script is present
	if (selectedAccount.Type == "p2sh-p2wpkh" || selectedAccount.Type == "nested-segwit") && selectedAccount.RedeemScript == "" {
		return fmt.Errorf("\033[1;31mError: Missing redeem script for P2SH-P2WPKH account.\033[0m\nThis wallet cannot be used for transactions until the redeem script is added to the wallet file.")
	}

	// Safety check for P2TR accounts - verify internal pubkey is present
	if (selectedAccount.Type == "p2tr" || selectedAccount.Type == "taproot") && selectedAccount.InternalPubKey == "" {
		return fmt.Errorf("\033[1;31mError: Missing internal pubkey for Taproot account.\033[0m\nThis wallet cannot be used for transactions until the internal pubkey is added to the wallet file.")
	}

	if selectedAccount.Type == "p2sh-p2wpkh" && selectedAccount.RedeemScript != "" {
		fmt.Printf("Redeem script: %s\n", selectedAccount.RedeemScript)
	}

	if (selectedAccount.Type == "p2tr" || selectedAccount.Type == "taproot") && selectedAccount.InternalPubKey != "" {
		fmt.Printf("Internal pubkey: %s\n", selectedAccount.InternalPubKey)
	}

	// Parse amount
	amountSat, err := parseAmount(amountStr)
	if err != nil {
		return fmt.Errorf("invalid amount: %v", err)
	}
	fmt.Printf("\nAmount to send: \033[1;33m%.8f BTC\033[0m (%s)\n", float64(amountSat)/100000000, formatSatoshis(amountSat))

	// Verify destination address
	fmt.Printf("Sending to: \033[1;32m%s\033[0m\n", toAddress)

	// Get UTXOs for the selected address
	fmt.Printf("\nFetching UTXOs for address %s...\n", selectedAccount.Address)
	utxos, err := util.FetchUTXOsWithOptions(selectedAccount.Address, apiURL, params == &chaincfg.TestNet3Params, true)
	if err != nil {
		return fmt.Errorf("error fetching UTXOs: %v", err)
	}

	if len(utxos) == 0 {
		return fmt.Errorf("no UTXOs found for address %s", selectedAccount.Address)
	}

	fmt.Printf("Found %d UTXOs for address %s\n", len(utxos), selectedAccount.Address)

	// Display balance information
	totalBalance := uint64(0)
	for _, utxo := range utxos {
		totalBalance += utxo.Value
	}
	fmt.Printf("Total balance: \033[1;33m%.8f BTC\033[0m (%s)\n",
		float64(totalBalance)/100000000, formatSatoshis(totalBalance))

	// Get the appropriate fee rate
	if feeRate == 0 {
		// Convert string preference to enum
		var prefEnum util.FeePreference
		switch strings.ToLower(feePreference) {
		case "fastest":
			prefEnum = util.FeeFastest
		case "fast":
			prefEnum = util.FeeFast
		case "normal":
			prefEnum = util.FeeNormal
		case "economic":
			prefEnum = util.FeeEconomic
		case "minimum":
			prefEnum = util.FeeMinimum
		default:
			prefEnum = util.FeeNormal
		}

		feeRate, err = util.GetRecommendedFeeRate(prefEnum, apiURL, params == &chaincfg.TestNet3Params)
		if err != nil {
			return fmt.Errorf("error getting fee rate: %v", err)
		}

		fmt.Printf("Using recommended fee rate (%s): \033[1;36m%d sat/byte\033[0m\n",
			feePreference, feeRate)
	} else {
		fmt.Printf("Using custom fee rate: \033[1;36m%d sat/byte\033[0m\n", feeRate)
	}

	// Prepare private key for signing
	privateKey, err := derivePrivateKeyForAccount(seed, selectedAccount, params)
	if err != nil {
		return fmt.Errorf("error deriving private key: %v", err)
	}

	// Calculate maximum fee we're willing to pay (10% of amount by default, min 1000 sats)
	maxFeeLimit := amountSat / 10
	if maxFeeLimit < 1000 {
		maxFeeLimit = 1000 // Minimum 1000 satoshis
	}

	// Select UTXOs for transaction
	fmt.Println("\nSelecting optimal UTXOs for transaction...")
	utxoResult, err := util.CreateUTXOsWithChangeAddr(
		utxos,
		amountSat,
		maxFeeLimit,
		feeRate,
		false, // Use both confirmed and unconfirmed UTXOs
		toAddress,
		selectedAccount.Address, // Send change back to sender
		params == &chaincfg.TestNet3Params,
	)

	if err != nil {
		return fmt.Errorf("error selecting UTXOs: %v", err)
	}

	// Display fee information
	fmt.Printf("\n\033[1;36mTransaction Details:\033[0m\n")
	fmt.Printf("From: \033[1;32m%s\033[0m\n", selectedAccount.Address)
	fmt.Printf("To: \033[1;32m%s\033[0m\n", toAddress)
	fmt.Printf("Amount: \033[1;33m%.8f BTC\033[0m (%s)\n",
		float64(amountSat)/100000000, formatSatoshis(amountSat))
	fmt.Printf("Fee: \033[1;33m%.8f BTC\033[0m (%s)\n",
		float64(utxoResult.Fee)/100000000, formatSatoshis(utxoResult.Fee))
	fmt.Printf("Fee Rate: \033[1;36m%d sat/byte\033[0m\n", feeRate)

	// Calculate effective fee percentage
	if amountSat > 0 {
		feePercent := float64(utxoResult.Fee) / float64(amountSat) * 100
		fmt.Printf("Fee percentage: \033[1;36m%.2f%%\033[0m of amount\n", feePercent)
	}

	if utxoResult.Change > 0 {
		fmt.Printf("Change: \033[1;33m%.8f BTC\033[0m (%s) returned to sender\n",
			float64(utxoResult.Change)/100000000, formatSatoshis(utxoResult.Change))
	}

	// Display selected UTXOs
	fmt.Printf("\n\033[1;36mSelected UTXOs:\033[0m\n")
	for i, utxo := range utxoResult.SelectedUTXOs {
		fmt.Printf("%d. %s:%d - \033[1;33m%.8f BTC\033[0m (%s)\n",
			i+1, utxo.Txid, utxo.Vout,
			float64(utxo.Value)/100000000, formatSatoshis(utxo.Value))

		// Show confirmation status
		if utxo.Status.Confirmed {
			fmt.Printf("   \033[1;32m✓ Confirmed\033[0m (Block height: %d)\n", utxo.Status.BlockHeight)
		} else {
			fmt.Printf("   \033[1;33m⟳ Unconfirmed\033[0m\n")
		}
	}

	// If fee-only, stop here
	if feeOnly {
		fmt.Println("\nFee estimation complete. Use --fee-only=false to create and broadcast transaction.")
		return nil
	}

	// Create and sign transaction
	fmt.Println("\nCreating and signing transaction...")
	signedTx, err := createAndSignTransaction(privateKey, utxoResult, toAddress, selectedAccount.Address, amountSat, params, selectedAccount)
	if err != nil {
		return fmt.Errorf("error creating transaction: %v", err)
	}

	// Calculate transaction size and real fee rate
	var txBuf bytes.Buffer
	signedTx.Serialize(&txBuf)
	txSize := txBuf.Len()
	txWeight := signedTx.SerializeSizeStripped()*3 + txSize // vSize calculation
	vSize := (txWeight + 3) / 4                             // Round up
	realFeeRate := float64(utxoResult.Fee) / float64(vSize)

	fmt.Printf("\nTransaction size: \033[1;36m%d bytes\033[0m (weight: %d, vsize: %d)\n",
		txSize, txWeight, vSize)
	fmt.Printf("Actual fee rate: \033[1;36m%.2f sat/byte\033[0m\n", realFeeRate)

	// Serialize transaction for broadcasting
	var signedTxHex string
	if signedTx != nil {
		var buf strings.Builder
		err = signedTx.Serialize(&hexWriter{&buf})
		if err != nil {
			return fmt.Errorf("error serializing transaction: %v", err)
		}
		signedTxHex = buf.String()
	}

	// Display raw transaction hex
	if dryRun {
		fmt.Printf("\nRaw Transaction (hex):\n\033[0;37m%s\033[0m\n", signedTxHex)
		fmt.Println("\nDry run complete. Use --dry-run=false to broadcast transaction.")
		return nil
	}

	// Ask for confirmation before broadcasting
	if !autoConfirm {
		fmt.Print("\n\033[1;31mDo you want to broadcast this transaction? (y/n): \033[0m")
		var confirmation string
		fmt.Scanln(&confirmation)
		if strings.ToLower(confirmation) != "y" && strings.ToLower(confirmation) != "yes" {
			fmt.Println("Transaction cancelled.")
			return nil
		}
	}

	// Broadcast transaction
	fmt.Println("\nBroadcasting transaction...")
	txid, err := util.BroadcastRawTransaction(signedTxHex, apiURL, params == &chaincfg.TestNet3Params)
	if err != nil {
		return fmt.Errorf("error broadcasting transaction: %v", err)
	}

	fmt.Printf("\n\033[1;32m✅ Transaction successfully broadcast!\033[0m\n")
	fmt.Printf("Transaction ID: \033[1;36m%s\033[0m\n", txid)

	// Display transaction explorer link if available
	if params == &chaincfg.TestNet3Params {
		fmt.Printf("Track your transaction: https://mempool.space/testnet/tx/%s\n", txid)
	} else {
		fmt.Printf("Track your transaction: https://mempool.space/tx/%s\n", txid)
	}

	return nil
}

// formatSatoshis formats a satoshi amount with thousands separators
func formatSatoshis(amount uint64) string {
	// Convert to string
	amountStr := strconv.FormatUint(amount, 10)

	// Add thousands separators
	var result strings.Builder
	for i, c := range amountStr {
		if i > 0 && (len(amountStr)-i)%3 == 0 {
			result.WriteRune(',')
		}
		result.WriteRune(c)
	}

	return result.String() + " sats"
}

// hexWriter implements an io.Writer that converts bytes to hex
type hexWriter struct {
	w io.Writer
}

func (hw *hexWriter) Write(p []byte) (n int, err error) {
	for _, b := range p {
		_, err = fmt.Fprintf(hw.w, "%02x", b)
		if err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// parseAmount parses an amount string into satoshis with high precision
func parseAmount(amount string) (uint64, error) {
	amount = strings.ToLower(strings.TrimSpace(amount))

	if strings.HasSuffix(amount, "btc") {
		// Remove the btc suffix
		btcAmount := strings.TrimSuffix(amount, "btc")
		return parseBtcToSatoshis(btcAmount)
	} else if strings.HasSuffix(amount, "sat") {
		// Direct satoshi amount
		satAmount := strings.TrimSuffix(amount, "sat")
		sat, err := strconv.ParseUint(satAmount, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid satoshi amount: %v", err)
		}
		return sat, nil
	} else {
		// Assume it's BTC format without suffix
		return parseBtcToSatoshis(amount)
	}
}

// parseBtcToSatoshis converts a BTC amount string to satoshis with high precision
func parseBtcToSatoshis(btcAmount string) (uint64, error) {
	// Split into whole and fractional parts
	parts := strings.Split(btcAmount, ".")

	if len(parts) > 2 {
		return 0, fmt.Errorf("invalid BTC amount format: %s", btcAmount)
	}

	var wholePart, fractionalPart uint64
	var err error

	// Parse the whole part
	if parts[0] != "" {
		wholePart, err = strconv.ParseUint(parts[0], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid whole part of BTC amount: %v", err)
		}
		// Convert whole BTC to satoshis (1 BTC = 100,000,000 satoshis)
		wholePart *= 100000000
	}

	// Parse the fractional part if it exists
	if len(parts) == 2 && parts[1] != "" {
		// Pad with zeros to 8 decimal places if needed
		fractionalStr := parts[1]
		if len(fractionalStr) > 8 {
			return 0, fmt.Errorf("BTC amount has too many decimal places (max 8): %s", btcAmount)
		}

		fractionalStr = fractionalStr + strings.Repeat("0", 8-len(fractionalStr))

		// Now we can safely parse as an integer
		fractionalPart, err = strconv.ParseUint(fractionalStr, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid fractional part of BTC amount: %v", err)
		}
	}

	// Sum the components
	totalSatoshis := wholePart + fractionalPart

	return totalSatoshis, nil
}

// derivePrivateKeyForAccount derives the private key for a specific account
func derivePrivateKeyForAccount(seed []byte, account AccountInfo, params *chaincfg.Params) (*btcec.PrivateKey, error) {
	// Create a master key from the seed using the correct network parameters
	masterKey, err := hdkeychain.NewMaster(seed, params)
	if err != nil {
		return nil, fmt.Errorf("error creating master key: %v", err)
	}

	// If the account has a derivation path, use it to derive the key
	if account.DerivationPath != "" {
		// Derive key from the path
		key, err := DeriveKeyFromPath(masterKey, account.DerivationPath)
		if err != nil {
			return nil, fmt.Errorf("error deriving key from path: %v", err)
		}

		// Extract the private key
		ecPrivKey, err := key.ECPrivKey()
		if err != nil {
			return nil, fmt.Errorf("error getting private key: %v", err)
		}

		// Convert to btcec.PrivateKey
		return ecPrivKey, nil
	} else if account.HDPath != "" {
		// Use HDPath if DerivationPath is not available
		key, err := DeriveKeyFromPath(masterKey, account.HDPath)
		if err != nil {
			return nil, fmt.Errorf("error deriving key from HD path: %v", err)
		}

		// Extract the private key
		ecPrivKey, err := key.ECPrivKey()
		if err != nil {
			return nil, fmt.Errorf("error getting private key: %v", err)
		}

		// Convert to btcec.PrivateKey
		return ecPrivKey, nil
	}

	// 不再支持没有明确派生路径的钱包
	return nil, fmt.Errorf("missing derivation path in wallet account: either DerivationPath or HDPath must be specified")
}

// createAndSignTransaction creates and signs a Bitcoin transaction
func createAndSignTransaction(
	privateKey *btcec.PrivateKey,
	utxoResult *util.CoinSelectionResult,
	toAddress string,
	fromAddress string,
	amount uint64,
	params *chaincfg.Params,
	selectedAccount AccountInfo,
) (*wire.MsgTx, error) {
	// Create a new transaction
	tx := wire.NewMsgTx(wire.TxVersion)

	// Map to store UTXO information for signing
	prevOuts := make(map[wire.OutPoint]*wire.TxOut)

	// Add inputs
	for _, utxo := range utxoResult.SelectedUTXOs {
		txHash, err := chainhash.NewHashFromStr(utxo.Txid)
		if err != nil {
			return nil, fmt.Errorf("invalid transaction hash: %v", err)
		}

		outPoint := wire.NewOutPoint(txHash, utxo.Vout)
		txIn := wire.NewTxIn(outPoint, nil, nil)

		// Set sequence to enable RBF (Replace-By-Fee) by default
		// This allows the transaction to be replaced with higher fee version if needed
		txIn.Sequence = 0xFFFFFFFD

		tx.AddTxIn(txIn)

		// Store UTXO info for later signing
		pkScript := utxo.PkScriptBytes
		if len(pkScript) == 0 && utxo.PkScript != "" {
			var decodeErr error
			pkScript, decodeErr = hex.DecodeString(utxo.PkScript)
			if decodeErr != nil {
				return nil, fmt.Errorf("error decoding script for input: %v", decodeErr)
			}
		}

		// Store previous output information for the sighash calculation
		prevOuts[*outPoint] = wire.NewTxOut(int64(utxo.Value), pkScript)
	}

	// Add output - payment to recipient
	destAddr, err := btcutil.DecodeAddress(toAddress, params)
	if err != nil {
		return nil, fmt.Errorf("invalid destination address: %v", err)
	}

	destScript, err := txscript.PayToAddrScript(destAddr)
	if err != nil {
		return nil, fmt.Errorf("error creating output script: %v", err)
	}

	tx.AddTxOut(wire.NewTxOut(int64(amount), destScript))

	// Add change output if needed
	if utxoResult.Change > 0 {
		changeAddr, err := btcutil.DecodeAddress(fromAddress, params)
		if err != nil {
			return nil, fmt.Errorf("invalid change address: %v", err)
		}

		changeScript, err := txscript.PayToAddrScript(changeAddr)
		if err != nil {
			return nil, fmt.Errorf("error creating change script: %v", err)
		}

		tx.AddTxOut(wire.NewTxOut(int64(utxoResult.Change), changeScript))
	}

	// Create the previous output fetcher for sighash calculation
	prevOutFetcher := txscript.NewMultiPrevOutFetcher(prevOuts)

	// Prepare scripts based on account type
	var redeemScript []byte
	var taprootInternalKey []byte

	// Based on the account type, prepare necessary scripts
	switch selectedAccount.Type {
	case "p2sh-p2wpkh", "nested-segwit":
		// Decode redeem script from account if available
		if selectedAccount.RedeemScript != "" {
			var err error
			redeemScript, err = hex.DecodeString(selectedAccount.RedeemScript)
			if err != nil {
				return nil, fmt.Errorf("error decoding redeem script from account: %v", err)
			}
		} else {
			// No fallback - require the redeem script to be present in the wallet
			return nil, fmt.Errorf("missing redeem script for P2SH-P2WPKH account - redeem script must be provided in the wallet file")
		}
	case "p2tr", "taproot":
		// For Taproot, decode the internal pubkey if available
		if selectedAccount.InternalPubKey != "" {
			var err error
			taprootInternalKey, err = hex.DecodeString(selectedAccount.InternalPubKey)
			if err != nil {
				return nil, fmt.Errorf("error decoding Taproot internal key: %v", err)
			}
			// Validate the key is 32 bytes
			if len(taprootInternalKey) != 32 {
				return nil, fmt.Errorf("invalid Taproot internal key length: %d (expected 32)", len(taprootInternalKey))
			}
		}
	}

	// Sign each input
	for i, utxo := range utxoResult.SelectedUTXOs {
		// Decode script from UTXO
		pkScript := utxo.PkScriptBytes
		if len(pkScript) == 0 && utxo.PkScript != "" {
			var err error
			pkScript, err = hex.DecodeString(utxo.PkScript)
			if err != nil {
				return nil, fmt.Errorf("error decoding script for input %d: %v", i, err)
			}
		}

		// Determine script type to apply appropriate signing method
		scriptClass := txscript.GetScriptClass(pkScript)

		var sigScript []byte
		var witnessData [][]byte
		var err error

		// Handle different script types based on account type and UTXO script class
		switch {
		// Native SegWit (P2WPKH)
		case scriptClass == txscript.WitnessV0PubKeyHashTy && (selectedAccount.Type == "p2wpkh" || selectedAccount.Type == "segwit"):
			witnessData, err = txscript.WitnessSignature(tx, txscript.NewTxSigHashes(tx, prevOutFetcher),
				i, int64(utxo.Value), pkScript, txscript.SigHashAll, privateKey, true)
			if err != nil {
				return nil, fmt.Errorf("error creating witness signature for input %d: %v", i, err)
			}
			tx.TxIn[i].Witness = witnessData

		// Taproot (P2TR)
		case scriptClass == txscript.WitnessV1TaprootTy && (selectedAccount.Type == "p2tr" || selectedAccount.Type == "taproot"):
			// For P2TR, we need special signing
			// Currently, we only support key path spending (not script path)

			// Safety check: Verify the internal key is available for Taproot
			if taprootInternalKey == nil || len(taprootInternalKey) != 32 {
				return nil, fmt.Errorf("missing or invalid internal pubkey for Taproot address - this should be stored in the wallet")
			}

			// Create the signature hash for Taproot input (using SigHashDefault which is equivalent to SIGHASH_ALL in Taproot)
			sigHash, err := txscript.CalcTaprootSignatureHash(
				txscript.NewTxSigHashes(tx, prevOutFetcher),
				txscript.SigHashDefault,
				tx,
				i,
				prevOutFetcher,
			)
			if err != nil {
				return nil, fmt.Errorf("error calculating taproot signature hash for input %d: %v", i, err)
			}

			// Create Schnorr signature
			signature, err := schnorr.Sign(privateKey, sigHash)
			if err != nil {
				return nil, fmt.Errorf("error creating schnorr signature for input %d: %v", i, err)
			}

			// Debug log
			fmt.Printf("  Creating Taproot key path signature for input %d\n", i)
			fmt.Printf("  Internal pubkey (hex): %x\n", taprootInternalKey)

			// Taproot signatures for key path spending are just a single Schnorr signature in the witness stack
			tx.TxIn[i].Witness = wire.TxWitness{signature.Serialize()}

		// P2SH-P2WPKH (nested SegWit)
		case scriptClass == txscript.ScriptHashTy && (selectedAccount.Type == "p2sh-p2wpkh" || selectedAccount.Type == "nested-segwit"):
			// Extract the script hash from the pkScript
			if len(pkScript) != 23 || pkScript[0] != txscript.OP_HASH160 || pkScript[22] != txscript.OP_EQUAL || pkScript[1] != 0x14 {
				return nil, fmt.Errorf("invalid P2SH script format for input %d", i)
			}

			// Extract the script hash (20 bytes)
			scriptHash := pkScript[2:22]

			// Verify this is the correct redeem script
			storedScriptHash := btcutil.Hash160(redeemScript)
			if !bytes.Equal(scriptHash, storedScriptHash) {
				return nil, fmt.Errorf("UTXO at input %d is not for the selected account's P2SH address (hash mismatch)", i)
			}

			// Sign with the redeem script
			witnessData, err = txscript.WitnessSignature(tx, txscript.NewTxSigHashes(tx, prevOutFetcher),
				i, int64(utxo.Value), redeemScript, txscript.SigHashAll, privateKey, true)
			if err != nil {
				return nil, fmt.Errorf("error creating witness signature for nested SegWit input %d: %v", i, err)
			}
			tx.TxIn[i].Witness = witnessData

			// For P2SH-P2WPKH, the signature script must contain just the redeem script
			sigScript, err = txscript.NewScriptBuilder().AddData(redeemScript).Script()
			if err != nil {
				return nil, fmt.Errorf("error creating signature script for input %d: %v", i, err)
			}
			tx.TxIn[i].SignatureScript = sigScript

		// Legacy address (P2PKH)
		case scriptClass == txscript.PubKeyHashTy && (selectedAccount.Type == "p2pkh" || selectedAccount.Type == "legacy"):
			sigScript, err = txscript.SignatureScript(tx, i, pkScript, txscript.SigHashAll, privateKey, true)
			if err != nil {
				return nil, fmt.Errorf("error signing P2PKH input %d: %v", i, err)
			}
			tx.TxIn[i].SignatureScript = sigScript

		default:
			// If script class doesn't match account type, something is wrong
			return nil, fmt.Errorf("input %d script type (%s) doesn't match account type (%s)",
				i, scriptClass, selectedAccount.Type)
		}
	}

	return tx, nil
}
