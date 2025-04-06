package cmd

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"syscall"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/wallet/txsizes"
	"github.com/ethanzhrepo/btc-cli-vault/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
	cmd.Flags().Bool("encodeOnly", false, "Only encode the transaction, do not broadcast")
	cmd.Flags().Bool("feeOnly", false, "Only display fee estimation")
	cmd.Flags().BoolP("yes", "y", false, "Automatically confirm the transaction")
	cmd.Flags().Uint64("feeRate", 0, "Fee rate in satoshis per byte (0 for auto-selection)")
	cmd.Flags().StringP("fee-preference", "", "normal", "Fee preference when auto-selecting (fastest, fast, normal, economic, minimum)")
	cmd.Flags().StringP("from-type", "", "p2pkh", "Address type to send from (p2pkh, p2wpkh, p2tr), set p2pkh for legacy addresses, p2wpkh for segwit addresses, p2tr for taproot addresses. If you are not sure, define your own address type by using the --from flag.")
	cmd.Flags().StringP("from", "", "", "Specific Bitcoin address to send from (will auto-detect type)")
	cmd.Flags().StringP("change-address", "c", "", "Change address (optional, defaults to sender address)")
	cmd.Flags().String("utxo", "", "Specify UTXOs to use, comma separated (txid:vout:amount format)")
	cmd.Flags().StringP("rpc", "R", "", "Bitcoin node RPC URL (overrides config)")

	cmd.MarkFlagsMutuallyExclusive("from", "from-type")
	cmd.MarkFlagRequired("amount")
	cmd.MarkFlagRequired("to")

	return cmd
}

// TransferWalletFile represents the structure of the wallet JSON file for transfer command
type TransferWalletFile struct {
	EncryptedMnemonic util.EncryptedMnemonic `json:"encrypted_mnemonic"`
	DerivationPath    string                 `json:"derivation_path"`
	TestNet           bool                   `json:"testnet"`
}

// UTXO represents an unspent transaction output
type UTXO struct {
	TxID   string
	Vout   uint32
	Amount uint64
}

func runTransferBTC(cmd *cobra.Command, args []string) error {
	// Parse flags
	amountStr, _ := cmd.Flags().GetString("amount")
	toAddress, _ := cmd.Flags().GetString("to")
	provider, _ := cmd.Flags().GetString("provider")
	name, _ := cmd.Flags().GetString("name")
	filePath, _ := cmd.Flags().GetString("file")
	encodeOnly, _ := cmd.Flags().GetBool("encodeOnly")
	feeOnly, _ := cmd.Flags().GetBool("feeOnly")
	autoConfirm, _ := cmd.Flags().GetBool("yes")
	userSetFeeRate, _ := cmd.Flags().GetUint64("feeRate")
	feePreferenceStr, _ := cmd.Flags().GetString("fee-preference")
	fromType, _ := cmd.Flags().GetString("from-type")
	fromAddress, _ := cmd.Flags().GetString("from")
	changeAddress, _ := cmd.Flags().GetString("change-address")
	utxoStr, _ := cmd.Flags().GetString("utxo")
	nodeURL, _ := cmd.Flags().GetString("rpc")

	// Check mutual exclusivity between provider+name and file
	if (provider != "" || name != "") && filePath != "" {
		return fmt.Errorf("--file and --provider/--name are mutually exclusive, use one or the other")
	}

	// Ensure we have either file or provider
	if provider == "" && filePath == "" {
		return fmt.Errorf("either --provider or --file must be specified")
	}

	// Get Bitcoin node RPC URL from config if not provided
	if nodeURL == "" && !encodeOnly {
		var err error
		nodeURL, err = initBitcoinRPCConfig()
		if err != nil {
			return fmt.Errorf("failed to initialize Bitcoin RPC config: %v", err)
		}
		// If nodeURL is still empty, we'll use the default API endpoints
		if nodeURL == "" {
			fmt.Println("No RPC URL configured. Using default mempool.space API.")
		}
	}

	// Print provider or file info
	if provider != "" {
		fmt.Printf("Using provider: %s\n", provider)
	} else {
		fmt.Printf("Using wallet file: %s\n", filePath)
	}

	// Parse amount with unit
	amountInSatoshis, err := parseBitcoinAmount(amountStr)
	if err != nil {
		return err
	}

	// Get wallet data from provider or file
	var walletData []byte
	if filePath != "" {
		// Load from local file system
		walletData, err = util.Get(filePath, filePath)
		if err != nil {
			return fmt.Errorf("error loading wallet from local file: %v", err)
		}
	} else {
		// Load from cloud provider
		cloudPath := strings.Join([]string{util.DEFAULT_CLOUD_FILE_DIR, name + ".json"}, "/")
		walletData, err = util.Get(provider, cloudPath)
		if err != nil {
			return fmt.Errorf("error loading wallet from %s: %v", provider, err)
		}
	}

	// Parse wallet file
	var wallet TransferWalletFile
	if err := json.Unmarshal(walletData, &wallet); err != nil {
		return fmt.Errorf("error parsing wallet file: %v", err)
	}

	// Get password
	fmt.Print("Please Enter \033[1;31mAES\033[0m Password: ")
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

	// Ask if a passphrase was used
	fmt.Print("Did you use a BIP39 passphrase for this wallet? (y/n): ")
	var answer string
	fmt.Scanln(&answer)

	var passphrase string
	if strings.ToLower(answer) == "y" || strings.ToLower(answer) == "yes" {
		fmt.Print("Please Enter \033[1;31mBIP39\033[0m Passphrase: ")
		passphraseBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("error reading passphrase: %v", err)
		}
		fmt.Println()
		passphrase = string(passphraseBytes)
	}

	// Generate seed from mnemonic
	seed := bip39.NewSeed(mnemonic, passphrase)

	// Determine network parameters
	var params *chaincfg.Params
	if wallet.TestNet {
		params = &chaincfg.TestNet3Params
		fmt.Println("Using TESTNET")
	} else {
		params = &chaincfg.MainNetParams
		fmt.Println("Using MAINNET")
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, params)
	if err != nil {
		return fmt.Errorf("error generating master key: %v", err)
	}

	// Derive private key using path from wallet
	path := wallet.DerivationPath
	derivedKey := masterKey
	if path != "" {
		// Use derivation path from wallet
		parts := strings.Split(path, "/")
		for _, part := range parts[1:] { // Skip the 'm'
			var childIdx uint32
			if strings.HasSuffix(part, "'") || strings.HasSuffix(part, "h") {
				// Hardened key
				idx, err := parseUint32(strings.TrimRight(strings.TrimRight(part, "'"), "h"))
				if err != nil {
					return fmt.Errorf("invalid derivation path: %v", err)
				}
				childIdx = idx + hdkeychain.HardenedKeyStart
			} else {
				// Non-hardened key
				idx, err := parseUint32(part)
				if err != nil {
					return fmt.Errorf("invalid derivation path: %v", err)
				}
				childIdx = idx
			}

			derivedKey, err = derivedKey.Derive(childIdx)
			if err != nil {
				return fmt.Errorf("error deriving key: %v", err)
			}
		}
	}

	// Get private key and public key
	privateKey, err := derivedKey.ECPrivKey()
	if err != nil {
		return fmt.Errorf("error getting private key: %v", err)
	}

	pubKey := privateKey.PubKey()

	// 确定发送地址，根据参数选择
	var senderAddress string
	var addressType string

	if fromAddress != "" {
		// 使用用户指定的地址
		senderAddress = fromAddress

		// 自动检测地址类型
		address, err := btcutil.DecodeAddress(fromAddress, params)
		if err != nil {
			return fmt.Errorf("invalid from address: %v", err)
		}

		// 根据地址类型设置类型参数
		switch address.(type) {
		case *btcutil.AddressPubKeyHash:
			addressType = "p2pkh"
		case *btcutil.AddressWitnessPubKeyHash:
			addressType = "p2wpkh"
		case *btcutil.AddressTaproot:
			addressType = "p2tr"
		case *btcutil.AddressScriptHash:
			addressType = "p2sh"
		default:
			return fmt.Errorf("unsupported address type: %T", address)
		}

		fmt.Printf("Detected address type: %s\n", addressType)
	} else {
		// 根据地址类型生成地址
		addressType = strings.ToLower(fromType)

		switch addressType {
		case "p2pkh":
			senderAddress, err = createP2PKHAddress(pubKey, params)
		case "p2wpkh":
			senderAddress, err = createP2WPKHAddress(pubKey, params)
		case "p2tr":
			senderAddress, err = createP2TRAddress(pubKey, params)
		default:
			return fmt.Errorf("unsupported address type: %s", fromType)
		}

		if err != nil {
			return fmt.Errorf("failed to generate %s address: %v", fromType, err)
		}
	}

	// Default change address to sender address if not specified
	if changeAddress == "" {
		changeAddress = senderAddress
	}

	// Handle UTXOs - either from command line or fetch them
	var selectedUTXOs []util.APIUtxo
	var totalInputValue btcutil.Amount

	if utxoStr != "" {
		// Parse UTXOs from command line
		manualUtxos, err := parseUTXOs(utxoStr)
		if err != nil {
			return fmt.Errorf("failed to parse UTXOs: %v", err)
		}

		// Convert manual UTXOs to APIUtxo format
		for _, utxo := range manualUtxos {
			apiUtxo := util.APIUtxo{
				Txid:  utxo.TxID,
				Vout:  utxo.Vout,
				Value: utxo.Amount,
				Status: struct {
					Confirmed   bool   `json:"confirmed"`
					BlockHeight uint64 `json:"block_height,omitempty"`
				}{
					Confirmed: true, // Assume manual UTXOs are confirmed
				},
			}
			selectedUTXOs = append(selectedUTXOs, apiUtxo)
		}
	} else if !encodeOnly {
		// Fetch UTXOs using the util function
		fetchedUTXOs, err := util.FetchUTXOs(senderAddress, nodeURL, wallet.TestNet)
		if err != nil {
			return fmt.Errorf("failed to fetch UTXOs: %v", err)
		}
		selectedUTXOs = fetchedUTXOs
	}

	// Determine fee rate - either user-set or from recommendation API
	var feeRate uint64
	if userSetFeeRate > 0 {
		// Use the user-specified fee rate
		feeRate = userSetFeeRate
		fmt.Printf("Using user-specified fee rate: %d sat/byte\n", feeRate)
	} else {
		// Convert string preference to FeePreference type
		var feePreference util.FeePreference
		switch strings.ToLower(feePreferenceStr) {
		case "fastest":
			feePreference = util.FeeFastest
		case "fast":
			feePreference = util.FeeFast
		case "normal", "standard":
			feePreference = util.FeeNormal
		case "economic", "economy":
			feePreference = util.FeeEconomic
		case "minimum", "min":
			feePreference = util.FeeMinimum
		default:
			feePreference = util.FeeNormal
		}

		// Get recommended fee rate
		var err error
		feeRate, err = util.GetRecommendedFeeRate(feePreference, nodeURL, wallet.TestNet)
		if err != nil {
			return fmt.Errorf("failed to get recommended fee rate: %v", err)
		}
		fmt.Printf("Using recommended fee rate (%s): %d sat/byte\n", feePreferenceStr, feeRate)
	}

	// Use the CreateUTXOsWithOptions function to perform coin selection
	options := util.UTXOSelectionOptions{
		UTXOs:              selectedUTXOs,
		Amount:             amountInSatoshis,
		FeeLimit:           feeRate * 1000, // Reasonable fee limit based on rate
		FeeRate:            feeRate,
		ConfirmedOnly:      true, // Only use confirmed UTXOs for safety
		DestinationAddress: toAddress,
		ChangeAddress:      changeAddress,
		UseTestnet:         wallet.TestNet,
	}

	coinSelection, err := util.CreateUTXOsWithOptions(options)
	if err != nil {
		return fmt.Errorf("failed to select UTXOs: %v", err)
	}

	// Convert selected UTXOs to inputs for signing
	var inputs []*wire.TxIn
	var inputValues []btcutil.Amount
	var inputScripts [][]byte

	for _, utxo := range coinSelection.SelectedUTXOs {
		txHash, err := chainhash.NewHashFromStr(utxo.Txid)
		if err != nil {
			return fmt.Errorf("invalid transaction hash: %v", err)
		}

		outPoint := wire.NewOutPoint(txHash, utxo.Vout)
		txIn := wire.NewTxIn(outPoint, nil, nil)
		inputs = append(inputs, txIn)
		inputValues = append(inputValues, btcutil.Amount(utxo.Value))
		inputScripts = append(inputScripts, []byte{}) // Placeholder for signing
	}

	totalInputValue = btcutil.Amount(coinSelection.TotalSelected)

	// Create InputSource function for txauthor - now uses the pre-selected UTXOs
	inputSource := func(target btcutil.Amount) (btcutil.Amount, []*wire.TxIn, []btcutil.Amount, [][]byte, error) {
		return totalInputValue, inputs, inputValues, inputScripts, nil
	}

	// Create ChangeSource function for txauthor
	changeAddr, err := btcutil.DecodeAddress(changeAddress, params)
	if err != nil {
		return fmt.Errorf("invalid change address: %v", err)
	}

	// Convert our change source to a txauthor.ChangeSource
	changeSourceFunc := txauthor.ChangeSource{
		NewScript: func() ([]byte, error) {
			return txscript.PayToAddrScript(changeAddr)
		},
		ScriptSize: txsizes.P2PKHPkScriptSize,
	}

	// Create transaction using txauthor
	authoredTx, err := txauthor.NewUnsignedTransaction(
		[]*wire.TxOut{
			{
				Value: int64(amountInSatoshis),
				PkScript: func() []byte {
					destAddr, err := btcutil.DecodeAddress(toAddress, params)
					if err != nil {
						return nil
					}
					script, err := txscript.PayToAddrScript(destAddr)
					if err != nil {
						return nil
					}
					return script
				}(),
			},
		},
		btcutil.Amount(feeRate*1000),
		inputSource,
		&changeSourceFunc,
	)
	if err != nil {
		return fmt.Errorf("failed to create transaction: %v", err)
	}

	// Calculate estimated transaction size
	estimatedTxSize := authoredTx.Tx.SerializeSize()
	if len(authoredTx.Tx.TxIn) > 0 && len(authoredTx.Tx.TxIn[0].Witness) > 0 {
		// For segwit transactions, calculate the virtual size
		// Weight = (base size * 3) + total size
		// vSize = (weight + 3) / 4
		baseSize := authoredTx.Tx.SerializeSizeStripped()
		totalSize := authoredTx.Tx.SerializeSize()
		weight := baseSize*3 + totalSize
		estimatedTxSize = (weight + 3) / 4
	}

	// If fee only, just display and exit
	if feeOnly {
		fee := authoredTx.TotalInput - txauthor.SumOutputValues(authoredTx.Tx.TxOut)
		fmt.Printf("Estimated Fee: %.8f BTC (%d satoshis)\n", float64(fee)/100000000.0, fee)
		fmt.Printf("Fee Rate: %d sat/byte (%.1f sat/kB)\n", feeRate, float64(feeRate*1000))
		fmt.Printf("Estimated Transaction Size: %d bytes\n", estimatedTxSize)
		return nil
	}

	// Create a SecretSource for signing
	secretSource := &transferSecretKeySource{
		privateKey:  privateKey,
		fromType:    addressType,
		chainParams: params,
	}

	// Sign the transaction
	err = authoredTx.AddAllInputScripts(secretSource)
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %v", err)
	}

	// Serialize transaction
	var signedTx bytes.Buffer
	authoredTx.Tx.Serialize(&signedTx)
	txHex := hex.EncodeToString(signedTx.Bytes())

	// If encode only, just display the raw transaction and exit
	if encodeOnly {
		fmt.Printf("Raw Transaction: %s\n", txHex)
		return nil
	}

	// Display transaction details for confirmation
	if !autoConfirm {
		fmt.Println("Transaction Details:")
		fmt.Printf("From: %s\n", senderAddress)
		fmt.Printf("To: %s\n", toAddress)
		fmt.Printf("Amount: %.8f BTC (%d satoshis)\n", float64(amountInSatoshis)/100000000.0, amountInSatoshis)

		// Calculate fee
		fee := authoredTx.TotalInput - txauthor.SumOutputValues(authoredTx.Tx.TxOut)
		fmt.Printf("Fee: %.8f BTC (%d satoshis @ %d sat/byte)\n", float64(fee)/100000000.0, fee, feeRate)

		// Display change output if any
		if len(authoredTx.Tx.TxOut) > 1 {
			changeValue := authoredTx.Tx.TxOut[len(authoredTx.Tx.TxOut)-1].Value
			fmt.Printf("Change: %.8f BTC (%d satoshis) to %s\n", float64(changeValue)/100000000.0, changeValue, changeAddress)
		}

		fmt.Printf("Transaction Size: ~%d bytes\n", estimatedTxSize)
		fmt.Printf("Raw Transaction: %s\n", txHex)

		// Ask for confirmation
		fmt.Print("Confirm transaction? (y/N): ")
		var response string
		fmt.Scanln(&response)
		if !strings.EqualFold(response, "y") {
			fmt.Println("Transaction cancelled.")
			return nil
		}
	}

	// For now, just output the transaction hex
	fmt.Printf("Signed Transaction Hex: %s\n", txHex)

	// Broadcast the transaction if not encode-only
	if !encodeOnly {
		fmt.Println("Broadcasting transaction...")
		// Use the BroadcastTransaction utility function
		txid, err := util.BroadcastRawTransaction(txHex, nodeURL, wallet.TestNet)
		if err != nil {
			fmt.Printf("Error broadcasting transaction: %v\n", err)
			fmt.Println("You can manually broadcast the transaction hex above.")
			return nil
		}
		fmt.Printf("Transaction successfully broadcast!\n")
		fmt.Printf("Transaction ID: %s\n", txid)

		// Construct a blockchain explorer URL for the transaction
		var explorerURL string
		if wallet.TestNet {
			explorerURL = fmt.Sprintf("https://mempool.space/testnet/tx/%s", txid)
		} else {
			explorerURL = fmt.Sprintf("https://mempool.space/tx/%s", txid)
		}
		fmt.Printf("Track your transaction: %s\n", explorerURL)
	}

	return nil
}

// transferSecretKeySource implements the txauthor.SecretsSource interface
type transferSecretKeySource struct {
	privateKey  *btcec.PrivateKey
	fromType    string
	chainParams *chaincfg.Params
}

// GetKey returns the private key for a given address
func (s *transferSecretKeySource) GetKey(addr btcutil.Address) (*btcec.PrivateKey, bool, error) {
	// In our simple implementation, we just return the same private key for all addresses
	// In a real wallet, you would look up the key by address
	return s.privateKey, true, nil
}

// GetScript returns the redeem script for a given address
func (s *transferSecretKeySource) GetScript(addr btcutil.Address) ([]byte, error) {
	// We don't support redeem scripts in this simple implementation
	return nil, nil
}

// ChainParams returns the chain parameters for this source
func (s *transferSecretKeySource) ChainParams() *chaincfg.Params {
	return s.chainParams
}

// parseUTXOs parses a comma-separated list of UTXOs
// Format: txid:vout:amount (amount in satoshis)
func parseUTXOs(utxoStr string) ([]UTXO, error) {
	var utxos []UTXO

	parts := strings.Split(utxoStr, ",")
	for _, part := range parts {
		fields := strings.Split(strings.TrimSpace(part), ":")
		if len(fields) != 3 {
			return nil, fmt.Errorf("invalid UTXO format, expected txid:vout:amount")
		}

		vout, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid vout: %v", err)
		}

		amount, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid amount: %v", err)
		}

		utxos = append(utxos, UTXO{
			TxID:   fields[0],
			Vout:   uint32(vout),
			Amount: amount,
		})
	}

	return utxos, nil
}

// createP2PKHAddress generates a P2PKH address from a public key
func createP2PKHAddress(pubKey *btcec.PublicKey, params *chaincfg.Params) (string, error) {
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	addr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, params)
	if err != nil {
		return "", err
	}
	return addr.String(), nil
}

// createP2WPKHAddress generates a P2WPKH address from a public key
func createP2WPKHAddress(pubKey *btcec.PublicKey, params *chaincfg.Params) (string, error) {
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	addr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, params)
	if err != nil {
		return "", err
	}
	return addr.String(), nil
}

// createP2TRAddress generates a P2TR address from a public key
func createP2TRAddress(pubKey *btcec.PublicKey, params *chaincfg.Params) (string, error) {
	// For P2TR, we would normally create a taproot output key
	// This is a simplified implementation
	addr, err := btcutil.NewAddressTaproot(schnorrKey(pubKey), params)
	if err != nil {
		return "", err
	}
	return addr.String(), nil
}

// schnorrKey generates a taproot key from a public key
// This is a simplified implementation
func schnorrKey(pubKey *btcec.PublicKey) []byte {
	// In a real implementation, this would properly create a taproot key
	// For now, just use the x-coordinate of the public key with a taproot prefix
	pubBytes := pubKey.SerializeCompressed()

	// Return x-coordinate with proper prefix
	return append([]byte{0x02}, pubBytes[1:33]...)
}

// Helper function to convert string to uint32
func parseUint32(s string) (uint32, error) {
	var i uint32
	_, err := fmt.Sscanf(s, "%d", &i)
	return i, err
}

// parseBitcoinAmount parses Bitcoin amount with units (e.g., "1.0btc", "10000sat")
func parseBitcoinAmount(amount string) (uint64, error) {
	amount = strings.TrimSpace(amount)
	if amount == "" {
		return 0, fmt.Errorf("amount cannot be empty")
	}

	// Default unit is BTC if no unit specified
	unit := "btc"
	value := amount

	// Check for unit in the string
	lowerAmount := strings.ToLower(amount)
	for _, u := range []string{"btc", "mbtc", "ubtc", "sat", "sats", "satoshi", "satoshis"} {
		if strings.HasSuffix(lowerAmount, u) {
			unit = u
			value = strings.TrimSuffix(amount, u)
			value = strings.TrimSpace(value)
			break
		}
	}

	// Parse the decimal value
	floatVal, ok := new(big.Float).SetString(value)
	if !ok {
		return 0, fmt.Errorf("invalid amount format: %s", amount)
	}

	// Convert to satoshis based on unit
	var multiplier float64
	switch unit {
	case "btc", "bitcoin":
		multiplier = 100000000 // 1 BTC = 10^8 satoshis
	case "mbtc", "millibtc":
		multiplier = 100000 // 1 mBTC = 10^5 satoshis
	case "ubtc", "microbtc":
		multiplier = 100 // 1 μBTC = 10^2 satoshis
	case "sat", "sats", "satoshi", "satoshis":
		multiplier = 1 // 1 satoshi
	default:
		return 0, fmt.Errorf("unsupported unit: %s", unit)
	}

	// Extract the float value
	floatAmount, _ := floatVal.Float64()

	// Convert to satoshis
	satoshis := uint64(math.Round(floatAmount * multiplier))

	return satoshis, nil
}

// initBitcoinRPCConfig reads Bitcoin RPC configuration
func initBitcoinRPCConfig() (string, error) {
	// Read from config file
	// Look for the btc.rpc key in config
	rpcURL := viper.GetString("rpc")
	if rpcURL == "" {
		// Instead of returning an error, return empty string to indicate
		// that we should use default APIs from constants.go
		return "", nil
	}
	return rpcURL, nil
}

// broadcastTransaction sends the raw transaction to the Bitcoin network
// This is kept for backward compatibility but should use util.BroadcastTransaction instead
func broadcastTransaction(txHex string, isTestnet bool) (string, error) {
	return util.BroadcastRawTransaction(txHex, "", isTestnet)
}

// BitcoinRPCRequest represents a JSON-RPC request to a Bitcoin node
type BitcoinRPCRequest struct {
	JSONRPCVersion string        `json:"jsonrpc"`
	ID             string        `json:"id"`
	Method         string        `json:"method"`
	Params         []interface{} `json:"params"`
}

// BitcoinRPCResponse represents a JSON-RPC response from a Bitcoin node
type BitcoinRPCResponse struct {
	JSONRPCVersion string          `json:"jsonrpc"`
	ID             string          `json:"id"`
	Result         json.RawMessage `json:"result"`
	Error          *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// UnspentOutput represents an unspent transaction output from the Bitcoin node
type UnspentOutput struct {
	TxID          string  `json:"txid"`
	Vout          uint32  `json:"vout"`
	Address       string  `json:"address"`
	ScriptPubKey  string  `json:"scriptPubKey"`
	Amount        float64 `json:"amount"`
	Confirmations int     `json:"confirmations"`
	Spendable     bool    `json:"spendable"`
	Solvable      bool    `json:"solvable"`
	Safe          bool    `json:"safe"`
}
