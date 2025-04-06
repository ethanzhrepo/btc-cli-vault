package util

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"encoding/hex"

	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
)

// APIUtxo represents a UTXO in the format returned by the mempool.space API
type APIUtxo struct {
	Txid   string `json:"txid"`
	Vout   uint32 `json:"vout"`
	Value  uint64 `json:"value"`
	Status struct {
		Confirmed   bool   `json:"confirmed"`
		BlockHeight uint64 `json:"block_height,omitempty"`
	} `json:"status"`
	// PkScript is the hex-encoded output script
	PkScript string `json:"scriptpubkey"`
	// ScriptType indicates the type of script (p2pkh, p2sh, p2wpkh, etc.)
	ScriptType string `json:"scriptpubkey_type,omitempty"`
	// PkScriptBytes holds the decoded bytes of the output script (filled internally, not from API)
	PkScriptBytes []byte `json:"-"`
}

// CoinSelectionResult represents the result of a coin selection algorithm
type CoinSelectionResult struct {
	SelectedUTXOs []APIUtxo // Selected UTXOs to be used as inputs
	TotalSelected uint64    // Total amount of the selected UTXOs
	Change        uint64    // Change amount to return to sender
	Fee           uint64    // Fee amount
}

// DustThreshold represents the minimum amount for an output to not be considered dust
// This is a simplification; in a real system it would depend on the size of the output script
const DustThreshold = uint64(546) // 546 satoshis is commonly used as dust threshold

// Script size constants for different address types
// These are the sizes in bytes of the serialized output scripts
const (
	// P2PKHPkScriptSize is the size of a P2PKH output script
	P2PKHPkScriptSize = 25
	// P2SHPkScriptSize is the size of a P2SH output script
	P2SHPkScriptSize = 23
	// P2WPKHPkScriptSize is the size of a native P2WPKH output script
	P2WPKHPkScriptSize = 22
	// P2WSHPkScriptSize is the size of a native P2WSH output script
	P2WSHPkScriptSize = 34
)

// FeeRecommendation represents the fee recommendations from mempool.space API
type FeeRecommendation struct {
	FastestFee  uint64 `json:"fastestFee"`  // Fastest fee (sats/byte) - first confirmation within 1-2 blocks
	HalfHourFee uint64 `json:"halfHourFee"` // Half hour fee (sats/byte) - first confirmation within ~3 blocks
	HourFee     uint64 `json:"hourFee"`     // Hour fee (sats/byte) - first confirmation within ~6 blocks
	EconomyFee  uint64 `json:"economyFee"`  // Economy fee (sats/byte) - first confirmation within ~144 blocks (1 day)
	MinimumFee  uint64 `json:"minimumFee"`  // Minimum fee (sats/byte) - minimum relay fee
}

// FeePreference represents different preferences for transaction confirmation speed
type FeePreference string

const (
	// FeeFastest aims for inclusion in the next 1-2 blocks
	FeeFastest FeePreference = "fastest"
	// FeeFast aims for inclusion within ~3 blocks
	FeeFast FeePreference = "fast"
	// FeeNormal aims for inclusion within ~6 blocks
	FeeNormal FeePreference = "normal"
	// FeeEconomic aims for inclusion within ~144 blocks
	FeeEconomic FeePreference = "economic"
	// FeeMinimum uses the absolute minimum relay fee
	FeeMinimum FeePreference = "minimum"
)

// Transaction represents the Bitcoin transaction structure returned by the API
type Transaction struct {
	Txid     string `json:"txid"`
	Version  int32  `json:"version"`
	Locktime uint32 `json:"locktime"`
	Size     int    `json:"size"`
	Weight   int    `json:"weight"`
	Fee      uint64 `json:"fee"`
	Vin      []struct {
		Txid      string   `json:"txid"`
		Vout      uint32   `json:"vout"`
		Prevout   *TxOut   `json:"prevout,omitempty"`
		ScriptSig string   `json:"scriptsig"`
		Witness   []string `json:"witness,omitempty"`
		Sequence  uint32   `json:"sequence"`
	} `json:"vin"`
	Vout   []TxOut `json:"vout"`
	Status struct {
		Confirmed   bool   `json:"confirmed"`
		BlockHeight uint64 `json:"block_height,omitempty"`
		BlockTime   int64  `json:"block_time,omitempty"`
		BlockHash   string `json:"block_hash,omitempty"`
	} `json:"status"`
}

// TxOut represents a transaction output in the Bitcoin transaction
type TxOut struct {
	ScriptPubKey     string `json:"scriptpubkey"`
	ScriptPubKeyType string `json:"scriptpubkey_type"`
	ScriptPubKeyAsm  string `json:"scriptpubkey_asm"`
	Value            uint64 `json:"value"`
}

// ValidateBitcoinAddress validates a Bitcoin address format against network parameters
func ValidateBitcoinAddress(address string, useTestnet bool) error {
	// Determine network parameters
	var params *chaincfg.Params
	if useTestnet {
		params = &chaincfg.TestNet3Params
	} else {
		params = &chaincfg.MainNetParams
	}

	// Validate address format
	_, err := btcutil.DecodeAddress(address, params)
	if err != nil {
		return fmt.Errorf("invalid Bitcoin address: %v", err)
	}

	return nil
}

// GetUTXOApiURL returns the appropriate UTXO API URL based on the network
func GetUTXOApiURL(address string, customApiURL string, useTestnet bool) string {
	apiURL := customApiURL

	// Use the provided API URL or the default one if not specified
	if apiURL == "" {
		if useTestnet {
			apiURL = DEFAULT_UTXO_TESTNET_API_URL
		} else {
			apiURL = DEFAULT_UTXO_API_URL
		}
	}

	// Replace the address placeholder in the API URL
	return fmt.Sprintf(apiURL, address)
}

// GetTransactionApiURL returns the appropriate transaction API URL based on the network
func GetTransactionApiURL(txid string, customApiURL string, useTestnet bool) string {
	apiURL := customApiURL

	// Use the provided API URL or the default one if not specified
	if apiURL == "" {
		if useTestnet {
			apiURL = DEFAULT_GET_TRANSACTION_TESTNET_URL
		} else {
			apiURL = DEFAULT_GET_TRANSACTION_URL
		}
	}

	// Replace the txid placeholder in the API URL
	return fmt.Sprintf(apiURL, txid)
}

// GetTransaction fetches transaction details for a given txid from an API endpoint
func GetTransaction(txid string, customApiURL string, useTestnet bool) (*Transaction, error) {
	// Validate txid format (basic check)
	if len(txid) != 64 {
		return nil, fmt.Errorf("invalid transaction ID format: %s", txid)
	}

	// Get the API URL
	apiURL := GetTransactionApiURL(txid, customApiURL, useTestnet)

	// Make HTTP request to the API
	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("error connecting to transaction API: %v", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse response
	var tx Transaction
	if err := json.NewDecoder(resp.Body).Decode(&tx); err != nil {
		return nil, fmt.Errorf("error decoding API response: %v", err)
	}

	return &tx, nil
}

// FetchUTXOs fetches UTXOs for a given address from an API endpoint
func FetchUTXOs(address string, customApiURL string, useTestnet bool) ([]APIUtxo, error) {
	return FetchUTXOsWithOptions(address, customApiURL, useTestnet, false)
}

// FetchUTXOsWithOptions fetches UTXOs for a given address from an API endpoint with additional options
func FetchUTXOsWithOptions(address string, customApiURL string, useTestnet bool, withScript bool) ([]APIUtxo, error) {
	// First validate the Bitcoin address
	if err := ValidateBitcoinAddress(address, useTestnet); err != nil {
		return nil, err
	}

	// Get the API URL - even if customApiURL is empty, the function will use default
	apiURL := GetUTXOApiURL(address, customApiURL, useTestnet)

	// Make HTTP request to the API
	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("error connecting to UTXO API: %v", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse response
	var apiUTXOs []APIUtxo
	if err := json.NewDecoder(resp.Body).Decode(&apiUTXOs); err != nil {
		return nil, fmt.Errorf("error decoding API response: %v", err)
	}

	// If withScript is true, fetch and complete script information for each UTXO
	if withScript {
		for i := range apiUTXOs {
			utxo := &apiUTXOs[i]

			// If the script information is missing, try to get it from the transaction
			if utxo.PkScript == "" || utxo.ScriptType == "" {
				tx, err := GetTransaction(utxo.Txid, customApiURL, useTestnet)
				if err != nil {
					// Log warning but continue with other UTXOs
					fmt.Printf("Warning: Failed to fetch transaction details for %s: %v\n", utxo.Txid, err)
					continue
				}

				// Validate vout index
				if int(utxo.Vout) >= len(tx.Vout) {
					fmt.Printf("Warning: Vout index %d out of range for transaction %s\n", utxo.Vout, utxo.Txid)
					continue
				}

				// Set script information from transaction output
				txOut := tx.Vout[utxo.Vout]
				utxo.PkScript = txOut.ScriptPubKey
				utxo.ScriptType = txOut.ScriptPubKeyType

				// Also update value if it's missing
				if utxo.Value == 0 {
					utxo.Value = txOut.Value
				}
			}

			// Decode PkScript from hex if provided
			if utxo.PkScript != "" {
				// Decode hex string to bytes
				var decodeErr error
				utxo.PkScriptBytes, decodeErr = hex.DecodeString(utxo.PkScript)
				if decodeErr != nil {
					// 不再使用虚拟脚本，而是返回错误
					return nil, fmt.Errorf("invalid script hex for UTXO %s:%d: %v", utxo.Txid, utxo.Vout, decodeErr)
				}
			} else if len(utxo.PkScriptBytes) > 0 {
				// Use pre-decoded bytes if available
				utxo.PkScriptBytes = utxo.PkScriptBytes
			} else {
				// 不再使用虚拟脚本，而是返回错误
				return nil, fmt.Errorf("missing script information for UTXO %s:%d - ensure UTXOs are fetched with withScript=true",
					utxo.Txid, utxo.Vout)
			}
		}
	}

	return apiUTXOs, nil
}

// GetNetworkParams returns the appropriate network parameters based on testnet flag
func GetNetworkParams(useTestnet bool) *chaincfg.Params {
	if useTestnet {
		return &chaincfg.TestNet3Params
	}
	return &chaincfg.MainNetParams
}

// UTXOSelectionOptions contains configuration options for UTXO selection
type UTXOSelectionOptions struct {
	// UTXOs available for selection
	UTXOs []APIUtxo
	// Amount to send in satoshis
	Amount uint64
	// Maximum fee allowed in satoshis
	FeeLimit uint64
	// Fee rate in satoshis per byte
	FeeRate uint64
	// Whether to use only confirmed UTXOs
	ConfirmedOnly bool
	// Destination Bitcoin address
	DestinationAddress string
	// Change Bitcoin address (if empty, uses DestinationAddress)
	ChangeAddress string
	// Whether to use testnet network parameters
	UseTestnet bool
}

// For backwards compatibility with tests - accepts 7 parameters
func CreateUTXOs(utxos []APIUtxo, amount uint64, feeLimit uint64, feeRate uint64, confirmedOnly bool,
	destinationAddress string, useTestnet bool) (*CoinSelectionResult, error) {
	return CreateUTXOsWithChangeAddr(utxos, amount, feeLimit, feeRate, confirmedOnly,
		destinationAddress, "", useTestnet)
}

// CreateUTXOsWithChangeAddr selects UTXOs to cover a specific amount with a fee limit
// Using the new options struct, but maintaining backwards compatibility with the old function signature
func CreateUTXOsWithChangeAddr(utxos []APIUtxo, amount uint64, feeLimit uint64, feeRate uint64, confirmedOnly bool,
	destinationAddress string, changeAddress string, useTestnet bool) (*CoinSelectionResult, error) {

	options := UTXOSelectionOptions{
		UTXOs:              utxos,
		Amount:             amount,
		FeeLimit:           feeLimit,
		FeeRate:            feeRate,
		ConfirmedOnly:      confirmedOnly,
		DestinationAddress: destinationAddress,
		ChangeAddress:      changeAddress,
		UseTestnet:         useTestnet,
	}

	return CreateUTXOsWithOptions(options)
}

// CreateUTXOsWithOptions selects UTXOs to cover a specific amount with a fee limit using btcwallet's txauthor package
// This version uses the options struct for more flexibility
func CreateUTXOsWithOptions(options UTXOSelectionOptions) (*CoinSelectionResult, error) {
	// Filter out unconfirmed UTXOs if requested
	var availableUTXOs []APIUtxo
	if options.ConfirmedOnly {
		for _, utxo := range options.UTXOs {
			if utxo.Status.Confirmed {
				availableUTXOs = append(availableUTXOs, utxo)
			}
		}
	} else {
		availableUTXOs = options.UTXOs
	}

	if len(availableUTXOs) == 0 {
		return nil, fmt.Errorf("no UTXOs available after filtering")
	}

	// Convert the fee rate from satoshis per byte to satoshis per kilobyte
	feeRateKB := btcutil.Amount(options.FeeRate * 1000)

	// Get network parameters
	params := GetNetworkParams(options.UseTestnet)

	// Map for quick lookup of UTXOs by outpoint
	utxosByOutpoint := make(map[wire.OutPoint]APIUtxo)

	// Convert APIUtxo to wire.TxIn, btcutil.Amount, and extract/decode the actual script
	var (
		inputs       []*wire.TxIn
		inputValues  []btcutil.Amount
		inputScripts [][]byte
	)

	for i := range availableUTXOs {
		utxo := &availableUTXOs[i]

		// Parse the transaction hash
		txHash, err := chainhash.NewHashFromStr(utxo.Txid)
		if err != nil {
			// Log a warning but continue with other UTXOs
			fmt.Printf("Warning: Invalid transaction hash %s: %v\n", utxo.Txid, err)
			continue
		}

		// Create the outpoint and use it as a key in our map
		outPoint := wire.NewOutPoint(txHash, utxo.Vout)
		utxosByOutpoint[*outPoint] = *utxo

		// Create the input with no script sig or witness (to be added later)
		txIn := wire.NewTxIn(outPoint, nil, nil)
		inputs = append(inputs, txIn)
		inputValues = append(inputValues, btcutil.Amount(utxo.Value))

		// Decode PkScript from hex if provided
		var pkScriptBytes []byte
		if utxo.PkScript != "" {
			// Decode hex string to bytes
			var decodeErr error
			pkScriptBytes, decodeErr = hex.DecodeString(utxo.PkScript)
			if decodeErr != nil {
				// 不再使用虚拟脚本，而是返回错误
				return nil, fmt.Errorf("invalid script hex for UTXO %s:%d: %v", utxo.Txid, utxo.Vout, decodeErr)
			}
		} else if len(utxo.PkScriptBytes) > 0 {
			// Use pre-decoded bytes if available
			pkScriptBytes = utxo.PkScriptBytes
		} else {
			// 不再使用虚拟脚本，而是返回错误
			return nil, fmt.Errorf("missing script information for UTXO %s:%d - ensure UTXOs are fetched with withScript=true",
				utxo.Txid, utxo.Vout)
		}

		// Store the script for this input
		inputScripts = append(inputScripts, pkScriptBytes)
	}

	if len(inputs) == 0 {
		return nil, fmt.Errorf("no valid UTXOs found")
	}

	// Create input source function for txauthor
	// This implementation allows txauthor to select the optimal set of inputs
	inputSource := func(target btcutil.Amount) (btcutil.Amount, []*wire.TxIn, []btcutil.Amount, [][]byte, error) {
		// Return all available inputs and let the txauthor package select the optimal ones
		return sumInputValues(inputValues), inputs, inputValues, inputScripts, nil
	}

	// Create output script for the destination address
	var destScript []byte
	var err error

	if options.DestinationAddress == "" {
		return nil, fmt.Errorf("destination address cannot be empty")
	}

	// Parse destination address and create the corresponding script
	destAddr, addrErr := btcutil.DecodeAddress(options.DestinationAddress, params)
	if addrErr != nil {
		return nil, fmt.Errorf("invalid destination address: %v", addrErr)
	}

	destScript, err = txscript.PayToAddrScript(destAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create output script: %v", err)
	}

	destinationOutput := &wire.TxOut{
		Value:    int64(options.Amount),
		PkScript: destScript,
	}

	// Create change script
	var changeScript []byte
	var changeScriptSize int

	// If changeAddress is empty, default to destinationAddress
	effectiveChangeAddress := options.ChangeAddress
	if effectiveChangeAddress == "" {
		effectiveChangeAddress = options.DestinationAddress
	}

	if effectiveChangeAddress != "" {
		// Parse the change address and create a script
		changeAddr, addrErr := btcutil.DecodeAddress(effectiveChangeAddress, params)
		if addrErr != nil {
			return nil, fmt.Errorf("invalid change address: %v", addrErr)
		}

		changeScript, err = txscript.PayToAddrScript(changeAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to create change script: %v", err)
		}

		// Determine script size based on address type
		switch changeAddr.(type) {
		case *btcutil.AddressPubKeyHash:
			changeScriptSize = P2PKHPkScriptSize
		case *btcutil.AddressScriptHash:
			changeScriptSize = P2SHPkScriptSize
		case *btcutil.AddressWitnessPubKeyHash:
			changeScriptSize = P2WPKHPkScriptSize
		case *btcutil.AddressWitnessScriptHash:
			changeScriptSize = P2WSHPkScriptSize
		default:
			// Default to P2PKH for unknown types
			changeScriptSize = P2PKHPkScriptSize
		}
	} else {
		// 这个分支不应该再被执行，因为我们确保effectiveChangeAddress不为空
		// 但为了防止未来的更改可能导致问题，添加一个明确的错误
		return nil, fmt.Errorf("invalid change address: cannot be empty")
	}

	// Create change source
	changeSource := txauthor.ChangeSource{
		NewScript: func() ([]byte, error) {
			return changeScript, nil
		},
		ScriptSize: changeScriptSize,
	}

	// Create the transaction using txauthor
	authoredTx, err := txauthor.NewUnsignedTransaction(
		[]*wire.TxOut{destinationOutput},
		feeRateKB,
		inputSource,
		&changeSource,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create transaction: %v", err)
	}

	// Calculate the fee
	fee := authoredTx.TotalInput - btcutil.Amount(options.Amount)
	if len(authoredTx.Tx.TxOut) > 1 {
		// There's a change output
		fee -= btcutil.Amount(authoredTx.Tx.TxOut[1].Value)
	}

	// Check if fee exceeds limit
	if fee > btcutil.Amount(options.FeeLimit) {
		return nil, fmt.Errorf("required fee %d exceeds limit %d", fee, options.FeeLimit)
	}

	// Create the result
	result := &CoinSelectionResult{
		TotalSelected: uint64(authoredTx.TotalInput),
		Fee:           uint64(fee),
	}

	// Extract the selected UTXOs using our lookup map for efficiency
	for _, input := range authoredTx.Tx.TxIn {
		if utxo, ok := utxosByOutpoint[input.PreviousOutPoint]; ok {
			result.SelectedUTXOs = append(result.SelectedUTXOs, utxo)
		}
	}

	// Calculate change
	if len(authoredTx.Tx.TxOut) > 1 {
		result.Change = uint64(authoredTx.Tx.TxOut[1].Value)

		// 检查找零输出是否高于粉尘阈值
		if result.Change < DustThreshold {
			// txauthor可能已经正确处理了粉尘找零，但我们在这里明确检查
			// 因为找零输出低于粉尘阈值可能会导致网络拒绝交易
			return nil, fmt.Errorf("change amount (%d satoshis) is below dust threshold (%d satoshis)",
				result.Change, DustThreshold)
		}
	} else {
		result.Change = 0
	}

	return result, nil
}

// sumInputValues sums all input values and returns the total
func sumInputValues(values []btcutil.Amount) btcutil.Amount {
	var sum btcutil.Amount
	for _, v := range values {
		sum += v
	}
	return sum
}

// GetFeeApiURL returns the appropriate fee API URL based on the network
func GetFeeApiURL(customApiURL string, useTestnet bool) string {
	if customApiURL != "" {
		return customApiURL
	}

	if useTestnet {
		return DEFAULT_FEE_TESTNET_URL
	}
	return DEFAULT_FEE_URL
}

// FetchFee fetches the recommended fee rates from the mempool.space API
func FetchFee(customApiURL string, useTestnet bool) (*FeeRecommendation, error) {
	// Get the API URL
	apiURL := GetFeeApiURL(customApiURL, useTestnet)

	// Make HTTP request to the API
	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("error connecting to fee API: %v", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse response
	var feeRecommendation FeeRecommendation
	if err := json.NewDecoder(resp.Body).Decode(&feeRecommendation); err != nil {
		return nil, fmt.Errorf("error decoding API response: %v", err)
	}

	return &feeRecommendation, nil
}

// GetRecommendedFeeRate fetches the recommended fee rate based on a preference
// Falls back to a default fee if the API call fails
func GetRecommendedFeeRate(preference FeePreference, customApiURL string, useTestnet bool) (uint64, error) {
	// Default fee rates to use if API call fails
	const defaultFastest = uint64(20)
	const defaultFast = uint64(10)
	const defaultNormal = uint64(5)
	const defaultEconomic = uint64(3)
	const defaultMinimum = uint64(1)

	// Try to fetch from API - if customApiURL is empty, it will use default APIs
	feeRecs, err := FetchFee(customApiURL, useTestnet)
	if err != nil {
		// Log the error
		fmt.Printf("Warning: Could not fetch fee recommendations: %v\n", err)
		fmt.Println("Using default fee rates instead.")

		// Fall back to defaults
		switch preference {
		case FeeFastest:
			return defaultFastest, nil
		case FeeFast:
			return defaultFast, nil
		case FeeNormal:
			return defaultNormal, nil
		case FeeEconomic:
			return defaultEconomic, nil
		case FeeMinimum:
			return defaultMinimum, nil
		default:
			return defaultNormal, nil
		}
	}

	// Return the appropriate fee based on preference
	switch preference {
	case FeeFastest:
		return feeRecs.FastestFee, nil
	case FeeFast:
		return feeRecs.HalfHourFee, nil
	case FeeNormal:
		return feeRecs.HourFee, nil
	case FeeEconomic:
		return feeRecs.EconomyFee, nil
	case FeeMinimum:
		return feeRecs.MinimumFee, nil
	default:
		return feeRecs.HourFee, nil // Default to normal
	}
}

// GetTransactionBroadcastURL returns the appropriate transaction API URL based on the network
func GetTransactionBroadcastURL(customApiURL string, useTestnet bool) string {
	if customApiURL != "" {
		return customApiURL
	}

	if useTestnet {
		return DEFAULT_POST_TRANSACTION_TESTNET_URL
	}
	return DEFAULT_POST_TRANSACTION_URL
}

// BroadcastRawTransaction sends the raw transaction to the Bitcoin network
func BroadcastRawTransaction(txHex string, customApiURL string, useTestnet bool) (string, error) {
	// Determine which URL to use
	url := GetTransactionBroadcastURL(customApiURL, useTestnet)

	// Create HTTP client
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest("POST", url, strings.NewReader(txHex))
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "text/plain")

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending transaction: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response: %v", err)
	}

	// Check for success
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("broadcast failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Return transaction ID (the response is the txid as text)
	return string(body), nil
}
