package cmd

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
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

// Constants for BIP32 derivation paths
const (
	// Coin type constants
	CoinTypeBTC        = uint32(0) // Mainnet
	CoinTypeBTCTestnet = uint32(1) // Testnet

	// Account, change constants
	DefaultAccount      = uint32(0)
	ExternalChain       = uint32(0) // Receiving addresses
	InternalChain       = uint32(1) // Change addresses
	DefaultAddressIndex = uint32(0)
	ScanDepth           = uint32(20) // How many addresses to scan in each derivation pattern
)

// Constants for transaction size estimation (in vbytes)
const (
	// Transaction overhead
	TxVersionSize  = 4
	TxLockTimeSize = 4
	TxInCountSize  = 1 // Can be more if many inputs
	TxOutCountSize = 1 // Can be more if many outputs

	// Input sizes
	P2PKHInputSize      = 148 // Non-witness input
	P2WPKHInputSize     = 68  // Native SegWit input
	P2SHP2WPKHInputSize = 91  // Nested SegWit input
	P2TRInputSize       = 58  // Taproot input (estimate)

	// Output sizes
	P2PKHOutputSize      = 34
	P2WPKHOutputSize     = 31
	P2SHP2WPKHOutputSize = 32
	P2TROutputSize       = 43
)

// PathPattern defines a BIP32 derivation path pattern to search
type PathPattern struct {
	Purpose   uint32
	CoinType  uint32
	Account   uint32
	Change    uint32
	Hardened  bool
	ScriptGen func(*btcec.PublicKey, *chaincfg.Params) (string, error)
	Name      string
}

// discoverPrivateKeyForAddress searches for a private key that derives the specified address
// using common derivation path patterns (BIP44, BIP49, BIP84, BIP86)
func discoverPrivateKeyForAddress(
	masterKey *hdkeychain.ExtendedKey,
	address string,
	coinType uint32,
	scanDepth uint32,
	params *chaincfg.Params,
) (*btcec.PrivateKey, string, error) {
	// Define common derivation path patterns to search
	var patterns []PathPattern

	// Add BIP44 path pattern (P2PKH addresses)
	patterns = append(patterns, PathPattern{
		Purpose:  BIP44Purpose,
		CoinType: coinType,
		Account:  DefaultAccount,
		Change:   ExternalChain,
		Hardened: true,
		ScriptGen: func(pubKey *btcec.PublicKey, params *chaincfg.Params) (string, error) {
			pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
			addr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, params)
			if err != nil {
				return "", err
			}
			return addr.String(), nil
		},
		Name: "BIP44 (P2PKH)",
	})

	// Add BIP44 internal path pattern (P2PKH change addresses)
	patterns = append(patterns, PathPattern{
		Purpose:  BIP44Purpose,
		CoinType: coinType,
		Account:  DefaultAccount,
		Change:   InternalChain,
		Hardened: true,
		ScriptGen: func(pubKey *btcec.PublicKey, params *chaincfg.Params) (string, error) {
			pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
			addr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, params)
			if err != nil {
				return "", err
			}
			return addr.String(), nil
		},
		Name: "BIP44 Internal (P2PKH change)",
	})

	// Add BIP84 path pattern (P2WPKH - Native SegWit addresses)
	patterns = append(patterns, PathPattern{
		Purpose:  BIP84Purpose,
		CoinType: coinType,
		Account:  DefaultAccount,
		Change:   ExternalChain,
		Hardened: true,
		ScriptGen: func(pubKey *btcec.PublicKey, params *chaincfg.Params) (string, error) {
			pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
			addr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, params)
			if err != nil {
				return "", err
			}
			return addr.String(), nil
		},
		Name: "BIP84 (P2WPKH)",
	})

	// Add BIP84 internal path pattern (P2WPKH change addresses)
	patterns = append(patterns, PathPattern{
		Purpose:  BIP84Purpose,
		CoinType: coinType,
		Account:  DefaultAccount,
		Change:   InternalChain,
		Hardened: true,
		ScriptGen: func(pubKey *btcec.PublicKey, params *chaincfg.Params) (string, error) {
			pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
			addr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, params)
			if err != nil {
				return "", err
			}
			return addr.String(), nil
		},
		Name: "BIP84 Internal (P2WPKH change)",
	})

	// Add BIP49 path pattern (P2SH-P2WPKH - Nested SegWit addresses)
	patterns = append(patterns, PathPattern{
		Purpose:  BIP49Purpose,
		CoinType: coinType,
		Account:  DefaultAccount,
		Change:   ExternalChain,
		Hardened: true,
		ScriptGen: func(pubKey *btcec.PublicKey, params *chaincfg.Params) (string, error) {
			pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
			segwitAddress, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, params)
			if err != nil {
				return "", err
			}
			script, err := txscript.PayToAddrScript(segwitAddress)
			if err != nil {
				return "", err
			}
			scriptHash := btcutil.Hash160(script)
			addr, err := btcutil.NewAddressScriptHash(scriptHash, params)
			if err != nil {
				return "", err
			}
			return addr.String(), nil
		},
		Name: "BIP49 (P2SH-P2WPKH)",
	})

	// Add BIP49 internal path pattern (P2SH-P2WPKH change addresses)
	patterns = append(patterns, PathPattern{
		Purpose:  BIP49Purpose,
		CoinType: coinType,
		Account:  DefaultAccount,
		Change:   InternalChain,
		Hardened: true,
		ScriptGen: func(pubKey *btcec.PublicKey, params *chaincfg.Params) (string, error) {
			pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
			segwitAddress, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, params)
			if err != nil {
				return "", err
			}
			script, err := txscript.PayToAddrScript(segwitAddress)
			if err != nil {
				return "", err
			}
			scriptHash := btcutil.Hash160(script)
			addr, err := btcutil.NewAddressScriptHash(scriptHash, params)
			if err != nil {
				return "", err
			}
			return addr.String(), nil
		},
		Name: "BIP49 Internal (P2SH-P2WPKH change)",
	})

	// Add BIP86 (Taproot) path pattern
	patterns = append(patterns, PathPattern{
		Purpose:  BIP86Purpose,
		CoinType: coinType,
		Account:  DefaultAccount,
		Change:   ExternalChain,
		Hardened: true,
		ScriptGen: func(pubKey *btcec.PublicKey, params *chaincfg.Params) (string, error) {
			// Create a Taproot x-only public key
			// Note: For proper Taproot key generation, internal Schnorr tweaking is required
			// This is a simplified approach for address discovery
			taprootPubKey := txscript.ComputeTaprootKeyNoScript(pubKey)
			addr, err := btcutil.NewAddressTaproot(taprootPubKey.SerializeCompressed()[1:], params)
			if err != nil {
				return "", err
			}
			return addr.String(), nil
		},
		Name: "BIP86 (P2TR)",
	})

	// Add BIP86 internal (change) path pattern
	patterns = append(patterns, PathPattern{
		Purpose:  BIP86Purpose,
		CoinType: coinType,
		Account:  DefaultAccount,
		Change:   InternalChain,
		Hardened: true,
		ScriptGen: func(pubKey *btcec.PublicKey, params *chaincfg.Params) (string, error) {
			// Create a Taproot x-only public key
			taprootPubKey := txscript.ComputeTaprootKeyNoScript(pubKey)
			addr, err := btcutil.NewAddressTaproot(taprootPubKey.SerializeCompressed()[1:], params)
			if err != nil {
				return "", err
			}
			return addr.String(), nil
		},
		Name: "BIP86 Internal (P2TR change)",
	})

	// Try to find the target address in our derivation patterns
	fmt.Println("Searching for the private key corresponding to the provided address...")
	var foundKey *btcec.PrivateKey
	var foundDerivationPath string

	for _, pattern := range patterns {
		fmt.Printf("Checking %s path pattern...\n", pattern.Name)

		// Derive purpose
		purposeKey, err := masterKey.Derive(hdkeychain.HardenedKeyStart + pattern.Purpose)
		if err != nil {
			fmt.Printf("Warning: Failed to derive purpose key for %s: %v\n", pattern.Name, err)
			continue
		}

		// Derive coin type
		coinTypeKey, err := purposeKey.Derive(hdkeychain.HardenedKeyStart + pattern.CoinType)
		if err != nil {
			fmt.Printf("Warning: Failed to derive coin type key for %s: %v\n", pattern.Name, err)
			continue
		}

		// Derive account
		accountKey, err := coinTypeKey.Derive(hdkeychain.HardenedKeyStart + pattern.Account)
		if err != nil {
			fmt.Printf("Warning: Failed to derive account key for %s: %v\n", pattern.Name, err)
			continue
		}

		// Derive change
		changeKey, err := accountKey.Derive(pattern.Change)
		if err != nil {
			fmt.Printf("Warning: Failed to derive change key for %s: %v\n", pattern.Name, err)
			continue
		}

		// Scan addresses in this pattern
		for i := uint32(0); i < scanDepth; i++ {
			indexKey, err := changeKey.Derive(i)
			if err != nil {
				fmt.Printf("Warning: Failed to derive index %d for %s: %v\n", i, pattern.Name, err)
				continue
			}

			// Get ECPrivKey from extended key
			privKey, err := indexKey.ECPrivKey()
			if err != nil {
				fmt.Printf("Warning: Failed to get EC private key for %s index %d: %v\n", pattern.Name, i, err)
				continue
			}

			// Generate address for this key
			pubKey := privKey.PubKey()
			derivedAddr, err := pattern.ScriptGen(pubKey, params)
			if err != nil {
				fmt.Printf("Warning: Failed to generate address for %s index %d: %v\n", pattern.Name, i, err)
				continue
			}

			// Check if this is our target address
			if derivedAddr == address {
				foundKey = privKey
				if pattern.Hardened {
					foundDerivationPath = fmt.Sprintf("m/%d'/%d'/%d'/%d/%d",
						pattern.Purpose, pattern.CoinType, pattern.Account, pattern.Change, i)
				} else {
					foundDerivationPath = fmt.Sprintf("m/%d'/%d'/%d/%d/%d",
						pattern.Purpose, pattern.CoinType, pattern.Account, pattern.Change, i)
				}
				break
			}
		}

		if foundKey != nil {
			break
		}
	}

	if foundKey == nil {
		return nil, "", fmt.Errorf("could not find the private key for address %s in the standard derivation paths. "+
			"Try using a different address that matches one of your wallet's derived addresses", address)
	}

	fmt.Printf("Found private key for address %s at derivation path: %s\n", address, foundDerivationPath)
	return foundKey, foundDerivationPath, nil
}

// ConsolidateUtxosCmd returns the consolidate command
func ConsolidateUtxosCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "consolidate",
		Short: "Consolidate multiple small UTXOs into a single output",
		Long:  `Consolidate multiple small unspent transaction outputs (UTXOs) into a single output to optimize wallet management and reduce future transaction fees.`,
		RunE:  runConsolidateUtxos,
	}

	// Required parameters
	cmd.Flags().StringP("file", "f", "", "Local wallet file path")
	cmd.Flags().StringP("name", "n", "", "Name of the wallet file in cloud storage")
	cmd.Flags().StringP("provider", "p", "", fmt.Sprintf("Cloud provider to use (%s)", strings.Join(util.CLOUD_PROVIDERS, ", ")))
	cmd.Flags().StringP("address", "a", "", "Bitcoin address to consolidate UTXOs from (optional, if not provided you'll be prompted to select one)")

	// Optional parameters with defaults
	cmd.Flags().Uint32P("max-inputs", "m", 50, "Maximum number of inputs to consolidate in a single transaction")
	cmd.Flags().Float64P("small-utxo-threshold", "s", 0.0001, "Prioritize UTXOs smaller than this amount in BTC")
	cmd.Flags().Float64P("max-fee-percent", "F", 2.0, "Maximum fee as percentage of total consolidated amount")
	cmd.Flags().Uint64P("fee-rate-limit", "r", 10, "Only consolidate when network fee rate is below this value (sat/vByte)")
	cmd.Flags().Float64P("fee-slippage", "S", 5.0, "Fee rate slippage percentage (5.0 = 5%) to ensure transaction acceptance")
	cmd.Flags().Bool("ignore-labels", false, "Ignore different labels/sources when consolidating UTXOs")
	cmd.Flags().Bool("testnet", false, "Use Bitcoin testnet instead of mainnet")
	cmd.Flags().StringP("api", "R", "", "Custom API endpoint URL for UTXOs and fee estimation (e.g. mempool.space)")
	cmd.Flags().BoolP("dry-run", "D", false, "Simulate the consolidation without broadcasting the transaction")
	cmd.Flags().Uint32("scan-depth", 20, "Number of addresses to scan in each derivation path pattern")
	cmd.Flags().Bool("force-consolidation", false, "Force consolidation even if fee exceeds maximum percentage")

	// Rename the flag for clarity but maintain backward compatibility
	cmd.Flags().StringP("rpc", "", "", "Alias for --api (deprecated)")
	cmd.MarkFlagsMutuallyExclusive("rpc", "api")

	return cmd
}

// UTXOGroup represents a group of UTXOs with the same label or source
type UTXOGroup struct {
	Label string
	UTXOs []util.APIUtxo
}

// runConsolidateUtxos handles the UTXO consolidation process
func runConsolidateUtxos(cmd *cobra.Command, args []string) error {
	// Get command flags
	filePath, _ := cmd.Flags().GetString("file")
	name, _ := cmd.Flags().GetString("name")
	provider, _ := cmd.Flags().GetString("provider")
	address, _ := cmd.Flags().GetString("address")
	maxInputs, _ := cmd.Flags().GetUint32("max-inputs")
	smallUtxoThreshold, _ := cmd.Flags().GetFloat64("small-utxo-threshold")
	maxFeePercent, _ := cmd.Flags().GetFloat64("max-fee-percent")
	feeRateLimit, _ := cmd.Flags().GetUint64("fee-rate-limit")
	feeSlippage, _ := cmd.Flags().GetFloat64("fee-slippage")
	ignoreLabels, _ := cmd.Flags().GetBool("ignore-labels")
	useTestnet, _ := cmd.Flags().GetBool("testnet")
	scanDepth, _ := cmd.Flags().GetUint32("scan-depth")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	forceConsolidation, _ := cmd.Flags().GetBool("force-consolidation")

	// Get API URL from either --api or --rpc flag (preferring --api if both are set)
	apiURL, _ := cmd.Flags().GetString("api")
	if apiURL == "" {
		apiURL, _ = cmd.Flags().GetString("rpc")
	}

	// Convert smallUtxoThreshold from BTC to satoshis
	smallUtxoThresholdSat := uint64(smallUtxoThreshold * 100000000)

	// Check mutual exclusivity between provider+name and file
	if (provider != "" || name != "") && filePath != "" {
		return fmt.Errorf("--file and --provider/--name are mutually exclusive, use one or the other")
	}

	// Ensure we have either file or provider
	if provider == "" && filePath == "" {
		return fmt.Errorf("either --provider or --file must be specified")
	}

	// Load and parse wallet data
	walletData, err := loadWalletData(filePath, provider, name)
	if err != nil {
		return err
	}

	var wallet WalletFile
	if err := json.Unmarshal(walletData, &wallet); err != nil {
		return fmt.Errorf("error parsing wallet file: %v", err)
	}

	// If testnet flag was provided, override wallet setting
	if cmd.Flags().Changed("testnet") {
		wallet.TestNet = useTestnet
	} else {
		// Otherwise use what's in the wallet file
		useTestnet = wallet.TestNet
	}

	// Get network parameters
	var params *chaincfg.Params
	if useTestnet {
		params = &chaincfg.TestNet3Params
		fmt.Println("Using TESTNET")
	} else {
		params = &chaincfg.MainNetParams
		fmt.Println("Using MAINNET")
	}

	// Get user credentials (password and optional passphrase)
	password, passphrase, err := promptForCredentials()
	if err != nil {
		return err
	}

	// Decrypt mnemonic and get master key
	mnemonic, err := util.DecryptMnemonic(wallet.EncryptedMnemonic, password)
	if err != nil {
		return fmt.Errorf("error decrypting mnemonic: %v", err)
	}

	// Generate seed and create master key
	seed := bip39.NewSeed(mnemonic, passphrase)
	masterKey, err := hdkeychain.NewMaster(seed, params)
	if err != nil {
		return fmt.Errorf("error creating master key: %v", err)
	}

	// Define the coinType based on network
	coinType := CoinTypeBTC
	if useTestnet {
		coinType = CoinTypeBTCTestnet
	}

	// Use the scanDepth value from the flag
	if scanDepth == 0 {
		scanDepth = ScanDepth // Use default if not provided or invalid
	}

	// If address is not provided, display available addresses and ask user to select one
	if address == "" {
		address, err = selectAddressFromWallet(masterKey, wallet, params, coinType, scanDepth)
		if err != nil {
			return fmt.Errorf("error selecting address: %v", err)
		}
	}

	// Validate address
	if err := util.ValidateBitcoinAddress(address, useTestnet); err != nil {
		return fmt.Errorf("invalid Bitcoin address: %v", err)
	}

	// Print information about the operation
	printOperationInfo(provider, name, filePath, address, useTestnet, maxInputs,
		smallUtxoThreshold, smallUtxoThresholdSat, maxFeePercent, feeRateLimit, ignoreLabels, dryRun, feeSlippage, forceConsolidation)

	// Find the private key for the address
	fmt.Println("Searching for the private key corresponding to the provided address...")
	privKey, _, err := discoverPrivateKeyForAddress(masterKey, address, coinType, scanDepth, params)
	if err != nil {
		return fmt.Errorf("error discovering private key: %v", err)
	}

	// Fetch UTXOs for this address
	fmt.Printf("Fetching UTXOs for address %s...\n", address)
	utxos, err := util.FetchUTXOsWithOptions(address, apiURL, useTestnet, true)
	if err != nil {
		return fmt.Errorf("error fetching UTXOs: %v", err)
	}

	if len(utxos) == 0 {
		fmt.Printf("No UTXOs found for address %s\n", address)
		return nil
	}

	fmt.Printf("Found %d UTXOs\n", len(utxos))

	// Check if the current fee rate is below our limit
	currentFeeRate, err := util.GetRecommendedFeeRate(util.FeeNormal, apiURL, useTestnet)
	if err != nil {
		fmt.Printf("Warning: Could not fetch current fee rate: %v\n", err)
		fmt.Println("Proceeding with the provided fee rate limit.")
		currentFeeRate = feeRateLimit
	}

	if currentFeeRate > feeRateLimit {
		return fmt.Errorf("current network fee rate (%d sat/vB) is higher than the limit (%d sat/vB). Try again later or increase --fee-rate-limit",
			currentFeeRate, feeRateLimit)
	}

	// Use the current network fee rate for our transaction
	fmt.Printf("Current network fee rate: %d sat/vB\n", currentFeeRate)
	fmt.Printf("Using this fee rate for the consolidation transaction\n")

	// Group and select UTXOs based on criteria
	utxoGroups, smallUtxoGroups, err := selectAndGroupUtxos(utxos, smallUtxoThresholdSat, int(maxInputs), ignoreLabels)
	if err != nil {
		return fmt.Errorf("error grouping UTXOs: %v", err)
	}

	// Check if we found any groups with small UTXOs
	smallGroupCount := 0
	for _, isSmall := range smallUtxoGroups {
		if isSmall {
			smallGroupCount++
		}
	}

	if smallGroupCount == 0 {
		fmt.Println("No groups with small UTXOs (below threshold) found. Nothing to consolidate.")
		return nil
	}

	fmt.Printf("Found %d UTXO groups with small UTXOs to consolidate\n", smallGroupCount)

	// Process each group with small UTXOs
	for label, utxos := range utxoGroups {
		// Skip groups with no small UTXOs
		if !smallUtxoGroups[label] {
			continue
		}

		fmt.Printf("\nProcessing UTXO group: %s (%d UTXOs)\n", label, len(utxos))

		// Process this group's UTXOs
		if err := processAndBroadcastTx(
			privKey,
			address,
			utxos,
			label,
			currentFeeRate,
			maxFeePercent,
			dryRun,
			apiURL,
			params,
			useTestnet,
			feeSlippage,
			forceConsolidation,
		); err != nil {
			// Just log the error and continue with other groups
			fmt.Printf("Error processing group %s: %v\n", label, err)
		}

		// Add a pause between processing groups if we have multiple
		if smallGroupCount > 1 {
			fmt.Println("\nPress Enter to continue with the next group...")
			fmt.Scanln()
		}
	}

	return nil
}

// selectAddressFromWallet allows the user to select an address from the wallet
func selectAddressFromWallet(masterKey *hdkeychain.ExtendedKey, wallet WalletFile, params *chaincfg.Params, coinType, scanDepth uint32) (string, error) {
	// First try to get addresses from wallet.Accounts if available
	if len(wallet.Accounts) > 0 {
		fmt.Println("\nAvailable addresses in wallet:")
		fmt.Println("================================")

		// Map to store account type display names
		accountTypeNames := map[string]string{
			"legacy":        "P2PKH (Legacy)",
			"segwit":        "P2WPKH (SegWit)",
			"nested-segwit": "P2SH-P2WPKH (Nested SegWit)",
			"taproot":       "P2TR (Taproot)",
		}

		var addresses []string
		var addressTypes []string

		// Display addresses from wallet accounts
		for i, account := range wallet.Accounts {
			displayType, ok := accountTypeNames[account.Type]
			if !ok {
				displayType = account.Type
			}

			fmt.Printf("%d) %s: %s\n", i+1, displayType, account.Address)
			addresses = append(addresses, account.Address)
			addressTypes = append(addressTypes, displayType)
		}

		// Ask user to select an address
		var selection int
		for {
			fmt.Print("\nSelect an address (1-" + fmt.Sprintf("%d", len(addresses)) + "): ")
			var input string
			fmt.Scanln(&input)

			var err error
			selection, err = strconv.Atoi(input)
			if err != nil || selection < 1 || selection > len(addresses) {
				fmt.Println("Invalid selection, please enter a number between 1 and", len(addresses))
				continue
			}
			break
		}

		// Return the selected address
		selectedIndex := selection - 1
		fmt.Printf("\nSelected address: %s (%s)\n", addresses[selectedIndex], addressTypes[selectedIndex])
		return addresses[selectedIndex], nil
	}

	// If no addresses in wallet.Accounts, use derivation paths to generate some
	fmt.Println("\nGenerating addresses from derivation paths:")
	fmt.Println("==========================================")

	// Define patterns to derive addresses
	var patterns []PathPattern

	// Add BIP44 path pattern (P2PKH addresses)
	patterns = append(patterns, PathPattern{
		Purpose:  BIP44Purpose,
		CoinType: coinType,
		Account:  DefaultAccount,
		Change:   ExternalChain,
		Hardened: true,
		ScriptGen: func(pubKey *btcec.PublicKey, params *chaincfg.Params) (string, error) {
			pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
			addr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, params)
			if err != nil {
				return "", err
			}
			return addr.String(), nil
		},
		Name: "BIP44 (P2PKH Legacy)",
	})

	// Add BIP84 path pattern (P2WPKH - Native SegWit addresses)
	patterns = append(patterns, PathPattern{
		Purpose:  BIP84Purpose,
		CoinType: coinType,
		Account:  DefaultAccount,
		Change:   ExternalChain,
		Hardened: true,
		ScriptGen: func(pubKey *btcec.PublicKey, params *chaincfg.Params) (string, error) {
			pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
			addr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, params)
			if err != nil {
				return "", err
			}
			return addr.String(), nil
		},
		Name: "BIP84 (P2WPKH SegWit)",
	})

	// Add BIP49 path pattern (P2SH-P2WPKH - Nested SegWit addresses)
	patterns = append(patterns, PathPattern{
		Purpose:  BIP49Purpose,
		CoinType: coinType,
		Account:  DefaultAccount,
		Change:   ExternalChain,
		Hardened: true,
		ScriptGen: func(pubKey *btcec.PublicKey, params *chaincfg.Params) (string, error) {
			pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
			segwitAddress, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, params)
			if err != nil {
				return "", err
			}
			script, err := txscript.PayToAddrScript(segwitAddress)
			if err != nil {
				return "", err
			}
			scriptHash := btcutil.Hash160(script)
			addr, err := btcutil.NewAddressScriptHash(scriptHash, params)
			if err != nil {
				return "", err
			}
			return addr.String(), nil
		},
		Name: "BIP49 (P2SH-P2WPKH Nested SegWit)",
	})

	// Add BIP86 (Taproot) path pattern
	patterns = append(patterns, PathPattern{
		Purpose:  BIP86Purpose,
		CoinType: coinType,
		Account:  DefaultAccount,
		Change:   ExternalChain,
		Hardened: true,
		ScriptGen: func(pubKey *btcec.PublicKey, params *chaincfg.Params) (string, error) {
			taprootPubKey := txscript.ComputeTaprootKeyNoScript(pubKey)
			addr, err := btcutil.NewAddressTaproot(taprootPubKey.SerializeCompressed()[1:], params)
			if err != nil {
				return "", err
			}
			return addr.String(), nil
		},
		Name: "BIP86 (P2TR Taproot)",
	})

	// Derive addresses from each pattern
	var addresses []string
	var addressTypes []string
	var derivationPaths []string

	for _, pattern := range patterns {
		// Derive purpose
		purposeKey, err := masterKey.Derive(hdkeychain.HardenedKeyStart + pattern.Purpose)
		if err != nil {
			fmt.Printf("Warning: Failed to derive purpose key for %s: %v\n", pattern.Name, err)
			continue
		}

		// Derive coin type
		coinTypeKey, err := purposeKey.Derive(hdkeychain.HardenedKeyStart + pattern.CoinType)
		if err != nil {
			fmt.Printf("Warning: Failed to derive coin type key for %s: %v\n", pattern.Name, err)
			continue
		}

		// Derive account
		accountKey, err := coinTypeKey.Derive(hdkeychain.HardenedKeyStart + pattern.Account)
		if err != nil {
			fmt.Printf("Warning: Failed to derive account key for %s: %v\n", pattern.Name, err)
			continue
		}

		// Derive change
		changeKey, err := accountKey.Derive(pattern.Change)
		if err != nil {
			fmt.Printf("Warning: Failed to derive change key for %s: %v\n", pattern.Name, err)
			continue
		}

		// Derive address index (we'll display up to 5 addresses for each type)
		for i := uint32(0); i < 5; i++ {
			indexKey, err := changeKey.Derive(i)
			if err != nil {
				fmt.Printf("Warning: Failed to derive index %d for %s: %v\n", i, pattern.Name, err)
				continue
			}

			// Get public key from extended key
			pubKey, err := indexKey.ECPubKey()
			if err != nil {
				fmt.Printf("Warning: Failed to get EC public key for %s index %d: %v\n", pattern.Name, i, err)
				continue
			}

			// Generate address
			addr, err := pattern.ScriptGen(pubKey, params)
			if err != nil {
				fmt.Printf("Warning: Failed to generate address for %s index %d: %v\n", pattern.Name, i, err)
				continue
			}

			// Create derivation path string
			path := fmt.Sprintf("m/%d'/%d'/%d'/%d/%d", pattern.Purpose, pattern.CoinType, pattern.Account, pattern.Change, i)

			// Add to our lists
			addresses = append(addresses, addr)
			addressTypes = append(addressTypes, pattern.Name)
			derivationPaths = append(derivationPaths, path)

			// Display to user
			fmt.Printf("%d) %s: %s (path: %s)\n", len(addresses), pattern.Name, addr, path)
		}
	}

	if len(addresses) == 0 {
		return "", fmt.Errorf("no addresses could be derived from wallet")
	}

	// Ask user to select an address
	var selection int
	for {
		fmt.Print("\nSelect an address (1-" + fmt.Sprintf("%d", len(addresses)) + "): ")
		var input string
		fmt.Scanln(&input)

		var err error
		selection, err = strconv.Atoi(input)
		if err != nil || selection < 1 || selection > len(addresses) {
			fmt.Println("Invalid selection, please enter a number between 1 and", len(addresses))
			continue
		}
		break
	}

	// Return the selected address
	selectedIndex := selection - 1
	fmt.Printf("\nSelected address: %s (%s)\n", addresses[selectedIndex], addressTypes[selectedIndex])
	fmt.Printf("Derivation path: %s\n", derivationPaths[selectedIndex])

	return addresses[selectedIndex], nil
}

// printOperationInfo prints information about the operation
func printOperationInfo(provider, name, filePath, address string, useTestnet bool, maxInputs uint32,
	smallUtxoThreshold float64, smallUtxoThresholdSat uint64, maxFeePercent float64,
	feeRateLimit uint64, ignoreLabels, dryRun bool, feeSlippage float64, forceConsolidation bool) {

	fmt.Println("UTXO Consolidation")
	fmt.Println("=====================================")
	if provider != "" {
		fmt.Printf("Using provider: %s, wallet: %s\n", provider, name)
	} else {
		fmt.Printf("Using wallet file: %s\n", filePath)
	}
	fmt.Printf("Address: %s\n", address)

	// Fix the ternary operator with a proper if-else statement
	networkName := "Mainnet"
	if useTestnet {
		networkName = "Testnet"
	}
	fmt.Printf("Network: %s\n", networkName)

	fmt.Printf("Maximum inputs per tx: %d\n", maxInputs)
	fmt.Printf("Small UTXO threshold: %.8f BTC (%d satoshis)\n", smallUtxoThreshold, smallUtxoThresholdSat)
	fmt.Printf("Maximum fee: %.2f%% of consolidated amount\n", maxFeePercent)
	fmt.Printf("Maximum fee rate: %d sat/vByte\n", feeRateLimit)
	fmt.Printf("Fee slippage: %.2f%% (to ensure transaction acceptance)\n", feeSlippage)
	if ignoreLabels {
		fmt.Println("Ignoring UTXO labels/sources")
	}
	if dryRun {
		fmt.Println("Dry run mode - transaction will not be broadcast")
	}
	if forceConsolidation {
		fmt.Println("Force consolidation: Yes (will ignore max fee percentage limit)")
	}
}

// loadWalletData loads wallet data from either a local file or cloud provider
func loadWalletData(filePath, provider, name string) ([]byte, error) {
	var err error
	var walletData []byte

	if provider != "" {
		// Load from cloud storage
		cloudPath := filepath.Join(util.GetCloudFileDir(), name+".json")
		walletData, err = util.Get(provider, cloudPath)
		if err != nil {
			return nil, fmt.Errorf("error loading wallet from %s: %v", provider, err)
		}
	} else {
		// Load from local file
		walletData, err = util.Get(filePath, filePath)
		if err != nil {
			return nil, fmt.Errorf("error loading wallet from local file: %v", err)
		}
	}

	return walletData, nil
}

// promptForCredentials prompts the user for password and optional passphrase
func promptForCredentials() (string, string, error) {
	// Prompt for password to decrypt mnemonic
	fmt.Print("Please Enter \033[1;31mEncryption Password\033[0m: ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", "", fmt.Errorf("\nerror reading password: %v", err)
	}
	fmt.Println()
	password := string(passwordBytes)

	// Ask if a passphrase was used
	fmt.Print("Did you use a BIP39 passphrase for this wallet? (y/n): ")
	var answer string
	fmt.Scanln(&answer)

	var passphrase string
	if strings.ToLower(answer) == "y" || strings.ToLower(answer) == "yes" {
		fmt.Print("Please Enter \033[1;31mBIP39 Passphrase\033[0m: ")
		passphraseBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", "", fmt.Errorf("\nerror reading passphrase: %v", err)
		}
		fmt.Println()
		passphrase = string(passphraseBytes)
	}

	return password, passphrase, nil
}

// selectAndGroupUtxos selects UTXOs based on the provided criteria and groups them by label
func selectAndGroupUtxos(
	utxos []util.APIUtxo,
	smallUtxoThreshold uint64,
	maxInputs int,
	ignoreLabels bool,
) (map[string][]util.APIUtxo, map[string]bool, error) {
	// Group UTXOs by label (or script type if label is not available)
	utxoGroups := make(map[string][]util.APIUtxo)
	smallUtxoGroups := make(map[string]bool)

	for _, utxo := range utxos {
		// Skip unconfirmed UTXOs
		if !utxo.Status.Confirmed {
			continue
		}

		// Default label if none exists
		label := "unlabeled"

		// If we have a script type available, use it as the label
		if utxo.ScriptType != "" {
			label = utxo.ScriptType
		}

		// Append this UTXO to its label group
		utxoGroups[label] = append(utxoGroups[label], utxo)

		// Mark this label as having small UTXOs if this UTXO is below the threshold
		if utxo.Value < smallUtxoThreshold {
			smallUtxoGroups[label] = true
		}
	}

	// If ignoring labels, consolidate all UTXOs into a single group
	if ignoreLabels {
		allUtxos := []util.APIUtxo{}
		for _, group := range utxoGroups {
			allUtxos = append(allUtxos, group...)
		}
		utxoGroups = map[string][]util.APIUtxo{"all": allUtxos}

		// Check if we have small UTXOs in the consolidated group
		smallUtxoGroups = map[string]bool{}
		for _, utxo := range allUtxos {
			if utxo.Value < smallUtxoThreshold {
				smallUtxoGroups["all"] = true
				break
			}
		}
	}

	// For each group, prioritize small UTXOs first if present
	for label, utxos := range utxoGroups {
		// Skip groups with no small UTXOs
		if !smallUtxoGroups[label] {
			continue
		}

		// Sort UTXOs by amount (ascending) so smaller UTXOs are first
		sort.Slice(utxos, func(i, j int) bool {
			return utxos[i].Value < utxos[j].Value
		})

		// Limit the number of inputs per group if maxInputs is specified
		if maxInputs > 0 && len(utxos) > maxInputs {
			utxoGroups[label] = utxos[:maxInputs]
		} else {
			utxoGroups[label] = utxos
		}
	}

	return utxoGroups, smallUtxoGroups, nil
}

// processAndBroadcastTx processes the UTXOs, creates a transaction, and optionally broadcasts it
func processAndBroadcastTx(
	privKey *btcec.PrivateKey,
	address string,
	utxos []util.APIUtxo,
	label string,
	feeRate uint64,
	maxFeePercent float64,
	dryRun bool,
	apiURL string,
	params *chaincfg.Params,
	useTestnet bool,
	feeSlippage float64,
	forceConsolidation bool,
) error {
	// Apply fee slippage to ensure transaction is accepted
	originalFeeRate := feeRate
	adjustedFeeRate := uint64(float64(feeRate) * (1.0 + feeSlippage/100.0))

	// Ensure we have at least 1 sat/vB increase if there's any slippage
	if feeSlippage > 0 && adjustedFeeRate <= originalFeeRate {
		adjustedFeeRate = originalFeeRate + 1
	}

	// Show the fee adjustment if slippage is applied
	if feeSlippage > 0 {
		fmt.Printf("Applying %.2f%% fee slippage: %d sat/vB -> %d sat/vB\n",
			feeSlippage, originalFeeRate, adjustedFeeRate)
	}

	// Create and sign the transaction with the adjusted fee rate
	consolidationTx, fee, err := createAndSignConsolidationTx(
		privKey,
		address,
		utxos,
		adjustedFeeRate,
		maxFeePercent,
		params,
		forceConsolidation,
	)
	if err != nil {
		return fmt.Errorf("error creating transaction: %v", err)
	}

	// Calculate total input amount and output amount
	var totalSats uint64
	for _, utxo := range utxos {
		totalSats += utxo.Value
	}
	outputAmount := totalSats - fee

	// Calculate actual fee rate
	txSizeVBytes := consolidationTx.SerializeSize()
	actualFeeRate := float64(fee) / float64(txSizeVBytes)

	// Print transaction summary with detailed fee information
	fmt.Printf("\nTransaction Summary (Group: %s)\n", label)
	fmt.Printf("Inputs: %d UTXOs with total value of %d satoshis (%.8f BTC)\n",
		len(utxos), totalSats, float64(totalSats)/100000000)
	fmt.Printf("Output: %d satoshis (%.8f BTC)\n",
		outputAmount, float64(outputAmount)/100000000)
	fmt.Printf("Fee: %d satoshis (%.8f BTC)\n",
		fee, float64(fee)/100000000)
	fmt.Printf("Transaction size: %d vBytes\n", txSizeVBytes)
	fmt.Printf("Requested fee rate: %d sat/vB (adjusted with %.2f%% slippage from %d sat/vB)\n",
		adjustedFeeRate, feeSlippage, originalFeeRate)
	fmt.Printf("Actual fee rate: %.2f sat/vB\n", actualFeeRate)

	// Check if actual fee rate is too low
	if actualFeeRate < float64(adjustedFeeRate) {
		fmt.Printf("WARNING: Actual fee rate (%.2f sat/vB) is lower than requested (%.2f sat/vB)\n",
			actualFeeRate, float64(adjustedFeeRate))

		// Force a higher fee if needed
		if actualFeeRate < 178 { // Minimum mempool.space relay fee observed previously
			fmt.Println("Actual fee rate is below minimum relay fee. Consider using a higher slippage value.")
		}
	}

	// Serialize transaction for broadcasting
	var signedTxBytes bytes.Buffer
	if err := consolidationTx.Serialize(&signedTxBytes); err != nil {
		return fmt.Errorf("error serializing transaction: %v", err)
	}
	signedTxHex := hex.EncodeToString(signedTxBytes.Bytes())

	// Print transaction hex
	fmt.Printf("Transaction Hex: %s\n", signedTxHex)

	// If dry run, don't broadcast
	if dryRun {
		fmt.Println("Dry run mode - transaction not broadcast")
		return nil
	}

	// Confirm broadcast
	fmt.Print("Broadcast this transaction? (y/n): ")
	var answer string
	fmt.Scanln(&answer)

	if strings.ToLower(answer) != "y" && strings.ToLower(answer) != "yes" {
		fmt.Println("Transaction broadcast cancelled")
		return nil
	}

	// Broadcast the transaction
	txid, err := util.BroadcastRawTransaction(signedTxHex, apiURL, useTestnet)
	if err != nil {
		return fmt.Errorf("error broadcasting transaction: %v", err)
	}

	fmt.Printf("Transaction successfully broadcast!\nTXID: %s\n", txid)

	// Provide a link to a block explorer
	if useTestnet {
		fmt.Printf("View transaction: https://blockstream.info/testnet/tx/%s\n", txid)
	} else {
		fmt.Printf("View transaction: https://blockstream.info/tx/%s\n", txid)
	}

	return nil
}

// createAndSignConsolidationTx creates a transaction that consolidates the given UTXOs
// and signs it with the provided private key
func createAndSignConsolidationTx(
	privKey *btcec.PrivateKey,
	address string,
	utxos []util.APIUtxo,
	feeRate uint64,
	maxFeePercent float64,
	params *chaincfg.Params,
	forceConsolidation bool,
) (*wire.MsgTx, uint64, error) {
	// Create a new transaction
	consolidationTx := wire.NewMsgTx(wire.TxVersion)

	// Add all UTXOs as inputs
	for _, utxo := range utxos {
		prevOutHash, err := chainhash.NewHashFromStr(utxo.Txid)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid transaction hash: %v", err)
		}

		outpoint := wire.NewOutPoint(prevOutHash, utxo.Vout)
		txIn := wire.NewTxIn(outpoint, nil, nil)

		// Unset the sequence to signal RBF (Replace-By-Fee)
		// This allows the user to bump the fee later if needed
		txIn.Sequence = wire.MaxTxInSequenceNum - 1

		consolidationTx.AddTxIn(txIn)
	}

	// Calculate total input amount
	var totalSats uint64
	for _, utxo := range utxos {
		totalSats += utxo.Value
	}

	// Estimate transaction size based on actual input types
	// This provides much more accurate fee estimates than using a fixed P2PKH size
	var estimatedTxSize int

	// Transaction overhead (version, locktime, input/output count)
	estimatedTxSize = TxVersionSize + TxLockTimeSize + TxInCountSize + TxOutCountSize

	// Add size for each input based on its script type
	for _, utxo := range utxos {
		switch {
		case strings.HasPrefix(utxo.ScriptType, "p2pkh") || strings.HasPrefix(utxo.ScriptType, "v0_p2pkh"):
			estimatedTxSize += P2PKHInputSize
		case strings.HasPrefix(utxo.ScriptType, "p2wpkh") || strings.HasPrefix(utxo.ScriptType, "v0_p2wpkh"):
			estimatedTxSize += P2WPKHInputSize
		case strings.HasPrefix(utxo.ScriptType, "p2sh-p2wpkh") || strings.HasPrefix(utxo.ScriptType, "v0_p2sh-p2wpkh"):
			estimatedTxSize += P2SHP2WPKHInputSize
		case strings.HasPrefix(utxo.ScriptType, "p2tr") || strings.HasPrefix(utxo.ScriptType, "v1_p2tr"):
			estimatedTxSize += P2TRInputSize
		default:
			// Default to P2PKH for unknown types (conservative estimate)
			estimatedTxSize += P2PKHInputSize
		}
	}

	// Add output size - we're using the original address as output
	// Determine the output size based on the address type
	outputAddr, err := btcutil.DecodeAddress(address, params)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to decode address: %v", err)
	}

	switch outputAddr.(type) {
	case *btcutil.AddressPubKeyHash:
		estimatedTxSize += P2PKHOutputSize
	case *btcutil.AddressWitnessPubKeyHash:
		estimatedTxSize += P2WPKHOutputSize
	case *btcutil.AddressScriptHash:
		estimatedTxSize += P2SHP2WPKHOutputSize
	case *btcutil.AddressTaproot:
		estimatedTxSize += P2TROutputSize
	default:
		// Default to P2PKH for unknown types
		estimatedTxSize += P2PKHOutputSize
	}

	// Add a 2-byte buffer to account for any estimation inaccuracies
	estimatedTxSize += 2

	// Print size estimation details
	fmt.Printf("Estimated transaction size: %d vBytes\n", estimatedTxSize)

	// Calculate fee (in satoshis)
	fee := uint64(estimatedTxSize) * feeRate

	// Ensure minimum fee is at least 1000 satoshis for very small transactions
	if fee < 1000 {
		fee = 1000
		fmt.Println("Using minimum fee of 1000 satoshis")
	}

	// Check if the fee exceeds the maximum percentage
	maxFeeSats := uint64(float64(totalSats) * maxFeePercent / 100.0)
	if fee > maxFeeSats && !forceConsolidation {
		return nil, 0, fmt.Errorf("estimated fee (%d sats) exceeds maximum allowed (%d sats, %.2f%% of total). Use --force-consolidation to override this limit",
			fee, maxFeeSats, maxFeePercent)
	} else if fee > maxFeeSats && forceConsolidation {
		actualFeePercent := (float64(fee) / float64(totalSats)) * 100.0
		fmt.Printf("WARNING: Fee (%d sats) is %.2f%% of the total amount (%d sats), exceeding the %.2f%% limit, but proceeding due to --force-consolidation flag\n",
			fee, actualFeePercent, totalSats, maxFeePercent)
	}

	// Verify we have enough value in inputs to pay the fee
	if totalSats <= fee {
		return nil, 0, fmt.Errorf("not enough value in UTXOs to pay fee. Total: %d sats, Fee: %d sats",
			totalSats, fee)
	}

	// Add output - Send everything minus the fee back to the same address
	outputAmount := totalSats - fee

	pkScript, err := txscript.PayToAddrScript(outputAddr)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create output script: %v", err)
	}

	txOut := wire.NewTxOut(int64(outputAmount), pkScript)
	consolidationTx.AddTxOut(txOut)

	// Create a custom previous output fetcher for txsighash
	prevOutputs := make(map[wire.OutPoint]*wire.TxOut)
	for i, utxo := range utxos {
		outpoint := consolidationTx.TxIn[i].PreviousOutPoint
		scriptBytes, err := hex.DecodeString(utxo.PkScript)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to decode script: %v", err)
		}

		prevOutputs[outpoint] = &wire.TxOut{
			Value:    int64(utxo.Value),
			PkScript: scriptBytes,
		}
	}

	// Create a custom PrevOutputFetcher
	prevOutputFetcher := txscript.NewMultiPrevOutFetcher(prevOutputs)

	// Create the transaction sighash for witness signatures
	txSigHashes := txscript.NewTxSigHashes(consolidationTx, prevOutputFetcher)

	// Sign all the inputs based on their script type
	for i, utxo := range utxos {
		// Decode the script from the UTXO
		scriptBytes, err := hex.DecodeString(utxo.PkScript)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to decode script: %v", err)
		}

		// Sign the input based on its script type
		switch {
		case strings.HasPrefix(utxo.ScriptType, "p2pkh") || strings.HasPrefix(utxo.ScriptType, "v0_p2pkh"):
			// P2PKH signature
			signature, err := txscript.SignatureScript(
				consolidationTx,
				i,
				scriptBytes,
				txscript.SigHashAll,
				privKey,
				true,
			)
			if err != nil {
				return nil, 0, fmt.Errorf("error signing P2PKH input %d: %v", i, err)
			}
			consolidationTx.TxIn[i].SignatureScript = signature

		case strings.HasPrefix(utxo.ScriptType, "p2wpkh") || strings.HasPrefix(utxo.ScriptType, "v0_p2wpkh"):
			// P2WPKH (Native SegWit) signature
			pubKey := privKey.PubKey()
			pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())

			// Create witness program
			witnessProgram, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_0).
				AddData(pubKeyHash).
				Script()
			if err != nil {
				return nil, 0, fmt.Errorf("error creating witness program for input %d: %v", i, err)
			}

			// Create signature
			sig, err := txscript.RawTxInWitnessSignature(
				consolidationTx,
				txSigHashes,
				i,
				int64(utxo.Value),
				witnessProgram,
				txscript.SigHashAll,
				privKey,
			)
			if err != nil {
				return nil, 0, fmt.Errorf("error creating witness signature for input %d: %v", i, err)
			}

			// Add witness data
			pubKeyBytes := pubKey.SerializeCompressed()
			consolidationTx.TxIn[i].Witness = wire.TxWitness{sig, pubKeyBytes}

		case strings.HasPrefix(utxo.ScriptType, "p2sh-p2wpkh") || strings.HasPrefix(utxo.ScriptType, "v0_p2sh-p2wpkh"):
			// P2SH-P2WPKH (Nested SegWit) signature
			pubKey := privKey.PubKey()
			pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())

			// Create witness program (redeem script)
			witnessProgram, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_0).
				AddData(pubKeyHash).
				Script()
			if err != nil {
				return nil, 0, fmt.Errorf("error creating witness program for input %d: %v", i, err)
			}

			// Script signature (redeemScript goes in scriptSig for p2sh-p2wpkh)
			consolidationTx.TxIn[i].SignatureScript = append([]byte{byte(len(witnessProgram))}, witnessProgram...)

			// Create signature for the witness
			sig, err := txscript.RawTxInWitnessSignature(
				consolidationTx,
				txSigHashes,
				i,
				int64(utxo.Value),
				witnessProgram,
				txscript.SigHashAll,
				privKey,
			)
			if err != nil {
				return nil, 0, fmt.Errorf("error creating witness signature for input %d: %v", i, err)
			}

			// Add witness data
			pubKeyBytes := pubKey.SerializeCompressed()
			consolidationTx.TxIn[i].Witness = wire.TxWitness{sig, pubKeyBytes}

		case strings.HasPrefix(utxo.ScriptType, "p2tr") || strings.HasPrefix(utxo.ScriptType, "v1_p2tr"):
			// P2TR (Taproot) signature using key path spending
			// No need to extract the public key as we're directly signing with the private key

			// Create the signature hash for Taproot input
			sigHash, err := txscript.CalcTaprootSignatureHash(
				txSigHashes,
				txscript.SigHashDefault,
				consolidationTx,
				i,
				prevOutputFetcher,
			)
			if err != nil {
				return nil, 0, fmt.Errorf("error calculating taproot signature hash for input %d: %v", i, err)
			}

			// Create Schnorr signature
			signature, err := schnorr.Sign(privKey, sigHash)
			if err != nil {
				return nil, 0, fmt.Errorf("error creating schnorr signature for input %d: %v", i, err)
			}

			// Taproot signatures are just a single Schnorr signature in the witness stack (for key path)
			consolidationTx.TxIn[i].Witness = wire.TxWitness{signature.Serialize()}

		default:
			return nil, 0, fmt.Errorf("unsupported script type: %s for UTXO %s:%d",
				utxo.ScriptType, utxo.Txid, utxo.Vout)
		}
	}

	return consolidationTx, fee, nil
}
