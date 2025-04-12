package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/ethanzhrepo/btc-cli-vault/util"
	"github.com/spf13/cobra"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/term"
)

func SignTxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign-raw-tx",
		Short: "Sign a Bitcoin transaction",
		Long:  `Sign a Bitcoin transaction with your private key.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Parse command flags
			filePath, _ := cmd.Flags().GetString("file")
			provider, _ := cmd.Flags().GetString("provider")
			name, _ := cmd.Flags().GetString("name")
			rawTxHex, _ := cmd.Flags().GetString("raw-tx")
			rawTxFile, _ := cmd.Flags().GetString("raw-tx-file")
			broadcast, _ := cmd.Flags().GetBool("broadcast")
			testnet, _ := cmd.Flags().GetBool("testnet")

			// Initialize config
			initConfig()

			// Validate input method flags
			if filePath != "" && (provider != "" || name != "") {
				return fmt.Errorf("error: --file and --provider/--name options are mutually exclusive")
			}

			if filePath == "" && (provider == "" || name == "") {
				return fmt.Errorf("error: either --file or both --provider and --name must be specified")
			}

			// Validate transaction input flags
			if rawTxHex != "" && rawTxFile != "" {
				return fmt.Errorf("error: --raw-tx and --raw-tx-file are mutually exclusive")
			}

			if rawTxHex == "" && rawTxFile == "" {
				return fmt.Errorf("error: either --raw-tx or --raw-tx-file must be specified")
			}

			// Get the raw transaction
			var txBytes []byte
			if rawTxHex != "" {
				// Decode hex transaction
				var err error
				txBytes, err = hex.DecodeString(rawTxHex)
				if err != nil {
					return fmt.Errorf("error decoding raw transaction hex: %v", err)
				}
			} else {
				// Read transaction from file
				var err error
				txBytes, err = os.ReadFile(rawTxFile)
				if err != nil {
					return fmt.Errorf("error reading raw transaction file: %v", err)
				}

				// If file contents is hex string, decode it
				txHexStr := strings.TrimSpace(string(txBytes))
				if isHexString(txHexStr) {
					txBytes, err = hex.DecodeString(txHexStr)
					if err != nil {
						return fmt.Errorf("error decoding hex from file: %v", err)
					}
				}
			}

			// Deserialize the transaction
			var tx wire.MsgTx
			if err := tx.Deserialize(strings.NewReader(string(txBytes))); err != nil {
				return fmt.Errorf("error deserializing transaction: %v", err)
			}

			fmt.Printf("Successfully parsed transaction with %d inputs and %d outputs\n", len(tx.TxIn), len(tx.TxOut))

			// Load wallet data
			var walletData []byte
			var err error

			if provider != "" {
				// Load from cloud storage
				cloudPath := filepath.Join(util.GetCloudFileDir(), name+".json")
				walletData, err = util.Get(provider, cloudPath)
				if err != nil {
					return fmt.Errorf("error loading wallet from %s: %v", provider, err)
				}
				fmt.Printf("Loaded wallet from %s cloud storage: %s\n", provider, name)
			} else {
				// Load from local file
				walletData, err = util.Get(filePath, filePath)
				if err != nil {
					return fmt.Errorf("error loading wallet from local file: %v", err)
				}
				fmt.Printf("Loaded wallet from local file: %s\n", filePath)
			}

			// Parse wallet file
			var wallet WalletFile
			if err := json.Unmarshal(walletData, &wallet); err != nil {
				return fmt.Errorf("error parsing wallet file: %v", err)
			}

			// Set network parameters
			var params *chaincfg.Params
			if testnet || wallet.TestNet {
				params = &chaincfg.TestNet3Params
				fmt.Println("Using testnet network")
			} else {
				params = &chaincfg.MainNetParams
				fmt.Println("Using mainnet network")
			}

			// Get password to decrypt wallet
			fmt.Print("Please Enter \033[1;31mEncryption Password\033[0m: ")
			passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return fmt.Errorf("\nerror reading password: %v", err)
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
					return fmt.Errorf("\nerror reading passphrase: %v", err)
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
				fmt.Print("\nSelect an address to sign with (enter number): ")
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
			fmt.Printf("Account type: \033[1;36m%s\033[0m\n", selectedAccount.Type)

			// Verify derivation path is present
			if selectedAccount.DerivationPath == "" && selectedAccount.HDPath == "" {
				return fmt.Errorf("\033[1;31mError: Selected account does not have a derivation path\033[0m\nThis wallet cannot be used for transactions until a proper derivation path is added")
			}

			// Display derivation path
			derivationPath := selectedAccount.DerivationPath
			if derivationPath == "" {
				derivationPath = selectedAccount.HDPath
			}
			fmt.Printf("Derivation path: \033[1;36m%s\033[0m\n", derivationPath)

			// Derive private key for signing
			privateKey, err := derivePrivateKeyForAccount(seed, selectedAccount, params)
			if err != nil {
				return fmt.Errorf("error deriving private key: %v", err)
			}

			// Sign the transaction
			signedTx, err := signRawTransaction(&tx, privateKey, selectedAccount, params)
			if err != nil {
				return fmt.Errorf("error signing transaction: %v", err)
			}

			// Serialize the signed transaction
			var signedTxBuf strings.Builder
			err = signedTx.Serialize(&hexWriter{&signedTxBuf})
			if err != nil {
				return fmt.Errorf("error serializing signed transaction: %v", err)
			}
			signedTxHex := signedTxBuf.String()

			// Display signed transaction
			fmt.Printf("\n\033[1;32m✓ Transaction successfully signed\033[0m\n")
			fmt.Printf("Signed Transaction (hex):\n\033[0;37m%s\033[0m\n", signedTxHex)

			// Broadcast if requested
			if broadcast {
				fmt.Println("\nBroadcasting transaction...")
				txid, err := util.BroadcastRawTransaction(signedTxHex, "", testnet)
				if err != nil {
					return fmt.Errorf("error broadcasting transaction: %v", err)
				}

				fmt.Printf("\n\033[1;32m✅ Transaction successfully broadcast!\033[0m\n")
				fmt.Printf("Transaction ID: \033[1;36m%s\033[0m\n", txid)

				// Display transaction explorer link
				if testnet {
					fmt.Printf("Track your transaction: https://mempool.space/testnet/tx/%s\n", txid)
				} else {
					fmt.Printf("Track your transaction: https://mempool.space/tx/%s\n", txid)
				}
			} else {
				fmt.Println("\nTransaction signed but not broadcast. Use --broadcast flag to broadcast.")
			}

			return nil
		},
	}

	// Add command flags
	cmd.Flags().StringP("file", "f", "", "Local wallet file path")
	cmd.Flags().StringP("provider", "p", "", "Cloud provider (e.g., google, dropbox, keychain)")
	cmd.Flags().StringP("name", "n", "", "Name of the wallet file in cloud storage")
	cmd.Flags().String("raw-tx", "", "Raw transaction hex to sign")
	cmd.Flags().String("raw-tx-file", "", "File containing raw transaction to sign")
	cmd.Flags().Bool("broadcast", false, "Broadcast transaction after signing")
	cmd.Flags().Bool("testnet", false, "Use Bitcoin testnet instead of mainnet")

	return cmd
}

// signRawTransaction signs a raw transaction using the provided private key
func signRawTransaction(tx *wire.MsgTx, privateKey *btcec.PrivateKey, selectedAccount AccountInfo, params *chaincfg.Params) (*wire.MsgTx, error) {
	// Make a copy of the transaction to sign
	signedTx := tx.Copy()

	// Fetch UTXOs for the inputs
	fmt.Println("\nFetching UTXOs for transaction inputs...")

	// Create a map to store input UTXO data for the prevOutFetcher
	prevOuts := make(map[wire.OutPoint]*wire.TxOut)

	// Query UTXO data for each input
	for i, txIn := range signedTx.TxIn {
		fmt.Printf("Getting data for input #%d (outpoint: %s:%d)...\n", i, txIn.PreviousOutPoint.Hash.String(), txIn.PreviousOutPoint.Index)

		// Get the previous transaction to extract value and script
		txid := txIn.PreviousOutPoint.Hash.String()
		vout := txIn.PreviousOutPoint.Index

		// Fetch the transaction details using mempool.space API
		prevTx, err := util.GetTransaction(txid, "", params == &chaincfg.TestNet3Params)
		if err != nil {
			return nil, fmt.Errorf("error fetching previous transaction %s: %v", txid, err)
		}

		// Validate vout index
		if int(vout) >= len(prevTx.Vout) {
			return nil, fmt.Errorf("invalid vout index %d for transaction %s", vout, txid)
		}

		// Get the previous output
		prevOutput := prevTx.Vout[vout]

		// Decode the script
		pkScript, err := hex.DecodeString(prevOutput.ScriptPubKey)
		if err != nil {
			return nil, fmt.Errorf("error decoding previous output script: %v", err)
		}

		// Store the previous output in the map
		outpoint := wire.OutPoint{
			Hash:  txIn.PreviousOutPoint.Hash,
			Index: txIn.PreviousOutPoint.Index,
		}
		prevOuts[outpoint] = wire.NewTxOut(int64(prevOutput.Value), pkScript)

		fmt.Printf("  Amount: %d satoshis\n", prevOutput.Value)
		fmt.Printf("  Script Type: %s\n", prevOutput.ScriptPubKeyType)
	}

	// Create the previous output fetcher for sighash calculation
	prevOutFetcher := txscript.NewMultiPrevOutFetcher(prevOuts)

	// Prepare information needed for signing
	var redeemScript []byte
	var taprootInternalKey []byte
	var err error

	// Based on the account type, prepare necessary scripts
	switch selectedAccount.Type {
	case "p2sh-p2wpkh", "nested-segwit":
		// Decode redeem script from account if available
		if selectedAccount.RedeemScript != "" {
			redeemScript, err = hex.DecodeString(selectedAccount.RedeemScript)
			if err != nil {
				return nil, fmt.Errorf("error decoding redeem script from account: %v", err)
			}
		} else {
			// Fallback: create redeem script from public key
			pubKey := privateKey.PubKey().SerializeCompressed()
			pubKeyHash := btcutil.Hash160(pubKey)
			redeemScript, err = txscript.NewScriptBuilder().
				AddOp(txscript.OP_0).
				AddData(pubKeyHash).
				Script()
			if err != nil {
				return nil, fmt.Errorf("error creating redeem script: %v", err)
			}
		}
	case "p2tr", "taproot":
		// For Taproot, decode the internal pubkey if available
		if selectedAccount.InternalPubKey != "" {
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

	// For each input, sign it based on its script type
	for i, txIn := range signedTx.TxIn {
		fmt.Printf("Signing input #%d (outpoint: %s:%d)...\n", i, txIn.PreviousOutPoint.Hash.String(), txIn.PreviousOutPoint.Index)

		// Get the previous output
		outpoint := wire.OutPoint{
			Hash:  txIn.PreviousOutPoint.Hash,
			Index: txIn.PreviousOutPoint.Index,
		}
		prevOut := prevOuts[outpoint]

		if prevOut == nil {
			return nil, fmt.Errorf("missing previous output for input %d", i)
		}

		// Get the script and value
		pkScript := prevOut.PkScript
		value := prevOut.Value

		switch selectedAccount.Type {
		case "p2pkh", "legacy":
			// Create a legacy signature
			pubKey := privateKey.PubKey().SerializeCompressed()
			addr, err := btcutil.NewAddressPubKeyHash(btcutil.Hash160(pubKey), params)
			if err != nil {
				return nil, fmt.Errorf("error creating address: %v", err)
			}

			pkScript, err := txscript.PayToAddrScript(addr)
			if err != nil {
				return nil, fmt.Errorf("error creating output script: %v", err)
			}

			sig, err := txscript.SignatureScript(signedTx, i, pkScript, txscript.SigHashAll, privateKey, true)
			if err != nil {
				return nil, fmt.Errorf("error creating signature script: %v", err)
			}

			signedTx.TxIn[i].SignatureScript = sig

		case "p2wpkh", "segwit":
			// Create a SegWit signature
			sig, err := txscript.WitnessSignature(signedTx, txscript.NewTxSigHashes(signedTx, prevOutFetcher),
				i, value, pkScript, txscript.SigHashAll, privateKey, true)
			if err != nil {
				return nil, fmt.Errorf("error creating witness signature: %v", err)
			}

			signedTx.TxIn[i].Witness = sig
			signedTx.TxIn[i].SignatureScript = nil

		case "p2sh-p2wpkh", "nested-segwit":
			// Create a nested SegWit signature
			pubKey := privateKey.PubKey().SerializeCompressed()
			pubKeyHash := btcutil.Hash160(pubKey)

			// Create the witness script
			witnessScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_DUP).
				AddOp(txscript.OP_HASH160).
				AddData(pubKeyHash).
				AddOp(txscript.OP_EQUALVERIFY).
				AddOp(txscript.OP_CHECKSIG).
				Script()
			if err != nil {
				return nil, fmt.Errorf("error creating witness script: %v", err)
			}

			sig, err := txscript.WitnessSignature(signedTx, txscript.NewTxSigHashes(signedTx, prevOutFetcher),
				i, value, witnessScript, txscript.SigHashAll, privateKey, true)
			if err != nil {
				return nil, fmt.Errorf("error creating witness signature: %v", err)
			}

			signedTx.TxIn[i].Witness = sig

			// Set the signature script to push the witnessScript
			signedTx.TxIn[i].SignatureScript, err = txscript.NewScriptBuilder().
				AddData(redeemScript).
				Script()
			if err != nil {
				return nil, fmt.Errorf("error creating signature script: %v", err)
			}

		case "p2tr", "taproot":
			// Create a Taproot signature
			if taprootInternalKey == nil {
				return nil, fmt.Errorf("missing internal key for Taproot address")
			}

			// Create signature hash for Taproot input
			sigHash, err := txscript.CalcTaprootSignatureHash(
				txscript.NewTxSigHashes(signedTx, prevOutFetcher),
				txscript.SigHashDefault,
				signedTx,
				i,
				prevOutFetcher,
			)
			if err != nil {
				return nil, fmt.Errorf("error calculating taproot signature hash: %v", err)
			}

			// Create Schnorr signature
			signature, err := schnorr.Sign(privateKey, sigHash)
			if err != nil {
				return nil, fmt.Errorf("error creating schnorr signature: %v", err)
			}

			// Set the witness for Taproot key path spending
			signedTx.TxIn[i].Witness = wire.TxWitness{signature.Serialize()}
			signedTx.TxIn[i].SignatureScript = nil
		}
	}

	return signedTx, nil
}

// isHexString checks if a string is a valid hex string
func isHexString(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}
