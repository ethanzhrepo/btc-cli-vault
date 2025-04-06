package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/ethanzhrepo/btc-cli-vault/util"
	"github.com/spf13/cobra"
)

// UtxoCmd returns the utxo command
func UtxoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "utxo",
		Short: "List unspent transaction outputs for an address",
		Long:  `List all unspent transaction outputs (UTXOs) for a specified Bitcoin address.`,
		RunE:  runUtxo,
	}

	cmd.Flags().StringP("address", "a", "", "Bitcoin address to check for UTXOs")
	cmd.Flags().StringP("rpc", "R", "", "UTXO API URL (overrides default)")
	cmd.Flags().BoolP("verbose", "V", false, "Show detailed information for each UTXO")
	cmd.Flags().Uint64P("min-confirmations", "c", 1, "Minimum confirmations required")
	cmd.Flags().BoolP("json", "j", false, "Output in JSON format")
	cmd.Flags().Bool("testnet", false, "Use Bitcoin testnet instead of mainnet")
	cmd.Flags().Bool("show-script", false, "Show script information for each UTXO")

	cmd.MarkFlagRequired("address")

	return cmd
}

func runUtxo(cmd *cobra.Command, args []string) error {
	// Parse flags
	address, _ := cmd.Flags().GetString("address")
	apiURL, _ := cmd.Flags().GetString("rpc")
	verbose, _ := cmd.Flags().GetBool("verbose")
	jsonOutput, _ := cmd.Flags().GetBool("json")
	useTestnet, _ := cmd.Flags().GetBool("testnet")
	showScript, _ := cmd.Flags().GetBool("show-script")

	// Display which network and API we're using
	if apiURL == "" {
		if useTestnet {
			fmt.Println("Using testnet UTXO API")
		} else {
			fmt.Println("Using mainnet UTXO API")
		}
	} else {
		if useTestnet {
			fmt.Println("Using custom testnet UTXO API URL")
		} else {
			fmt.Println("Using custom mainnet UTXO API URL")
		}
	}

	// Fetch UTXOs for the address using the utility function with script option if requested
	var utxos []util.APIUtxo
	var err error
	if showScript {
		utxos, err = util.FetchUTXOsWithOptions(address, apiURL, useTestnet, true)
	} else {
		utxos, err = util.FetchUTXOs(address, apiURL, useTestnet)
	}

	if err != nil {
		return fmt.Errorf("failed to fetch UTXOs: %v", err)
	}

	// Output the results
	if len(utxos) == 0 {
		fmt.Printf("No unspent transaction outputs found for address %s\n", address)
		return nil
	}

	if jsonOutput {
		// Output in JSON format
		jsonData, err := json.MarshalIndent(utxos, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to format JSON output: %v", err)
		}
		fmt.Println(string(jsonData))
		return nil
	}

	// Standard output format
	totalAmount := uint64(0)
	fmt.Printf("Unspent Transaction Outputs for %s\n", address)
	fmt.Println("===============================================")

	for i, utxo := range utxos {
		totalAmount += utxo.Value

		fmt.Printf("%d. TxID: %s\n", i+1, utxo.Txid)
		fmt.Printf("   Vout: %d\n", utxo.Vout)
		fmt.Printf("   Amount: %.8f BTC (%d satoshis)\n", float64(utxo.Value)/100000000, utxo.Value)

		if verbose {
			// In a real implementation, we would fetch and display additional
			// information like scriptPubKey, confirmations, etc.
			fmt.Printf("   Confirmed: %t\n", utxo.Status.Confirmed)
			fmt.Printf("   BlockHeight: %d\n", utxo.Status.BlockHeight)
		}

		if showScript {
			fmt.Printf("   Script: %s\n", utxo.PkScript)
			fmt.Printf("   Script Type: %s\n", utxo.ScriptType)
			fmt.Printf("   Script Bytes: %v\n", utxo.PkScriptBytes)
		}

		fmt.Println()
	}

	fmt.Printf("Total: %.8f BTC (%d satoshis) in %d UTXOs\n",
		float64(totalAmount)/100000000, totalAmount, len(utxos))

	// Log the number of UTXOs found
	fmt.Printf("Found %d UTXOs via API\n", len(utxos))

	return nil
}
