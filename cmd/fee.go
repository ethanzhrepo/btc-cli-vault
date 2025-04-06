package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/ethanzhrepo/btc-cli-vault/util"
	"github.com/spf13/cobra"
)

// FeeCmd returns the fee command
func FeeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fee",
		Short: "Get current recommended Bitcoin transaction fees",
		Long: `Get current recommended Bitcoin transaction fees from mempool.space API.
The fees are reported in satoshis per byte for different confirmation time targets.`,
		RunE: runFee,
	}

	cmd.Flags().StringP("api", "a", "", "Custom fee API URL (overrides default)")
	cmd.Flags().BoolP("json", "j", false, "Output in JSON format")
	cmd.Flags().Bool("testnet", false, "Use Bitcoin testnet instead of mainnet")

	return cmd
}

func runFee(cmd *cobra.Command, args []string) error {
	// Parse flags
	apiURL, _ := cmd.Flags().GetString("api")
	jsonOutput, _ := cmd.Flags().GetBool("json")
	useTestnet, _ := cmd.Flags().GetBool("testnet")

	// Display which network we're using
	if useTestnet {
		fmt.Println("Using testnet fee API")
	} else {
		fmt.Println("Using mainnet fee API")
	}

	// Fetch fee recommendations
	fees, err := util.FetchFee(apiURL, useTestnet)
	if err != nil {
		return fmt.Errorf("failed to fetch fee recommendations: %v", err)
	}

	// Output the results
	if jsonOutput {
		// Output in JSON format
		jsonData, err := json.MarshalIndent(fees, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to format JSON output: %v", err)
		}
		fmt.Println(string(jsonData))
		return nil
	}

	// Standard output format
	fmt.Println("Current Recommended Bitcoin Transaction Fees")
	fmt.Println("===========================================")
	fmt.Printf("Fastest  (≈10min): %d sat/byte - aim for confirmation within 1-2 blocks\n", fees.FastestFee)
	fmt.Printf("Fast     (≈30min): %d sat/byte - aim for confirmation within ~3 blocks\n", fees.HalfHourFee)
	fmt.Printf("Standard (≈1hour): %d sat/byte - aim for confirmation within ~6 blocks\n", fees.HourFee)
	fmt.Printf("Economy  (≈1 day): %d sat/byte - aim for confirmation within ~144 blocks\n", fees.EconomyFee)
	fmt.Printf("Minimum          : %d sat/byte - minimum relay fee\n", fees.MinimumFee)

	return nil
}
