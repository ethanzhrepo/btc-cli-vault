package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethanzhrepo/btc-cli-vault/util"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// CopyCmd creates the wallet copy command
func CopyCmd() *cobra.Command {
	var fromLocation string
	var toLocation string
	var walletName string

	cmd := &cobra.Command{
		Use:   "copy",
		Short: "Copy wallet between storage providers",
		Long:  `Copy a wallet file from one storage provider to another (e.g., from Google Drive to local file or from local file to Dropbox).`,
		Run: func(cmd *cobra.Command, args []string) {
			// Initialize config
			initConfig()

			// Check required parameters
			if fromLocation == "" {
				fmt.Println("Error: --from parameter is required")
				cmd.Usage()
				os.Exit(1)
			}

			if toLocation == "" {
				fmt.Println("Error: --to parameter is required")
				cmd.Usage()
				os.Exit(1)
			}

			// Process the source
			var sourceData []byte
			var err error

			// Determine if source is a cloud provider or local file
			isSourceCloud := false
			for _, provider := range util.CLOUD_PROVIDERS {
				if fromLocation == provider {
					isSourceCloud = true
					break
				}
			}

			if isSourceCloud {
				// Need a wallet name for cloud storage
				if walletName == "" {
					fmt.Println("Error: --name parameter is required when using cloud storage")
					cmd.Usage()
					os.Exit(1)
				}

				cloudPath := filepath.Join(util.GetCloudFileDir(), walletName+".json")
				sourceData, err = util.Get(fromLocation, cloudPath)
				if err != nil {
					fmt.Printf("Error loading wallet from %s: %v\n", fromLocation, err)
					os.Exit(1)
				}
			} else {
				// From local file
				sourceData, err = util.Get(fromLocation, fromLocation)
				if err != nil {
					fmt.Printf("Error loading wallet from local file: %v\n", err)
					os.Exit(1)
				}

				// Extract wallet name from file path if not specified
				if walletName == "" {
					baseFileName := filepath.Base(fromLocation)
					walletName = strings.TrimSuffix(baseFileName, filepath.Ext(baseFileName))
				}
			}

			// Process the destination
			isDestCloud := false
			for _, provider := range util.CLOUD_PROVIDERS {
				if toLocation == provider {
					isDestCloud = true
					break
				}
			}

			// Check if destination already has a wallet with the same name
			if isDestCloud {
				destDir := util.GetCloudFileDir()
				// Save to cloud storage
				cloudPath := filepath.Join(destDir, walletName+".json")
				result, err := util.Put(toLocation, sourceData, cloudPath, false)
				if err != nil {
					fmt.Printf("Error copying wallet to %s: %v\n", toLocation, err)
					os.Exit(1)
				}

				green := color.New(color.FgGreen, color.Bold)
				green.Printf("Wallet '%s' copied to %s successfully!\n", walletName, toLocation)
				fmt.Println(result)
				fmt.Printf("\nVerify with: go run main.go get --input %s --name %s\n", toLocation, walletName)
			} else {
				// Destination is a local file
				destPath := toLocation

				// Check if the destination is a directory
				fi, err := os.Stat(toLocation)
				if err == nil && fi.IsDir() {
					// It's a directory, so append the wallet name
					destPath = filepath.Join(toLocation, walletName+".json")
				}

				// Check if file already exists
				if _, err := os.Stat(destPath); err == nil {
					red := color.New(color.FgRed, color.Bold)
					red.Printf("Copy failed: File already exists at %s\n", destPath)
					os.Exit(1)
				}

				// Save to local file
				result, err := util.Put(toLocation, sourceData, destPath, false)
				if err != nil {
					fmt.Printf("Error copying wallet to %s: %v\n", destPath, err)
					os.Exit(1)
				}

				green := color.New(color.FgGreen, color.Bold)
				green.Printf("Wallet copied to %s successfully!\n", destPath)
				fmt.Println(result)
				fmt.Printf("\nVerify with: go run main.go get --input %s\n", destPath)
			}
		},
	}

	// Add command flags
	cmd.Flags().StringVarP(&fromLocation, "from", "f", "", "Source location (cloud provider name or local file path)")
	cmd.Flags().StringVarP(&toLocation, "to", "t", "", "Destination location (cloud provider name or local file path)")
	cmd.Flags().StringVarP(&walletName, "name", "n", "", "Name of the wallet to copy (required for cloud storage sources)")

	cmd.MarkFlagRequired("from")
	cmd.MarkFlagRequired("to")

	return cmd
}
