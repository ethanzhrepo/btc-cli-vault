package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/ethanzhrepo/btc-cli-vault/cmd"
	"github.com/ethanzhrepo/btc-cli-vault/util"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Variables that will be set by ldflags during build
var (
	version                 = "0.1.0"
	googleOAuthClientID     = ""
	googleOAuthClientSecret = ""
	boxClientID             = ""
	boxClientSecret         = ""
	dropboxAppKey           = ""
	awsAccessKeyID          = ""
	awsSecretAccessKey      = ""
	awsS3Bucket             = ""
	awsRegion               = ""
)

func init() {
	// Pass values to util package
	util.DefaultGoogleOAuthClientID = googleOAuthClientID
	util.DefaultGoogleOAuthClientSecret = googleOAuthClientSecret
	util.DefaultBoxClientID = boxClientID
	util.DefaultBoxClientSecret = boxClientSecret
	util.DefaultDropboxAppKey = dropboxAppKey
	util.DefaultAwsAccessKeyID = awsAccessKeyID
	util.DefaultAwsSecretAccessKey = awsSecretAccessKey
	util.DefaultAwsS3Bucket = awsS3Bucket
	util.DefaultAwsRegion = awsRegion
}

func main() {
	// Create root command
	rootCmd := &cobra.Command{
		Use:   "btc-cli",
		Short: "Bitcoin CLI Wallet - A simple command-line wallet for Bitcoin",
		Long: `A simple command-line wallet for Bitcoin with secure key management.
Author: https://x.com/0x99_Ethan`,
		Run: func(cmd *cobra.Command, args []string) {
			// If no subcommand is provided, show help
			cmd.Help()
		},
	}

	// Add version flag
	rootCmd.PersistentFlags().BoolP("version", "v", false, "Show version information")
	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		versionFlag, _ := cmd.Flags().GetBool("version")
		if versionFlag {
			fmt.Printf("btc-cli version %s\n", version)
			os.Exit(0)
		}
	}

	// Add subcommands
	rootCmd.AddCommand(cmd.ConfigCmd())
	rootCmd.AddCommand(cmd.CreateCmd())
	rootCmd.AddCommand(cmd.GetAddressCmd())
	rootCmd.AddCommand(cmd.ListCmd())
	rootCmd.AddCommand(cmd.CopyCmd())

	// Add the new transaction commands
	rootCmd.AddCommand(cmd.TransferBTCCmd())
	rootCmd.AddCommand(cmd.SignTxCmd())
	rootCmd.AddCommand(cmd.SignMessageCmd())
	rootCmd.AddCommand(cmd.UtxoCmd())
	rootCmd.AddCommand(cmd.FeeCmd())
	rootCmd.AddCommand(cmd.ConsolidateUtxosCmd())
	rootCmd.AddCommand(cmd.QRCmd())

	fd := int(os.Stdin.Fd())

	oldState, err := term.GetState(fd)
	if err != nil {
		fmt.Printf("\nError getting terminal state: %v\n", err)
		os.Exit(1)
	}
	defer term.Restore(fd, oldState)
	// 监听ctrl+c, 恢复终端状态
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		term.Restore(fd, oldState)
		fmt.Println("Ctrl+C pressed, exiting...")
		os.Exit(0)
	}()
	// Execute the command
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
