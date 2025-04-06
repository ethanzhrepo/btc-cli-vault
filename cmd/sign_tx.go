package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func SignTxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "signtx",
		Short: "Sign a Bitcoin transaction",
		Long:  `Sign a Bitcoin transaction with your private key.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Transaction signing feature is under development.")
			fmt.Println("This feature will allow you to sign Bitcoin transactions offline.")
		},
	}

	return cmd
}
