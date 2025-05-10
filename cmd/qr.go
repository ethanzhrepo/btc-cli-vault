package cmd

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/skip2/go-qrcode"
	"github.com/spf13/cobra"
)

// QRCmd returns the cobra command for QR code generation.
func QRCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "qr [address]",
		Short: "Display QR code for a Bitcoin address",
		Long:  `Display a QR code representation of the given Bitcoin address in the console.`,
		Args:  cobra.ExactArgs(1), // Ensures exactly one argument (the address) is provided.
		Run: func(cmd *cobra.Command, args []string) {
			address := args[0]

			// Generate QR code
			// qrcode.Medium is a common recovery level.
			// The false argument to ToSmallString means don't invert the colors (black on white).
			qr, err := qrcode.New(address, qrcode.Medium)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error generating QR code: %v\n", err)
				os.Exit(1)
			}

			// Print QR code to console
			// The second parameter `false` means the QR code will be black on a white background.
			// Set to `true` for white on black.
			fmt.Println(qr.ToSmallString(false))

			//
			green := color.New(color.FgGreen).SprintFunc()
			fmt.Println(green(address))
		},
	}
	return cmd
}
