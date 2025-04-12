package cmd

import (
	"fmt"
	"os"

	"github.com/ethanzhrepo/btc-cli-vault/util"
	"github.com/spf13/cobra"
)

// ListCmd 返回 list 命令
func ListCmd() *cobra.Command {
	var inputLocation string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available wallets",
		Long:  `List wallet files available in specified cloud storage location.`,
		Run: func(cmd *cobra.Command, args []string) {
			// 初始化配置
			initConfig()

			// 检查必要参数
			if inputLocation == "" {
				fmt.Println("Error: --input parameter is required")
				cmd.Usage()
				os.Exit(1)
			}

			// 检查是否为有效的云存储提供商
			isValidProvider := false
			for _, provider := range util.CLOUD_PROVIDERS {
				if inputLocation == provider {
					isValidProvider = true
					break
				}
			}

			if !isValidProvider {
				fmt.Printf("Error: Invalid input '%s'. Must be one of: %v\n", inputLocation, util.CLOUD_PROVIDERS)
				os.Exit(1)
			}

			// 使用存储工厂获取钱包列表
			wallets, err := util.List(inputLocation, util.GetCloudFileDir())
			if err != nil {
				fmt.Printf("Error listing wallets from %s: %v\n", inputLocation, err)
				os.Exit(1)
			}

			// 显示钱包列表
			fmt.Println("List of wallets")
			fmt.Println("----------------------------")
			if len(wallets) == 0 {
				fmt.Println("No wallets found")
			} else {
				for _, wallet := range wallets {
					fmt.Println(wallet)
				}
			}
		},
	}

	// 添加命令参数
	cmd.Flags().StringVarP(&inputLocation, "input", "i", "", "Input location (must be a supported cloud provider)")

	cmd.MarkFlagRequired("input")

	return cmd
}
