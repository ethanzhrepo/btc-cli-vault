package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethanzhrepo/btc-cli-vault/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// 配置文件路径
var configFile string
var configDir string

// 初始化配置
func initConfig() {
	// 获取用户主目录
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Error getting home directory:", err)
		os.Exit(1)
	}

	// 设置配置目录和文件路径
	configDir = filepath.Join(home, util.ConfigDir)
	configFile = filepath.Join(configDir, util.ConfigFile)

	// 确保配置目录存在
	if err := os.MkdirAll(configDir, 0755); err != nil {
		fmt.Println("Error creating config directory:", err)
		os.Exit(1)
	}

	// 设置 viper 配置
	viper.SetConfigFile(configFile)
	viper.SetConfigType("json")

	// 如果配置文件存在，读取配置
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// 配置文件不存在，创建空配置文件
			if err := viper.SafeWriteConfig(); err != nil {
				fmt.Println("Error creating config file:", err)
			}
		} else {
			fmt.Println("Error reading config file:", err)
		}
	}
}

// ConfigCmd 返回 config 命令
func ConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage configuration settings",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			initConfig()
		},
	}

	// 添加子命令
	cmd.AddCommand(configGetCmd())
	cmd.AddCommand(configSetCmd())
	cmd.AddCommand(configDeleteCmd())
	cmd.AddCommand(configListCmd())

	return cmd
}

// configGetCmd 返回 config get 子命令
func configGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get [key]",
		Short: "Get a configuration value",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			key := args[0]
			if viper.IsSet(key) {
				fmt.Printf("%s: %v\n", key, viper.Get(key))
			} else {
				fmt.Printf("Key '%s' not found in configuration\n", key)
			}
		},
	}
}

// configSetCmd 返回 config set 子命令
func configSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set [key] [value]",
		Short: "Set a configuration value",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			key := args[0]
			value := args[1]

			viper.Set(key, value)
			if err := viper.WriteConfig(); err != nil {
				fmt.Println("Error writing config:", err)
				return
			}
			fmt.Printf("Set '%s' to '%s'\n", key, value)
		},
	}
}

// configDeleteCmd 返回 config delete 子命令
func configDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete [key]",
		Short: "Delete a configuration value",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			key := args[0]

			// 检查键是否存在
			if !viper.IsSet(key) {
				fmt.Printf("Key '%s' not found in configuration\n", key)
				return
			}

			// 删除键
			allSettings := viper.AllSettings()
			deleteNestedKey(allSettings, strings.Split(key, "."))

			// 清除当前配置并重新设置
			viper.Reset()
			viper.SetConfigFile(configFile)

			for k, v := range allSettings {
				viper.Set(k, v)
			}

			if err := viper.WriteConfig(); err != nil {
				fmt.Println("Error writing config:", err)
				return
			}

			fmt.Printf("Deleted key '%s'\n", key)
		},
	}
}

// configListCmd 返回 config list 子命令
func configListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all configuration values",
		Run: func(cmd *cobra.Command, args []string) {
			settings := viper.AllSettings()
			if len(settings) == 0 {
				fmt.Println("No configuration values set")
				return
			}

			printSettings(settings, "")
		},
	}
}

// 打印配置设置
func printSettings(settings map[string]interface{}, prefix string) {
	for k, v := range settings {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}

		if nested, ok := v.(map[string]interface{}); ok {
			printSettings(nested, key)
		} else {
			fmt.Printf("%s: %v\n", key, v)
		}
	}
}

// 删除嵌套键
func deleteNestedKey(settings map[string]interface{}, keyParts []string) bool {
	if len(keyParts) == 1 {
		if _, exists := settings[keyParts[0]]; exists {
			delete(settings, keyParts[0])
			return true
		}
		return false
	}

	if nested, ok := settings[keyParts[0]].(map[string]interface{}); ok {
		deleted := deleteNestedKey(nested, keyParts[1:])
		if deleted && len(nested) == 0 {
			delete(settings, keyParts[0])
		}
		return deleted
	}

	return false
}
