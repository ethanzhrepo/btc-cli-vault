package util

import (
	"github.com/spf13/viper"
)

const (
	ConfigDir               = ".btc-cli-wallet"
	ConfigFile              = "config.json"
	DEFAULT_CLOUD_FILE_DIR  = "/BtcWallet"
	DEFAULT_CLOUD_FILE_NAME = "wallet.json"

	DEFAULT_UTXO_API_URL         = "https://mempool.space/api/address/%s/utxo"
	DEFAULT_UTXO_TESTNET_API_URL = "https://mempool.space/testnet/api/address/%s/utxo"

	DEFAULT_FEE_URL         = "https://mempool.space/api/v1/fees/recommended"
	DEFAULT_FEE_TESTNET_URL = "https://mempool.space/testnet/api/v1/fees/recommended"

	DEFAULT_POST_TRANSACTION_URL         = "https://mempool.space/api/tx"
	DEFAULT_POST_TRANSACTION_TESTNET_URL = "https://mempool.space/testnet/api/tx"

	DEFAULT_GET_TRANSACTION_URL         = "https://mempool.space/api/tx/%s"
	DEFAULT_GET_TRANSACTION_TESTNET_URL = "https://mempool.space/testnet/api/tx/%s"

	// Storage provider constants
	PROVIDER_GOOGLE   = "google"
	PROVIDER_DROPBOX  = "dropbox"
	PROVIDER_S3       = "s3"
	PROVIDER_BOX      = "box"
	PROVIDER_LOCAL    = "local"
	PROVIDER_KEYCHAIN = "keychain"
)

var CLOUD_PROVIDERS = []string{PROVIDER_GOOGLE, PROVIDER_DROPBOX, PROVIDER_S3, PROVIDER_BOX, PROVIDER_KEYCHAIN}

// GetCloudFileDir retrieves the cloud file directory from config or uses default
func GetCloudFileDir() string {
	// First check if the config has a wallet.btc.dir parameter
	if viper.IsSet("wallet.btc.dir") {
		return viper.GetString("wallet.btc.dir")
	}
	// Fall back to default value
	return DEFAULT_CLOUD_FILE_DIR
}
