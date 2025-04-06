package util

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/keybase/go-keychain"
)

// KeychainStorage implements Storage interface for Apple Keychain
type KeychainStorage struct{}

// Put stores data in the Apple Keychain
func (k *KeychainStorage) Put(data []byte, filePath string, withForce bool) (string, error) {
	// Check if running on macOS
	if !IsMacOS() {
		return "", fmt.Errorf("keychain storage is only available on macOS")
	}

	// Extract wallet name from filepath to use as key in keychain
	walletName := strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath))

	// Check if wallet already exists in keychain if withForce is false
	if !withForce {
		query := keychain.NewItem()
		query.SetSecClass(keychain.SecClassGenericPassword)
		query.SetService("ltd.wrb.btc-cli-vault")
		query.SetAccount(walletName)
		query.SetMatchLimit(keychain.MatchLimitOne)

		// Try to find the item
		results, _ := keychain.QueryItem(query)
		if len(results) > 0 {
			fmt.Printf("Error: Wallet already exists in Apple Keychain: %s\n", walletName)
			os.Exit(1)
		}
	}

	// Set up keychain item
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService("ltd.wrb.btc-cli-vault")
	item.SetAccount(walletName)
	item.SetData(data)
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlocked)

	// Delete any existing item with the same key
	deleteItem := keychain.NewItem()
	deleteItem.SetSecClass(keychain.SecClassGenericPassword)
	deleteItem.SetService("ltd.wrb.btc-cli-vault")
	deleteItem.SetAccount(walletName)
	_ = keychain.DeleteItem(deleteItem)

	// Add the new item
	err := keychain.AddItem(item)
	if err != nil {
		return "", fmt.Errorf("failed to store wallet in keychain: %v", err)
	}

	return fmt.Sprintf("Wallet stored in Apple Keychain: %s", walletName), nil
}

// Get retrieves data from the Apple Keychain
func (k *KeychainStorage) Get(filePath string) ([]byte, error) {
	// Check if running on macOS
	if !IsMacOS() {
		return nil, fmt.Errorf("keychain storage is only available on macOS")
	}

	// Extract wallet name from filepath
	walletName := strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath))

	// Set up query
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService("ltd.wrb.btc-cli-vault")
	query.SetAccount(walletName)
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnData(true)

	// Query keychain
	results, err := keychain.QueryItem(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query keychain: %v", err)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("wallet not found in keychain: %s", walletName)
	}

	return results[0].Data, nil
}

// List returns a list of wallet files stored in the Apple Keychain
func (k *KeychainStorage) List(dir string) ([]string, error) {
	// Check if running on macOS
	if !IsMacOS() {
		return nil, fmt.Errorf("keychain storage is only available on macOS")
	}

	// Set up query to find all wallets
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService("ltd.wrb.btc-cli-vault")
	query.SetMatchLimit(keychain.MatchLimitAll)
	query.SetReturnAttributes(true)

	// Query keychain
	results, err := keychain.QueryItem(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list wallets in keychain: %v", err)
	}

	// Extract wallet names from results
	var walletNames []string
	for _, item := range results {
		walletNames = append(walletNames, item.Account)
	}

	return walletNames, nil
}

// IsMacOS checks if the current system is macOS
func IsMacOS() bool {
	return runtime.GOOS == "darwin"
}
