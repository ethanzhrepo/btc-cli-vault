package util

import (
	"bytes"
	"runtime"
	"testing"

	"github.com/keybase/go-keychain"
)

func TestIsMacOS(t *testing.T) {
	result := IsMacOS()
	expected := runtime.GOOS == "darwin"
	if result != expected {
		t.Errorf("IsMacOS() = %v, want %v", result, expected)
	}
}

func TestKeychainStorage(t *testing.T) {
	// Skip test if not running on macOS
	if !IsMacOS() {
		t.Skip("Skipping test on non-macOS platform")
	}

	storage := &KeychainStorage{}
	testData := []byte("test wallet data")
	testPath := "test-wallet.json"

	// Clean up any previous test data
	deleteQuery := keychain.NewItem()
	deleteQuery.SetSecClass(keychain.SecClassGenericPassword)
	deleteQuery.SetService("com.ethanzhrepo.btc-cli-vault")
	deleteQuery.SetAccount("test-wallet")
	_ = keychain.DeleteItem(deleteQuery)

	// Test Put
	result, err := storage.Put(testData, testPath, true)
	if err != nil {
		t.Fatalf("Failed to store data in keychain: %v", err)
	}
	if result == "" {
		t.Errorf("Expected non-empty result from Put")
	}

	// Test Get
	retrievedData, err := storage.Get(testPath)
	if err != nil {
		t.Fatalf("Failed to retrieve data from keychain: %v", err)
	}
	if !bytes.Equal(retrievedData, testData) {
		t.Errorf("Retrieved data doesn't match stored data")
	}

	// Test List
	walletList, err := storage.List("")
	if err != nil {
		t.Fatalf("Failed to list wallets: %v", err)
	}

	found := false
	for _, name := range walletList {
		if name == "test-wallet" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Test wallet not found in wallet list")
	}

	// Clean up
	_ = keychain.DeleteItem(deleteQuery)
}
