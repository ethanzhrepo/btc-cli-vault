//go:build !darwin

package util

import (
	"fmt"
	"runtime"
)

// KeychainStorage implements Storage interface for non-Apple platforms
type KeychainStorage struct{}

// Put returns an error on non-macOS platforms
func (k *KeychainStorage) Put(data []byte, filePath string, withForce bool) (string, error) {
	return "", fmt.Errorf("keychain storage not supported on %s", runtime.GOOS)
}

// Get returns an error on non-macOS platforms
func (k *KeychainStorage) Get(filePath string) ([]byte, error) {
	return nil, fmt.Errorf("keychain storage not supported on %s", runtime.GOOS)
}

// List returns an error on non-macOS platforms
func (k *KeychainStorage) List(dir string) ([]string, error) {
	return nil, fmt.Errorf("keychain storage not supported on %s", runtime.GOOS)
}

// IsMacOS checks if the current system is macOS
func IsMacOS() bool {
	return runtime.GOOS == "darwin"
}
