package util

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
)

// Storage interface defines methods that any storage provider must implement
type Storage interface {
	Put(data []byte, filePath string, withForce bool) (string, error)
	Get(filePath string) ([]byte, error)
	List(dir string) ([]string, error)
}

// StorageFactory creates storage implementations based on provided string
type StorageFactory struct{}

// NewStorage creates a new storage implementation based on the provider
func (f *StorageFactory) NewStorage(provider string) (Storage, error) {
	switch provider {
	case PROVIDER_GOOGLE:
		return &GoogleDriveStorage{}, nil
	case PROVIDER_DROPBOX:
		return &DropboxStorage{}, nil
	case PROVIDER_S3:
		return &S3Storage{}, nil
	case PROVIDER_BOX:
		return &BoxStorage{}, nil
	case PROVIDER_LOCAL:
		return &LocalStorage{}, nil
	case PROVIDER_KEYCHAIN:
		// Check if we're on macOS before allowing keychain storage
		if runtime.GOOS == "darwin" {
			return &KeychainStorage{}, nil
		}
		return nil, fmt.Errorf("keychain storage is only available on macOS")
	default:
		// If the provider is not one of the cloud providers, treat it as a local path
		if isLocalPath(provider) {
			return &LocalStorage{}, nil
		}
		return nil, fmt.Errorf("unsupported storage provider: %s", provider)
	}
}

// Put is a convenience method to put data using a specific provider
func Put(provider string, data []byte, filePath string, withForce bool) (string, error) {
	factory := &StorageFactory{}
	storage, err := factory.NewStorage(provider)
	if err != nil {
		return "", err
	}
	return storage.Put(data, filePath, withForce)
}

// Get is a convenience method to get data using a specific provider
func Get(provider string, filePath string) ([]byte, error) {
	factory := &StorageFactory{}
	storage, err := factory.NewStorage(provider)
	if err != nil {
		return nil, err
	}
	return storage.Get(filePath)
}

// List is a convenience method to list files using a specific provider
func List(provider string, dir string) ([]string, error) {
	factory := &StorageFactory{}
	storage, err := factory.NewStorage(provider)
	if err != nil {
		return nil, err
	}

	// Get list of wallet files
	files, err := storage.List(dir)
	if err != nil {
		return nil, err
	}

	// Strip file extensions to get wallet names
	var walletNames []string
	for _, file := range files {
		name := filepath.Base(file)
		walletNames = append(walletNames, strings.TrimSuffix(name, filepath.Ext(name)))
	}

	return walletNames, nil
}

// isLocalPath checks if the given path is a local file system path
func isLocalPath(path string) bool {
	// Check if path is a cloud provider
	for _, provider := range CLOUD_PROVIDERS {
		if path == provider {
			return false
		}
	}
	return true
}
