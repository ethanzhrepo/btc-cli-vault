package util

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LocalStorage implements Storage interface for local file system
type LocalStorage struct{}

func (l *LocalStorage) Put(data []byte, filePath string, withForce bool) (string, error) {
	err := SaveToFileSystem(data, filePath, withForce)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("File saved to local file system: %s", filePath), nil
}

func (l *LocalStorage) Get(filePath string) ([]byte, error) {
	return LoadFromFileSystem(filePath)
}

func (l *LocalStorage) List(dir string) ([]string, error) {
	return ListFilesFromFileSystem(dir)
}

// SaveToFileSystem 将数据保存到本地文件系统
func SaveToFileSystem(data []byte, path string, withForce bool) error {
	// 检查文件是否已存在
	if _, err := os.Stat(path); err == nil && !withForce {
		fmt.Printf("Error: Wallet file already exists in local file system: %s\n", path)
		fmt.Println("Use --force to overwrite.")
		os.Exit(1)
	}

	// 创建必要的目录
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("无法创建目录 %s: %v", dir, err)
	}

	// 写入文件
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("无法写入文件 %s: %v", path, err)
	}

	return nil
}

// LoadFromFileSystem 从本地文件系统加载数据
func LoadFromFileSystem(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("无法读取文件 %s: %v", path, err)
	}
	return data, nil
}

// 从本地文件系统下载文件
func DownloadFromFileSystem(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("无法读取文件 %s: %v", path, err)
	}
	return data, nil
}

// ListFilesFromFileSystem lists files from the specified directory in the local file system
func ListFilesFromFileSystem(dir string) ([]string, error) {
	// Ensure the directory exists
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		// Directory doesn't exist - return empty list
		return []string{}, nil
	}

	// List all files in the directory
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %v", dir, err)
	}

	// Filter for wallet files (json files)
	var walletFiles []string
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		name := file.Name()
		if strings.HasSuffix(strings.ToLower(name), ".json") {
			walletFiles = append(walletFiles, filepath.Join(dir, name))
		}
	}

	return walletFiles, nil
}
