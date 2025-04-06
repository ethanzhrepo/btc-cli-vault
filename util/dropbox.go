package util

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox"
	"github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox/files"
	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

// DropboxStorage implements Storage interface for Dropbox
type DropboxStorage struct{}

func (d *DropboxStorage) Put(data []byte, filePath string, withForce bool) (string, error) {
	return UploadToDropbox(data, filePath, withForce)
}

func (d *DropboxStorage) Get(filePath string) ([]byte, error) {
	return DownloadFromDropbox(filePath)
}

func (d *DropboxStorage) List(dir string) ([]string, error) {
	return ListDropboxFiles(dir)
}

// Variable that will be injected from main package when built using ldflags
var DefaultDropboxAppKey = ""

// 添加DropboxOAuthConfig结构体
type DropboxOAuthConfig struct {
	AppKey string `json:"app_key"`
}

// GetDropboxOAuthConfig retrieves OAuth configuration from environment variables or falls back to defaults
func GetDropboxOAuthConfig() (DropboxOAuthConfig, error) {
	// Try to get credentials from environment variables first
	appKey := os.Getenv("DROPBOX_APP_KEY")

	// If environment variable is not set, use default value from main package
	if appKey == "" {
		appKey = DefaultDropboxAppKey
	}

	// Default configuration (only used if environment variables are not set)
	defaultConfig := DropboxOAuthConfig{
		AppKey: appKey,
	}

	// If environment variables are not set, try to load from config file
	if appKey == "" {
		// Get user home directory
		usr, err := user.Current()
		if err != nil {
			return defaultConfig, fmt.Errorf("cannot get user home directory: %v", err)
		}

		// Config directory and file path
		configDir := filepath.Join(usr.HomeDir, ConfigDir)
		configFile := filepath.Join(configDir, "dropbox.json")

		// Check if config file exists
		if _, err := os.Stat(configFile); os.IsNotExist(err) {
			// Create config directory
			if err := os.MkdirAll(configDir, 0700); err != nil {
				return defaultConfig, fmt.Errorf("failed to create config directory: %v", err)
			}

			// Write default config to file
			configData, err := json.MarshalIndent(defaultConfig, "", "  ")
			if err != nil {
				return defaultConfig, fmt.Errorf("failed to marshal config: %v", err)
			}

			if err := os.WriteFile(configFile, configData, 0600); err != nil {
				return defaultConfig, fmt.Errorf("failed to write config file: %v", err)
			}

			fmt.Printf("Created new Dropbox OAuth configuration at %s\n", configFile)
			fmt.Println("Please set DROPBOX_APP_KEY environment variable")
			return defaultConfig, nil
		}

		// Read existing config file
		configData, err := os.ReadFile(configFile)
		if err != nil {
			return defaultConfig, fmt.Errorf("failed to read config file: %v", err)
		}

		// Parse config
		var config DropboxOAuthConfig
		if err := json.Unmarshal(configData, &config); err != nil {
			return defaultConfig, fmt.Errorf("failed to parse config file: %v", err)
		}

		return config, nil
	}

	return defaultConfig, nil
}

// 修改Dropbox OAuth配置中的重定向URI
func UploadToDropbox(data []byte, filePath string, withForce bool) (string, error) {
	ctx := context.Background()

	// 获取OAuth配置
	oauthConfig, err := GetDropboxOAuthConfig()
	if err != nil {
		fmt.Printf("Warning: Using default Dropbox OAuth credentials: %v\n", err)
		// 继续使用默认值
	}

	// 检查凭据是否为空
	if oauthConfig.AppKey == "" {
		return "", fmt.Errorf("\033[1;31mDropbox App Key is not configured. Please set DROPBOX_APP_KEY environment variable or configure it in %s/dropbox.json\033[0m", ConfigDir)
	}

	// 设置OAuth 2.0配置 - 使用PKCE模式，不需要client_secret
	redirectURI := "http://localhost:18081/dropbox-callback"
	config := &oauth2.Config{
		ClientID: oauthConfig.AppKey,
		// 不需要ClientSecret
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://www.dropbox.com/oauth2/authorize",
			TokenURL: "https://api.dropboxapi.com/oauth2/token",
		},
		RedirectURL: redirectURI,
	}

	// 创建一个随机状态字符串
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.StdEncoding.EncodeToString(b)

	// 创建PKCE代码验证器和挑战
	verifier := make([]byte, 32)
	if _, err := rand.Read(verifier); err != nil {
		return "", fmt.Errorf("failed to generate PKCE verifier: %v", err)
	}
	verifierStr := base64.RawURLEncoding.EncodeToString(verifier)

	// 创建代码挑战 - S256方法
	h := sha256.Sum256([]byte(verifierStr))
	challengeStr := base64.RawURLEncoding.EncodeToString(h[:])

	// 添加authCode变量声明
	var authCode string

	// 创建独立的路由多路复用器
	mux := http.NewServeMux()

	// 设置服务器使用自定义多路复用器
	server := &http.Server{Addr: ":18081", Handler: mux}

	// 为dropbox使用专用路径
	mux.HandleFunc("/dropbox-callback", func(w http.ResponseWriter, r *http.Request) {
		// 验证状态值
		if r.FormValue("state") != state {
			http.Error(w, "Invalid state", http.StatusBadRequest)
			return
		}

		authCode = r.FormValue("code")
		if authCode == "" {
			http.Error(w, "No code found", http.StatusBadRequest)
			return
		}

		// 响应用户
		fmt.Fprint(w, "<h1>Success!</h1><p>You can now close this window and return to the command line.</p>")

		// 关闭HTTP服务器
		go func() {
			time.Sleep(1 * time.Second)
			server.Shutdown(ctx)
		}()
	})

	// 构建授权URL并添加PKCE参数
	authURL := config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", challengeStr),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	// 打开浏览器获取授权
	fmt.Println("Opening browser for Dropbox authentication...")
	if err := browser.OpenURL(authURL); err != nil {
		return "", fmt.Errorf("failed to open browser: %v, please visit this URL manually: %s", err, authURL)
	}

	// 等待接收重定向
	fmt.Println("Waiting for authentication...")
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		return "", fmt.Errorf("HTTP server error: %v", err)
	}

	if authCode == "" {
		return "", fmt.Errorf("failed to get authorization code")
	}

	fmt.Println("Authorization code received, exchanging for token...")

	// 创建自定义HTTP客户端以获取更详细的错误信息
	httpClient := &http.Client{}

	// 准备token交换请求 - 使用PKCE验证器
	tokenData := url.Values{}
	tokenData.Set("code", authCode)
	tokenData.Set("grant_type", "authorization_code")
	tokenData.Set("client_id", config.ClientID)
	tokenData.Set("redirect_uri", config.RedirectURL)
	tokenData.Set("code_verifier", verifierStr) // 添加验证器

	req, err := http.NewRequest("POST", config.Endpoint.TokenURL, strings.NewReader(tokenData.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %v", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send token request: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token exchange failed: HTTP %d: %s\nPlease verify your Dropbox app settings at https://www.dropbox.com/developers/apps and ensure the redirect URI is set to %s and that PKCE is enabled for your app",
			resp.StatusCode, string(bodyBytes), redirectURI)
	}

	// 解析token响应
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in,omitempty"`
	}

	if err := json.Unmarshal(bodyBytes, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse token response: %v", err)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("received empty access token")
	}

	fmt.Println("Token exchange successful!")

	// 创建Dropbox客户端
	config1 := dropbox.Config{
		Token:    tokenResp.AccessToken,
		LogLevel: dropbox.LogOff,
	}
	client := files.New(config1)

	// 确保文件路径以/开头
	if !strings.HasPrefix(filePath, "/") {
		filePath = "/" + filePath
	}

	// 检查文件是否已存在
	fileExists := false
	_, err = client.GetMetadata(&files.GetMetadataArg{Path: filePath})
	if err == nil {
		fileExists = true
	}

	// 如果文件存在且不允许覆盖，退出
	if fileExists && !withForce {
		fmt.Printf("Error: Wallet file already exists in Dropbox: %s\n", filePath)
		fmt.Println("Use --force to overwrite.")
		os.Exit(1)
	}

	// 上传文件，根据是否覆盖设置不同的模式
	var mode files.WriteMode
	if withForce && fileExists {
		// 使用覆盖模式
		mode = files.WriteMode{
			Tagged: dropbox.Tagged{
				Tag: "overwrite",
			},
		}
		fmt.Printf("Overwriting existing file in Dropbox: %s\n", filePath)
	} else {
		// 使用添加模式
		mode = files.WriteMode{
			Tagged: dropbox.Tagged{
				Tag: "add",
			},
		}
	}

	commitInfo := files.CommitInfo{
		Path: filePath,
		Mode: &mode,
	}
	uploadArg := &files.UploadArg{
		CommitInfo: commitInfo,
	}
	uploadResult, err := client.Upload(uploadArg, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("failed to upload to Dropbox: %v", err)
	}

	// 去掉创建共享链接的部分
	return fmt.Sprintf("File uploaded successfully to Dropbox: %s (private)", uploadResult.PathDisplay), nil
}

// 从Dropbox下载文件
func DownloadFromDropbox(filePath string) ([]byte, error) {
	ctx := context.Background()

	// 获取OAuth配置
	oauthConfig, err := GetDropboxOAuthConfig()
	if err != nil {
		fmt.Printf("Warning: Using default Dropbox OAuth credentials: %v\n", err)
		// 继续使用默认值
	}

	// 检查凭据是否为空
	if oauthConfig.AppKey == "" {
		return nil, fmt.Errorf("\033[1;31mDropbox App Key is not configured. Please set DROPBOX_APP_KEY environment variable or configure it in %s/dropbox.json\033[0m", ConfigDir)
	}

	// 设置OAuth 2.0配置 - 使用PKCE模式，不需要client_secret
	redirectURI := "http://localhost:18081/dropbox-callback"
	config := &oauth2.Config{
		ClientID: oauthConfig.AppKey,
		// 不需要ClientSecret
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://www.dropbox.com/oauth2/authorize",
			TokenURL: "https://api.dropboxapi.com/oauth2/token",
		},
		RedirectURL: redirectURI,
	}

	// 创建一个随机状态字符串
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.StdEncoding.EncodeToString(b)

	// 创建PKCE代码验证器和挑战
	verifier := make([]byte, 32)
	if _, err := rand.Read(verifier); err != nil {
		return nil, fmt.Errorf("failed to generate PKCE verifier: %v", err)
	}
	verifierStr := base64.RawURLEncoding.EncodeToString(verifier)

	// 创建代码挑战 - S256方法
	h := sha256.Sum256([]byte(verifierStr))
	challengeStr := base64.RawURLEncoding.EncodeToString(h[:])

	// 添加authCode变量声明
	var authCode string

	// 创建独立的路由多路复用器
	mux := http.NewServeMux()

	// 设置服务器使用自定义多路复用器
	server := &http.Server{Addr: ":18081", Handler: mux}

	// 为dropbox使用专用路径
	mux.HandleFunc("/dropbox-callback", func(w http.ResponseWriter, r *http.Request) {
		// 验证状态值
		if r.FormValue("state") != state {
			http.Error(w, "Invalid state", http.StatusBadRequest)
			return
		}

		authCode = r.FormValue("code")
		if authCode == "" {
			http.Error(w, "No code found", http.StatusBadRequest)
			return
		}

		// 响应用户
		fmt.Fprint(w, "<h1>Success!</h1><p>You can now close this window and return to the command line.</p>")

		// 关闭HTTP服务器
		go func() {
			time.Sleep(1 * time.Second)
			server.Shutdown(ctx)
		}()
	})

	// 构建授权URL并添加PKCE参数
	authURL := config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", challengeStr),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	// 打开浏览器获取授权
	fmt.Println("Opening browser for Dropbox authentication...")
	if err := browser.OpenURL(authURL); err != nil {
		return nil, fmt.Errorf("failed to open browser: %v, please visit this URL manually: %s", err, authURL)
	}

	// 等待接收重定向
	fmt.Println("Waiting for authentication...")
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		return nil, fmt.Errorf("HTTP server error: %v", err)
	}

	if authCode == "" {
		return nil, fmt.Errorf("failed to get authorization code")
	}

	fmt.Println("Authorization code received, exchanging for token...")

	// 创建自定义HTTP客户端以获取更详细的错误信息
	httpClient := &http.Client{}

	// 准备token交换请求 - 使用PKCE验证器
	tokenData := url.Values{}
	tokenData.Set("code", authCode)
	tokenData.Set("grant_type", "authorization_code")
	tokenData.Set("client_id", config.ClientID)
	tokenData.Set("redirect_uri", config.RedirectURL)
	tokenData.Set("code_verifier", verifierStr) // 添加验证器

	req, err := http.NewRequest("POST", config.Endpoint.TokenURL, strings.NewReader(tokenData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %v", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send token request: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: HTTP %d: %s\nPlease verify your Dropbox app settings at https://www.dropbox.com/developers/apps and ensure the redirect URI is set to %s and that PKCE is enabled for your app",
			resp.StatusCode, string(bodyBytes), redirectURI)
	}

	// 解析token响应
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in,omitempty"`
	}

	if err := json.Unmarshal(bodyBytes, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %v", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("received empty access token")
	}

	fmt.Println("Token exchange successful!")

	// 创建Dropbox客户端
	config1 := dropbox.Config{
		Token:    tokenResp.AccessToken,
		LogLevel: dropbox.LogOff,
	}
	client := files.New(config1)

	// 确保文件路径以/开头
	if !strings.HasPrefix(filePath, "/") {
		filePath = "/" + filePath
	}

	// 检查文件是否存在
	metadata, err := client.GetMetadata(&files.GetMetadataArg{Path: filePath})
	if err != nil {
		return nil, fmt.Errorf("file not found in Dropbox: %s - %v", filePath, err)
	}

	// 检查元数据类型确保是文件而不是文件夹
	fileMetadata, ok := metadata.(*files.FileMetadata)
	if !ok {
		return nil, fmt.Errorf("path refers to a folder, not a file: %s", filePath)
	}

	// 下载文件
	downloadArg := &files.DownloadArg{
		Path: filePath,
	}

	_, reader, err := client.Download(downloadArg)
	if err != nil {
		return nil, fmt.Errorf("failed to download file from Dropbox: %v", err)
	}
	defer reader.Close()

	// 读取文件内容
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read file content: %v", err)
	}

	fmt.Printf("Successfully downloaded file from Dropbox: %s (%d bytes)\n",
		fileMetadata.Name, len(data))
	return data, nil
}

// ListDropboxFiles lists files from the specified directory in Dropbox
func ListDropboxFiles(dirPath string) ([]string, error) {
	ctx := context.Background()

	// 获取OAuth配置
	oauthConfig, err := GetDropboxOAuthConfig()
	if err != nil {
		fmt.Printf("Warning: Using default Dropbox OAuth credentials: %v\n", err)
		// 继续使用默认值
	}

	// 检查凭据是否为空
	if oauthConfig.AppKey == "" {
		return nil, fmt.Errorf("\033[1;31mDropbox App Key is not configured. Please set DROPBOX_APP_KEY environment variable or configure it in %s/dropbox.json\033[0m", ConfigDir)
	}

	// 设置OAuth 2.0配置 - 使用PKCE模式，不需要client_secret
	redirectURI := "http://localhost:18081/dropbox-callback"
	config := &oauth2.Config{
		ClientID: oauthConfig.AppKey,
		// 不需要ClientSecret
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://www.dropbox.com/oauth2/authorize",
			TokenURL: "https://api.dropboxapi.com/oauth2/token",
		},
		RedirectURL: redirectURI,
	}

	// 创建一个随机状态字符串
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.StdEncoding.EncodeToString(b)

	// 创建PKCE代码验证器和挑战
	verifier := make([]byte, 32)
	if _, err := rand.Read(verifier); err != nil {
		return nil, fmt.Errorf("failed to generate PKCE verifier: %v", err)
	}
	verifierStr := base64.RawURLEncoding.EncodeToString(verifier)

	// 创建代码挑战 - S256方法
	h := sha256.Sum256([]byte(verifierStr))
	challengeStr := base64.RawURLEncoding.EncodeToString(h[:])

	// 添加authCode变量声明
	var authCode string

	// 创建独立的路由多路复用器
	mux := http.NewServeMux()

	// 设置服务器使用自定义多路复用器
	server := &http.Server{Addr: ":18081", Handler: mux}

	// 为dropbox使用专用路径
	mux.HandleFunc("/dropbox-callback", func(w http.ResponseWriter, r *http.Request) {
		// 验证状态值
		if r.FormValue("state") != state {
			http.Error(w, "Invalid state", http.StatusBadRequest)
			return
		}

		authCode = r.FormValue("code")
		if authCode == "" {
			http.Error(w, "No code found", http.StatusBadRequest)
			return
		}

		// 响应用户
		fmt.Fprint(w, "<h1>Success!</h1><p>You can now close this window and return to the command line.</p>")

		// 关闭HTTP服务器
		go func() {
			time.Sleep(1 * time.Second)
			server.Shutdown(ctx)
		}()
	})

	// 构建授权URL并添加PKCE参数
	authURL := config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", challengeStr),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	// 打开浏览器获取授权
	fmt.Println("Opening browser for Dropbox authentication...")
	if err := browser.OpenURL(authURL); err != nil {
		return nil, fmt.Errorf("failed to open browser: %v, please visit this URL manually: %s", err, authURL)
	}

	// 等待接收重定向
	fmt.Println("Waiting for authentication...")
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		return nil, fmt.Errorf("HTTP server error: %v", err)
	}

	if authCode == "" {
		return nil, fmt.Errorf("failed to get authorization code")
	}

	fmt.Println("Authorization code received, exchanging for token...")

	// 创建自定义HTTP客户端以获取更详细的错误信息
	httpClient := &http.Client{}

	// 准备token交换请求 - 使用PKCE验证器
	tokenData := url.Values{}
	tokenData.Set("code", authCode)
	tokenData.Set("grant_type", "authorization_code")
	tokenData.Set("client_id", config.ClientID)
	tokenData.Set("redirect_uri", config.RedirectURL)
	tokenData.Set("code_verifier", verifierStr) // 添加验证器

	req, err := http.NewRequest("POST", config.Endpoint.TokenURL, strings.NewReader(tokenData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %v", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send token request: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: HTTP %d: %s\nPlease verify your Dropbox app settings at https://www.dropbox.com/developers/apps and ensure the redirect URI is set to %s and that PKCE is enabled for your app",
			resp.StatusCode, string(bodyBytes), redirectURI)
	}

	// 解析token响应
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in,omitempty"`
	}

	if err := json.Unmarshal(bodyBytes, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %v", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("received empty access token")
	}

	fmt.Println("Token exchange successful!")

	// 创建Dropbox客户端
	config1 := dropbox.Config{
		Token:    tokenResp.AccessToken,
		LogLevel: dropbox.LogOff,
	}
	client := files.New(config1)

	// 如果目录路径是默认的，使用默认的钱包目录
	if dirPath == "" {
		dirPath = DEFAULT_CLOUD_FILE_DIR
	}

	// 确保文件路径以/开头
	if !strings.HasPrefix(dirPath, "/") {
		dirPath = "/" + dirPath
	}

	// 列出目录内容
	listArg := files.NewListFolderArg(dirPath)
	res, err := client.ListFolder(listArg)
	if err != nil {
		// 如果文件夹不存在，返回空列表
		return []string{}, nil
	}

	// 过滤出 JSON 文件
	var result []string
	for _, entry := range res.Entries {
		// 检查是否是文件
		if file, ok := entry.(*files.FileMetadata); ok {
			if strings.HasSuffix(strings.ToLower(file.Name), ".json") {
				result = append(result, filepath.Join(dirPath, file.Name))
			}
		}
	}

	// 检查是否有更多结果
	for res.HasMore {
		cursor := res.Cursor
		arg := files.NewListFolderContinueArg(cursor)
		res, err = client.ListFolderContinue(arg)
		if err != nil {
			return nil, fmt.Errorf("failed to get more files: %v", err)
		}

		for _, entry := range res.Entries {
			// 检查是否是文件
			if file, ok := entry.(*files.FileMetadata); ok {
				if strings.HasSuffix(strings.ToLower(file.Name), ".json") {
					result = append(result, filepath.Join(dirPath, file.Name))
				}
			}
		}
	}

	return result, nil
}
