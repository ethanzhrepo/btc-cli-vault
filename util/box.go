package util

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

// BoxStorage implements Storage interface for Box
type BoxStorage struct{}

func (b *BoxStorage) Put(data []byte, filePath string, withForce bool) (string, error) {
	return UploadToBox(data, filePath, withForce)
}

func (b *BoxStorage) Get(filePath string) ([]byte, error) {
	return DownloadFromBox(filePath)
}

func (b *BoxStorage) List(dir string) ([]string, error) {
	return ListBoxFiles(dir)
}

var (
	// Default values that can be set at build time
	DefaultBoxClientID     = ""
	DefaultBoxClientSecret = ""

	boxConfig = &oauth2.Config{
		ClientID:     getEnvOrDefault("BOX_CLIENT_ID", DefaultBoxClientID),
		ClientSecret: getEnvOrDefault("BOX_CLIENT_SECRET", DefaultBoxClientSecret),
		RedirectURL:  "http://localhost:18084/box-callback",
		Scopes: []string{
			"root_readwrite",
		},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://account.box.com/api/oauth2/authorize",
			TokenURL: "https://api.box.com/oauth2/token",
		},
	}

	// Variables to ensure we only register the HTTP handler once
	boxServerOnce sync.Once
)

// Helper function to get environment variable or default value
func getEnvOrDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// BoxToken represents the Box OAuth2 token
type BoxToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

// BoxItem represents a Box file or folder
type BoxItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// BoxResponse represents a Box API response
type BoxResponse struct {
	Entries []BoxItem `json:"entries"`
}

// UploadToBox uploads a file to Box
func UploadToBox(data []byte, filePath string, withForce bool) (string, error) {
	// For debugging
	fmt.Println("Starting Box upload process...")

	token, err := getBoxToken()
	if err != nil {
		return "", fmt.Errorf("failed to get Box token: %v", err)
	}
	fmt.Println("Successfully obtained Box authentication token")

	client := boxConfig.Client(context.Background(), token)

	// Get parent folder ID
	parentPath := filepath.Dir(filePath)
	fmt.Printf("Getting parent folder ID for path: %s\n", parentPath)

	parentID, err := getBoxFolderID(parentPath, token)
	if err != nil {
		return "", fmt.Errorf("failed to get parent folder ID: %v", err)
	}
	fmt.Printf("Parent folder ID: %s\n", parentID)

	// Check if file already exists
	fileName := filepath.Base(filePath)
	exists := false
	var existingFileID string

	// List items in current folder to check if file exists
	url := fmt.Sprintf("https://api.box.com/2.0/folders/%s/items", parentID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to list items: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to list items: status code %d, response: %s", resp.StatusCode, string(respBody))
	}

	var result BoxResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %v", err)
	}

	// Find matching file
	for _, item := range result.Entries {
		if item.Name == fileName && item.Type == "file" {
			exists = true
			existingFileID = item.ID
			break
		}
	}

	// If file exists and force is not enabled, exit
	if exists && !withForce {
		fmt.Printf("Error: Wallet file already exists in Box: %s\n", filePath)
		fmt.Println("Use --force to overwrite.")
		os.Exit(1)
	}

	// If file exists and force is enabled, delete the existing file
	if exists && withForce {
		deleteURL := fmt.Sprintf("https://api.box.com/2.0/files/%s", existingFileID)
		deleteReq, err := http.NewRequest("DELETE", deleteURL, nil)
		if err != nil {
			return "", fmt.Errorf("failed to create delete request: %v", err)
		}

		deleteReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))

		deleteResp, err := client.Do(deleteReq)
		if err != nil {
			return "", fmt.Errorf("failed to delete existing file: %v", err)
		}
		defer deleteResp.Body.Close()

		if deleteResp.StatusCode != http.StatusNoContent {
			respBody, _ := io.ReadAll(deleteResp.Body)
			return "", fmt.Errorf("failed to delete existing file: status code %d, response: %s", deleteResp.StatusCode, string(respBody))
		}

		fmt.Printf("Overwriting existing file in Box: %s\n", filePath)
	}

	// Create multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add attributes as JSON field
	attributes := map[string]interface{}{
		"name": filepath.Base(filePath),
		"parent": map[string]string{
			"id": parentID,
		},
	}

	attributesJSON, err := json.Marshal(attributes)
	if err != nil {
		return "", fmt.Errorf("failed to marshal attributes: %v", err)
	}

	if err := writer.WriteField("attributes", string(attributesJSON)); err != nil {
		return "", fmt.Errorf("failed to write attributes field: %v", err)
	}

	// Add file data
	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return "", fmt.Errorf("failed to create form file: %v", err)
	}
	if _, err := part.Write(data); err != nil {
		return "", fmt.Errorf("failed to write file data: %v", err)
	}

	// Close the writer
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("failed to close writer: %v", err)
	}

	// Create the request
	// Using the correct API endpoint
	uploadURL := "https://upload.box.com/api/2.0/files/content"
	fmt.Printf("Using Box API endpoint: %s\n", uploadURL)

	uploadReq, err := http.NewRequest("POST", uploadURL, body)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers
	uploadReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))
	uploadReq.Header.Set("Content-Type", writer.FormDataContentType())

	fmt.Println("Sending upload request to Box...")
	uploadResp, err := client.Do(uploadReq)
	if err != nil {
		return "", fmt.Errorf("failed to upload file: %v", err)
	}
	defer uploadResp.Body.Close()

	// Read response body regardless of status code for better debugging
	respBody, _ := io.ReadAll(uploadResp.Body)

	if uploadResp.StatusCode != http.StatusCreated && uploadResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to upload file: status code %d, response: %s", uploadResp.StatusCode, string(respBody))
	}

	fmt.Println("Successfully uploaded file, parsing response...")

	// Try to parse the response
	var uploadResult struct {
		Entries []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"entries"`
		// For non-array responses
		ID   string `json:"id"`
		Name string `json:"name"`
	}

	if err := json.Unmarshal(respBody, &uploadResult); err != nil {
		return "", fmt.Errorf("failed to decode response: %v, response body: %s", err, string(respBody))
	}

	// Handle both response formats
	if len(uploadResult.Entries) > 0 {
		return fmt.Sprintf("File uploaded to Box: %s (ID: %s)", uploadResult.Entries[0].Name, uploadResult.Entries[0].ID), nil
	} else if uploadResult.ID != "" {
		return fmt.Sprintf("File uploaded to Box: %s (ID: %s)", uploadResult.Name, uploadResult.ID), nil
	}

	return "", fmt.Errorf("unexpected response format: %s", string(respBody))
}

// DownloadFromBox downloads a file from Box
func DownloadFromBox(filePath string) ([]byte, error) {
	token, err := getBoxToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get Box token: %v", err)
	}

	client := boxConfig.Client(context.Background(), token)

	// Get file ID from path
	fileID, err := getBoxFileID(filePath, token)
	if err != nil {
		return nil, fmt.Errorf("failed to get file ID: %v", err)
	}

	// Download the file
	url := fmt.Sprintf("https://api.box.com/2.0/files/%s/content", fileID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to download file: status code %d, response: %s", resp.StatusCode, string(respBody))
	}

	return io.ReadAll(resp.Body)
}

// ListBoxFiles lists files in a Box directory
func ListBoxFiles(dir string) ([]string, error) {
	token, err := getBoxToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get Box token: %v", err)
	}

	client := boxConfig.Client(context.Background(), token)

	// Get folder ID from path
	folderID, err := getBoxFolderID(dir, token)
	if err != nil {
		return nil, fmt.Errorf("failed to get folder ID: %v", err)
	}

	// List files in the folder
	url := fmt.Sprintf("https://api.box.com/2.0/folders/%s/items", folderID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list files: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list files: status code %d, response: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Entries []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"entries"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	var files []string
	for _, entry := range result.Entries {
		if entry.Type == "folder" {
			files = append(files, entry.Name+"/")
		} else {
			files = append(files, entry.Name)
		}
	}

	return files, nil
}

// getBoxToken retrieves or refreshes the Box OAuth2 token
func getBoxToken() (*oauth2.Token, error) {
	// Create a context that can be used for the HTTP server and token exchange
	ctx := context.Background()

	// Generate the authorization URL
	authURL := boxConfig.AuthCodeURL("box-state")
	fmt.Printf("Opening browser for Box authentication...\n")

	// Create a channel to receive the auth code
	authCodeChan := make(chan string, 1)

	// Start a local server to receive the callback
	server := &http.Server{Addr: ":18084"}

	// Set up the callback handler
	http.HandleFunc("/box-callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "No code received", http.StatusBadRequest)
			return
		}

		// Respond with success message
		fmt.Fprint(w, "<h1>Success!</h1><p>You can now close this window and return to the command line.</p>")

		// Send the code to the channel
		authCodeChan <- code

		// Shutdown the server after a short delay
		go func() {
			time.Sleep(1 * time.Second)
			server.Shutdown(ctx)
		}()
	})

	// Start the HTTP server in a goroutine
	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Printf("HTTP server error: %v\n", err)
		}
	}()

	// Open browser to auth URL
	if err := browser.OpenURL(authURL); err != nil {
		return nil, fmt.Errorf("failed to open browser: %v, please visit this URL manually: %s", err, authURL)
	}

	fmt.Println("Waiting for authentication...")

	// Wait for the callback
	code := <-authCodeChan

	// Exchange the code for a token
	token, err := boxConfig.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %v", err)
	}

	return token, nil
}

// getBoxFileID retrieves the Box file ID from a path
func getBoxFileID(path string, token *oauth2.Token) (string, error) {

	client := boxConfig.Client(context.Background(), token)

	// Split path into components
	components := strings.Split(strings.Trim(path, "/"), "/")
	if len(components) == 0 {
		return "", fmt.Errorf("invalid path")
	}

	// Start from root
	currentID := "0"
	for _, component := range components {
		// List items in current folder
		url := fmt.Sprintf("https://api.box.com/2.0/folders/%s/items", currentID)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return "", fmt.Errorf("failed to create request: %v", err)
		}

		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))

		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("failed to list items: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			respBody, _ := io.ReadAll(resp.Body)
			return "", fmt.Errorf("failed to list items: status code %d, response: %s", resp.StatusCode, string(respBody))
		}

		var result BoxResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return "", fmt.Errorf("failed to decode response: %v", err)
		}

		// Find matching item
		found := false
		for _, item := range result.Entries {
			if item.Name == component {
				currentID = item.ID
				found = true
				break
			}
		}

		if !found {
			return "", fmt.Errorf("item not found: %s", component)
		}
	}

	return currentID, nil
}

// getBoxFolderID retrieves the Box folder ID from a path
func getBoxFolderID(path string, token *oauth2.Token) (string, error) {
	// If path is empty or root, return root folder ID
	if path == "" || path == "/" {
		return "0", nil
	}

	client := boxConfig.Client(context.Background(), token)

	// Split path into components
	components := strings.Split(strings.Trim(path, "/"), "/")
	if len(components) == 0 {
		return "0", nil
	}

	// Start from root
	currentID := "0"
	for _, component := range components {
		// List items in current folder
		url := fmt.Sprintf("https://api.box.com/2.0/folders/%s/items", currentID)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return "", fmt.Errorf("failed to create request: %v", err)
		}

		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))

		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("failed to list items: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			respBody, _ := io.ReadAll(resp.Body)
			return "", fmt.Errorf("failed to list items: status code %d, response: %s", resp.StatusCode, string(respBody))
		}

		var result BoxResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return "", fmt.Errorf("failed to decode response: %v", err)
		}

		// Find matching item
		found := false
		for _, item := range result.Entries {
			if item.Name == component && item.Type == "folder" {
				currentID = item.ID
				found = true
				break
			}
		}

		// If folder not found, create it
		if !found {
			// Create the folder
			folder := map[string]interface{}{
				"name": component,
				"parent": map[string]string{
					"id": currentID,
				},
			}

			folderData, err := json.Marshal(folder)
			if err != nil {
				return "", fmt.Errorf("failed to marshal folder data: %v", err)
			}

			createURL := "https://api.box.com/2.0/folders"
			createReq, err := http.NewRequest("POST", createURL, bytes.NewBuffer(folderData))
			if err != nil {
				return "", fmt.Errorf("failed to create folder request: %v", err)
			}

			createReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))
			createReq.Header.Set("Content-Type", "application/json")

			createResp, err := client.Do(createReq)
			if err != nil {
				return "", fmt.Errorf("failed to create folder: %v", err)
			}
			defer createResp.Body.Close()

			if createResp.StatusCode != http.StatusCreated {
				respBody, _ := io.ReadAll(createResp.Body)
				return "", fmt.Errorf("failed to create folder '%s': status code %d, response: %s", component, createResp.StatusCode, string(respBody))
			}

			var newFolder struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			}

			if err := json.NewDecoder(createResp.Body).Decode(&newFolder); err != nil {
				return "", fmt.Errorf("failed to decode create folder response: %v", err)
			}

			currentID = newFolder.ID
			fmt.Printf("Created new Box folder: %s (ID: %s)\n", component, currentID)
		}
	}

	return currentID, nil
}
