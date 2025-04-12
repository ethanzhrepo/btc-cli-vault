package util

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/fatih/color"
)

const (
	// Environment variable names for AWS credentials
	AWS_ACCESS_KEY_ID     = "AWS_ACCESS_KEY_ID"
	AWS_SECRET_ACCESS_KEY = "AWS_SECRET_ACCESS_KEY"
	AWS_REGION            = "AWS_REGION"
	AWS_S3_BUCKET         = "AWS_S3_BUCKET"
)

// These variables will be injected from main package when built using ldflags
var (
	DefaultAwsAccessKeyID     = ""
	DefaultAwsSecretAccessKey = ""
	DefaultAwsRegion          = ""
	DefaultAwsS3Bucket        = ""
)

// S3Storage implements Storage interface for AWS S3
type S3Storage struct{}

func (s *S3Storage) Put(data []byte, filePath string, withForce bool) (string, error) {
	return UploadToS3(data, filePath, withForce)
}

func (s *S3Storage) Get(filePath string) ([]byte, error) {
	return DownloadFromS3(filePath)
}

func (s *S3Storage) List(dir string) ([]string, error) {
	return ListS3Files(dir)
}

// Creates a new AWS S3 client using environment variables
func createS3Client() (*s3.Client, string, error) {
	// Check for required environment variables
	accessKey := os.Getenv(AWS_ACCESS_KEY_ID)
	secretKey := os.Getenv(AWS_SECRET_ACCESS_KEY)
	region := os.Getenv(AWS_REGION)
	bucket := os.Getenv(AWS_S3_BUCKET)

	// If environment variables are not set, use default values from main package
	if accessKey == "" {
		accessKey = DefaultAwsAccessKeyID
	}
	if secretKey == "" {
		secretKey = DefaultAwsSecretAccessKey
	}
	if region == "" {
		region = DefaultAwsRegion
	}
	if bucket == "" {
		bucket = DefaultAwsS3Bucket
	}

	// Display error and exit if any required variable is missing
	if accessKey == "" || secretKey == "" || region == "" || bucket == "" {
		red := color.New(color.FgRed, color.Bold)
		red.Printf("\nError: AWS S3 credentials not found in environment variables\n")
		red.Printf("Please set the following environment variables:\n")
		red.Printf("- %s\n", AWS_ACCESS_KEY_ID)
		red.Printf("- %s\n", AWS_SECRET_ACCESS_KEY)
		red.Printf("- %s\n", AWS_REGION)
		red.Printf("- %s\n", AWS_S3_BUCKET)
		os.Exit(1)
	}

	// Create a custom credentials provider
	provider := credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")

	// Create an AWS configuration
	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		config.WithCredentialsProvider(provider),
		config.WithRegion(region),
	)

	if err != nil {
		return nil, "", fmt.Errorf("failed to load AWS configuration: %v", err)
	}

	// Create and return S3 client
	return s3.NewFromConfig(cfg), bucket, nil
}

// UploadToS3 uploads data to S3 bucket
func UploadToS3(data []byte, filePath string, withForce bool) (string, error) {
	client, bucket, err := createS3Client()
	if err != nil {
		return "", err
	}

	// Normalize the file path for S3
	filePath = normalizeS3Path(filePath)

	// Create a context for the upload operation
	ctx := context.TODO()

	// Check if file already exists
	exists, err := checkFileExistsInS3(client, bucket, filePath)
	if err != nil {
		return "", fmt.Errorf("failed to check if file exists: %v", err)
	}

	if exists && !withForce {
		fmt.Printf("Error: Wallet file already exists in S3: s3://%s/%s\n", bucket, filePath)
		fmt.Println("Use --force to overwrite.")
		os.Exit(1)
	}

	if exists && withForce {
		fmt.Printf("Overwriting existing file in S3: s3://%s/%s\n", bucket, filePath)
	}

	// Upload the file to S3
	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(filePath),
		Body:   bytes.NewReader(data),
	})

	if err != nil {
		return "", fmt.Errorf("failed to upload to S3: %v", err)
	}

	return fmt.Sprintf("File uploaded to S3: s3://%s/%s", bucket, filePath), nil
}

// Check if a file exists in S3
func checkFileExistsInS3(client *s3.Client, bucket string, key string) (bool, error) {
	ctx := context.TODO()

	// Use HeadObject to check if the object exists
	_, err := client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})

	if err != nil {
		// Check if error is NoSuchKey or NotFound
		var nsk *types.NoSuchKey
		var notFound *types.NotFound
		if errors.As(err, &nsk) || errors.As(err, &notFound) {
			return false, nil
		}

		// For any other error, return it
		return false, err
	}

	// If we get here, the object exists
	return true, nil
}

// DownloadFromS3 downloads data from S3 bucket
func DownloadFromS3(filePath string) ([]byte, error) {
	client, bucket, err := createS3Client()
	if err != nil {
		return nil, err
	}

	// Normalize the file path for S3
	filePath = normalizeS3Path(filePath)

	// Create a context for the download operation
	ctx := context.TODO()

	// Get the object from S3
	result, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(filePath),
	})

	if err != nil {
		return nil, fmt.Errorf("failed to download from S3: %v", err)
	}
	defer result.Body.Close()

	// Read the response body
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(result.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read S3 object body: %v", err)
	}

	return buf.Bytes(), nil
}

// ListS3Files lists files in the specified S3 directory
func ListS3Files(dir string) ([]string, error) {
	client, bucket, err := createS3Client()
	if err != nil {
		return nil, err
	}

	// Normalize the directory path for S3
	dir = normalizeS3Path(dir)
	if dir != "" && !strings.HasSuffix(dir, "/") {
		dir = dir + "/"
	}

	// Create a context for the list operation
	ctx := context.TODO()

	// List objects in the S3 bucket with the specified prefix
	result, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(dir),
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list objects in S3: %v", err)
	}

	// Extract file paths from the results
	var files []string
	for _, item := range result.Contents {
		key := *item.Key
		if strings.HasSuffix(strings.ToLower(key), ".json") {
			files = append(files, key)
		}
	}

	return files, nil
}

// normalizeS3Path removes leading slash and handles empty paths
func normalizeS3Path(path string) string {
	// Remove leading slash as S3 doesn't need it
	if strings.HasPrefix(path, "/") {
		path = path[1:]
	}

	// If path is empty, use the default directory and filename
	if path == "" {
		path = filepath.Join(GetCloudFileDir(), DEFAULT_CLOUD_FILE_NAME)
		// Remove leading slash again if present
		if strings.HasPrefix(path, "/") {
			path = path[1:]
		}
	}

	return path
}
