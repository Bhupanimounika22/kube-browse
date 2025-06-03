package minio

import (
	"context"
	"log"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// MinioClient represents a MinIO client instance
type MinioClient struct {
	Client *minio.Client
}

// NewMinioClient creates a new MinIO client
func NewMinioClient(endpoint, accessKeyID, secretAccessKey string, useSSL bool) (*MinioClient, error) {
	// Initialize MinIO client
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKeyID, secretAccessKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		return nil, err
	}

	return &MinioClient{Client: client}, nil
}

// CreateBucket creates a new bucket if it doesn't exist
func (m *MinioClient) CreateBucket(ctx context.Context, bucketName string, location string) error {
	// Check if bucket exists
	exists, err := m.Client.BucketExists(ctx, bucketName)
	if err != nil {
		return err
	}

	// If bucket doesn't exist, create it
	if !exists {
		err = m.Client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{Region: location})
		if err != nil {
			return err
		}
		log.Printf("Successfully created bucket: %s\n", bucketName)
	} else {
		log.Printf("Bucket %s already exists\n", bucketName)
	}

	return nil
}
