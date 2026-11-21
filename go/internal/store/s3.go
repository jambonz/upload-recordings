package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type s3Uploader struct {
	client *s3.Client
	bucket string
}

type s3ClientKey struct {
	region, endpoint, accessKey string
	secretHash                  [sha256.Size]byte
}

// s3Clients caches one client (and so one connection pool) per tenant
// endpoint and credential. It is consulted once per session, not per frame.
type s3Clients struct {
	mu      sync.Mutex
	clients map[s3ClientKey]*s3.Client
}

func (c *s3Clients) uploader(accessKey, secretKey, region, endpoint, bucket string, maxConns int) (Uploader, error) {
	key := s3ClientKey{region, endpoint, accessKey, sha256.Sum256([]byte(secretKey))}
	c.mu.Lock()
	client, ok := c.clients[key]
	if !ok {
		client = newS3Client(accessKey, secretKey, region, endpoint, maxConns)
		if c.clients == nil {
			c.clients = make(map[s3ClientKey]*s3.Client)
		}
		c.clients[key] = client
	}
	c.mu.Unlock()
	return &s3Uploader{client: client, bucket: bucket}, nil
}

func newS3Client(accessKey, secretKey, region, endpoint string, maxConns int) *s3.Client {
	if region == "" {
		region = "us-east-1"
	}
	cfg := aws.Config{
		Region:           region,
		Credentials:      credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
		HTTPClient:       &http.Client{Transport: newTransport(maxConns)},
		RetryMaxAttempts: 3,
		// Do not add the SDK's default CRC trailers: several S3-compatible
		// stores reject them, and they cost a pass over every recording.
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	}
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		// UNSIGNED-PAYLOAD, as the C++ client used: the body is protected by
		// TLS, and hashing it would read every recording twice.
		o.APIOptions = append(o.APIOptions, v4.SwapComputePayloadSHA256ForUnsignedPayloadMiddleware)
		if endpoint != "" {
			host := endpointHost(endpoint)
			// Always HTTPS, whatever scheme the credential's endpoint has.
			o.BaseEndpoint = aws.String("https://" + host)
			o.UsePathStyle = usePathStyle(host)
		}
	})
}

// endpointHost strips the scheme and a trailing slash from a credential's
// endpoint.
func endpointHost(endpoint string) string {
	endpoint = strings.TrimSuffix(endpoint, "/")
	endpoint = strings.TrimPrefix(endpoint, "https://")
	endpoint = strings.TrimPrefix(endpoint, "http://")
	return endpoint
}

// usePathStyle reports whether a custom endpoint needs path-style addressing:
// localhost always does, as does any host matching an entry of the
// comma-separated S3_PATH_STYLE_SERVICES environment variable.
func usePathStyle(host string) bool {
	if strings.Contains(host, "localhost") || strings.Contains(host, "127.0.0.1") {
		return true
	}
	for _, svc := range strings.Split(os.Getenv("S3_PATH_STYLE_SERVICES"), ",") {
		if svc = strings.Trim(svc, " \t"); svc != "" && strings.Contains(host, svc) {
			return true
		}
	}
	return false
}

// UploadRecording streams the file in a single PutObject. That is good for
// objects up to 5 GB, more than a WAV header can describe, so there is no
// multipart path to buffer parts or to abort on failure.
func (u *s3Uploader) UploadRecording(ctx context.Context, key string, f *os.File, size int64, info CallInfo) error {
	_, err := u.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(u.bucket),
		Key:           aws.String(key),
		Body:          io.NewSectionReader(f, 0, size),
		ContentLength: aws.Int64(size),
		ContentType:   aws.String("binary/octet-stream"),
		Metadata: map[string]string{
			"Account-Sid":                info.AccountSid,
			"Call-Sid":                   info.CallSid,
			"Direction":                  info.Direction,
			"From":                       info.From,
			"To":                         info.To,
			"Application-Sid":            info.ApplicationSid,
			"Originating-Sip-Id":         info.OriginatingSipIP,
			"Originating-Sip-Trunk-Name": info.OriginatingSipTrunkName,
			"Sample-Rate":                strconv.Itoa(info.SampleRate),
		},
	})
	return err
}

func (u *s3Uploader) UploadSessionJSON(ctx context.Context, key string, body []byte) error {
	_, err := u.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(u.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(body),
		ContentType: aws.String("application/json"),
	})
	return err
}
