// Package store uploads finished recordings to the account's bucket: AWS S3,
// an S3-compatible service, Azure Blob Storage or Google Cloud Storage.
package store

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/jambonz/upload-recordings/go/internal/creds"
)

// CallInfo is the call metadata attached to the stored recording (as S3 user
// metadata; Azure and Google objects carry none, as before).
type CallInfo struct {
	AccountSid              string
	CallSid                 string
	Direction               string
	From                    string
	To                      string
	ApplicationSid          string
	OriginatingSipIP        string
	OriginatingSipTrunkName string
	SampleRate              int
}

// Uploader stores one account's recordings. Implementations are safe for
// concurrent use and are shared between sessions.
type Uploader interface {
	// UploadRecording stores the first size bytes of f under key.
	UploadRecording(ctx context.Context, key string, f *os.File, size int64, info CallInfo) error
	// UploadSessionJSON stores session.json under key.
	UploadSessionJSON(ctx context.Context, key string, body []byte) error
}

// Factory builds uploaders and owns the HTTP connection pools they share.
type Factory struct {
	maxConns int
	s3       s3Clients
	plain    *http.Client // Azure and Google
}

// NewFactory returns a factory whose uploaders open at most maxConns
// concurrent connections per storage host. Uploads beyond that wait their
// turn; this is the only limit on upload concurrency.
func NewFactory(maxConns int) *Factory {
	return &Factory{
		maxConns: maxConns,
		plain:    &http.Client{Transport: newTransport(maxConns)},
	}
}

func newTransport(maxConns int) *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxConnsPerHost:       maxConns,
		MaxIdleConnsPerHost:   maxConns,
		MaxIdleConns:          0,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ExpectContinueTimeout: time.Second,
		// HTTP/1.1 only, as the C++ client was: one upload per connection is
		// what makes MaxConnsPerHost a real concurrency limit.
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
}

// For returns the uploader for a decrypted bucket credential.
func (f *Factory) For(b creds.Bucket) (Uploader, error) {
	switch b.Vendor {
	case "aws_s3":
		// A custom endpoint is honoured for s3_compatible only.
		return f.s3.uploader(b.AccessKeyID, b.SecretAccessKey, b.Region, "", b.Name, f.maxConns)
	case "s3_compatible":
		return f.s3.uploader(b.AccessKeyID, b.SecretAccessKey, b.Region, b.Endpoint, b.Name, f.maxConns)
	case "azure":
		return newAzure(f.plain, b.ConnectionString, b.Name)
	case "google":
		return newGoogle(f.plain, b.Name, b.ClientEmail, b.PrivateKey, b.TokenURI)
	default:
		return nil, fmt.Errorf("unsupported storage service: %q", b.Vendor)
	}
}

func checkStatus(resp *http.Response, what string, want ...int) error {
	for _, w := range want {
		if resp.StatusCode == w {
			return nil
		}
	}
	return fmt.Errorf("%s failed with HTTP code: %d", what, resp.StatusCode)
}
