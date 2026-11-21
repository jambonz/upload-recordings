package store

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	gcsChunkSize = 8 * 1024 * 1024
	gcsScope     = "https://www.googleapis.com/auth/devstorage.read_write"
)

type googleUploader struct {
	hc          *http.Client
	bucket      string
	clientEmail string
	key         *rsa.PrivateKey
	tokenURI    string
	uploadBase  string // overridden in tests
}

func newGoogle(hc *http.Client, bucket, clientEmail, privateKeyPEM, tokenURI string) (*googleUploader, error) {
	if privateKeyPEM == "" || clientEmail == "" || tokenURI == "" {
		return nil, errors.New("missing required Google credentials")
	}
	key, err := parseRSAKey(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	// GCS answers an unfinished chunk with 308 and no Location; never follow.
	noRedirect := *hc
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &googleUploader{
		hc:          &noRedirect,
		bucket:      bucket,
		clientEmail: clientEmail,
		key:         key,
		tokenURI:    tokenURI,
		uploadBase:  "https://storage.googleapis.com/upload/storage/v1/b/",
	}, nil
}

func parseRSAKey(pemText string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("failed to load Google private key")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return rk, nil
		}
		return nil, errors.New("Google private key is not an RSA key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// token exchanges a self-signed JWT for an access token. One is fetched per
// recording, as the C++ service does; it is not cached.
func (g *googleUploader) token(ctx context.Context) (string, error) {
	b64 := base64.RawURLEncoding.EncodeToString
	now := time.Now().Unix()
	claims, _ := json.Marshal(map[string]any{
		"iss": g.clientEmail, "scope": gcsScope, "aud": g.tokenURI, "exp": now + 3600, "iat": now,
	})
	unsigned := b64([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + b64(claims)
	digest := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, g.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {unsigned + "." + b64(sig)},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.tokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := g.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch OAuth token: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil || out.AccessToken == "" {
		return "", fmt.Errorf("OAuth token response (HTTP %d) does not contain an access token", resp.StatusCode)
	}
	return out.AccessToken, nil
}

// UploadRecording uses a resumable upload session, sending the file in 8 MB
// chunks.
func (g *googleUploader) UploadRecording(ctx context.Context, key string, f *os.File, size int64, _ CallInfo) error {
	token, err := g.token(ctx)
	if err != nil {
		return err
	}
	initURL := g.uploadBase + g.bucket + "/o?uploadType=resumable&name=" + url.QueryEscape(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, initURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	resp, err := g.hc.Do(req)
	if err != nil {
		return fmt.Errorf("failed to initiate resumable upload: %w", err)
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	sessionURL := resp.Header.Get("Location")
	if sessionURL == "" {
		return fmt.Errorf("resumable upload session URL not received (HTTP %d)", resp.StatusCode)
	}

	for offset := int64(0); offset < size; offset += gcsChunkSize {
		n := min(int64(gcsChunkSize), size-offset)
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, sessionURL, io.NewSectionReader(f, offset, n))
		if err != nil {
			return err
		}
		req.ContentLength = n
		req.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", offset, offset+n-1, size))
		req.Header.Set("Content-Type", "application/octet-stream")
		resp, err := g.hc.Do(req)
		if err != nil {
			return fmt.Errorf("failed to upload chunk (offset %d): %w", offset, err)
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if offset+n < size {
			err = checkStatus(resp, "intermediate chunk upload", http.StatusPermanentRedirect)
		} else {
			err = checkStatus(resp, "final chunk upload", http.StatusOK, http.StatusCreated)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (g *googleUploader) UploadSessionJSON(ctx context.Context, key string, body []byte) error {
	token, err := g.token(ctx)
	if err != nil {
		return err
	}
	u := g.uploadBase + g.bucket + "/o?uploadType=media&name=" + url.QueryEscape(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.hc.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upload session.json: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return checkStatus(resp, "session.json upload", http.StatusOK)
}
