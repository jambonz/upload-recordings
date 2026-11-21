// Package creds decrypts and parses the per-account bucket credential that
// the jambonz api-server stores in accounts.bucket_credential.
package creds

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
)

// The api-server derives its AES-256 key as the first 32 characters of
// base64(sha256(ENCRYPTION_SECRET)), used as raw key bytes.
func key(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return []byte(base64.StdEncoding.EncodeToString(sum[:])[:32])
}

type envelope struct {
	IV      string `json:"iv"`
	Content string `json:"content"`
}

// Decrypt reverses the api-server's {"iv":hex,"content":hex} AES-256-CBC
// envelope.
func Decrypt(secret, encrypted string) (string, error) {
	var env envelope
	if err := json.Unmarshal([]byte(encrypted), &env); err != nil {
		return "", errors.New("failed to parse encrypted data JSON")
	}
	if env.IV == "" {
		return "", errors.New("IV not found in encrypted data JSON")
	}
	if env.Content == "" {
		return "", errors.New("content not found in encrypted data JSON")
	}
	iv, err := hex.DecodeString(env.IV)
	if err != nil || len(iv) != aes.BlockSize {
		return "", errors.New("invalid IV")
	}
	data, err := hex.DecodeString(env.Content)
	if err != nil || len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return "", errors.New("invalid encrypted content")
	}
	block, err := aes.NewCipher(key(secret))
	if err != nil {
		return "", err
	}
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(data, data)
	pad := int(data[len(data)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(data) ||
		!bytes.Equal(data[len(data)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
		return "", errors.New("decryption failed (wrong ENCRYPTION_SECRET?)")
	}
	return string(data[:len(data)-pad]), nil
}

// Encrypt produces the same envelope the api-server writes. The service never
// encrypts; this exists for tests and for seeding the benchmark database.
func Encrypt(secret, plain string) (string, error) {
	block, err := aes.NewCipher(key(secret))
	if err != nil {
		return "", err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	data := append([]byte(plain), bytes.Repeat([]byte{byte(pad)}, pad)...)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, data)
	out, _ := json.Marshal(envelope{IV: hex.EncodeToString(iv), Content: hex.EncodeToString(data)})
	return string(out), nil
}

// Bucket is a decrypted bucket credential. Which fields are set depends on
// Vendor: aws_s3, s3_compatible, azure or google.
type Bucket struct {
	Vendor string
	Name   string // bucket (S3, Google) or container (Azure)

	AccessKeyID     string
	SecretAccessKey string
	Region          string
	Endpoint        string

	ConnectionString string

	ClientEmail string
	PrivateKey  string
	TokenURI    string
}

// s3.<region>.<domain>.<tld>, with or without a scheme.
var endpointRegion = regexp.MustCompile(`(^|://)s3\.([^.]+-[^.]+)\.[^.]+\.[^.]+`)

// ParseBucket parses the decrypted credential JSON. Fields of the wrong JSON
// type are ignored rather than rejected, as the C++ service does.
func ParseBucket(plain string) (Bucket, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(plain), &m); err != nil {
		return Bucket{}, errors.New("failed to parse bucket credential JSON")
	}
	str := func(src map[string]any, k string) string {
		s, _ := src[k].(string)
		return s
	}
	b := Bucket{Vendor: str(m, "vendor"), Name: str(m, "name")}
	switch b.Vendor {
	case "aws_s3", "s3_compatible":
		b.AccessKeyID = str(m, "access_key_id")
		b.SecretAccessKey = str(m, "secret_access_key")
		b.Endpoint = str(m, "endpoint")
		if r, ok := m["region"].(string); ok {
			b.Region = r
		} else if b.Endpoint != "" {
			if sub := endpointRegion.FindStringSubmatch(b.Endpoint); sub != nil {
				b.Region = sub[2]
			}
		}
	case "azure":
		b.ConnectionString = str(m, "connection_string")
	case "google":
		var sk map[string]any
		if json.Unmarshal([]byte(str(m, "service_key")), &sk) == nil {
			b.PrivateKey = str(sk, "private_key")
			b.ClientEmail = str(sk, "client_email")
			b.TokenURI = str(sk, "token_uri")
		}
	}
	return b, nil
}
