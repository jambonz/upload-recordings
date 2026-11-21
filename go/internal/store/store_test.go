package store

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
)

func tempFile(t *testing.T, size int) (*os.File, []byte) {
	t.Helper()
	data := make([]byte, size)
	rand.Read(data)
	f, err := os.CreateTemp(t.TempDir(), "rec")
	if err != nil {
		t.Fatal(err)
	}
	f.Write(data)
	t.Cleanup(func() { f.Close() })
	return f, data
}

// azureSignature is written from Microsoft's "Authorize with Shared Key"
// document independently of the code under test.
func azureSignature(r *http.Request, account string, key []byte) string {
	var ms []string
	for k := range r.Header {
		if lk := strings.ToLower(k); strings.HasPrefix(lk, "x-ms-") {
			ms = append(ms, lk+":"+r.Header.Get(k))
		}
	}
	sort.Strings(ms)
	resource := "/" + account + r.URL.Path
	q := r.URL.Query()
	var names []string
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		resource += "\n" + strings.ToLower(k) + ":" + q.Get(k)
	}
	sts := strings.Join([]string{
		r.Method, r.Header.Get("Content-Encoding"), r.Header.Get("Content-Language"),
		r.Header.Get("Content-Length"), r.Header.Get("Content-MD5"), r.Header.Get("Content-Type"),
		"", "", "", "", "", "", // Date, If-Modified-Since, If-Match, If-None-Match, If-Unmodified-Since, Range
		strings.Join(ms, "\n"), resource,
	}, "\n")
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(sts))
	return "SharedKey " + account + ":" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func TestAzureBlockUpload(t *testing.T) {
	accountKey := []byte("0123456789abcdef0123456789abcdef")
	var mu sync.Mutex
	blocks := map[string][]byte{}
	var blob, sessionJSON []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Header.Set("Content-Length", fmt.Sprint(len(body)))
		if got, want := r.Header.Get("Authorization"), azureSignature(r, "acct", accountKey); got != want {
			t.Errorf("%s %s: bad signature", r.Method, r.URL)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.Header.Get("x-ms-version") != azureVersion {
			t.Errorf("missing x-ms-version")
		}
		mu.Lock()
		defer mu.Unlock()
		q := r.URL.Query()
		switch {
		case q.Get("comp") == "block":
			blocks[q.Get("blockid")] = body
		case q.Get("comp") == "blocklist":
			for _, part := range strings.Split(string(body), "<Latest>")[1:] {
				blob = append(blob, blocks[part[:strings.Index(part, "<")]]...)
			}
		case r.Header.Get("x-ms-blob-type") == "BlockBlob":
			sessionJSON = body
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	cs := "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=" +
		base64.StdEncoding.EncodeToString(accountKey) + ";EndpointSuffix=core.windows.net"
	up, err := newAzure(srv.Client(), cs, "recordings")
	if err != nil {
		t.Fatal(err)
	}
	if up.baseURL != "https://acct.blob.core.windows.net/recordings/" {
		t.Fatalf("baseURL %q", up.baseURL)
	}
	up.baseURL = srv.URL + "/recordings/"

	f, data := tempFile(t, 2*azureBlockSize+12345) // three blocks
	if err := up.UploadRecording(context.Background(), "2026/11/20/CA1.wav", f, int64(len(data)), CallInfo{}); err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 3 || !bytes.Equal(blob, data) {
		t.Fatalf("%d blocks, blob %d bytes, want %d", len(blocks), len(blob), len(data))
	}
	if err := up.UploadSessionJSON(context.Background(), "2026/11/20/CA1/session.json", []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if string(sessionJSON) != `{"a":1}` {
		t.Fatalf("session.json %q", sessionJSON)
	}

	if _, err := newAzure(srv.Client(), "AccountName=x", "c"); err == nil {
		t.Error("expected an error for a malformed connection string")
	}
}

func TestGoogleResumableUpload(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	var mu sync.Mutex
	var object, sessionJSON []byte
	var ranges []string
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/token":
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ParseForm()
			parts := strings.Split(r.PostForm.Get("assertion"), ".")
			if len(parts) != 3 || r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
				t.Errorf("bad token request")
				return
			}
			sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
			digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
			if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
				t.Errorf("JWT signature: %v", err)
			}
			claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
			var c map[string]any
			json.Unmarshal(claims, &c)
			if c["iss"] != "svc@example.iam" || c["scope"] != gcsScope || c["aud"] != srv.URL+"/token" {
				t.Errorf("claims %v", c)
			}
			w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
		case r.Header.Get("Authorization") == "Bearer tok" && r.URL.Query().Get("uploadType") == "resumable":
			if r.URL.Query().Get("name") != "2026/11/20/CA1.mp3" {
				t.Errorf("name %q", r.URL.Query().Get("name"))
			}
			w.Header().Set("Location", srv.URL+"/session/abc")
		case r.URL.Path == "/session/abc":
			ranges = append(ranges, r.Header.Get("Content-Range"))
			object = append(object, body...)
			var start, end, total int
			fmt.Sscanf(r.Header.Get("Content-Range"), "bytes %d-%d/%d", &start, &end, &total)
			if end+1 < total {
				w.WriteHeader(http.StatusPermanentRedirect) // 308 Resume Incomplete
			}
		case r.Header.Get("Authorization") == "Bearer tok" && r.URL.Query().Get("uploadType") == "media":
			sessionJSON = body
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	up, err := newGoogle(srv.Client(), "bkt", "svc@example.iam", keyPEM, srv.URL+"/token")
	if err != nil {
		t.Fatal(err)
	}
	up.uploadBase = srv.URL + "/upload/storage/v1/b/"

	f, data := tempFile(t, gcsChunkSize+777) // two chunks
	if err := up.UploadRecording(context.Background(), "2026/11/20/CA1.mp3", f, int64(len(data)), CallInfo{}); err != nil {
		t.Fatal(err)
	}
	wantRanges := []string{
		fmt.Sprintf("bytes 0-%d/%d", gcsChunkSize-1, len(data)),
		fmt.Sprintf("bytes %d-%d/%d", gcsChunkSize, len(data)-1, len(data)),
	}
	if !bytes.Equal(object, data) || fmt.Sprint(ranges) != fmt.Sprint(wantRanges) {
		t.Fatalf("object %d bytes, ranges %v", len(object), ranges)
	}
	if err := up.UploadSessionJSON(context.Background(), "2026/11/20/CA1/session.json", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if string(sessionJSON) != `{}` {
		t.Fatalf("session.json %q", sessionJSON)
	}
}

func TestS3Addressing(t *testing.T) {
	t.Setenv("S3_PATH_STYLE_SERVICES", "minio, storage.example.net")
	cases := map[string]bool{
		"localhost:9000":         true,
		"127.0.0.1:9000":         true,
		"minio:9000":             true,
		"a.storage.example.net":  true,
		"s3.us-west-1.wasabi.io": false,
	}
	for host, want := range cases {
		if got := usePathStyle(host); got != want {
			t.Errorf("usePathStyle(%q) = %v", host, got)
		}
	}
	for in, want := range map[string]string{
		"https://minio:9000/": "minio:9000", "http://h": "h", "h:1": "h:1",
	} {
		if got := endpointHost(in); got != want {
			t.Errorf("endpointHost(%q) = %q", in, got)
		}
	}
}
