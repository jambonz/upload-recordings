package store

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	azureBlockSize = 4 * 1024 * 1024
	azureVersion   = "2020-02-10"
	// Every request, session.json included, is sent (and signed) with this
	// content type, as the C++ service does.
	azureContentType = "application/octet-stream"
)

var azureConnString = regexp.MustCompile(
	`^DefaultEndpointsProtocol=(https|http);AccountName=([^;]+);AccountKey=([^;]+);EndpointSuffix=([^;]+)$`)

type azureUploader struct {
	hc      *http.Client
	account string
	key     []byte
	baseURL string // <proto>://<account>.blob.<suffix>/<container>/
	now     func() time.Time
}

func newAzure(hc *http.Client, connectionString, container string) (*azureUploader, error) {
	m := azureConnString.FindStringSubmatch(connectionString)
	if m == nil {
		return nil, errors.New("invalid Azure connection string format")
	}
	key, err := base64.StdEncoding.DecodeString(m[3])
	if err != nil {
		return nil, errors.New("invalid Azure account key")
	}
	return &azureUploader{
		hc:      hc,
		account: m[2],
		key:     key,
		baseURL: m[1] + "://" + m[2] + ".blob." + m[4] + "/" + container + "/",
		now:     time.Now,
	}, nil
}

// UploadRecording uploads the file as a block blob: Put Block for each 4 MB,
// then Put Block List.
func (a *azureUploader) UploadRecording(ctx context.Context, key string, f *os.File, size int64, _ CallInfo) error {
	blobURL := a.baseURL + key
	var blockIDs []string
	for offset := int64(0); offset < size; offset += azureBlockSize {
		n := min(int64(azureBlockSize), size-offset)
		id := base64.StdEncoding.EncodeToString(fmt.Appendf(nil, "block-%06d", len(blockIDs)+1))
		blockIDs = append(blockIDs, id)
		u := blobURL + "?comp=block&blockid=" + url.QueryEscape(id)
		if err := a.put(ctx, u, io.NewSectionReader(f, offset, n), n, nil, "block upload"); err != nil {
			return err
		}
	}
	var list strings.Builder
	list.WriteString(`<?xml version="1.0" encoding="utf-8"?><BlockList>`)
	for _, id := range blockIDs {
		list.WriteString("<Latest>" + id + "</Latest>")
	}
	list.WriteString("</BlockList>")
	body := list.String()
	return a.put(ctx, blobURL+"?comp=blocklist", strings.NewReader(body), int64(len(body)), nil, "commit block list")
}

func (a *azureUploader) UploadSessionJSON(ctx context.Context, key string, body []byte) error {
	return a.put(ctx, a.baseURL+key, bytes.NewReader(body), int64(len(body)),
		map[string]string{"x-ms-blob-type": "BlockBlob"}, "session.json upload")
}

func (a *azureUploader) put(ctx context.Context, rawURL string, body io.Reader, size int64, extra map[string]string, what string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, rawURL, body)
	if err != nil {
		return err
	}
	req.ContentLength = size
	// The date is taken per request: a signature is only valid for 15 minutes.
	date := a.now().UTC().Format(http.TimeFormat)
	headers := map[string]string{"x-ms-date": date, "x-ms-version": azureVersion}
	for k, v := range extra {
		headers[k] = v
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", azureContentType)
	req.Header.Set("Authorization", a.authorization(http.MethodPut, req.URL, size, headers))

	resp, err := a.hc.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return checkStatus(resp, what, http.StatusCreated)
}

// authorization builds the SharedKey header for a request
// (https://learn.microsoft.com/rest/api/storageservices/authorize-with-shared-key).
func (a *azureUploader) authorization(method string, u *url.URL, contentLength int64, msHeaders map[string]string) string {
	names := make([]string, 0, len(msHeaders))
	for k := range msHeaders {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, k := range names {
		canonHeaders.WriteString(k + ":" + msHeaders[k] + "\n")
	}

	resource := "/" + a.account + u.EscapedPath()
	query := u.Query()
	params := make([]string, 0, len(query))
	for k := range query {
		params = append(params, k)
	}
	sort.Strings(params)
	for _, k := range params {
		resource += "\n" + k + ":" + query.Get(k)
	}

	stringToSign := method + "\n" +
		"\n" + // Content-Encoding
		"\n" + // Content-Language
		strconv.FormatInt(contentLength, 10) + "\n" +
		"\n" + // Content-MD5
		azureContentType + "\n" +
		"\n" + // Date (x-ms-date is used instead)
		"\n" + // If-Modified-Since
		"\n" + // If-Match
		"\n" + // If-None-Match
		"\n" + // If-Unmodified-Since
		"\n" + // Range
		canonHeaders.String() +
		resource

	mac := hmac.New(sha256.New, a.key)
	mac.Write([]byte(stringToSign))
	return "SharedKey " + a.account + ":" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
