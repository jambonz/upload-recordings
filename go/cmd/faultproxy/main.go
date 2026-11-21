// Command faultproxy is a TLS reverse proxy that makes object storage slow
// or broken on demand, for testing how the recording server behaves when
// uploads fall behind.
package main

import (
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"time"
)

// throttled delays reads so the request body arrives at about bps bytes/s.
type throttled struct {
	io.ReadCloser
	bps   int
	start time.Time
	read  int64
}

func (t *throttled) Read(p []byte) (int, error) {
	if len(p) > 16*1024 {
		p = p[:16*1024]
	}
	n, err := t.ReadCloser.Read(p)
	t.read += int64(n)
	if ahead := time.Duration(float64(t.read)/float64(t.bps)*float64(time.Second)) - time.Since(t.start); ahead > 0 {
		time.Sleep(ahead)
	}
	return n, err
}

func main() {
	listen := flag.String("listen", ":9000", "listen address")
	upstream := flag.String("upstream", "https://minio:9000", "storage to forward to")
	cert := flag.String("cert", "/certs/public.crt", "TLS certificate")
	key := flag.String("key", "/certs/private.key", "TLS key")
	delay := flag.Duration("delay", 0, "wait this long before forwarding each PUT")
	bps := flag.Int("bps", 0, "throttle each PUT body to this many bytes per second")
	fail := flag.Int("fail", 0, "answer every PUT with this HTTP status instead of forwarding")
	flag.Parse()

	target, err := url.Parse(*upstream)
	if err != nil {
		log.Fatal(err)
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = r.In.Host // the SigV4 signature covers the Host the client used
		},
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // test rig only
			MaxIdleConnsPerHost: 256,
		},
		FlushInterval: -1,
	}
	var puts atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			n := puts.Add(1)
			if *fail != 0 {
				io.Copy(io.Discard, r.Body)
				http.Error(w, "<Error><Code>ServiceUnavailable</Code><Message>injected</Message></Error>", *fail)
				return
			}
			if *delay > 0 {
				time.Sleep(*delay)
			}
			if *bps > 0 {
				r.Body = &throttled{ReadCloser: r.Body, bps: *bps, start: time.Now()}
			}
			if n%100 == 1 {
				log.Printf("PUT #%d %s", n, r.URL.Path)
			}
		}
		proxy.ServeHTTP(w, r)
	})
	log.Printf("faultproxy %s -> %s delay=%s bps=%d fail=%d", *listen, *upstream, *delay, *bps, *fail)
	log.Fatal(http.ListenAndServeTLS(*listen, *cert, *key, handler))
}
