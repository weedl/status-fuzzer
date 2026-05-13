package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/vetle/status-fuzzer/internal/probes"
)

const maxBodyBytes = 1 << 20 // 1 MB

type Config struct {
	Timeout   time.Duration
	SkipTLS   bool
	UserAgent string
}

type Client struct {
	http      *http.Client
	userAgent string
}

func New(cfg Config) *Client {
	ua := cfg.UserAgent
	if ua == "" {
		ua = "status-fuzzer/1.0"
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.SkipTLS}, //nolint:gosec
	}
	return &Client{
		userAgent: ua,
		http: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
			// Never follow redirects — they can hide disclosure.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (c *Client) Execute(ctx context.Context, req probes.Request) probes.Result {
	var bodyReader io.Reader
	if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bodyReader)
	if err != nil {
		return probes.Result{Request: req, Err: err}
	}

	httpReq.Header.Set("User-Agent", c.userAgent)
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := c.http.Do(httpReq)
	if err != nil {
		tlsErr := strings.Contains(err.Error(), "tls") ||
			strings.Contains(err.Error(), "certificate") ||
			strings.Contains(err.Error(), "x509")
		return probes.Result{Request: req, Err: err, TLSError: tlsErr}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return probes.Result{
		Request:    req,
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
	}
}
