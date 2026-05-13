package probes

import "net/http"

// Request describes a single HTTP probe to fire.
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
	Label   string // e.g. "method-fuzz:TRACE", "path-fuzz:/.env"
}

// Result is the raw outcome of executing a Request.
type Result struct {
	Request    Request
	StatusCode int
	Headers    http.Header
	Body       []byte
	TLSError   bool
	Err        error
}

// Probe generates a set of Requests for a given base URL.
type Probe interface {
	Name() string
	Requests(baseURL string) []Request
}
