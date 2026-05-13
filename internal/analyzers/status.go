package analyzers

import (
	"fmt"
	"net/url"

	"github.com/vetle/status-fuzzer/internal/findings"
	"github.com/vetle/status-fuzzer/internal/probes"
)

// sensitivePaths are paths that should never return 200 on a production server.
var sensitivePaths = map[string]bool{
	"/.env":              true,
	"/.env.local":        true,
	"/.env.production":   true,
	"/.git/config":       true,
	"/.git/HEAD":         true,
	"/backup.sql":        true,
	"/dump.sql":          true,
	"/database.sql":      true,
	"/composer.json":     true,
	"/composer.lock":     true,
	"/package.json":      true,
	"/phpinfo.php":       true,
	"/info.php":          true,
	"/server-status":     true,
	"/server-info":       true,
	"/actuator/env":      true,
	"/actuator/beans":    true,
	"/actuator/heapdump": true,
	"/actuator/loggers":  true,
	"/.htpasswd":         true,
	"/web.config":        true,
	"/WEB-INF/web.xml":   true,
}

type StatusAnalyzer struct{}

func (StatusAnalyzer) Analyze(result probes.Result) []findings.Finding {
	// TLS errors are a finding of their own.
	if result.TLSError {
		return []findings.Finding{{
			Severity:    findings.Medium,
			Title:       "TLS certificate error",
			Description: "The server has a TLS/SSL certificate issue (expired, self-signed, or hostname mismatch).",
			Evidence:    result.Err.Error(),
			Source:      result.Request.Label,
			URL:         result.Request.URL,
		}}
	}

	if result.Err != nil || result.StatusCode == 0 {
		return nil
	}

	var out []findings.Finding
	code := result.StatusCode
	method := result.Request.Method

	// TRACE returning 2xx → XST risk.
	if method == "TRACE" && code >= 200 && code < 300 {
		out = append(out, findings.Finding{
			Severity:    findings.Medium,
			Title:       "TRACE method enabled (XST risk)",
			Description: "The server accepts HTTP TRACE requests, enabling Cross-Site Tracing (XST) attacks.",
			Evidence:    fmt.Sprintf("TRACE → %d", code),
			Source:      result.Request.Label,
			URL:         result.Request.URL,
		})
	}

	// CONNECT returning 2xx → open proxy risk.
	if method == "CONNECT" && code >= 200 && code < 300 {
		out = append(out, findings.Finding{
			Severity:    findings.High,
			Title:       "CONNECT method enabled (open proxy risk)",
			Description: "The server accepts HTTP CONNECT requests, which may allow it to be used as an open proxy.",
			Evidence:    fmt.Sprintf("CONNECT → %d", code),
			Source:      result.Request.Label,
			URL:         result.Request.URL,
		})
	}

	// Non-standard method accepted.
	if method == "FOOBAR" && code >= 200 && code < 300 {
		out = append(out, findings.Finding{
			Severity:    findings.Low,
			Title:       "Non-standard HTTP method accepted",
			Description: "The server returned 2xx to an invalid HTTP method (FOOBAR), suggesting lax method validation.",
			Evidence:    fmt.Sprintf("FOOBAR → %d", code),
			Source:      result.Request.Label,
			URL:         result.Request.URL,
		})
	}

	// 500 with a non-empty body → body analyzer will dig further, but flag the status itself.
	if code == 500 && len(result.Body) > 0 {
		out = append(out, findings.Finding{
			Severity:    findings.Medium,
			Title:       "Internal server error with response body",
			Description: "The server returned HTTP 500 with a body that may contain stack traces or internal details.",
			Evidence:    fmt.Sprintf("HTTP 500 from %s (%d bytes)", result.Request.Label, len(result.Body)),
			Source:      result.Request.Label,
			URL:         result.Request.URL,
		})
	}

	// Sensitive path returning 200.
	if code == 200 {
		if u, err := url.Parse(result.Request.URL); err == nil && sensitivePaths[u.Path] {
			out = append(out, findings.Finding{
				Severity:    findings.High,
				Title:       fmt.Sprintf("Sensitive path publicly accessible: %s", u.Path),
				Description: "A sensitive file or endpoint returned HTTP 200, indicating it may be publicly accessible.",
				Evidence:    fmt.Sprintf("GET %s → 200 (%d bytes)", u.Path, len(result.Body)),
				Source:      result.Request.Label,
				URL:         result.Request.URL,
			})
		}
	}

	return out
}
