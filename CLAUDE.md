# status-fuzzer

A Go CLI tool for detecting information disclosure vulnerabilities in web applications.
It probes a target URL using multiple HTTP techniques and analyzes responses for leaked
version numbers, framework details, stack traces, internal paths, and other sensitive data.

---

## Goal

Given a target URL, the tool should:
1. Fire a battery of HTTP probes (varied methods, paths, headers, malformed requests)
2. Collect every response (status, headers, body)
3. Analyze responses for information disclosure patterns
4. Report findings to the terminal (colored, severity-ranked) and optionally to a JSON file

---

## Project structure

```
status-fuzzer/
├── CLAUDE.md
├── go.mod
├── go.sum
├── main.go                     # CLI entry point — flag parsing, orchestration
├── internal/
│   ├── client/
│   │   └── client.go           # Configurable HTTP client (timeout, redirects, TLS, UA)
│   ├── probes/
│   │   ├── probe.go            # Probe interface + Request/Response types
│   │   ├── methods.go          # HTTP method fuzzing (GET POST PUT DELETE OPTIONS HEAD PATCH TRACE)
│   │   ├── paths.go            # Path fuzzing (admin, api/version, actuator, .env, .git, etc.)
│   │   └── headers.go          # Header manipulation (X-Forwarded-For, Host, Accept, Content-Type)
│   ├── analyzers/
│   │   ├── analyzer.go         # Analyzer interface
│   │   ├── headers.go          # Header fingerprinting (Server, X-Powered-By, X-AspNet-Version, etc.)
│   │   ├── body.go             # Body analysis (stack traces, version strings, internal paths)
│   │   └── status.go           # Status code anomalies (unexpected 200s, 500s, 403 vs 404 enum)
│   ├── findings/
│   │   └── findings.go         # Finding type + Severity (Info / Low / Medium / High / Critical)
│   └── reporter/
│       ├── terminal.go         # Colored terminal output (sorted by severity)
│       └── json.go             # JSON file output via --output flag
└── wordlists/
    └── paths.txt               # Common disclosure paths
```

---

## Probes

### Method fuzzing (`probes/methods.go`)
Send every HTTP method to the base URL: GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH, TRACE, CONNECT.
Record whether methods that should be denied (TRACE, CONNECT) return unexpected 2xx/3xx.

### Path fuzzing (`probes/paths.go`)
Try common paths likely to expose information. Wordlist in `wordlists/paths.txt`. Examples:
- `/.env`, `/.git/config`, `/backup.sql`, `/composer.json`, `/package.json`
- `/api/version`, `/actuator`, `/actuator/health`, `/actuator/env`, `/actuator/beans`
- `/server-status`, `/server-info`, `/phpinfo.php`, `/info.php`
- `/admin`, `/wp-admin`, `/wp-login.php`, `/console`, `/manager`
- `/_profiler`, `/debug`, `/telescope`, `/horizon`

### Header manipulation (`probes/headers.go`)
Re-issue the base GET with varied headers to trigger different code paths:
- Vary `Accept` (text/html vs application/json vs `*/*`)
- Add `X-Forwarded-For: 127.0.0.1` (bypass IP checks)
- Add `X-Original-URL` / `X-Rewrite-URL` (WAF bypass paths)
- Add `Content-Type: application/json` with empty body (trigger JSON error serializer)

---

## Analyzers

### Header fingerprinting (`analyzers/headers.go`)
Inspect response headers on every probe result. Flag:
- `Server` — value present (e.g. `Apache/2.4.51`)
- `X-Powered-By` — framework + version (PHP, ASP.NET, Express, etc.)
- `X-AspNet-Version`, `X-AspNetMvc-Version`
- `X-Generator`, `X-Drupal-Cache`, `X-Magento-*`, `X-Varnish`
- `Via`, `X-Cache` — proxy/CDN stack disclosure
- `X-Runtime` — Rails response time (confirms Rails)

### Body analysis (`analyzers/body.go`)
Regex scan response bodies. Flag:
- Stack traces: `at .*\(.*\.java:\d+\)`, `Traceback (most recent call last)`, `Exception in thread`, `Fatal error:`
- Version strings: `v\d+\.\d+\.\d+`, `version":`, `"version":"`
- Internal file paths: `/var/www/`, `/home/`, `C:\`, `D:\`
- Internal IPs: `192\.168\.`, `10\.`, `172\.(1[6-9]|2\d|3[01])\.`
- Framework error templates: `Whitelabel Error Page`, `Django`, `Laravel`, `Rails`, `Express`, `Spring Boot`
- Debug flags: `DEBUG=True`, `APP_DEBUG=true`, `debug: true`

### Status code analysis (`analyzers/status.go`)
Across all probe results:
- A path returning 200 that is in the "sensitive" category → High finding
- Any 500 response with a non-empty body → at least Medium (body analyzer will escalate)
- 403 vs 404 distinction for the same path family → path enumeration possible → Low
- TRACE returning 2xx → Medium (XST risk)
- OPTIONS listing unexpected methods → Low

---

## Findings

```go
type Severity int
const (
    Info     Severity = iota
    Low
    Medium
    High
    Critical
)

type Finding struct {
    Severity    Severity
    Title       string
    Description string
    Evidence    string   // the header value, snippet, etc.
    Source      string   // which probe triggered it
    URL         string
}
```

---

## CLI interface

```
Usage: status-fuzzer [flags] <url>

Flags:
  -output string     Write JSON report to this file path
  -timeout int       Per-request timeout in seconds (default 10)
  -concurrency int   Max parallel requests (default 5)
  -wordlist string   Custom path wordlist file
  -no-color          Disable colored terminal output
  -verbose           Print each request as it fires
  -skip-tls          Skip TLS certificate verification
```

---

## Build & run

```sh
go mod init github.com/vetle/status-fuzzer
go mod tidy
go build -o status-fuzzer ./...
./status-fuzzer https://example.com
./status-fuzzer -output report.json https://example.com
```

---

## Implementation order

1. [ ] `go.mod` + project skeleton
2. [ ] `internal/findings/findings.go` — core types
3. [ ] `internal/client/client.go` — HTTP client
4. [ ] `internal/probes/probe.go` + `methods.go` — method fuzzing
5. [ ] `internal/probes/paths.go` — path fuzzing + wordlist
6. [ ] `internal/probes/headers.go` — header manipulation probes
7. [ ] `internal/analyzers/` — all three analyzers
8. [ ] `internal/reporter/terminal.go` — colored output
9. [ ] `internal/reporter/json.go` — JSON file output
10. [ ] `main.go` — wire everything together
11. [ ] Manual test against a local intentionally-vulnerable app

---

## Notes

- All probes respect `concurrency` flag — use a worker pool with a semaphore channel.
- The client follows 0 redirects by default (redirects can hide information).
- TLS errors should be captured as a finding (misconfigured cert) rather than aborting.
- Findings are deduplicated by (Title + URL) before reporting.
