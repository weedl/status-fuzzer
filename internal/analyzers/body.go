package analyzers

import (
	"regexp"

	"github.com/vetle/status-fuzzer/internal/findings"
	"github.com/vetle/status-fuzzer/internal/probes"
)

type BodyAnalyzer struct{}

type bodyRule struct {
	pattern  *regexp.Regexp
	severity findings.Severity
	title    string
	desc     string
}

var bodyRules = []bodyRule{
	// Stack traces
	{
		regexp.MustCompile(`at [\w\.$]+\([\w\.]+\.java:\d+\)`),
		findings.High,
		"Java stack trace in response",
		"A Java stack trace reveals internal class names, method names, and line numbers.",
	},
	{
		regexp.MustCompile(`Traceback \(most recent call last\)`),
		findings.High,
		"Python traceback in response",
		"A Python traceback reveals internal file paths and code structure.",
	},
	{
		regexp.MustCompile(`Exception in thread`),
		findings.High,
		"Java thread exception in response",
		"A Java thread exception reveals internal application details.",
	},
	{
		regexp.MustCompile(`(?i)Fatal error:`),
		findings.High,
		"PHP fatal error in response",
		"A PHP fatal error may reveal file paths and internal code details.",
	},
	// Framework fingerprints
	{
		regexp.MustCompile(`Whitelabel Error Page`),
		findings.Medium,
		"Spring Boot default error page",
		"The Spring Boot 'Whitelabel Error Page' confirms the framework in use.",
	},
	{
		regexp.MustCompile(`(?i)(?:django|python/django)`),
		findings.Low,
		"Django framework reference in response",
		"A reference to the Django framework was found in the response body.",
	},
	{
		regexp.MustCompile(`(?i)laravel`),
		findings.Low,
		"Laravel framework reference in response",
		"A reference to the Laravel framework was found in the response body.",
	},
	{
		regexp.MustCompile(`(?i)Ruby on Rails`),
		findings.Low,
		"Ruby on Rails reference in response",
		"A reference to Ruby on Rails was found in the response body.",
	},
	// Debug flags
	{
		regexp.MustCompile(`DEBUG\s*=\s*True`),
		findings.High,
		"Django debug mode active (DEBUG=True)",
		"The application has debug mode enabled, which exposes detailed error pages and internal data.",
	},
	{
		regexp.MustCompile(`(?i)APP_DEBUG\s*=\s*true`),
		findings.High,
		"Application debug mode active (APP_DEBUG=true)",
		"The application has debug mode enabled.",
	},
	{
		regexp.MustCompile(`"debug"\s*:\s*true`),
		findings.High,
		"Debug flag set in JSON response",
		"The JSON response contains \"debug\":true indicating debug mode is active.",
	},
	// Internal paths
	{
		regexp.MustCompile(`/(?:var|home|usr|etc|opt|srv|tmp)/[\w/\-\.]+`),
		findings.Medium,
		"Unix filesystem path in response",
		"An internal Unix filesystem path was found in the response body.",
	},
	{
		regexp.MustCompile(`[A-Za-z]:\\[\w\\\-\. ]+`),
		findings.Medium,
		"Windows filesystem path in response",
		"An internal Windows filesystem path was found in the response body.",
	},
	// Internal IPs
	{
		regexp.MustCompile(`\b(?:192\.168\.|10\.\d{1,3}\.|172\.(?:1[6-9]|2\d|3[01])\.)\d{1,3}\.\d{1,3}\b`),
		findings.Medium,
		"Internal IP address in response",
		"A private/internal IP address was found in the response body.",
	},
	// Version strings
	{
		regexp.MustCompile(`(?i)"version"\s*:\s*"[\d\w\.\-]+"`),
		findings.Low,
		"Version string in JSON response",
		"A version field was found in the JSON response body.",
	},
	{
		regexp.MustCompile(`\bv\d+\.\d+\.\d+\b`),
		findings.Info,
		"Semantic version number in response",
		"A semantic version string was found in the response body.",
	},
	// SQL errors
	{
		regexp.MustCompile(`(?i)You have an error in your SQL syntax`),
		findings.Critical,
		"MySQL error message in response",
		"A MySQL syntax error was returned, revealing SQL structure and the database layer.",
	},
	{
		regexp.MustCompile(`ORA-\d{4,5}:`),
		findings.Critical,
		"Oracle database error in response",
		"An Oracle database error was returned, revealing the database engine.",
	},
	{
		regexp.MustCompile(`SQLSTATE\[[\w\d]+\]`),
		findings.High,
		"SQLSTATE error code in response",
		"A SQLSTATE error code reveals the database layer and query failure details.",
	},
	// Credentials / secrets
	{
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		findings.Critical,
		"AWS access key ID in response",
		"What appears to be an AWS access key ID (AKIA...) was found in the response body.",
	},
	{
		regexp.MustCompile(`(?i)(?:password|passwd|secret|api_key|apikey)\s*[:=]\s*\S{4,}`),
		findings.Critical,
		"Credential-like pattern in response",
		"A string matching credential patterns (password=, secret=, api_key=, etc.) was found.",
	},
}

func (BodyAnalyzer) Analyze(result probes.Result) []findings.Finding {
	if result.Err != nil || len(result.Body) == 0 {
		return nil
	}
	body := string(result.Body)
	var out []findings.Finding
	for _, rule := range bodyRules {
		match := rule.pattern.FindString(body)
		if match == "" {
			continue
		}
		evidence := match
		if len(evidence) > 120 {
			evidence = evidence[:120] + "..."
		}
		out = append(out, findings.Finding{
			Severity:    rule.severity,
			Title:       rule.title,
			Description: rule.desc,
			Evidence:    evidence,
			Source:      result.Request.Label,
			URL:         result.Request.URL,
		})
	}
	return out
}
