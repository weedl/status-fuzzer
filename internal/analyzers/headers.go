package analyzers

import (
	"fmt"
	"strings"

	"github.com/vetle/status-fuzzer/internal/findings"
	"github.com/vetle/status-fuzzer/internal/probes"
)

type HeaderAnalyzer struct{}

type headerRule struct {
	header   string
	severity findings.Severity
	title    string
	desc     string
}

var headerRules = []headerRule{
	{
		"Server", findings.Low,
		"Server header discloses software",
		"The Server header reveals the web server software and possibly its version.",
	},
	{
		"X-Powered-By", findings.Medium,
		"X-Powered-By discloses technology stack",
		"The X-Powered-By header reveals the server-side technology (e.g. PHP, ASP.NET, Express).",
	},
	{
		"X-AspNet-Version", findings.Medium,
		"ASP.NET version disclosed",
		"The X-AspNet-Version header reveals the exact .NET framework version in use.",
	},
	{
		"X-AspNetMvc-Version", findings.Medium,
		"ASP.NET MVC version disclosed",
		"The X-AspNetMvc-Version header reveals the exact ASP.NET MVC version.",
	},
	{
		"X-Generator", findings.Low,
		"X-Generator discloses CMS or framework",
		"The X-Generator header reveals the CMS or framework used to generate the page.",
	},
	{
		"X-Runtime", findings.Info,
		"X-Runtime header present (Rails fingerprint)",
		"The X-Runtime header is emitted by Ruby on Rails and confirms the framework.",
	},
	{
		"X-Varnish", findings.Info,
		"Varnish cache detected via X-Varnish",
		"The X-Varnish header reveals Varnish cache is in use.",
	},
	{
		"Via", findings.Info,
		"Proxy or CDN stack disclosed via Via header",
		"The Via header reveals intermediate proxies or CDN nodes.",
	},
	{
		"X-Cache", findings.Info,
		"Cache infrastructure disclosed via X-Cache",
		"The X-Cache header reveals caching infrastructure details.",
	},
}

// cookieFingerprints maps session cookie names to the technology they indicate.
var cookieFingerprints = map[string]string{
	"PHPSESSID":         "PHP",
	"JSESSIONID":        "Java (Servlet/JSP)",
	"ASP.NET_SessionId": "ASP.NET",
	"CFID":              "ColdFusion",
	"CFTOKEN":           "ColdFusion",
}

func (HeaderAnalyzer) Analyze(result probes.Result) []findings.Finding {
	if result.Err != nil || result.StatusCode == 0 {
		return nil
	}
	var out []findings.Finding

	for _, rule := range headerRules {
		val := result.Headers.Get(rule.header)
		if val == "" {
			continue
		}
		out = append(out, findings.Finding{
			Severity:    rule.severity,
			Title:       rule.title,
			Description: rule.desc,
			Evidence:    fmt.Sprintf("%s: %s", rule.header, val),
			Source:      result.Request.Label,
			URL:         result.Request.URL,
		})
	}

	for _, cookie := range result.Headers["Set-Cookie"] {
		for name, tech := range cookieFingerprints {
			if strings.Contains(cookie, name+"=") {
				out = append(out, findings.Finding{
					Severity:    findings.Low,
					Title:       "Technology fingerprinted via session cookie name",
					Description: fmt.Sprintf("The session cookie '%s' identifies the server-side technology as %s.", name, tech),
					Evidence:    cookie,
					Source:      result.Request.Label,
					URL:         result.Request.URL,
				})
			}
		}
	}

	return out
}
