package probes

type HeaderProbe struct{}

func (HeaderProbe) Name() string { return "header-fuzz" }

func (HeaderProbe) Requests(baseURL string) []Request {
	return []Request{
		{
			Method:  "GET",
			URL:     baseURL,
			Headers: map[string]string{"Accept": "application/json"},
			Label:   "header-fuzz:accept-json",
		},
		{
			Method:  "GET",
			URL:     baseURL,
			Headers: map[string]string{"X-Forwarded-For": "127.0.0.1"},
			Label:   "header-fuzz:x-forwarded-for",
		},
		{
			Method:  "GET",
			URL:     baseURL,
			Headers: map[string]string{"X-Original-URL": "/admin"},
			Label:   "header-fuzz:x-original-url",
		},
		{
			Method:  "GET",
			URL:     baseURL,
			Headers: map[string]string{"X-Rewrite-URL": "/admin"},
			Label:   "header-fuzz:x-rewrite-url",
		},
		{
			Method:  "POST",
			URL:     baseURL,
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    []byte("{}"),
			Label:   "header-fuzz:post-json",
		},
		{
			Method:  "GET",
			URL:     baseURL,
			Headers: map[string]string{"X-HTTP-Method-Override": "DELETE"},
			Label:   "header-fuzz:method-override",
		},
		{
			Method: "GET",
			URL:    baseURL,
			Headers: map[string]string{
				"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			},
			Label: "header-fuzz:bot-ua",
		},
	}
}
