package probes

var httpMethods = []string{
	"GET", "POST", "PUT", "DELETE", "OPTIONS",
	"HEAD", "PATCH", "TRACE", "CONNECT", "FOOBAR",
}

type MethodProbe struct{}

func (MethodProbe) Name() string { return "method-fuzz" }

func (MethodProbe) Requests(baseURL string) []Request {
	reqs := make([]Request, 0, len(httpMethods))
	for _, method := range httpMethods {
		reqs = append(reqs, Request{
			Method: method,
			URL:    baseURL,
			Label:  "method-fuzz:" + method,
		})
	}
	return reqs
}
