package probes

import (
	"bufio"
	_ "embed"
	"os"
	"strings"
)

//go:embed paths.txt
var defaultPathsData string

type PathProbe struct {
	paths []string
}

func NewPathProbe(customWordlist string) (*PathProbe, error) {
	if customWordlist != "" {
		paths, err := loadWordlist(customWordlist)
		if err != nil {
			return nil, err
		}
		return &PathProbe{paths: paths}, nil
	}
	return &PathProbe{paths: parseWordlist(defaultPathsData)}, nil
}

func (p *PathProbe) Name() string { return "path-fuzz" }

func (p *PathProbe) Requests(baseURL string) []Request {
	base := strings.TrimRight(baseURL, "/")
	reqs := make([]Request, 0, len(p.paths))
	for _, path := range p.paths {
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		reqs = append(reqs, Request{
			Method: "GET",
			URL:    base + path,
			Label:  "path-fuzz:" + path,
		})
	}
	return reqs
}

func loadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, sc.Err()
}

func parseWordlist(s string) []string {
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}
