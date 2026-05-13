package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/vetle/status-fuzzer/internal/analyzers"
	"github.com/vetle/status-fuzzer/internal/client"
	"github.com/vetle/status-fuzzer/internal/findings"
	"github.com/vetle/status-fuzzer/internal/probes"
	"github.com/vetle/status-fuzzer/internal/reporter"
)

func main() {
	var (
		output      = flag.String("output", "", "write JSON report to this file")
		timeout     = flag.Int("timeout", 10, "per-request timeout in seconds")
		concurrency = flag.Int("concurrency", 5, "max parallel requests")
		wordlist    = flag.String("wordlist", "", "custom path wordlist file (default: embedded)")
		noColor     = flag.Bool("no-color", false, "disable colored terminal output")
		verbose     = flag.Bool("verbose", false, "print each request as it fires")
		skipTLS     = flag.Bool("skip-tls", false, "skip TLS certificate verification")
	)
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: status-fuzzer [flags] <url>")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	target := flag.Arg(0)
	if _, err := url.ParseRequestURI(target); err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid URL %q: %v\n", target, err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	c := client.New(client.Config{
		Timeout: time.Duration(*timeout) * time.Second,
		SkipTLS: *skipTLS,
	})

	pathProbe, err := probes.NewPathProbe(*wordlist)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading wordlist: %v\n", err)
		os.Exit(1)
	}

	allProbes := []probes.Probe{
		probes.MethodProbe{},
		pathProbe,
		probes.HeaderProbe{},
	}

	var requests []probes.Request
	for _, p := range allProbes {
		requests = append(requests, p.Requests(target)...)
	}

	fmt.Printf("Target:      %s\n", target)
	fmt.Printf("Requests:    %d\n", len(requests))
	fmt.Printf("Concurrency: %d\n\n", *concurrency)

	sem := make(chan struct{}, *concurrency)
	var mu sync.Mutex
	var allResults []probes.Result
	var wg sync.WaitGroup

	for _, req := range requests {
		req := req
		select {
		case <-ctx.Done():
			break
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if *verbose {
				fmt.Printf("  → %-8s %s\n", req.Method, req.URL)
			}
			result := c.Execute(ctx, req)
			if *verbose && result.StatusCode != 0 {
				fmt.Printf("  ← %-8s %d\n", req.Method, result.StatusCode)
			}
			mu.Lock()
			allResults = append(allResults, result)
			mu.Unlock()
		}()
	}
	wg.Wait()

	analyzerList := []analyzers.Analyzer{
		analyzers.HeaderAnalyzer{},
		analyzers.BodyAnalyzer{},
		analyzers.StatusAnalyzer{},
	}

	seen := map[string]bool{}
	var allFindings []findings.Finding
	for _, result := range allResults {
		for _, a := range analyzerList {
			for _, f := range a.Analyze(result) {
				key := f.Title + "|" + f.URL
				if !seen[key] {
					seen[key] = true
					allFindings = append(allFindings, f)
				}
			}
		}
	}

	reporter.PrintFindings(allFindings, *noColor)

	if *output != "" {
		if err := reporter.WriteJSON(allFindings, *output); err != nil {
			fmt.Fprintf(os.Stderr, "error writing JSON report: %v\n", err)
			os.Exit(1)
		}
	}
}
