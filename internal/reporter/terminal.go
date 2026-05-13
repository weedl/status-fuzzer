package reporter

import (
	"fmt"
	"sort"

	"github.com/vetle/status-fuzzer/internal/findings"
)

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	gray   = "\033[90m"
	cyan   = "\033[36m"
	yellow = "\033[33m"
	red    = "\033[31m"
	bred   = "\033[1;31m"
)

func severityColor(s findings.Severity) string {
	switch s {
	case findings.Critical:
		return bred
	case findings.High:
		return red
	case findings.Medium:
		return yellow
	case findings.Low:
		return cyan
	default:
		return gray
	}
}

func PrintFindings(fs []findings.Finding, noColor bool) {
	if len(fs) == 0 {
		fmt.Println("No findings.")
		return
	}

	sort.Slice(fs, func(i, j int) bool {
		return fs[i].Severity > fs[j].Severity
	})

	if noColor {
		fmt.Printf("\n===== Found %d finding(s) =====\n\n", len(fs))
		for _, f := range fs {
			fmt.Printf("[%s] %s\n", f.Severity, f.Title)
			fmt.Printf("  URL:      %s\n", f.URL)
			fmt.Printf("  Source:   %s\n", f.Source)
			fmt.Printf("  Evidence: %s\n\n", f.Evidence)
		}
		return
	}

	fmt.Printf("\n%s===== Found %d finding(s) =====%s\n\n", bold, len(fs), reset)
	for _, f := range fs {
		col := severityColor(f.Severity)
		fmt.Printf("%s▶ [%s]%s %s%s%s\n", col, f.Severity, reset, bold, f.Title, reset)
		fmt.Printf("  %sURL:%s      %s\n", gray, reset, f.URL)
		fmt.Printf("  %sSource:%s   %s\n", gray, reset, f.Source)
		fmt.Printf("  %sEvidence:%s %s\n\n", gray, reset, f.Evidence)
	}
}
