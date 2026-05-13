package reporter

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/vetle/status-fuzzer/internal/findings"
)

type jsonFinding struct {
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Source      string `json:"source"`
	URL         string `json:"url"`
}

func WriteJSON(fs []findings.Finding, path string) error {
	out := make([]jsonFinding, len(fs))
	for i, f := range fs {
		out[i] = jsonFinding{
			Severity:    f.Severity.String(),
			Title:       f.Title,
			Description: f.Description,
			Evidence:    f.Evidence,
			Source:      f.Source,
			URL:         f.URL,
		}
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	fmt.Printf("JSON report written to %s\n", path)
	return nil
}
