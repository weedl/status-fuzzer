package analyzers

import (
	"github.com/vetle/status-fuzzer/internal/findings"
	"github.com/vetle/status-fuzzer/internal/probes"
)

// Analyzer inspects a single probe Result and returns any findings.
type Analyzer interface {
	Analyze(result probes.Result) []findings.Finding
}
