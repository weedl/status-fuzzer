package findings

import "fmt"

type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Info:
		return "INFO"
	case Low:
		return "LOW"
	case Medium:
		return "MEDIUM"
	case High:
		return "HIGH"
	case Critical:
		return "CRITICAL"
	default:
		return fmt.Sprintf("SEVERITY(%d)", int(s))
	}
}

type Finding struct {
	Severity    Severity
	Title       string
	Description string
	Evidence    string
	Source      string
	URL         string
}
