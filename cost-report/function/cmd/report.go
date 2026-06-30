package main

import (
	"fmt"
	"sort"
	"strings"
)

// nameWidth is the fixed left-justified width of the service-name column. Long
// names are truncated so the monospace table stays aligned in Slack.
const nameWidth = 28

// ServiceLine is one row of the Top-N table: a service, its gross MTD cost, and
// its integer percentage of the gross MTD grand total.
type ServiceLine struct {
	Name    string
	Amount  float64
	Percent int
}

// ReportData is the fully-computed input to the Markdown builder. It carries no
// AWS types so the builder is testable in isolation.
type ReportData struct {
	MonthLabel        string
	CreditsAppliedMTD float64
	ForecastedGross   float64
	CreditsUsedYTD    float64
	Services          []ServiceLine
}

// formatAmount renders a value as $X.XX (two decimals, no thousands separator,
// matching the target Slack layout).
func formatAmount(v float64) string {
	return fmt.Sprintf("$%.2f", v)
}

// truncateName clips name to width runes so wide service names don't break the
// fixed-width column alignment.
func truncateName(name string, width int) string {
	r := []rune(name)
	if len(r) <= width {
		return name
	}
	return string(r[:width])
}

// ComputeServiceLines sorts services by cost descending, keeps the top `limit`,
// and computes each kept service's integer percentage of the grand total across
// ALL services (so percentages reflect true share, not just the kept subset).
func ComputeServiceLines(raw map[string]float64, limit int) ([]ServiceLine, float64) {
	var total float64
	lines := make([]ServiceLine, 0, len(raw))
	for name, amount := range raw {
		total += amount
		lines = append(lines, ServiceLine{Name: name, Amount: amount})
	}
	// Sort by amount desc; tie-break on name for deterministic output (maps are
	// unordered, so without this the report order would vary run to run).
	sort.Slice(lines, func(i, j int) bool {
		if lines[i].Amount != lines[j].Amount {
			return lines[i].Amount > lines[j].Amount
		}
		return lines[i].Name < lines[j].Name
	})
	if len(lines) > limit {
		lines = lines[:limit]
	}
	for i := range lines {
		if total > 0 {
			lines[i].Percent = int(lines[i].Amount/total*100 + 0.5)
		}
	}
	return lines, total
}

// BuildMarkdown renders ReportData into the exact Slack message shape. The
// Top-N table is a fenced code block (no header, fixed-width) so the alerter
// renders it as monospace, matching the target layout.
func BuildMarkdown(d ReportData) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# 💸 AWS Cost Report %s\n\n", d.MonthLabel)
	fmt.Fprintf(&b, "- **Credits applied (MTD):** %s\n", formatAmount(d.CreditsAppliedMTD))
	fmt.Fprintf(&b, "- **Forecasted gross:** %s\n", formatAmount(d.ForecastedGross))
	fmt.Fprintf(&b, "- **Credits used YTD:** %s\n\n", formatAmount(d.CreditsUsedYTD))
	b.WriteString("### Top 10 Services (Gross MTD)\n\n")
	b.WriteString("```\n")
	for _, s := range d.Services {
		name := truncateName(s.Name, nameWidth)
		// %-28s left-justifies the (possibly truncated) name; amount right-
		// justified in 8, percent right-justified in 5.
		fmt.Fprintf(&b, "%-*s%8s%5s\n", nameWidth, name, formatAmount(s.Amount), fmt.Sprintf("%d%%", s.Percent))
	}
	b.WriteString("```\n")
	return b.String()
}
