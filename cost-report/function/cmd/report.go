package main

import (
	"fmt"
	"sort"
	"strings"
)

// UsageLine is one usage-type sub-row under a service (e.g. "NatGateway-Hours").
// Usage types carry no percentage — only the parent service does.
type UsageLine struct {
	Name   string
	Amount float64
}

// ServiceLine is one row of the Top-N table: a service, its gross MTD cost, its
// integer percentage of the gross MTD grand total, and its top usage-type
// sub-rows (what is actually driving that service's cost).
type ServiceLine struct {
	Name    string
	Amount  float64
	Percent int
	Usages  []UsageLine
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

// ComputeServiceLines turns the per-service / per-usage-type cost map into the
// display rows. For each service it sums its usage types, drops services whose
// total rounds to $0.00 (negligible clutter), sorts services by cost descending,
// and keeps the top `limit`. Within each kept service it sorts usage types
// descending, drops $0.00 usage types, and keeps the top `usageLimit`. Each
// service's percentage is its share of the grand total across ALL services. The
// returned total is that full grand total (INCLUDING dropped near-zero services),
// so percentages reflect true share and callers can use it as the accurate
// gross-MTD base.
func ComputeServiceLines(raw map[string]map[string]float64, limit, usageLimit int) ([]ServiceLine, float64) {
	var total float64
	lines := make([]ServiceLine, 0, len(raw))
	for service, usages := range raw {
		var svcTotal float64
		for _, amt := range usages {
			svcTotal += amt
		}
		total += svcTotal
		// Skip services that display as $0.00 — kept out of the rows but still
		// counted in `total` above so the gross base stays accurate.
		if formatAmount(svcTotal) == "$0.00" {
			continue
		}
		lines = append(lines, ServiceLine{
			Name:   service,
			Amount: svcTotal,
			Usages: topUsages(usages, usageLimit),
		})
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

// topUsages sorts a service's usage types by cost descending (name tie-break for
// determinism), drops those that display as $0.00, and returns the top `limit`.
func topUsages(usages map[string]float64, limit int) []UsageLine {
	ul := make([]UsageLine, 0, len(usages))
	for name, amount := range usages {
		if formatAmount(amount) == "$0.00" {
			continue
		}
		ul = append(ul, UsageLine{Name: name, Amount: amount})
	}
	sort.Slice(ul, func(i, j int) bool {
		if ul[i].Amount != ul[j].Amount {
			return ul[i].Amount > ul[j].Amount
		}
		return ul[i].Name < ul[j].Name
	})
	if len(ul) > limit {
		ul = ul[:limit]
	}
	return ul
}

// BuildMarkdown renders ReportData into the exact Slack message shape. The
// Top-N table is a fenced code block (no header) so the alerter renders it as
// monospace. Service names are shown IN FULL (no truncation); the name column is
// padded to the longest name so the amount/percent columns stay aligned.
func BuildMarkdown(d ReportData) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# 💸 AWS Cost Report %s\n\n", d.MonthLabel)
	fmt.Fprintf(&b, "- **Credits applied (MTD):** %s\n", formatAmount(d.CreditsAppliedMTD))
	fmt.Fprintf(&b, "- **Forecasted gross:** %s\n", formatAmount(d.ForecastedGross))
	fmt.Fprintf(&b, "- **Credits used YTD:** %s\n\n", formatAmount(d.CreditsUsedYTD))
	b.WriteString("### Top 10 Services (Gross MTD)\n\n")
	b.WriteString("```\n")
	const indent = "    " // usage-type sub-rows are indented under their service
	// Width of the name column = the widest of all service names and indented
	// usage names, so every amount starts at the same offset across service and
	// usage rows alike. AWS names are ASCII, so byte width (%-*s) == rune width.
	nameCol := 0
	for _, s := range d.Services {
		if n := len(s.Name); n > nameCol {
			nameCol = n
		}
		for _, u := range s.Usages {
			if n := len(indent) + len(u.Name); n > nameCol {
				nameCol = n
			}
		}
	}
	for _, s := range d.Services {
		// Service row: name left-justified to nameCol, amount right-justified in
		// 8 (guarantees a gap after the longest name), percent in 5.
		fmt.Fprintf(&b, "%-*s%8s%5s\n", nameCol, s.Name, formatAmount(s.Amount), fmt.Sprintf("%d%%", s.Percent))
		// Usage sub-rows: indented name, amount aligned to the same column, no percent.
		for _, u := range s.Usages {
			fmt.Fprintf(&b, "%-*s%8s\n", nameCol, indent+u.Name, formatAmount(u.Amount))
		}
	}
	b.WriteString("```\n")
	return b.String()
}
