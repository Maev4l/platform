package main

import (
	"strings"
	"testing"
)

func TestFormatAmount(t *testing.T) {
	cases := map[float64]string{
		2.06:  "$2.06",
		0:     "$0.00",
		22.7:  "$22.70",
		245.5: "$245.50",
	}
	for in, want := range cases {
		if got := formatAmount(in); got != want {
			t.Errorf("formatAmount(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestComputeServiceLinesDropsZeroCost(t *testing.T) {
	raw := map[string]map[string]float64{
		"Simple Storage Service": {"TimedStorage-ByteHrs": 2.00},
		"Key Management Service": {"KMS-Keys": 1.00},
		"Zero Service":           {"z": 0},     // exactly $0.00 → dropped
		"Tiny Service":           {"t": 0.004}, // rounds to $0.00 → dropped
	}
	lines, total := ComputeServiceLines(raw, 10, 3)

	if len(lines) != 2 {
		t.Fatalf("expected 2 non-zero lines, got %d: %+v", len(lines), lines)
	}
	for _, l := range lines {
		if l.Name == "Zero Service" || l.Name == "Tiny Service" {
			t.Errorf("zero-cost service %q should have been dropped", l.Name)
		}
	}
	// total still includes the dropped services' (negligible) cost.
	if total < 3.0 || total > 3.01 {
		t.Errorf("total = %v, want ~3.004 (grand total including dropped)", total)
	}
}

func TestComputeServiceLinesUsageBreakdown(t *testing.T) {
	raw := map[string]map[string]float64{
		"Amazon Virtual Private Cloud": {
			"NatGateway-Hours":  1.20,
			"NatGateway-Bytes":  0.45,
			"VpcEndpoint-Hours": 0.14,
			"PublicIPv4":        0.10, // 4th-largest → dropped by usageLimit=3
			"ZeroUsage":         0,    // $0.00 → dropped
		},
	}
	lines, _ := ComputeServiceLines(raw, 10, 3)

	if len(lines) != 1 {
		t.Fatalf("expected 1 service, got %d", len(lines))
	}
	s := lines[0]
	// service total = sum of ALL its usage types (incl. the dropped sub-rows)
	if s.Amount < 1.88 || s.Amount > 1.90 {
		t.Errorf("service total = %v, want ~1.89", s.Amount)
	}
	// top 3 usage types, $0.00 dropped, sorted descending
	if len(s.Usages) != 3 {
		t.Fatalf("expected 3 usage rows, got %d: %+v", len(s.Usages), s.Usages)
	}
	wantOrder := []string{"NatGateway-Hours", "NatGateway-Bytes", "VpcEndpoint-Hours"}
	for i, w := range wantOrder {
		if s.Usages[i].Name != w {
			t.Errorf("usage[%d] = %q, want %q", i, s.Usages[i].Name, w)
		}
	}
	for _, u := range s.Usages {
		if u.Name == "ZeroUsage" {
			t.Errorf("$0.00 usage type should have been dropped")
		}
	}
}

func TestCleanUsageType(t *testing.T) {
	cases := map[string]string{
		"EUC1-NatGateway-Hours":     "NatGateway-Hours",       // region code stripped
		"EU-DataTransfer-Out-Bytes": "DataTransfer-Out-Bytes", // short region code
		"USE1-BoxUsage:t4g.small":   "BoxUsage:t4g.small",     // colon/dot preserved
		"Requests-Tier1":            "Requests-Tier1",         // no region prefix (lowercase) → unchanged
		"TimedStorage-ByteHrs":      "TimedStorage-ByteHrs",   // unchanged
		"NoDash":                    "NoDash",                 // no dash → unchanged
	}
	for in, want := range cases {
		if got := cleanUsageType(in); got != want {
			t.Errorf("cleanUsageType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildMarkdownShowsFullServiceNames(t *testing.T) {
	// Regression: names longer than the old 28-char cap must NOT be truncated,
	// and the amount column must stay aligned across rows of differing name length.
	d := ReportData{
		MonthLabel: "June 2026",
		Services: []ServiceLine{
			{Name: "Amazon Elastic Container Service", Amount: 5.00, Percent: 50},
			{Name: "Amazon S3", Amount: 5.00, Percent: 50},
		},
	}
	got := BuildMarkdown(d)

	for _, name := range []string{"Amazon Elastic Container Service", "Amazon S3"} {
		if !strings.Contains(got, name) {
			t.Errorf("service name truncated/missing: %q\n--- got ---\n%s", name, got)
		}
	}

	// Both rows carry "$5.00"; with the name column padded to the longest name,
	// the amount must start at the same column offset on every row.
	var rows []string
	for _, l := range strings.Split(got, "\n") {
		if strings.Contains(l, "$5.00") {
			rows = append(rows, l)
		}
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 data rows, got %d:\n%s", len(rows), got)
	}
	if strings.Index(rows[0], "$5.00") != strings.Index(rows[1], "$5.00") {
		t.Errorf("amount columns not aligned:\n%q\n%q", rows[0], rows[1])
	}
}

func TestComputeServiceLines(t *testing.T) {
	raw := map[string]map[string]float64{
		"Simple Storage Service": {"TimedStorage-ByteHrs": 2.06},
		"Key Management Service": {"KMS-Keys": 1.08},
		"EC2 - Other":            {"NatGateway-Hours": 0.59},
	}
	lines, total := ComputeServiceLines(raw, 2, 3)
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	// total is the grand total across ALL services, not just kept ones.
	if total < 3.72 || total > 3.74 {
		t.Errorf("total = %v, want ~3.73", total)
	}
	// sorted descending by amount
	if lines[0].Name != "Simple Storage Service" || lines[1].Name != "Key Management Service" {
		t.Errorf("wrong order: %+v", lines)
	}
	// percent is integer share of grand total: 2.06/3.73 = 55%
	if lines[0].Percent != 55 {
		t.Errorf("line[0].Percent = %d, want 55", lines[0].Percent)
	}
	// 1.08/3.73 = 28.95% → rounds to 29
	if lines[1].Percent != 29 {
		t.Errorf("line[1].Percent = %d, want 29", lines[1].Percent)
	}
}

func TestBuildMarkdown(t *testing.T) {
	d := ReportData{
		MonthLabel:        "June 2026",
		CreditsAppliedMTD: 4.58,
		ForecastedGross:   22.74,
		CreditsUsedYTD:    245.53,
		Services: []ServiceLine{
			{Name: "Simple Storage Service", Amount: 2.06, Percent: 45},
			{Name: "Key Management Service", Amount: 1.08, Percent: 23},
		},
	}
	got := BuildMarkdown(d)

	wantContains := []string{
		"# 💸 AWS Cost Report June 2026",
		"- **Credits applied (MTD):** $4.58",
		"- **Forecasted gross:** $22.74",
		"- **Credits used YTD:** $245.53",
		"### Top 10 Services (Gross MTD)",
		"```",
		"Simple Storage Service", // service name appears in the table
		"$2.06",
		"45%",
	}
	for _, w := range wantContains {
		if !strings.Contains(got, w) {
			t.Errorf("BuildMarkdown missing %q\n--- got ---\n%s", w, got)
		}
	}
	// the table must be wrapped in a fenced code block (open + close)
	if strings.Count(got, "```") != 2 {
		t.Errorf("expected exactly one fenced code block, got %d fences", strings.Count(got, "```"))
	}
}

func TestBuildMarkdownRendersUsageBreakdown(t *testing.T) {
	d := ReportData{
		MonthLabel: "June 2026",
		Services: []ServiceLine{
			{
				Name: "Amazon Virtual Private Cloud", Amount: 1.79, Percent: 23,
				Usages: []UsageLine{
					{Name: "NatGateway-Hours", Amount: 1.20},
					{Name: "NatGateway-Bytes", Amount: 0.45},
				},
			},
		},
	}
	got := BuildMarkdown(d)

	// usage sub-rows appear, indented under the service
	if !strings.Contains(got, "    NatGateway-Hours") {
		t.Errorf("missing indented usage row:\n%s", got)
	}
	// the usage amount aligns with the service amount column
	var svcRow, usageRow string
	for _, l := range strings.Split(got, "\n") {
		if strings.Contains(l, "$1.79") {
			svcRow = l
		}
		if strings.Contains(l, "$1.20") {
			usageRow = l
		}
	}
	if svcRow == "" || usageRow == "" {
		t.Fatalf("expected service and usage rows:\n%s", got)
	}
	if strings.Index(svcRow, "$1.79") != strings.Index(usageRow, "$1.20") {
		t.Errorf("usage amount not aligned with service amount:\n%q\n%q", svcRow, usageRow)
	}
}

func TestParseAmount(t *testing.T) {
	if got := parseAmount("2.06"); got != 2.06 {
		t.Errorf("parseAmount(\"2.06\") = %v", got)
	}
	if got := parseAmount("-4.58"); got != -4.58 {
		t.Errorf("parseAmount(\"-4.58\") = %v", got)
	}
	if got := parseAmount("not-a-number"); got != 0 {
		t.Errorf("parseAmount(bad) = %v, want 0", got)
	}
}
