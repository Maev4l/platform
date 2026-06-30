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

func TestTruncateName(t *testing.T) {
	if got := truncateName("EC2 Container Registry (Amazon ECR)", 28); got != "EC2 Container Registry (Amaz" {
		t.Errorf("truncateName long = %q", got)
	}
	if got := truncateName("CloudFront", 28); got != "CloudFront" {
		t.Errorf("truncateName short = %q", got)
	}
}

func TestComputeServiceLines(t *testing.T) {
	raw := map[string]float64{
		"Simple Storage Service": 2.06,
		"Key Management Service": 1.08,
		"EC2 - Other":            0.59,
	}
	lines, total := ComputeServiceLines(raw, 2)
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
