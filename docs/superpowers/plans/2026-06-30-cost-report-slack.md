# Cost Report → Slack Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a `cost-report/` Go Lambda that queries AWS Cost Explorer weekly (and on demand) and publishes a Markdown cost summary to the existing `alerting-events` SNS topic, which the `alerter` renders into Slack.

**Architecture:** `cost-report` is a *producer* on the existing alerting pipeline. A scheduled (Monday 06:00 UTC) or manually-invoked Lambda runs four Cost Explorer queries, assembles a `ReportData` struct, renders it to Markdown with a pure builder, and publishes a `notifications.Message{target:"slack", format:"markdown"}` to the topic. No Slack or rendering code lives here — the `alerter` already handles Markdown → Slack (including monospace code blocks).

**Tech Stack:** Go (arm64, zip-packaged `provided.al2023`), AWS SDK for Go v2 (costexplorer, sns, config), `github.com/aws/aws-lambda-go`, zerolog, Terraform via `github.com/Maev4l/terraform-modules`.

## Global Constraints

- Go module path: `isnan.eu/cost-report`; Go version `1.26`.
- Logging library: **zerolog** (`github.com/rs/zerolog`), not logrus.
- Shared message contract: `github.com/Maev4l/platform/notifications v1.1.0` — `Message{Target, Source, SourceDescription, Content, Format}`.
- Lambda: `architecture = "arm64"`, runtime `provided.al2023`, handler `bootstrap`. Build with `GOOS=linux GOARCH=arm64`. Terraform zip hash uses the **binary** (`filebase64sha256(".../bin/bootstrap")`), never the zip.
- Infrastructure: Terraform, region `eu-central-1`, S3 backend `global-tf-states`, AWS provider `~> 6.0`. Use only modules from `github.com/Maev4l/terraform-modules//modules/...?ref=v1.6.0`.
- Cost Explorer is global — its SDK client is pinned to `us-east-1`; the Lambda and SNS client run in `eu-central-1`.
- All monetary metrics use the `UnblendedCost` metric. "Gross" = before credits (`RECORD_TYPE = Usage`). Credits via `RECORD_TYPE = Credit` (returned negative; display absolute).
- `bin/` and `dist/` are git-ignored.
- Slack message must match this exact shape (current month label via `time.Now().UTC()` as `January 2006`):

  ```
  # 💸 AWS Cost Report June 2026

  - **Credits applied (MTD):** $4.58
  - **Forecasted gross:** $22.74
  - **Credits used YTD:** $245.53

  ### Top 10 Services (Gross MTD)

  ​```
  Simple Storage Service        $2.06   45%
  ...
  ​```
  ```

---

## File Structure

```
cost-report/
├── function/
│   ├── cmd/main.go            # handler, wiring, SNS publish, failure alert
│   ├── cmd/costexplorer.go    # CE client interface + fetchReport (4 queries)
│   ├── cmd/report.go          # ReportData types + pure Markdown builder + formatting
│   ├── cmd/report_test.go     # table-driven tests for the builder + helpers
│   ├── go.mod
│   ├── go.sum
│   ├── Makefile
│   ├── bin/                   # git-ignored (bootstrap)
│   └── dist/                  # git-ignored (cost-report.zip)
├── infrastructure/
│   ├── main.tf               # provider, backend, lambda-function + scheduler modules, SNS data source
│   ├── iam.tf                # ce + sns:Publish policy
│   ├── variables.tf
│   └── .gitignore
├── README.md
└── Makefile                  # cost-report/Makefile: build app + deploy infra + manual invoke
```

---

## Task 1: Scaffold Go module, Makefile, and build

**Files:**
- Create: `cost-report/function/go.mod`
- Create: `cost-report/function/cmd/main.go` (temporary stub, replaced in Task 4)
- Create: `cost-report/function/Makefile`
- Create: `cost-report/.gitignore`

**Interfaces:**
- Consumes: nothing.
- Produces: a buildable Go module `isnan.eu/cost-report` with `make package` producing `dist/cost-report.zip`.

- [ ] **Step 1: Create the module and add dependencies**

Run:
```bash
cd cost-report/function
go mod init isnan.eu/cost-report
go mod edit -go=1.26
go get github.com/Maev4l/platform/notifications@v1.1.0
go get github.com/aws/aws-lambda-go@v1.40.0
go get github.com/aws/aws-sdk-go-v2/config
go get github.com/aws/aws-sdk-go-v2/service/costexplorer
go get github.com/aws/aws-sdk-go-v2/service/sns
go get github.com/rs/zerolog
```

- [ ] **Step 2: Write the temporary stub handler**

Create `cost-report/function/cmd/main.go`:
```go
package main

import (
	"context"

	"github.com/aws/aws-lambda-go/lambda"
)

func handler(ctx context.Context) error {
	return nil
}

func main() {
	lambda.Start(handler)
}
```

- [ ] **Step 3: Write the Makefile**

Create `cost-report/function/Makefile`:
```makefile
# Build settings for AWS Lambda (ARM64)
GOOS := linux
GOARCH := arm64
LDFLAGS := -s -w

.PHONY: build package lint format clean

BIN_DIR := bin
PACKAGE_DIR := dist

build:
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/bootstrap ./cmd

package: build
	mkdir -p $(PACKAGE_DIR)
	cd $(BIN_DIR) && zip ../$(PACKAGE_DIR)/cost-report.zip bootstrap

lint:
	golangci-lint run ./...

format:
	golangci-lint fmt ./...

clean:
	rm -rf $(BIN_DIR) $(PACKAGE_DIR)
```

- [ ] **Step 4: Write .gitignore**

Create `cost-report/.gitignore`:
```
function/bin/
function/dist/
```

- [ ] **Step 5: Build to verify the toolchain works**

Run:
```bash
cd cost-report/function && go mod tidy && make package
```
Expected: `dist/cost-report.zip` created, no errors.

- [ ] **Step 6: Commit**

```bash
cd /Users/jrsue/dev/repos/platform
git add cost-report/function/go.mod cost-report/function/go.sum cost-report/function/cmd/main.go cost-report/function/Makefile cost-report/.gitignore
git commit -m "chore(cost-report): scaffold Go lambda module and build"
```

---

## Task 2: Report data types and Markdown builder (TDD)

**Files:**
- Create: `cost-report/function/cmd/report.go`
- Test: `cost-report/function/cmd/report_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type ServiceLine struct { Name string; Amount float64; Percent int }`
  - `type ReportData struct { MonthLabel string; CreditsAppliedMTD float64; ForecastedGross float64; CreditsUsedYTD float64; Services []ServiceLine }`
  - `func ComputeServiceLines(raw map[string]float64, limit int) (lines []ServiceLine, total float64)` — sorts services by amount desc, takes top `limit`, computes integer percent of `total` (the grand total across ALL raw services, not just the kept ones).
  - `func BuildMarkdown(d ReportData) string` — renders the exact Slack message shape.
  - `func formatAmount(v float64) string` — returns `$X.XX`.
  - `func truncateName(name string, width int) string` — truncates to `width` runes.
  - Column constant `nameWidth = 28`.

- [ ] **Step 1: Write the failing tests**

Create `cost-report/function/cmd/report_test.go`:
```go
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd cost-report/function && go test ./cmd/ -run 'TestFormatAmount|TestTruncateName|TestComputeServiceLines|TestBuildMarkdown' -v`
Expected: FAIL — undefined `formatAmount`, `truncateName`, `ComputeServiceLines`, `BuildMarkdown`, `ReportData`, `ServiceLine`.

- [ ] **Step 3: Implement report.go**

Create `cost-report/function/cmd/report.go`:
```go
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd cost-report/function && go test ./cmd/ -v`
Expected: PASS (all four tests).

- [ ] **Step 5: Commit**

```bash
cd /Users/jrsue/dev/repos/platform
git add cost-report/function/cmd/report.go cost-report/function/cmd/report_test.go
git commit -m "feat(cost-report): add report data types and markdown builder"
```

---

## Task 3: Cost Explorer fetch layer

**Files:**
- Create: `cost-report/function/cmd/costexplorer.go`
- Test: `cost-report/function/cmd/report_test.go` (append)

**Interfaces:**
- Consumes: `ReportData`, `ComputeServiceLines` from Task 2.
- Produces:
  - `type costExplorerAPI interface { GetCostAndUsage(...); GetCostForecast(...) }` (matching the SDK client method signatures).
  - `func parseAmount(s string) float64` — parses a CE amount string, returns 0 on error.
  - `func fetchReport(ctx context.Context, ce costExplorerAPI, now time.Time) (ReportData, error)` — runs the four queries against the windows below and assembles `ReportData` (services via `ComputeServiceLines(raw, 10)`). Credits are stored as absolute values.

Date windows (all `DateInterval.End` is **exclusive**), with `now` in UTC:
- `firstOfMonth = first day of now's month`; `tomorrow = now + 1 day`; `firstOfNextMonth = first day of next month`; `firstOfYear = Jan 1 of now's year`. Date format `2006-01-02`.
- Top services + gross total: `[firstOfMonth, tomorrow)`, `GroupBy SERVICE`, filter `RECORD_TYPE=Usage`.
- Credits applied MTD: `[firstOfMonth, tomorrow)`, filter `RECORD_TYPE=Credit`.
- Credits used YTD: `[firstOfYear, tomorrow)`, filter `RECORD_TYPE=Credit`.
- Forecast remainder: `GetCostForecast` over `[tomorrow, firstOfNextMonth)`. If `tomorrow >= firstOfNextMonth` (last day of month) **skip** the call and use 0. `ForecastedGross = grossMTDTotal + forecastRemainder`.

- [ ] **Step 1: Write the failing test for parseAmount**

Append to `cost-report/function/cmd/report_test.go`:
```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd cost-report/function && go test ./cmd/ -run TestParseAmount -v`
Expected: FAIL — undefined `parseAmount`.

- [ ] **Step 3: Implement costexplorer.go**

Create `cost-report/function/cmd/costexplorer.go`:
```go
package main

import (
	"context"
	"math"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
)

const (
	metricUnblended = "UnblendedCost"
	dateLayout      = "2006-01-02"
)

// costExplorerAPI is the subset of the CE client used here, declared as an
// interface so fetchReport can be exercised with a mock in tests.
type costExplorerAPI interface {
	GetCostAndUsage(ctx context.Context, in *costexplorer.GetCostAndUsageInput, optFns ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageOutput, error)
	GetCostForecast(ctx context.Context, in *costexplorer.GetCostForecastInput, optFns ...func(*costexplorer.Options)) (*costexplorer.GetCostForecastOutput, error)
}

// parseAmount parses a Cost Explorer amount string; returns 0 on any error so a
// single malformed value never aborts the whole report.
func parseAmount(s string) float64 {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return v
}

// recordTypeFilter builds a RECORD_TYPE dimension filter (e.g. "Usage", "Credit").
func recordTypeFilter(value string) *cetypes.Expression {
	return &cetypes.Expression{
		Dimensions: &cetypes.DimensionValues{
			Key:    cetypes.DimensionRecordType,
			Values: []string{value},
		},
	}
}

// sumTotals sums a single metric across all ResultsByTime[*].Total entries.
func sumTotals(results []cetypes.ResultByTime, metric string) float64 {
	var sum float64
	for _, r := range results {
		if v, ok := r.Total[metric]; ok && v.Amount != nil {
			sum += parseAmount(*v.Amount)
		}
	}
	return sum
}

// fetchReport runs the four Cost Explorer queries and assembles ReportData.
func fetchReport(ctx context.Context, ce costExplorerAPI, now time.Time) (ReportData, error) {
	now = now.UTC()
	firstOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	firstOfNextMonth := firstOfMonth.AddDate(0, 1, 0)
	firstOfYear := time.Date(now.Year(), 1, 1, 0, 0, 0, 0, time.UTC)
	tomorrow := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1)

	monthStart := firstOfMonth.Format(dateLayout)
	yearStart := firstOfYear.Format(dateLayout)
	mtdEnd := tomorrow.Format(dateLayout)

	// 1. Top services + gross MTD total (RECORD_TYPE=Usage, grouped by SERVICE).
	usage, err := ce.GetCostAndUsage(ctx, &costexplorer.GetCostAndUsageInput{
		TimePeriod:  &cetypes.DateInterval{Start: aws.String(monthStart), End: aws.String(mtdEnd)},
		Granularity: cetypes.GranularityMonthly,
		Metrics:     []string{metricUnblended},
		Filter:      recordTypeFilter("Usage"),
		GroupBy: []cetypes.GroupDefinition{
			{Type: cetypes.GroupDefinitionTypeDimension, Key: aws.String("SERVICE")},
		},
	})
	if err != nil {
		return ReportData{}, err
	}
	raw := map[string]float64{}
	for _, r := range usage.ResultsByTime {
		for _, g := range r.Groups {
			name := "Unknown"
			if len(g.Keys) > 0 {
				name = g.Keys[0]
			}
			if v, ok := g.Metrics[metricUnblended]; ok && v.Amount != nil {
				raw[name] += parseAmount(*v.Amount)
			}
		}
	}
	services, grossTotal := ComputeServiceLines(raw, 10)

	// 2. Credits applied MTD (negative in CE; store absolute).
	creditsMTD, err := ce.GetCostAndUsage(ctx, &costexplorer.GetCostAndUsageInput{
		TimePeriod:  &cetypes.DateInterval{Start: aws.String(monthStart), End: aws.String(mtdEnd)},
		Granularity: cetypes.GranularityMonthly,
		Metrics:     []string{metricUnblended},
		Filter:      recordTypeFilter("Credit"),
	})
	if err != nil {
		return ReportData{}, err
	}

	// 3. Credits used YTD.
	creditsYTD, err := ce.GetCostAndUsage(ctx, &costexplorer.GetCostAndUsageInput{
		TimePeriod:  &cetypes.DateInterval{Start: aws.String(yearStart), End: aws.String(mtdEnd)},
		Granularity: cetypes.GranularityMonthly,
		Metrics:     []string{metricUnblended},
		Filter:      recordTypeFilter("Credit"),
	})
	if err != nil {
		return ReportData{}, err
	}

	// 4. Forecast remainder (today already counted in grossTotal via end=tomorrow,
	// so forecast starts tomorrow). Skip when the month is over.
	var forecastRemainder float64
	if tomorrow.Before(firstOfNextMonth) {
		fc, ferr := ce.GetCostForecast(ctx, &costexplorer.GetCostForecastInput{
			TimePeriod:  &cetypes.DateInterval{Start: aws.String(mtdEnd), End: aws.String(firstOfNextMonth.Format(dateLayout))},
			Metric:      cetypes.MetricUnblendedCost,
			Granularity: cetypes.GranularityMonthly,
		})
		// Forecast can fail when AWS lacks enough history; degrade to 0 rather
		// than dropping the whole report.
		if ferr == nil && fc.Total != nil && fc.Total.Amount != nil {
			forecastRemainder = parseAmount(*fc.Total.Amount)
		}
	}

	return ReportData{
		MonthLabel:        now.Format("January 2006"),
		CreditsAppliedMTD: math.Abs(sumTotals(creditsMTD.ResultsByTime, metricUnblended)),
		ForecastedGross:   grossTotal + forecastRemainder,
		CreditsUsedYTD:    math.Abs(sumTotals(creditsYTD.ResultsByTime, metricUnblended)),
		Services:          services,
	}, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd cost-report/function && go test ./cmd/ -v`
Expected: PASS (including `TestParseAmount`).

- [ ] **Step 5: Commit**

```bash
cd /Users/jrsue/dev/repos/platform
git add cost-report/function/cmd/costexplorer.go cost-report/function/cmd/report_test.go
git commit -m "feat(cost-report): add cost explorer fetch layer"
```

---

## Task 4: Handler, SNS publish, and failure alert

**Files:**
- Modify: `cost-report/function/cmd/main.go` (replace the Task 1 stub entirely)

**Interfaces:**
- Consumes: `fetchReport`, `BuildMarkdown`, `ReportData` from Tasks 2–3; `notifications.Message`.
- Produces: the Lambda entrypoint. Reads env var `SNS_TOPIC_ARN`. On success publishes a `markdown` message; on any error publishes a short `plain` failure alert and returns the error.

- [ ] **Step 1: Replace main.go**

Replace the entire contents of `cost-report/function/cmd/main.go`:
```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Maev4l/platform/notifications"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	source      = "cost-report"
	ceRegion    = "us-east-1" // Cost Explorer is a global service reached via us-east-1
	failureText = "AWS Cost Report failed to generate — check CloudWatch logs for cost-report."
)

// snsPublisher is the subset of the SNS client we use (small interface keeps
// the publish path swappable/testable).
type snsPublisher interface {
	Publish(ctx context.Context, in *sns.PublishInput, optFns ...func(*sns.Options)) (*sns.PublishOutput, error)
}

// publish marshals a notifications.Message and sends it to the topic.
func publish(ctx context.Context, client snsPublisher, topicArn, content, format string) error {
	body, err := json.Marshal(notifications.Message{
		Target:            "slack",
		Source:            source,
		SourceDescription: "",
		Content:           content,
		Format:            format,
	})
	if err != nil {
		return err
	}
	_, err = client.Publish(ctx, &sns.PublishInput{
		TopicArn: aws.String(topicArn),
		Message:  aws.String(string(body)),
	})
	return err
}

func handler(ctx context.Context) error {
	topicArn := os.Getenv("SNS_TOPIC_ARN")
	if topicArn == "" {
		return fmt.Errorf("SNS_TOPIC_ARN is not set")
	}

	// Default config (eu-central-1) for SNS.
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("load aws config: %w", err)
	}
	snsClient := sns.NewFromConfig(cfg)

	// CE client pinned to us-east-1.
	ceClient := costexplorer.NewFromConfig(cfg, func(o *costexplorer.Options) {
		o.Region = ceRegion
	})

	report, err := fetchReport(ctx, ceClient, time.Now())
	if err != nil {
		log.Error().Err(err).Msg("failed to fetch cost report")
		// Surface the failure in Slack rather than failing silently.
		if perr := publish(ctx, snsClient, topicArn, failureText, "plain"); perr != nil {
			log.Error().Err(perr).Msg("failed to publish failure alert")
		}
		return err
	}

	if err := publish(ctx, snsClient, topicArn, BuildMarkdown(report), "markdown"); err != nil {
		log.Error().Err(err).Msg("failed to publish cost report")
		return err
	}

	log.Info().Str("month", report.MonthLabel).Msg("cost report published")
	return nil
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	lambda.Start(handler)
}
```

- [ ] **Step 2: Build and run all tests**

Run:
```bash
cd cost-report/function && go mod tidy && go build ./... && go test ./cmd/ -v
```
Expected: build succeeds; all tests PASS.

- [ ] **Step 3: Verify the package builds**

Run: `cd cost-report/function && make package`
Expected: `dist/cost-report.zip` produced.

- [ ] **Step 4: Commit**

```bash
cd /Users/jrsue/dev/repos/platform
git add cost-report/function/cmd/main.go cost-report/function/go.mod cost-report/function/go.sum
git commit -m "feat(cost-report): add lambda handler with sns publish and failure alert"
```

---

## Task 5: Infrastructure (Terraform)

**Files:**
- Create: `cost-report/infrastructure/variables.tf`
- Create: `cost-report/infrastructure/main.tf`
- Create: `cost-report/infrastructure/iam.tf`
- Create: `cost-report/infrastructure/.gitignore`

**Interfaces:**
- Consumes: `dist/cost-report.zip` + `bin/bootstrap` from the function build; the existing `alerting-events` SNS topic.
- Produces: deployed Lambda `platform-cost-report` with a weekly schedule and CE/SNS permissions.

- [ ] **Step 1: Write variables.tf**

Create `cost-report/infrastructure/variables.tf`:
```hcl
variable "region" {
  description = "AWS region"
  type        = string
  default     = "eu-central-1"
}
```

- [ ] **Step 2: Write .gitignore**

Create `cost-report/infrastructure/.gitignore`:
```
.terraform/
.terraform.lock.hcl
*.tfstate
*.tfstate.*
```

- [ ] **Step 3: Write iam.tf**

Create `cost-report/infrastructure/iam.tf`:
```hcl
# Cost Explorer is a global (resource-less) API — ce:* actions only support "*".
# sns:Publish is scoped to the alerting topic.
data "aws_iam_policy_document" "cost_report" {
  statement {
    sid    = "CostExplorerRead"
    effect = "Allow"
    actions = [
      "ce:GetCostAndUsage",
      "ce:GetCostForecast",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "PublishAlert"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [data.aws_sns_topic.alerting.arn]
  }
}

resource "aws_iam_policy" "cost_report" {
  name        = "platform-cost-report-policy"
  description = "Allow cost-report Lambda to read Cost Explorer and publish alerts"
  policy      = data.aws_iam_policy_document.cost_report.json
}
```

- [ ] **Step 4: Write main.tf**

Create `cost-report/infrastructure/main.tf`:
```hcl
terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  backend "s3" {
    bucket       = "global-tf-states"
    key          = "platform/cost-report.tfstate"
    region       = "eu-central-1"
    use_lockfile = true
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      application = "platform-cost-report"
      owner       = "terraform"
    }
  }
}

# Existing alerting pipeline topic this Lambda publishes to.
data "aws_sns_topic" "alerting" {
  name = "alerting-events"
}

module "cost_report_function" {
  source        = "github.com/Maev4l/terraform-modules//modules/lambda-function?ref=v1.6.0"
  function_name = "platform-cost-report"
  zip = {
    filename = "../function/dist/cost-report.zip"
    runtime  = "provided.al2023"
    handler  = "bootstrap"
    hash     = filebase64sha256("../function/bin/bootstrap")
  }
  architecture = "arm64"

  environment_variables = {
    "SNS_TOPIC_ARN" : data.aws_sns_topic.alerting.arn
  }

  additional_policy_arns = [aws_iam_policy.cost_report.arn]
}

module "weekly_schedule" {
  source = "github.com/Maev4l/terraform-modules//modules/lambda-trigger-scheduler?ref=v1.6.0"

  function_name = module.cost_report_function.function_name
  function_arn  = module.cost_report_function.function_arn

  schedule_name        = "platform-cost-report-weekly"
  description          = "Weekly AWS cost report to Slack (Monday 06:00 UTC)"
  schedule_expression  = "cron(0 6 ? * MON *)"
  timezone             = "UTC"
  flexible_time_window = 0
}
```

- [ ] **Step 5: Validate the Terraform**

Run:
```bash
cd cost-report/function && make package && cd ../infrastructure && terraform init && terraform validate
```
Expected: `Success! The configuration is valid.`

Note: requires AWS credentials + the `alerting-events` topic to exist for `terraform plan`/`apply`; `validate` alone needs only `init`.

- [ ] **Step 6: Commit**

```bash
cd /Users/jrsue/dev/repos/platform
git add cost-report/infrastructure/variables.tf cost-report/infrastructure/main.tf cost-report/infrastructure/iam.tf cost-report/infrastructure/.gitignore
git commit -m "feat(cost-report): add terraform infrastructure with weekly schedule"
```

---

## Task 6: cost-report/Makefile, README, and manual-invoke target

**Files:**
- Create: `cost-report/Makefile` (in the `cost-report/` folder, NOT the repo root)
- Create: `cost-report/README.md`

**Interfaces:**
- Consumes: the function build + infrastructure from prior tasks.
- Produces: build/deploy/invoke make targets and documentation.

- [ ] **Step 1: Write the Makefile**

Located at `cost-report/Makefile` and run from inside `cost-report/` (its
`function`/`infrastructure` paths are relative to that folder). Mirrors
`monitoring/Makefile` — delegates to the function Makefile via `make -C` and
drives Terraform via `terraform -chdir=`, per the no-yarn-workspaces rule.

Create `cost-report/Makefile`:
```makefile
.PHONY: build deploy invoke infra-plan infra-apply infra-output clean

FUNCTION := function
INFRA    := infrastructure

# Build the Lambda zip (delegates to the function Makefile).
build:
	$(MAKE) -C $(FUNCTION) package

# Full deploy: build the zip, then apply the infra.
deploy: build infra-apply

infra-plan:
	terraform -chdir=$(INFRA) plan

infra-apply:
	terraform -chdir=$(INFRA) apply -auto-approve

infra-output:
	terraform -chdir=$(INFRA) output -json

# Manually trigger the report (writes the Lambda response to stdout).
invoke:
	aws lambda invoke --function-name platform-cost-report --region eu-central-1 /dev/stdout

clean:
	$(MAKE) -C $(FUNCTION) clean
```

- [ ] **Step 2: Write README.md**

Create `cost-report/README.md`:
```markdown
# Cost Report

Weekly AWS Cost Explorer summary delivered to Slack via the shared
`alerting-events` pipeline. Runs every Monday 06:00 UTC and on demand.

## How it works

A Go Lambda (`platform-cost-report`) queries Cost Explorer, renders a Markdown
summary, and publishes a `notifications.Message{target:"slack", format:"markdown"}`
to the `alerting-events` SNS topic. The `alerter` Lambda renders it to Slack.

## Metrics

All amounts use the `UnblendedCost` metric. MTD = month-to-date, YTD = year-to-date,
gross = before credits.

| Line                    | Source                                                                   |
| ----------------------- | ------------------------------------------------------------------------ |
| Credits applied (MTD)   | `GetCostAndUsage`, current month, `RECORD_TYPE=Credit` (absolute value)  |
| Forecasted gross        | gross MTD usage + `GetCostForecast` for the remainder of the month       |
| Credits used YTD        | `GetCostAndUsage`, Jan 1 → today, `RECORD_TYPE=Credit` (absolute value)  |
| Top 10 Services (gross) | `GetCostAndUsage`, current month, grouped by SERVICE, `RECORD_TYPE=Usage` |

## AWS prerequisites (one-time)

1. Enable **Cost Explorer** in the Billing console (~24h to backfill data).
2. The Cost Explorer API bills **$0.01 per request** (~4 requests per run).

## Deploy

```bash
make deploy
```

## Manual trigger

```bash
make invoke
```
```

- [ ] **Step 3: Commit**

```bash
cd /Users/jrsue/dev/repos/platform
git add cost-report/Makefile cost-report/README.md
git commit -m "docs(cost-report): add root makefile and readme"
```

---

## Final verification

- [ ] **Build, lint, and test the function**

Run:
```bash
cd cost-report/function && go build ./... && go test ./cmd/ -v && golangci-lint run ./... && gofmt -l .
```
Expected: build OK, tests PASS, lint clean, `gofmt -l .` prints nothing.

- [ ] **Validate infrastructure**

Run: `cd cost-report/infrastructure && terraform validate`
Expected: configuration valid.

- [ ] **Deploy and smoke-test (requires AWS credentials + Cost Explorer enabled)**

Run:
```bash
cd cost-report && make deploy && make invoke
```
Expected: Lambda returns null/no error; the cost report appears in the Slack channel.
