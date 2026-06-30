package main

import (
	"context"
	"math"
	"strconv"
	"strings"
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

// cleanUsageType strips the leading AWS region code from a USAGE_TYPE value so
// the Slack report shows the readable part. CE usage types are region-prefixed,
// e.g. "EUC1-NatGateway-Hours" -> "NatGateway-Hours", "EU-DataTransfer-Out-Bytes"
// -> "DataTransfer-Out-Bytes". Values without a region prefix (e.g.
// "Requests-Tier1", "TimedStorage-ByteHrs", or no dash at all) are left as-is.
func cleanUsageType(s string) string {
	i := strings.IndexByte(s, '-')
	if i <= 0 {
		return s
	}
	if isRegionCode(s[:i]) {
		return s[i+1:]
	}
	return s
}

// isRegionCode reports whether prefix looks like a CE region code: at least two
// chars, all uppercase letters or digits (e.g. "EU", "EUC1", "USE1", "APN1").
// Region codes are uppercase-only, so any lowercase rules a segment out.
func isRegionCode(prefix string) bool {
	if len(prefix) < 2 {
		return false
	}
	for _, r := range prefix {
		if !((r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
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

	// 1. Top services + per-service usage-type breakdown + gross MTD total
	// (RECORD_TYPE=Usage, grouped by SERVICE then USAGE_TYPE). Grouping by two
	// dimensions can return many rows, so page through NextPageToken.
	usageInput := &costexplorer.GetCostAndUsageInput{
		TimePeriod:  &cetypes.DateInterval{Start: aws.String(monthStart), End: aws.String(mtdEnd)},
		Granularity: cetypes.GranularityMonthly,
		Metrics:     []string{metricUnblended},
		Filter:      recordTypeFilter("Usage"),
		GroupBy: []cetypes.GroupDefinition{
			{Type: cetypes.GroupDefinitionTypeDimension, Key: aws.String("SERVICE")},
			{Type: cetypes.GroupDefinitionTypeDimension, Key: aws.String("USAGE_TYPE")},
		},
	}
	raw := map[string]map[string]float64{}
	for {
		usage, err := ce.GetCostAndUsage(ctx, usageInput)
		if err != nil {
			return ReportData{}, err
		}
		for _, r := range usage.ResultsByTime {
			for _, g := range r.Groups {
				if len(g.Keys) < 2 {
					continue
				}
				service := g.Keys[0]
				usageType := cleanUsageType(g.Keys[1])
				v, ok := g.Metrics[metricUnblended]
				if !ok || v.Amount == nil {
					continue
				}
				if raw[service] == nil {
					raw[service] = map[string]float64{}
				}
				raw[service][usageType] += parseAmount(*v.Amount)
			}
		}
		if usage.NextPageToken == nil || *usage.NextPageToken == "" {
			break
		}
		usageInput.NextPageToken = usage.NextPageToken
	}
	services, grossTotal := ComputeServiceLines(raw, 10, 3)

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
	// so forecast starts tomorrow). Skip when the month is over (tomorrow >= firstOfNextMonth).
	var forecastRemainder float64
	if tomorrow.Before(firstOfNextMonth) {
		fc, ferr := ce.GetCostForecast(ctx, &costexplorer.GetCostForecastInput{
			TimePeriod:  &cetypes.DateInterval{Start: aws.String(mtdEnd), End: aws.String(firstOfNextMonth.Format(dateLayout))},
			Metric:      cetypes.MetricUnblendedCost,
			Granularity: cetypes.GranularityMonthly,
		})
		// Forecast can fail when AWS lacks enough history; degrade to 0 rather
		// than dropping the whole report.
		if ferr == nil && fc != nil && fc.Total != nil && fc.Total.Amount != nil {
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
