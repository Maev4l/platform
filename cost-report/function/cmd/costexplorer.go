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
