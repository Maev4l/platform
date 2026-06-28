package query

import (
	"errors"
	"fmt"
	"strings"
)

var ErrBadGroupBy = errors.New("invalid groupBy")

// Physical Parquet column names (quoted). Centralised: fix here if a name
// differs (Task 12 verification query confirms the real names).
const (
	colDate    = `"date"`
	colIP      = `"c-ip"`
	colCountry = `"c-country"`
	colStatus  = `"sc-status"`
	colURI     = `"cs-uri-stem"`
)

// partKey converts a validated YYYY-MM-DD date to the integer composite key
// YYYYMMDD (e.g. 2026-06-14 -> 20260614). The handler validates from/to as
// strict YYYY-MM-DD before they reach the builder, so stripping dashes yields a
// safe integer literal — no injection vector.
func partKey(d string) string { return strings.ReplaceAll(d, "-", "") }

// partitionPredicate prunes scans to [from,to] using the year/month/day
// partition columns. The columns are varchar (Glue declares partition keys as
// string; projection.type=integer only governs partition enumeration, not the
// SQL type), so each is CAST to integer and combined into a YYYYMMDD key
// compared against the two inlined integer bounds (computed from validated
// dates — no positional params, no injection vector). CAST also normalises any
// zero-padding ("06" -> 6).
func partitionPredicate(from, to string) string {
	return fmt.Sprintf(`(CAST("year" AS integer) * 10000 + CAST("month" AS integer) * 100 + CAST("day" AS integer)) BETWEEN %s AND %s`, partKey(from), partKey(to))
}

func Access(table, from, to, groupBy string) (string, []string, error) {
	switch groupBy {
	case "day", "week", "month":
	default:
		return "", nil, ErrBadGroupBy
	}
	sql := fmt.Sprintf(`
SELECT date_trunc('%s', date_parse(%s, '%%Y-%%m-%%d')) AS bucket,
       count_if(%s BETWEEN '200' AND '299') AS s2,
       count_if(%s BETWEEN '300' AND '399') AS s3,
       count_if(%s BETWEEN '400' AND '499') AS s4,
       count_if(%s BETWEEN '500' AND '599') AS s5
FROM %q
WHERE %s
GROUP BY 1
ORDER BY 1`, groupBy, colDate, colStatus, colStatus, colStatus, colStatus, table, partitionPredicate(from, to))
	return sql, nil, nil
}

// GeoAllIPs aggregates request counts per client IP across the whole range
// (no country filter). The handler resolves each IP to a country via MaxMind —
// used for both the world view (aggregate by resolved country) and the
// country drill-down (keep IPs resolving to the selected country). This is
// IP-based because the c-country log field is unpopulated for these sources.
func GeoAllIPs(table, from, to string) (string, []string) {
	sql := fmt.Sprintf(`
SELECT %s AS ip, count(*) AS requests
FROM %q
WHERE %s
GROUP BY 1
ORDER BY requests DESC
LIMIT 50000`, colIP, table, partitionPredicate(from, to))
	return sql, nil
}

func Summary(table, from, to string) (string, []string) {
	sql := fmt.Sprintf(`
SELECT count(*) AS total,
       count(DISTINCT %s) AS unique_ips,
       count(DISTINCT %s) AS countries,
       count_if(%s BETWEEN '400' AND '599') AS errors
FROM %q
WHERE %s`, colIP, colCountry, colStatus, table, partitionPredicate(from, to))
	return sql, nil
}

func TopURIs(table, from, to string, limit int) (string, []string) {
	sql := fmt.Sprintf(`
SELECT %s AS uri, count(*) AS hits
FROM %q
WHERE %s
GROUP BY 1
ORDER BY hits DESC
LIMIT %d`, colURI, table, partitionPredicate(from, to), limit)
	return sql, nil
}
