package query

import (
	"errors"
	"fmt"
	"strings"
)

var ErrBadGroupBy = errors.New("invalid groupBy")

// Physical Parquet column names (quoted). The CloudFront v2 Parquet uses
// UNDERSCORES (verified against a real file): date, time, c_ip, c_country, asn,
// cs_method, cs_protocol, cs_Host, cs_uri_stem, cs_uri_query, sc_status,
// x_edge_result_type, x_edge_location, cs_User_Agent.
const (
	colDate    = `"date"`
	colIP      = `"c_ip"`
	colCountry = `"c_country"`
	colStatus  = `"sc_status"`
	colURI     = `"cs_uri_stem"`
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

// GeoCountries aggregates callers + distinct IPs by the CloudFront-provided
// c_country (cheap, no MaxMind). The handler uses this first and falls back to
// IP geolocation only when it returns nothing (c_country unpopulated).
func GeoCountries(table, from, to string) (string, []string) {
	sql := fmt.Sprintf(`
SELECT %s AS country, count(*) AS callers, count(DISTINCT %s) AS ips
FROM %q
WHERE %s AND %s <> ''
GROUP BY 1
ORDER BY callers DESC`, colCountry, colIP, table, partitionPredicate(from, to), colCountry)
	return sql, nil
}

// GeoIPs aggregates request counts per IP for one c_country (drill-down when
// c_country is populated). The handler resolves each IP's coords via MaxMind.
func GeoIPs(table, from, to, country string) (string, []string) {
	sql := fmt.Sprintf(`
SELECT %s AS ip, count(*) AS requests
FROM %q
WHERE %s AND %s = ?
GROUP BY 1
ORDER BY requests DESC
LIMIT 5000`, colIP, table, partitionPredicate(from, to), colCountry)
	return sql, []string{country}
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
	// No country count here: c-country is unpopulated, so the "Countries" KPI is
	// derived client-side from the IP-resolved world geo (matching the map).
	sql := fmt.Sprintf(`
SELECT count(*) AS total,
       count(DISTINCT %s) AS unique_ips,
       count_if(%s BETWEEN '400' AND '599') AS errors
FROM %q
WHERE %s`, colIP, colStatus, table, partitionPredicate(from, to))
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
