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

// partitionPredicate prunes scans to [from,to] using the integer-projected
// year/month/day partition columns: (year*10000 + month*100 + day) compared
// against the two integer keys. Bounds are inlined computed integers (not
// positional params) — this avoids the varchar/integer ambiguity that bare
// `?` date parameters hit, and works regardless of zero-padding because the
// projection presents year/month/day as integers.
func partitionPredicate(from, to string) string {
	return fmt.Sprintf(`("year" * 10000 + "month" * 100 + "day") BETWEEN %s AND %s`, partKey(from), partKey(to))
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

func GeoCountries(table, from, to string) (string, []string) {
	sql := fmt.Sprintf(`
SELECT %s AS country, count(*) AS callers, count(DISTINCT %s) AS ips
FROM %q
WHERE %s AND %s <> ''
GROUP BY 1
ORDER BY callers DESC`, colCountry, colIP, table, partitionPredicate(from, to), colCountry)
	return sql, nil
}

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
