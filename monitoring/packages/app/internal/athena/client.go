package athena

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	atypes "github.com/aws/aws-sdk-go-v2/service/athena/types"
)

// AthenaAPI is the subset of the AWS Athena SDK we depend on.
// Keeping it narrow lets tests inject a fake without pulling in live AWS machinery.
type AthenaAPI interface {
	StartQueryExecution(context.Context, *athena.StartQueryExecutionInput, ...func(*athena.Options)) (*athena.StartQueryExecutionOutput, error)
	GetQueryExecution(context.Context, *athena.GetQueryExecutionInput, ...func(*athena.Options)) (*athena.GetQueryExecutionOutput, error)
	GetQueryResults(context.Context, *athena.GetQueryResultsInput, ...func(*athena.Options)) (*athena.GetQueryResultsOutput, error)
}

// Querier is the domain interface consumed by other packages.
type Querier interface {
	Query(ctx context.Context, sql string, args []string) ([]map[string]string, error)
}

// Client wraps AthenaAPI and carries the fixed database/workgroup for all queries.
type Client struct {
	api       AthenaAPI
	database  string
	workgroup string
}

// New returns a ready-to-use Client bound to the given database and workgroup.
func New(api AthenaAPI, database, workgroup string) *Client {
	return &Client{api: api, database: database, workgroup: workgroup}
}

// Query runs sql (with optional positional args via ExecutionParameters), waits for
// completion using exponential backoff, and returns rows as []map[string]string keyed
// by column name. The first result row (header) is consumed internally and not returned.
func (c *Client) Query(ctx context.Context, sql string, args []string) ([]map[string]string, error) {
	// Athena substitutes ExecutionParameters into the `?` placeholders literally,
	// so string values must be passed as quoted SQL string literals (a bare
	// 2026-06-14 would be read as integer arithmetic, and FR as an identifier).
	// All our positional args are strings, so quote each (escaping embedded ').
	params := make([]string, len(args))
	for i, a := range args {
		params[i] = "'" + strings.ReplaceAll(a, "'", "''") + "'"
	}
	start, err := c.api.StartQueryExecution(ctx, &athena.StartQueryExecutionInput{
		QueryString:           aws.String(sql),
		WorkGroup:             aws.String(c.workgroup),
		QueryExecutionContext: &atypes.QueryExecutionContext{Database: aws.String(c.database)},
		ExecutionParameters:   params,
	})
	if err != nil {
		return nil, fmt.Errorf("start query: %w", err)
	}
	id := start.QueryExecutionId
	// Guard against nil execution ID from SDK (not guaranteed to be non-nil).
	if id == nil {
		return nil, fmt.Errorf("start query: no execution id returned")
	}

	// Poll with exponential backoff (200 ms → 2 s cap) until terminal state.
	backoff := 200 * time.Millisecond
	for {
		ex, err := c.api.GetQueryExecution(ctx, &athena.GetQueryExecutionInput{QueryExecutionId: id})
		if err != nil {
			return nil, fmt.Errorf("poll query: %w", err)
		}
		// Guard against nil QueryExecution or Status from SDK (not guaranteed to be non-nil).
		if ex.QueryExecution == nil || ex.QueryExecution.Status == nil {
			return nil, fmt.Errorf("poll query: empty execution status")
		}
		switch ex.QueryExecution.Status.State {
		case atypes.QueryExecutionStateSucceeded:
			return c.fetch(ctx, id)
		case atypes.QueryExecutionStateFailed, atypes.QueryExecutionStateCancelled:
			reason := ""
			if ex.QueryExecution.Status.StateChangeReason != nil {
				reason = *ex.QueryExecution.Status.StateChangeReason
			}
			return nil, fmt.Errorf("query %s: %s", ex.QueryExecution.Status.State, reason)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < 2*time.Second {
			backoff *= 2
		}
	}
}

// fetch pages through GetQueryResults and maps each data row (skipping the header row)
// into a map[columnName]value, returning the full slice when pagination is exhausted.
func (c *Client) fetch(ctx context.Context, id *string) ([]map[string]string, error) {
	var header []string
	var out []map[string]string
	var token *string
	first := true

	for {
		res, err := c.api.GetQueryResults(ctx, &athena.GetQueryResultsInput{QueryExecutionId: id, NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("fetch results: %w", err)
		}
		// Guard against nil ResultSet from SDK (not guaranteed to be non-nil).
		if res.ResultSet == nil {
			break
		}
		rows := res.ResultSet.Rows
		startIdx := 0

		// The very first row across all pages is always the column-name header.
		if first && len(rows) > 0 {
			for _, d := range rows[0].Data {
				header = append(header, deref(d.VarCharValue))
			}
			startIdx, first = 1, false
		}

		for _, r := range rows[startIdx:] {
			m := make(map[string]string, len(header))
			for i, d := range r.Data {
				if i < len(header) {
					m[header[i]] = deref(d.VarCharValue)
				}
			}
			out = append(out, m)
		}

		if res.NextToken == nil {
			break
		}
		token = res.NextToken
	}
	return out, nil
}

// deref safely dereferences a *string, returning "" for nil.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
