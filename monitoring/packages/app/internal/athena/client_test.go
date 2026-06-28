package athena

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	atypes "github.com/aws/aws-sdk-go-v2/service/athena/types"
)

type fakeAPI struct {
	lastParams []string // ExecutionParameters seen by StartQueryExecution
}

func (f *fakeAPI) StartQueryExecution(ctx context.Context, in *athena.StartQueryExecutionInput, _ ...func(*athena.Options)) (*athena.StartQueryExecutionOutput, error) {
	f.lastParams = in.ExecutionParameters
	return &athena.StartQueryExecutionOutput{QueryExecutionId: aws.String("q1")}, nil
}
func (f *fakeAPI) GetQueryExecution(ctx context.Context, in *athena.GetQueryExecutionInput, _ ...func(*athena.Options)) (*athena.GetQueryExecutionOutput, error) {
	return &athena.GetQueryExecutionOutput{QueryExecution: &atypes.QueryExecution{
		Status: &atypes.QueryExecutionStatus{State: atypes.QueryExecutionStateSucceeded},
	}}, nil
}
func (f *fakeAPI) GetQueryResults(ctx context.Context, in *athena.GetQueryResultsInput, _ ...func(*athena.Options)) (*athena.GetQueryResultsOutput, error) {
	row := func(vals ...string) atypes.Row {
		d := make([]atypes.Datum, len(vals))
		for i, v := range vals {
			vv := v
			d[i] = atypes.Datum{VarCharValue: &vv}
		}
		return atypes.Row{Data: d}
	}
	return &athena.GetQueryResultsOutput{ResultSet: &atypes.ResultSet{
		Rows: []atypes.Row{row("country", "callers"), row("FR", "9241")},
	}}, nil
}

func TestQueryMapsRows(t *testing.T) {
	c := New(&fakeAPI{}, "monitoring", "monitoring")
	rows, err := c.Query(context.Background(), "SELECT 1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["country"] != "FR" || rows[0]["callers"] != "9241" {
		t.Fatalf("unexpected rows: %v", rows)
	}
}

func TestQueryOmitsEmptyParams(t *testing.T) {
	// Athena rejects an empty (but present) ExecutionParameters list, so with no
	// args the client must send nil (omit it entirely).
	f := &fakeAPI{}
	c := New(f, "monitoring", "monitoring")
	if _, err := c.Query(context.Background(), "SELECT 1", nil); err != nil {
		t.Fatal(err)
	}
	if f.lastParams != nil {
		t.Fatalf("expected nil ExecutionParameters for no args, got %#v", f.lastParams)
	}
}

func TestQueryQuotesStringParams(t *testing.T) {
	// String args must be passed as quoted SQL literals (with embedded ' doubled).
	f := &fakeAPI{}
	c := New(f, "monitoring", "monitoring")
	if _, err := c.Query(context.Background(), "SELECT ?", []string{"FR", "a'b"}); err != nil {
		t.Fatal(err)
	}
	if len(f.lastParams) != 2 || f.lastParams[0] != "'FR'" || f.lastParams[1] != "'a''b'" {
		t.Fatalf("bad quoted params: %#v", f.lastParams)
	}
}
