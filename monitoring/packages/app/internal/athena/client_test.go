package athena

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	atypes "github.com/aws/aws-sdk-go-v2/service/athena/types"
)

type fakeAPI struct{}

func (fakeAPI) StartQueryExecution(ctx context.Context, in *athena.StartQueryExecutionInput, _ ...func(*athena.Options)) (*athena.StartQueryExecutionOutput, error) {
	return &athena.StartQueryExecutionOutput{QueryExecutionId: aws.String("q1")}, nil
}
func (fakeAPI) GetQueryExecution(ctx context.Context, in *athena.GetQueryExecutionInput, _ ...func(*athena.Options)) (*athena.GetQueryExecutionOutput, error) {
	return &athena.GetQueryExecutionOutput{QueryExecution: &atypes.QueryExecution{
		Status: &atypes.QueryExecutionStatus{State: atypes.QueryExecutionStateSucceeded},
	}}, nil
}
func (fakeAPI) GetQueryResults(ctx context.Context, in *athena.GetQueryResultsInput, _ ...func(*athena.Options)) (*athena.GetQueryResultsOutput, error) {
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
	c := New(fakeAPI{}, "monitoring", "monitoring")
	rows, err := c.Query(context.Background(), "SELECT 1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["country"] != "FR" || rows[0]["callers"] != "9241" {
		t.Fatalf("unexpected rows: %v", rows)
	}
}
