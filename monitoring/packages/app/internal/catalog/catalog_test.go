package catalog

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
)

// fakeLister returns canned pages; if err is set the first call fails.
type fakeLister struct {
	pages [][]string // table names per page
	err   error
	calls int
}

func (f *fakeLister) GetTables(_ context.Context, in *glue.GetTablesInput, _ ...func(*glue.Options)) (*glue.GetTablesOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	idx := f.calls
	f.calls++
	out := &glue.GetTablesOutput{}
	for _, n := range f.pages[idx] {
		name := n
		out.TableList = append(out.TableList, gluetypes.Table{Name: &name})
	}
	// Set NextToken on every page but the last so Discover paginates.
	if idx < len(f.pages)-1 {
		tok := "next"
		out.NextToken = &tok
	}
	return out, nil
}

func TestDiscoverReversesTableNameToDisplayName(t *testing.T) {
	f := &fakeLister{pages: [][]string{{"alexandria", "brigitte_leroux_site", "meal_planner"}}}
	got, err := Discover(context.Background(), f, "platform-monitoring")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{ // table -> display name
		"alexandria":           "alexandria",
		"brigitte_leroux_site": "brigitte-leroux-site",
		"meal_planner":         "meal-planner",
	}
	if len(got) != 3 {
		t.Fatalf("want 3 sources, got %d: %+v", len(got), got)
	}
	for _, s := range got {
		if want[s.Table] != s.Name {
			t.Fatalf("table %q: want name %q, got %q", s.Table, want[s.Table], s.Name)
		}
	}
}

func TestDiscoverPaginates(t *testing.T) {
	f := &fakeLister{pages: [][]string{{"a"}, {"b_c"}}}
	got, err := Discover(context.Background(), f, "db")
	if err != nil {
		t.Fatal(err)
	}
	if f.calls != 2 || len(got) != 2 {
		t.Fatalf("want 2 calls / 2 sources, got %d calls / %d sources", f.calls, len(got))
	}
}

func TestDiscoverPropagatesError(t *testing.T) {
	f := &fakeLister{err: errors.New("access denied")}
	if _, err := Discover(context.Background(), f, "db"); err == nil {
		t.Fatal("want error, got nil")
	}
}
