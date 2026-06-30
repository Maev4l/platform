// Package catalog discovers log sources directly from the Glue Data Catalog so
// the tables `terraform apply` creates are the single source of truth — no
// separate LOG_SOURCES list to keep in sync, and no dependency on `terraform
// output` (which needs AWS creds before the app's SSO login has run).
package catalog

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/glue"
	"isnan.eu/monitoring/internal/config"
)

// Lister is the subset of the Glue API we use; an interface so tests can fake it.
type Lister interface {
	GetTables(ctx context.Context, in *glue.GetTablesInput, opts ...func(*glue.Options)) (*glue.GetTablesOutput, error)
}

// Discover lists every table in the given Glue database and maps each to a log
// source. The UI display name reverses Terraform's table-name sanitization
// (source name '-' -> table '_'); our source names only ever use hyphens, so
// the reverse transform is exact.
func Discover(ctx context.Context, g Lister, database string) ([]config.Source, error) {
	var sources []config.Source
	var token *string
	for {
		out, err := g.GetTables(ctx, &glue.GetTablesInput{DatabaseName: &database, NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("glue GetTables(%s): %w", database, err)
		}
		for _, t := range out.TableList {
			if t.Name == nil {
				continue
			}
			sources = append(sources, config.Source{Name: strings.ReplaceAll(*t.Name, "_", "-"), Table: *t.Name})
		}
		if out.NextToken == nil {
			break
		}
		token = out.NextToken
	}
	return sources, nil
}
