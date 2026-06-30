package mdslack

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRender_SimpleTable(t *testing.T) {
	src := "| Svc | Status |\n|-----|--------|\n| api | down |"
	blocks, err := Render(src)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	b, _ := json.Marshal(blocks)
	js := string(b)
	if !strings.Contains(js, `"type":"table"`) {
		t.Fatalf("expected a table block: %s", js)
	}
	if !strings.Contains(js, `"type":"rich_text"`) {
		t.Fatalf("expected rich_text cells: %s", js)
	}
	if !strings.Contains(js, `"text":"Svc"`) || !strings.Contains(js, `"text":"api"`) {
		t.Fatalf("cell text missing: %s", js)
	}
}

func TestRender_TableAlignmentAndRichCells(t *testing.T) {
	src := "| Name | Count |\n|:-----|------:|\n| **api** | [1](https://x) |"
	blocks, err := Render(src)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	b, _ := json.Marshal(blocks)
	js := string(b)
	if !strings.Contains(js, `"align":"left"`) || !strings.Contains(js, `"align":"right"`) {
		t.Fatalf("column alignment missing: %s", js)
	}
	if !strings.Contains(js, `"bold":true`) {
		t.Fatalf("bold cell text missing: %s", js)
	}
	if !strings.Contains(js, `"type":"link"`) || !strings.Contains(js, `https://x`) {
		t.Fatalf("link cell missing: %s", js)
	}
}

func TestRender_TableProseInterleaving(t *testing.T) {
	src := "before\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\nafter"
	blocks, err := Render(src)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if len(blocks) != 3 {
		t.Fatalf("expected section,table,section (3 blocks), got %d", len(blocks))
	}
}

func TestRender_OverLimitTableFallsBackToCodeBlock(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("| a |\n|---|\n")
	for i := 0; i < 150; i++ { // > maxTableRows
		sb.WriteString("| x |\n")
	}
	blocks, err := Render(sb.String())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	b, _ := json.Marshal(blocks)
	js := string(b)
	if strings.Contains(js, `"type":"table"`) {
		t.Fatalf("over-limit table should not produce a table block: %s", js)
	}
	if !strings.Contains(js, "```") {
		t.Fatalf("over-limit table should fall back to a code block: %s", js)
	}
}
