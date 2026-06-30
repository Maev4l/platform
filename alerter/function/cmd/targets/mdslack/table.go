package mdslack

import (
	"fmt"
	"strings"

	"github.com/slack-go/slack"
	"github.com/yuin/goldmark/ast"
	east "github.com/yuin/goldmark/extension/ast"
)

// tableBlock converts a GFM table to a native Slack table block with rich_text
// cells. If the table exceeds Slack's limits, it degrades to a fenced code block
// (monospace, space-padded) so the data is never lost.
func tableBlock(t *east.Table, src []byte) slack.Block {
	rows := collectRows(t)

	cols, chars := 0, 0
	for _, row := range rows {
		if len(row) > cols {
			cols = len(row)
		}
		for _, cell := range row {
			chars += len(inline(cell, src))
		}
	}
	if len(rows) > maxTableRows || cols > maxTableCols || chars > maxTableChars {
		return slack.NewSectionBlock(
			slack.NewTextBlockObject(slack.MarkdownType, tableToCodeBlock(rows, src), false, false), nil, nil)
	}

	tb := slack.NewTableBlock("")
	for _, row := range rows {
		cells := make([]slack.TableCell, 0, len(row))
		for _, cell := range row {
			cells = append(cells, richCell(cell, src))
		}
		tb.AddRow(cells...)
	}
	if cs := columnSettings(t.Alignments); len(cs) > 0 {
		tb.WithColumnSettings(cs...)
	}
	return tb
}

func collectRows(t *east.Table) [][]*east.TableCell {
	var rows [][]*east.TableCell
	for r := t.FirstChild(); r != nil; r = r.NextSibling() {
		var cells []*east.TableCell
		for c := r.FirstChild(); c != nil; c = c.NextSibling() {
			if cell, ok := c.(*east.TableCell); ok {
				cells = append(cells, cell)
			}
		}
		rows = append(rows, cells)
	}
	return rows
}

// richCell builds a rich_text cell preserving inline bold/italic/strike/code/links.
func richCell(cell ast.Node, src []byte) slack.TableCell {
	var elems []slack.RichTextSectionElement
	collectRich(cell, src, &elems, slack.RichTextSectionTextStyle{})
	if len(elems) == 0 {
		elems = append(elems, slack.NewRichTextSectionTextElement("", nil))
	}
	return slack.NewTableRichTextCell(slack.NewRichTextSection(elems...))
}

func collectRich(n ast.Node, src []byte, out *[]slack.RichTextSectionElement, style slack.RichTextSectionTextStyle) {
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		switch v := c.(type) {
		case *ast.Text:
			st := style
			*out = append(*out, slack.NewRichTextSectionTextElement(string(v.Segment.Value(src)), &st))
		case *ast.String:
			st := style
			*out = append(*out, slack.NewRichTextSectionTextElement(string(v.Value), &st))
		case *ast.CodeSpan:
			st := style
			st.Code = true
			*out = append(*out, slack.NewRichTextSectionTextElement(inlineText(c, src), &st))
		case *ast.Emphasis:
			st := style
			if v.Level >= 2 {
				st.Bold = true
			} else {
				st.Italic = true
			}
			collectRich(c, src, out, st)
		case *east.Strikethrough:
			st := style
			st.Strike = true
			collectRich(c, src, out, st)
		case *ast.Link:
			st := style
			*out = append(*out, slack.NewRichTextSectionLinkElement(string(v.Destination), inlineText(c, src), &st))
		case *ast.AutoLink:
			st := style
			url := string(v.URL(src))
			*out = append(*out, slack.NewRichTextSectionLinkElement(url, url, &st))
		default:
			collectRich(c, src, out, style)
		}
	}
}

func columnSettings(aligns []east.Alignment) []slack.ColumnSetting {
	cs := make([]slack.ColumnSetting, 0, len(aligns))
	for _, a := range aligns {
		// Default to left; override for center and right only.
		col := slack.ColumnSetting{Align: slack.ColumnAlignmentLeft}
		switch a {
		case east.AlignCenter:
			col.Align = slack.ColumnAlignmentCenter
		case east.AlignRight:
			col.Align = slack.ColumnAlignmentRight
		}
		cs = append(cs, col)
	}
	return cs
}

// tableToCodeBlock renders an over-limit table as a space-padded monospace block
// so the data is preserved without being silently truncated.
func tableToCodeBlock(rows [][]*east.TableCell, src []byte) string {
	text := make([][]string, len(rows))
	widths := []int{}
	for i, row := range rows {
		text[i] = make([]string, len(row))
		for j, cell := range row {
			s := inline(cell, src)
			text[i][j] = s
			if j >= len(widths) {
				widths = append(widths, 0)
			}
			if len(s) > widths[j] {
				widths[j] = len(s)
			}
		}
	}
	var sb strings.Builder
	sb.WriteString("```\n")
	for _, row := range text {
		cells := make([]string, len(row))
		for j, s := range row {
			cells[j] = fmt.Sprintf("%-*s", widths[j], s)
		}
		sb.WriteString(strings.Join(cells, " | "))
		sb.WriteString("\n")
	}
	sb.WriteString("```")
	return sb.String()
}
