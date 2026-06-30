// Package mdslack converts standard (CommonMark/GFM) Markdown into Slack Block
// Kit blocks: mrkdwn section blocks for prose and native table blocks for GFM
// tables. It is intentionally pure — no logging, no I/O — so the alerter can
// unit-test the exact payload and fall back on error.
package mdslack

import (
	"fmt"
	"strings"

	"github.com/slack-go/slack"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	east "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/text"
)

const (
	maxSectionChars = 3000 // Slack section text limit
	maxTableRows    = 100  // Slack table-block limits
	maxTableCols    = 20
	maxTableChars   = 10000
)

// extension.GFM bundles tables + strikethrough + autolinks, matching what
// producers expect from "standard" Markdown.
var md = goldmark.New(goldmark.WithExtensions(extension.GFM))

// Render parses Markdown and returns Slack blocks. It returns an error when the
// source has no renderable content so the caller can fall back to plain text.
func Render(src string) ([]slack.Block, error) {
	source := []byte(src)
	doc := md.Parser().Parse(text.NewReader(source))

	var blocks []slack.Block
	var prose strings.Builder

	flush := func() {
		if prose.Len() == 0 {
			return
		}
		blocks = append(blocks, sectionsFromText(prose.String())...)
		prose.Reset()
	}

	for n := doc.FirstChild(); n != nil; n = n.NextSibling() {
		if tbl, ok := n.(*east.Table); ok {
			flush()
			blocks = append(blocks, tableBlock(tbl, source))
			continue
		}
		s := renderBlock(n, source)
		if strings.TrimSpace(s) == "" {
			continue
		}
		if prose.Len() > 0 {
			prose.WriteString("\n\n")
		}
		prose.WriteString(s)
	}
	flush()

	if len(blocks) == 0 {
		return nil, fmt.Errorf("mdslack: no renderable content")
	}
	return blocks, nil
}

// renderBlock turns a block-level node into a Slack mrkdwn string.
func renderBlock(n ast.Node, src []byte) string {
	switch b := n.(type) {
	case *ast.Heading:
		// Slack mrkdwn has no headings; bold the line so it still stands out.
		return "*" + inline(n, src) + "*"
	case *ast.Blockquote:
		var lines []string
		for c := n.FirstChild(); c != nil; c = c.NextSibling() {
			lines = append(lines, renderBlock(c, src))
		}
		var qb strings.Builder
		for i, line := range strings.Split(strings.Join(lines, "\n"), "\n") {
			if i > 0 {
				qb.WriteString("\n")
			}
			qb.WriteString("> " + line)
		}
		return qb.String()
	case *ast.List:
		return renderList(b, src)
	case *ast.FencedCodeBlock:
		return "```\n" + codeText(n, src) + "```"
	case *ast.CodeBlock:
		return "```\n" + codeText(n, src) + "```"
	case *ast.ThematicBreak:
		return "──────────"
	default: // Paragraph, TextBlock, etc.
		return inline(n, src)
	}
}

// renderList renders ordered/unordered lists, indenting nested lists.
func renderList(l *ast.List, src []byte) string {
	var sb strings.Builder
	idx := l.Start
	if idx == 0 {
		idx = 1
	}
	for li := l.FirstChild(); li != nil; li = li.NextSibling() {
		marker := "• "
		if l.IsOrdered() {
			marker = fmt.Sprintf("%d. ", idx)
			idx++
		}
		var parts []string
		for c := li.FirstChild(); c != nil; c = c.NextSibling() {
			if nested, ok := c.(*ast.List); ok {
				parts = append(parts, indentLines(renderList(nested, src), "    "))
			} else {
				parts = append(parts, renderBlock(c, src))
			}
		}
		if sb.Len() > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(marker + strings.Join(parts, "\n"))
	}
	return sb.String()
}

func indentLines(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = prefix + lines[i]
	}
	return strings.Join(lines, "\n")
}

// inline concatenates the inline rendering of a node's children.
func inline(n ast.Node, src []byte) string {
	var sb strings.Builder
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		sb.WriteString(inlineNode(c, src))
	}
	return sb.String()
}

func inlineNode(n ast.Node, src []byte) string {
	switch v := n.(type) {
	case *ast.Text:
		s := string(v.Segment.Value(src))
		if v.SoftLineBreak() || v.HardLineBreak() {
			s += "\n"
		}
		return s
	case *ast.String:
		return string(v.Value)
	case *ast.CodeSpan:
		return "`" + inlineText(n, src) + "`"
	case *ast.Emphasis:
		inner := inline(n, src)
		if v.Level >= 2 {
			return "*" + inner + "*" // bold
		}
		return "_" + inner + "_" // italic
	case *east.Strikethrough:
		return "~" + inline(n, src) + "~"
	case *ast.Link:
		return "<" + string(v.Destination) + "|" + inline(n, src) + ">"
	case *ast.AutoLink:
		url := string(v.URL(src))
		return "<" + url + ">"
	default:
		return inline(n, src)
	}
}

// inlineText extracts raw text (no markup) — used for code spans and link/cell text.
func inlineText(n ast.Node, src []byte) string {
	var sb strings.Builder
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		if t, ok := c.(*ast.Text); ok {
			sb.Write(t.Segment.Value(src))
		} else {
			sb.WriteString(inlineText(c, src))
		}
	}
	return sb.String()
}

// codeText returns the literal lines of a (fenced) code block.
func codeText(n ast.Node, src []byte) string {
	var sb strings.Builder
	lines := n.Lines()
	for i := 0; i < lines.Len(); i++ {
		seg := lines.At(i)
		sb.Write(seg.Value(src))
	}
	return sb.String()
}

// sectionsFromText wraps text in one or more mrkdwn section blocks under the limit.
func sectionsFromText(s string) []slack.Block {
	return sectionsOfType(s, slack.MarkdownType)
}

// PlainSections wraps literal text in one or more plain_text section blocks,
// splitting on Slack's 3000-char section limit. Used for the format:"plain"
// path and as the Markdown fallback so large content is never rejected by
// Slack — i.e. an alert is never dropped.
func PlainSections(s string) []slack.Block {
	return sectionsOfType(s, slack.PlainTextType)
}

// sectionsOfType splits s under the section limit and wraps each chunk in a
// section block of the given text-object type (mrkdwn or plain_text).
func sectionsOfType(s, objType string) []slack.Block {
	var blocks []slack.Block
	for _, chunk := range splitChars(s, maxSectionChars) {
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(objType, chunk, false, false), nil, nil))
	}
	return blocks
}

// splitChars splits s into pieces of at most max runes, preferring to break at
// the last newline so formatting is not severed mid-line.
func splitChars(s string, max int) []string {
	r := []rune(s)
	if len(r) <= max {
		return []string{s}
	}
	var out []string
	for len(r) > max {
		cut := max
		if nl := lastIndexRune(r[:max], '\n'); nl > 0 {
			cut = nl
		}
		out = append(out, string(r[:cut]))
		r = r[cut:]
	}
	if len(r) > 0 {
		out = append(out, string(r))
	}
	return out
}

func lastIndexRune(r []rune, target rune) int {
	for i := len(r) - 1; i >= 0; i-- {
		if r[i] == target {
			return i
		}
	}
	return -1
}
