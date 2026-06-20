# Shared `notifications` Module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the alerting-events SNS message contract into one shared Go module (`github.com/Maev4l/platform/notifications`) consumed by every producer and the alerter consumer, eliminating the three divergent copies.

**Architecture:** New standalone module at the platform repo root holding a single `Message` struct (the SNS wire contract). `users-management` keeps `cognito.NotificationPayload` as a backward-compatible type alias; the `alerter` consumer drops its private `models.AlertMessage` and uses the shared type. Each module is released independently via path-prefixed tags, so consumers `go get` a published version.

**Tech Stack:** Go (multi-module repo), AWS SNS, golangci-lint.

**Repo:** `/Users/jrsue/dev/repos/platform` (separate from meal-planner). This plan is a **prerequisite** for the meal-planner `invite-auto-approval` plan (Plan B), which consumes `notifications/v1.0.0`.

**⛔ Release gates (your manual actions — never automated):** tagging + pushing `notifications/v1.0.0` (after Task 1) and `users-management/v1.3.0` (after Task 2), and deploying the alerter Lambda (after Task 3). Each gate must complete before the next task's `go get` can resolve.

---

## File Structure

- **Create** `notifications/go.mod` — new module `github.com/Maev4l/platform/notifications`, `go 1.24` (≤ every consumer: meal-planner 1.25, users-management 1.25, alerter 1.26).
- **Create** `notifications/message.go` — the `Message` struct (single responsibility: the wire contract).
- **Create** `notifications/message_test.go` — JSON round-trip test locking the lowercase tags.
- **Modify** `users-management/pkg/cognito/types.go` — replace the `NotificationPayload` struct with a type alias to `notifications.Message`.
- **Modify** `users-management/go.mod` — require `notifications`.
- **Modify** `alerter/function/cmd/main.go`, `alerter/function/cmd/targets/target.go`, `alerter/function/cmd/targets/slack.go` — use `notifications.Message`.
- **Delete** `alerter/function/cmd/models/alert_message.go` (and the now-empty `models/` dir).
- **Modify** `alerter/function/go.mod` — require `notifications`.

---

### Task 1: Create the `notifications` module

**Files:**
- Create: `notifications/go.mod`
- Create: `notifications/message.go`
- Create: `notifications/message_test.go`

- [ ] **Step 1: Create the module file**

`notifications/go.mod`:
```
module github.com/Maev4l/platform/notifications

go 1.24
```

- [ ] **Step 2: Write the failing test**

`notifications/message_test.go`:
```go
package notifications

import (
	"encoding/json"
	"testing"
)

// The JSON tags are the SNS wire contract shared with the alerter consumer.
// This test fails loudly if a tag or field order regresses.
func TestMessage_WireContract(t *testing.T) {
	m := Message{Target: "slack", Source: "svc", SourceDescription: "desc", Content: "hello"}

	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"target":"slack","source":"svc","sourceDescription":"desc","content":"hello"}`
	if string(b) != want {
		t.Fatalf("wire mismatch:\n got=%s\nwant=%s", b, want)
	}

	var rt Message
	if err := json.Unmarshal(b, &rt); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rt != m {
		t.Fatalf("round-trip mismatch: %+v != %+v", rt, m)
	}
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd /Users/jrsue/dev/repos/platform/notifications && go test ./...`
Expected: FAIL — `undefined: Message`.

- [ ] **Step 4: Write the struct**

`notifications/message.go`:
```go
// Package notifications defines the alerting-events SNS message contract shared
// by every producer (publishers to the topic) and the alerter consumer. Keeping
// one struct here prevents the producer/consumer copies from drifting.
package notifications

// Message is the SNS body. The alerter unmarshals it and routes on Target.
// The json tags ARE the wire contract — changing them breaks every consumer.
type Message struct {
	Target            string `json:"target"`            // routing key, e.g. "slack"
	Source            string `json:"source"`            // producer id
	SourceDescription string `json:"sourceDescription"` // human label (Slack pretext)
	Content           string `json:"content"`           // message body (Slack text)
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd /Users/jrsue/dev/repos/platform/notifications && go test ./...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/jrsue/dev/repos/platform
git add notifications/
git commit -m "feat(notifications): add shared alerting-events message contract"
```

- [ ] **Step 7: ⛔ RELEASE GATE (manual) — tag + push**

```bash
cd /Users/jrsue/dev/repos/platform
git tag notifications/v1.0.0
git push origin HEAD notifications/v1.0.0
```
The module must be fetchable before Tasks 2 and 3 (and meal-planner Plan B) can `go get` it.

---

### Task 2: Migrate `users-management` to the shared type (alias)

**Files:**
- Modify: `users-management/pkg/cognito/types.go:42-48`
- Modify: `users-management/go.mod`

- [ ] **Step 1: Replace the struct with an alias**

In `users-management/pkg/cognito/types.go`, add the import at the top (after `package cognito`):
```go
import "github.com/Maev4l/platform/notifications"
```

Then replace the existing block:
```go
// NotificationPayload defines the structure for signup notifications
type NotificationPayload struct {
	Source            string `json:"source"`
	SourceDescription string `json:"sourceDescription"`
	Target            string `json:"target"`
	Content           string `json:"content"`
}
```
with:
```go
// NotificationPayload is retained as a backward-compatible alias. The canonical
// type now lives in the shared notifications module so producers and the alerter
// consumer share one wire contract. Existing hooks returning *NotificationPayload
// keep compiling unchanged.
type NotificationPayload = notifications.Message
```

- [ ] **Step 2: Add the dependency**

Run:
```bash
cd /Users/jrsue/dev/repos/platform/users-management
go get github.com/Maev4l/platform/notifications@v1.0.0
go mod tidy
```
Expected: `go.mod` now requires `github.com/Maev4l/platform/notifications v1.0.0`.

- [ ] **Step 3: Verify build + existing behavior**

Run:
```bash
cd /Users/jrsue/dev/repos/platform/users-management
go build ./... && go test ./... && golangci-lint run ./...
```
Expected: PASS. (`handler.go`'s `json.Marshal(payload)` and the `GetNotificationFunc` signatures are unchanged because the alias is identical on the wire.)

- [ ] **Step 4: Commit**

```bash
cd /Users/jrsue/dev/repos/platform
git add users-management/
git commit -m "refactor(users-management): use shared notifications.Message via alias"
```

- [ ] **Step 5: ⛔ RELEASE GATE (manual) — tag + push**

```bash
cd /Users/jrsue/dev/repos/platform
git tag users-management/v1.3.0
git push origin HEAD users-management/v1.3.0
```

---

### Task 3: Migrate the `alerter` consumer to the shared type

**Files:**
- Delete: `alerter/function/cmd/models/alert_message.go` (then remove the empty `models/` dir)
- Modify: `alerter/function/cmd/main.go`
- Modify: `alerter/function/cmd/targets/target.go`
- Modify: `alerter/function/cmd/targets/slack.go`
- Modify: `alerter/function/go.mod`

> **Behavior change (intended):** the consumer's `Content` goes from `json.RawMessage` to `string`. Unmarshaling a JSON string into a Go `string` strips the surrounding quotes, so Slack text will no longer be quote-wrapped. This is the cosmetic improvement signed off in the spec.

- [ ] **Step 1: Add the dependency**

```bash
cd /Users/jrsue/dev/repos/platform/alerter/function
go get github.com/Maev4l/platform/notifications@v1.0.0
```

- [ ] **Step 2: Delete the private model**

```bash
rm /Users/jrsue/dev/repos/platform/alerter/function/cmd/models/alert_message.go
rmdir /Users/jrsue/dev/repos/platform/alerter/function/cmd/models
```

- [ ] **Step 3: Update `target.go`**

`alerter/function/cmd/targets/target.go` — replace the `models` import and the method signature:
```go
package targets

import "github.com/Maev4l/platform/notifications"

type Target interface {
	GetName() string
	SendAlert(alert *notifications.Message) error
}
```
(Keep any other lines in the file unchanged.)

- [ ] **Step 4: Update `slack.go`**

In `alerter/function/cmd/targets/slack.go`:
- Replace the import `"isnan.eu/alerting/cmd/models"` with `"github.com/Maev4l/platform/notifications"`.
- Change the method signature and the content line:
```go
func (n slackNotifier) SendAlert(alert *notifications.Message) error {
	content := alert.Content
	if content != "" {
		attachment := slack.Attachment{
			Pretext: alert.SourceDescription,
			Text:    content,
		}
		_, _, err := n.slackClient.PostMessage(channelId, slack.MsgOptionAttachments(attachment))
		if err != nil {
			log.Errorf("Failed to send alert to %s", n.name)
			return err
		}
	}
	return nil
}
```

- [ ] **Step 5: Update `main.go`**

In `alerter/function/cmd/main.go`:
- Replace the import `"isnan.eu/alerting/cmd/models"` with `"github.com/Maev4l/platform/notifications"`.
- Change the message construction:
```go
		message := &notifications.Message{}
```
(The `isnan.eu/alerting/cmd/targets` import stays.)

- [ ] **Step 6: Tidy + build**

```bash
cd /Users/jrsue/dev/repos/platform/alerter/function
go mod tidy && go build ./...
```
Expected: PASS, no remaining references to `cmd/models`.

- [ ] **Step 7: Commit**

```bash
cd /Users/jrsue/dev/repos/platform
git add alerter/
git commit -m "refactor(alerter): consume shared notifications.Message; drop private model"
```

- [ ] **Step 8: ⛔ DEPLOY GATE (manual) — redeploy the alerter Lambda**

Deploy per the alerter's normal process (its `Makefile` / `package.json` in `alerter/`). The quote-removal takes effect here. Verify a test alert renders in Slack without surrounding quotes.

---

## Self-Review

**Spec coverage:** new module (Task 1) ✓; users-management migration via alias (Task 2) ✓; alerter migration + quote-removal (Task 3) ✓; release gates ✓. idp confirmed out of scope (SNS-triggered, not an alerting producer).

**Placeholder scan:** none — all code blocks complete, all commands explicit.

**Type consistency:** `notifications.Message` field/tag set identical across struct, alias, and both alerter usages. `Content` is `string` everywhere post-migration; `slack.go` and `main.go` updated to match.
