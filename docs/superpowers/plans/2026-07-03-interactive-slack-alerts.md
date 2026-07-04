# Interactive Slack Alerts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Post-implementation amendments (naming):** the two Lambdas were renamed after the
> tasks below were written — `function_name` `platform-alerter`→`platform-notifier` and
> `platform-alerter-responder`→`platform-notifier-responder`; IAM policies
> `platform-alerter-*-policy`→`platform-notifier-*-policy`; the notifier Go module
> `isnan.eu/alerting`→`isnan.eu/notifier` (and its `cmd/mdslack` import); the notifier zip
> artifact `alerter.zip`→`notifier.zip`. The Lambda handler binary stays `bootstrap`
> (runtime requirement). The `application` default tag stays `platform-alerter`.
> Task text below shows the original names where it narrates the historical steps.

**Goal:** Let alerts carry OK/Cancel-style buttons; a click by an allow-listed Slack user relays a decision back to the originating producer via a new SNS responses topic.

**Architecture:** The alerter stays a decoupled router. The existing **notifier** Lambda (SNS→Slack) is moved into a `packages/` layout, has its dead multi-channel abstraction removed, and gains interactive-button rendering. A new **responder** Lambda behind a Lambda Function URL receives Slack button clicks, verifies the signature, checks a user allow-list, publishes the decision to the alerter-owned `alerting-responses` SNS topic, and updates the original Slack message via its `response_url`.

**Tech Stack:** Go 1.26, AWS Lambda (arm64, `provided.al2023`), `slack-go/slack`, aws-sdk-go-v2 (sns, ssm), zerolog, Terraform (~> 6.0 AWS provider), shared `github.com/Maev4l/platform/notifications` module.

## Global Constraints

- Language: Go. Logging: **zerolog**. Lint/format: `golangci-lint run` / `golangci-lint fmt`. Run `gofmt -l` before every commit; the tree must be clean.
- Lambda arch: **arm64**; runtime `provided.al2023`; handler binary named `bootstrap`.
- Region: **eu-central-1**. State backend key unchanged: `platform/alerter.tfstate`.
- The `notifications` JSON tags ARE the SNS wire contract — additions must be `omitempty` so `v1.1.0` producers' bytes are unchanged. Changes ship as a **new module tag `notifications/v1.2.0`**.
- Slack button `value` max length is **2000 chars** — the context JSON must stay small.
- Responder authorizes on TWO gates: Slack request signature (replay window ≤5 min) AND a Slack-user-ID allow-list.
- Responder needs **no bot token** — `response_url` posting is pre-authorized. Only the signing secret + operators list.
- SSM params (already provisioned, SecureString): `slack.alerting.signing_secret`, `slack.alerting.operators` (comma-separated `U…` IDs). Existing: `slack.alerting.token`.
- **Commits/pushes are user-gated.** The user has stated they will say when to commit and push. Do NOT run `git commit`/`git push` without explicit approval — pause at each commit step and ask.

---

## File Structure

```
alerter/
├── Makefile                              # root orchestrator (rewritten)
├── README.md                             # updated: layout, interactive contract, Slack setup
└── packages/
    ├── notifier/                         # moved from alerter/function/
    │   ├── Makefile                      # unchanged content
    │   ├── go.mod / go.sum               # module isnan.eu/notifier; require notifications v1.2.0
    │   └── cmd/
    │       ├── main.go                   # de-abstracted handler + direct Slack send
    │       ├── slack.go                  # moved from cmd/targets/slack.go (package main)
    │       ├── slack_blocks_test.go      # moved; package main; + interactive tests
    │       └── mdslack/                  # moved from cmd/targets/mdslack/ (import path shortens)
    ├── responder/                        # NEW module isnan.eu/responder
    │   ├── Makefile
    │   ├── go.mod / go.sum               # require notifications v1.2.0
    │   └── cmd/
    │       ├── main.go                   # Function URL handler + init (SSM fetch, SNS/slack clients)
    │       ├── context.go                # button-value context encode/decode
    │       ├── context_test.go
    │       ├── verify.go                 # Slack signature verification wrapper
    │       ├── verify_test.go
    │       ├── authz.go                  # operator allow-list
    │       ├── authz_test.go
    │       ├── respond.go                # response_url message builders (confirm / ephemeral)
    │       └── respond_test.go
    └── infrastructure/                   # moved from alerter/infrastructure/
        ├── main.tf                       # terraform/provider/locals/data only
        ├── functions.tf                  # BOTH Lambdas: notifier module + sns_trigger, responder module + function URL + permission
        ├── sns.tf                        # + alerting_responses topic, policy (ARN via output, not an SSM param)
        ├── iam.tf                        # + responder policy (SSM read + sns:Publish)
        ├── variables.tf                  # unchanged
        └── outputs.tf                    # NEW: function URL + responses topic ARN
```

The context struct is duplicated across the two modules (notifier encodes, responder decodes) — it is 3 fields; a shared module for it is not worth the coupling (YAGNI).

---

## Task 1: Refactor to `packages/` layout (keep everything green)

Pure mechanical move — no behavior change. Establishes the new layout so later tasks build in place.

**Files:**
- Move: `alerter/function/` → `alerter/packages/notifier/`
- Move: `alerter/infrastructure/` → `alerter/packages/infrastructure/`
- Modify: `alerter/packages/infrastructure/main.tf` (notifier zip/binary paths)
- Modify: `alerter/Makefile` (function dir path)

**Interfaces:**
- Produces: notifier at `alerter/packages/notifier/` (module `isnan.eu/notifier` — see the top-of-plan amendment; the move itself kept the then-current name); infra at `alerter/packages/infrastructure/`.

- [ ] **Step 1: Move the two directories with git**

```bash
cd /Users/jrsue/dev/repos/platform/alerter
mkdir -p packages
git mv function packages/notifier
git mv infrastructure packages/infrastructure
```

- [ ] **Step 2: Repoint the notifier zip/binary paths in Terraform**

In `alerter/packages/infrastructure/main.tf`, the `alerter_function` module's `zip` block: change `../function/dist/alerter.zip` → `../notifier/dist/alerter.zip` and `../function/bin/bootstrap` → `../notifier/bin/bootstrap`.

```hcl
  zip = {
    filename = "../notifier/dist/alerter.zip"
    runtime  = "provided.al2023"
    handler  = "bootstrap"
    hash     = filebase64sha256("../notifier/bin/bootstrap")
  }
```

- [ ] **Step 3: Update the root Makefile FUNCTION path**

In `alerter/Makefile`, change `FUNCTION := function` → `FUNCTION := packages/notifier` and `INFRA := infrastructure` → `INFRA := packages/infrastructure`.

- [ ] **Step 4: Verify the notifier still builds and tests pass**

Run: `make -C /Users/jrsue/dev/repos/platform/alerter/packages/notifier build && cd /Users/jrsue/dev/repos/platform/alerter/packages/notifier && go test ./...`
Expected: build succeeds (produces `bin/bootstrap`); tests PASS.

- [ ] **Step 5: Verify Terraform still initialises/validates**

Run: `terraform -chdir=/Users/jrsue/dev/repos/platform/alerter/packages/infrastructure init -backend=false && terraform -chdir=/Users/jrsue/dev/repos/platform/alerter/packages/infrastructure validate`
Expected: `Success! The configuration is valid.`

- [ ] **Step 6: Commit** (user-gated — ask before running)

```bash
git add -A
git commit -m "refactor(alerter): move to packages/ layout"
```

---

## Task 2: Add `Action`/`Interactive` types to the notifications contract — ✅ DONE

Completed and released ahead of the rest of the plan. `notifications/message.go` now
defines `Action{ID, Label, Style}`, `Interactive{CallbackID, Payload, Actions}`, and
`Message.Interactive *Interactive` (json `interactive,omitempty`). Tests pass; committed to
`main` (`94b56d3`) and published as tag **`notifications/v1.2.0`** (verified resolvable via
`go list -m`). No `replace` directives are needed — downstream modules `require
github.com/Maev4l/platform/notifications v1.2.0` directly.

---

## Task 3: Remove the multi-channel abstraction from the notifier

Slack is the only channel. Delete the `Target` interface/registry; call Slack directly. No producer changes — the `target` field stays in the contract.

**Files:**
- Delete: `alerter/packages/notifier/cmd/targets/target.go`
- Move: `cmd/targets/slack.go` → `cmd/slack.go`; `cmd/targets/slack_blocks_test.go` → `cmd/slack_blocks_test.go`; `cmd/targets/mdslack/` → `cmd/mdslack/`
- Modify: `alerter/packages/notifier/cmd/main.go`

**Interfaces:**
- Produces: package `main` func `sendAlert(alert *notifications.Message) error`; pure func `buildMessageBlocks(alert *notifications.Message) []slack.Block` (retained, now package `main`).
- Consumes: `notifications.Message` (Task 2).

- [ ] **Step 1: Move files and delete the interface**

```bash
cd /Users/jrsue/dev/repos/platform/alerter/packages/notifier
git rm cmd/targets/target.go
git mv cmd/targets/slack.go cmd/slack.go
git mv cmd/targets/slack_blocks_test.go cmd/slack_blocks_test.go
git mv cmd/targets/mdslack cmd/mdslack
rmdir cmd/targets 2>/dev/null || true
```

- [ ] **Step 2: Rewrite `cmd/slack.go` as package `main`, no interface**

Replace the top of `cmd/slack.go`: package name and mdslack import path, drop the `Target`/`GetName`/`NewSlackTarget` machinery, expose a package-level client + `sendAlert`.

```go
package main

import (
	"context"
	"os"

	"github.com/Maev4l/platform/notifications"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/rs/zerolog/log"
	"github.com/slack-go/slack"
	"isnan.eu/alerting/cmd/mdslack"
)

// SSM parameter name holding the Slack bot token - read from env var.
var slackTokenParam string = os.Getenv("SLACK_TOKEN")

var channelId string = os.Getenv("SLACK_CHANNEL_ID")

// slackClient is initialised once in main() after the token is fetched.
var slackClient *slack.Client

func getSlackTokenFromSSM() string {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to load AWS SDK config")
	}
	ssmClient := ssm.NewFromConfig(cfg)
	withDecryption := true
	input := &ssm.GetParameterInput{Name: &slackTokenParam, WithDecryption: &withDecryption}
	result, err := ssmClient.GetParameter(context.Background(), input)
	if err != nil {
		log.Fatal().Err(err).Str("parameter", slackTokenParam).Msg("Failed to get Slack token from SSM")
	}
	return *result.Parameter.Value
}

// buildMessageBlocks assembles the Slack Block Kit payload: a context block for
// the source label (when present) followed by the rendered body.
func buildMessageBlocks(alert *notifications.Message) []slack.Block {
	var blocks []slack.Block
	if alert.SourceDescription != "" {
		blocks = append(blocks, slack.NewContextBlock("",
			slack.NewTextBlockObject(slack.MarkdownType, alert.SourceDescription, false, false)))
	}
	return append(blocks, bodyBlocks(alert)...)
}

// bodyBlocks renders the content. "plain" sends literal text; otherwise Markdown,
// falling back to literal sections so an alert is never dropped.
func bodyBlocks(alert *notifications.Message) []slack.Block {
	if alert.Format == "plain" {
		return mdslack.PlainSections(alert.Content)
	}
	blocks, err := mdslack.Render(alert.Content)
	if err != nil {
		log.Warn().Err(err).Msg("Markdown render error, falling back to plain text")
		return mdslack.PlainSections(alert.Content)
	}
	if len(blocks) == 0 {
		log.Warn().Msg("Markdown render produced no blocks, falling back to plain text")
		return mdslack.PlainSections(alert.Content)
	}
	return blocks
}

// sendAlert posts the alert to the configured Slack channel. Slack is the only
// channel, so there is no target registry — the call is direct.
func sendAlert(alert *notifications.Message) error {
	if alert.Content == "" {
		return nil
	}
	blocks := buildMessageBlocks(alert)
	_, _, err := slackClient.PostMessage(channelId, slack.MsgOptionBlocks(blocks...))
	if err != nil {
		log.Error().Err(err).Msg("Failed to send alert")
		return err
	}
	return nil
}
```

- [ ] **Step 3: Rewrite `cmd/main.go` without the registry**

```go
package main

import (
	"context"
	"encoding/json"

	"github.com/Maev4l/platform/notifications"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/slack-go/slack"
)

func handler(ctx context.Context, snsEvent events.SNSEvent) {
	for _, record := range snsEvent.Records {
		message := &notifications.Message{}
		if err := json.Unmarshal([]byte(record.SNS.Message), message); err != nil {
			log.Error().Err(err).Msg("Failed to unmarshall SNS event message")
			return
		}
		// Slack is the only channel. Keep the field for producer compatibility;
		// warn (do not drop) on anything else so a misrouted producer is visible.
		if message.Target != "" && message.Target != "slack" {
			log.Warn().Str("target", message.Target).Msg("Unknown target; sending to Slack anyway")
		}
		if err := sendAlert(message); err != nil {
			log.Error().Err(err).Str("source", message.Source).Msg("Failed to send message")
			return
		}
		log.Debug().Str("source", message.Source).Msg("Message sent")
	}
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	slackClient = slack.New(getSlackTokenFromSSM())
	lambda.Start(handler)
}
```

- [ ] **Step 4: Fix the moved test's package + mdslack references**

In `cmd/slack_blocks_test.go` change `package targets` → `package main`. (It calls `buildMessageBlocks`, now in package `main` — no other change.)

- [ ] **Step 5: Run build + tests**

Run: `cd /Users/jrsue/dev/repos/platform/alerter/packages/notifier && go build ./... && go test ./... && gofmt -l .`
Expected: builds; existing block tests PASS; `gofmt -l` prints nothing.

- [ ] **Step 6: Commit** (user-gated)

```bash
git add -A
git commit -m "refactor(notifier): drop multi-channel abstraction, send to Slack directly"
```

---

## Task 4: Render interactive action buttons in the notifier

**Files:**
- Modify: `alerter/packages/notifier/cmd/slack.go` (add `buildActionBlock`, call from `buildMessageBlocks`)
- Test: `alerter/packages/notifier/cmd/slack_blocks_test.go`

**Interfaces:**
- Produces: `buildActionBlock(alert *notifications.Message) slack.Block` and `encodeButtonValue(source, callbackID, payload string) string` returning compact JSON `{"s","c","p"}`.
- Consumes: `notifications.Interactive`/`Action` (requires notifications v1.2.0).

- [ ] **Step 0: Bump the notifier to notifications v1.2.0** (first task to use the new types)

In `alerter/packages/notifier/go.mod`, change the require to `github.com/Maev4l/platform/notifications v1.2.0`, then:

Run: `cd /Users/jrsue/dev/repos/platform/alerter/packages/notifier && go mod tidy && go build ./...`
Expected: fetches `notifications@v1.2.0`; builds clean.

- [ ] **Step 1: Write the failing tests**

Append to `cmd/slack_blocks_test.go`:

```go
func TestBuildBlocks_InteractiveButtons(t *testing.T) {
	js := blocksJSON(t, &notifications.Message{
		Source: "idp", SourceDescription: "IdP", Content: "Approve deploy?",
		Interactive: &notifications.Interactive{
			CallbackID: "req-1", Payload: "tok",
			Actions: []notifications.Action{
				{ID: "approve", Label: "OK", Style: "primary"},
				{ID: "reject", Label: "Cancel", Style: "danger"},
			},
		},
	})
	if !strings.Contains(js, `"type":"actions"`) {
		t.Fatalf("expected actions block: %s", js)
	}
	// action_id carries the decision; style is passed through from the producer.
	if !strings.Contains(js, `"action_id":"approve"`) || !strings.Contains(js, `"style":"primary"`) {
		t.Fatalf("approve button not rendered: %s", js)
	}
	if !strings.Contains(js, `"action_id":"reject"`) || !strings.Contains(js, `"style":"danger"`) {
		t.Fatalf("reject button not rendered: %s", js)
	}
	// button value carries the routing context as compact JSON.
	if !strings.Contains(js, `{\"s\":\"idp\",\"c\":\"req-1\",\"p\":\"tok\"}`) {
		t.Fatalf("button value context missing: %s", js)
	}
}

func TestBuildBlocks_NoActionsWhenNotInteractive(t *testing.T) {
	js := blocksJSON(t, &notifications.Message{Source: "svc", Content: "plain alert"})
	if strings.Contains(js, `"type":"actions"`) {
		t.Fatalf("unexpected actions block: %s", js)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/jrsue/dev/repos/platform/alerter/packages/notifier && go test ./cmd/ -run TestBuildBlocks_Interactive -v`
Expected: FAIL — no actions block rendered.

- [ ] **Step 3: Implement the action block**

Add to `cmd/slack.go` (and `"encoding/json"` to its imports):

```go
// buttonContext is the routing context embedded in each button's value. It is
// short-keyed to stay well under Slack's 2000-char value cap. The responder
// decodes the identical shape.
type buttonContext struct {
	Source     string `json:"s"`
	CallbackID string `json:"c"`
	Payload    string `json:"p,omitempty"`
}

func encodeButtonValue(source, callbackID, payload string) string {
	b, _ := json.Marshal(buttonContext{Source: source, CallbackID: callbackID, Payload: payload})
	return string(b)
}

// buildActionBlock renders the producer's buttons. The action_id carries the
// decision; the value carries routing context the responder echoes back.
func buildActionBlock(alert *notifications.Message) slack.Block {
	value := encodeButtonValue(alert.Source, alert.Interactive.CallbackID, alert.Interactive.Payload)
	if len(value) > 2000 {
		// Slack rejects values > 2000 chars; log so an oversized payload is visible.
		log.Warn().Int("len", len(value)).Str("source", alert.Source).
			Msg("Button value exceeds Slack 2000-char limit; click routing may fail")
	}
	elements := make([]slack.BlockElement, 0, len(alert.Interactive.Actions))
	for _, a := range alert.Interactive.Actions {
		btn := slack.NewButtonBlockElement(a.ID, value,
			slack.NewTextBlockObject(slack.PlainTextType, a.Label, false, false))
		if a.Style != "" {
			btn.Style = slack.Style(a.Style)
		}
		elements = append(elements, btn)
	}
	// block_id is the callbackId so the acted-on message is self-identifying in logs.
	return slack.NewActionBlock(alert.Interactive.CallbackID, elements...)
}
```

Then in `buildMessageBlocks`, append the action block when present:

```go
	blocks = append(blocks, bodyBlocks(alert)...)
	if alert.Interactive != nil && len(alert.Interactive.Actions) > 0 {
		blocks = append(blocks, buildActionBlock(alert))
	}
	return blocks
```

(Replace the existing `return append(blocks, bodyBlocks(alert)...)` tail accordingly.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/jrsue/dev/repos/platform/alerter/packages/notifier && go test ./... && gofmt -l .`
Expected: all tests PASS; `gofmt -l` prints nothing.

- [ ] **Step 5: Commit** (user-gated)

```bash
git add -A
git commit -m "feat(notifier): render interactive action buttons"
```

---

## Task 5: Scaffold the responder module

**Files:**
- Create: `alerter/packages/responder/go.mod`, `alerter/packages/responder/Makefile`, `alerter/packages/responder/cmd/main.go`

**Interfaces:**
- Produces: buildable module `isnan.eu/responder` with a Function URL handler stub that returns 200.

- [ ] **Step 1: Create `go.mod` with the dev replace**

`alerter/packages/responder/go.mod`:

```
module isnan.eu/responder

go 1.26

require (
	github.com/Maev4l/platform/notifications v1.2.0
	github.com/aws/aws-lambda-go v1.40.0
	github.com/aws/aws-sdk-go-v2 v1.24.0
	github.com/aws/aws-sdk-go-v2/config v1.26.1
	github.com/aws/aws-sdk-go-v2/service/sns v1.26.7
	github.com/aws/aws-sdk-go-v2/service/ssm v1.44.5
	github.com/rs/zerolog v1.35.1
	github.com/slack-go/slack v0.27.0
)
```

(`notifications@v1.2.0` is already published, so no `replace` is needed. The responder does
not import `notifications` directly today; `go mod tidy` in the next step reconciles exact
indirect versions and drops the require if genuinely unused.)

- [ ] **Step 2: Create the Makefile** (identical build recipe to the notifier, different zip name)

`alerter/packages/responder/Makefile`:

```make
# Build settings for AWS Lambda (ARM64)
GOOS := linux
GOARCH := arm64
LDFLAGS := -s -w

.PHONY: build package lint format clean

BIN_DIR := bin
PACKAGE_DIR := dist

build:
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/bootstrap ./cmd

package: build
	mkdir -p $(PACKAGE_DIR)
	cd $(BIN_DIR) && zip ../$(PACKAGE_DIR)/responder.zip bootstrap

lint:
	golangci-lint run ./...

format:
	golangci-lint fmt ./...

clean:
	rm -rf $(BIN_DIR)
```

- [ ] **Step 3: Create the handler stub**

`alerter/packages/responder/cmd/main.go`:

```go
package main

import (
	"context"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/rs/zerolog"
)

func handler(ctx context.Context, req events.LambdaFunctionURLRequest) (events.LambdaFunctionURLResponse, error) {
	return events.LambdaFunctionURLResponse{StatusCode: 200, Body: ""}, nil
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	lambda.Start(handler)
}
```

- [ ] **Step 4: Resolve deps and build**

Run: `cd /Users/jrsue/dev/repos/platform/alerter/packages/responder && go mod tidy && make build`
Expected: `go mod tidy` writes `go.sum`; `make build` produces `bin/bootstrap`.

- [ ] **Step 5: Commit** (user-gated)

```bash
git add alerter/packages/responder
git commit -m "feat(responder): scaffold Function URL lambda module"
```

---

## Task 6: Button-value context encode/decode

**Files:**
- Create: `alerter/packages/responder/cmd/context.go`, `alerter/packages/responder/cmd/context_test.go`

**Interfaces:**
- Produces: `type clickContext struct { Source, CallbackID, Payload string }` and `func decodeButtonValue(v string) (clickContext, error)` parsing `{"s","c","p"}`.

- [ ] **Step 1: Write the failing test**

`alerter/packages/responder/cmd/context_test.go`:

```go
package main

import "testing"

func TestDecodeButtonValue(t *testing.T) {
	c, err := decodeButtonValue(`{"s":"idp","c":"req-1","p":"tok"}`)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if c.Source != "idp" || c.CallbackID != "req-1" || c.Payload != "tok" {
		t.Fatalf("bad decode: %+v", c)
	}
}

func TestDecodeButtonValue_Invalid(t *testing.T) {
	if _, err := decodeButtonValue("not-json"); err == nil {
		t.Fatal("expected error for invalid value")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/jrsue/dev/repos/platform/alerter/packages/responder && go test ./cmd/ -run TestDecodeButtonValue -v`
Expected: FAIL — `undefined: decodeButtonValue`.

- [ ] **Step 3: Implement**

`alerter/packages/responder/cmd/context.go`:

```go
package main

import "encoding/json"

// clickContext is the routing context the notifier embedded in each button's
// value. Short keys mirror the notifier's encoder to fit Slack's 2000-char cap.
type clickContext struct {
	Source     string `json:"s"`
	CallbackID string `json:"c"`
	Payload    string `json:"p,omitempty"`
}

func decodeButtonValue(v string) (clickContext, error) {
	var c clickContext
	err := json.Unmarshal([]byte(v), &c)
	return c, err
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/jrsue/dev/repos/platform/alerter/packages/responder && go test ./cmd/ -run TestDecodeButtonValue -v && gofmt -l .`
Expected: PASS; `gofmt -l` prints nothing.

- [ ] **Step 5: Commit** (user-gated)

```bash
git add alerter/packages/responder/cmd/context.go alerter/packages/responder/cmd/context_test.go
git commit -m "feat(responder): decode button-value routing context"
```

---

## Task 7: Slack request-signature verification

**Files:**
- Create: `alerter/packages/responder/cmd/verify.go`, `alerter/packages/responder/cmd/verify_test.go`

**Interfaces:**
- Produces: `func verifySignature(headers map[string]string, body []byte, signingSecret string) error` — nil when valid, non-nil on bad signature or stale (>5 min) timestamp. Wraps `slack.NewSecretsVerifier`.

- [ ] **Step 1: Write the failing test** (compute a valid HMAC the same way Slack does)

`alerter/packages/responder/cmd/verify_test.go`:

```go
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

const testSecret = "shhh-signing-secret"

// slackSign reproduces Slack's v0 signature over "v0:{ts}:{body}".
func slackSign(ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(testSecret))
	fmt.Fprintf(mac, "v0:%s:%s", ts, body)
	return "v0=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifySignature_Valid(t *testing.T) {
	body := []byte("payload=%7B%7D")
	ts := fmt.Sprintf("%d", time.Now().Unix())
	headers := map[string]string{
		"x-slack-request-timestamp": ts,
		"x-slack-signature":         slackSign(ts, body),
	}
	if err := verifySignature(headers, body, testSecret); err != nil {
		t.Fatalf("expected valid signature, got %v", err)
	}
}

func TestVerifySignature_BadSignature(t *testing.T) {
	body := []byte("payload=%7B%7D")
	ts := fmt.Sprintf("%d", time.Now().Unix())
	headers := map[string]string{
		"x-slack-request-timestamp": ts,
		"x-slack-signature":         "v0=deadbeef",
	}
	if err := verifySignature(headers, body, testSecret); err == nil {
		t.Fatal("expected error for bad signature")
	}
}

func TestVerifySignature_StaleTimestamp(t *testing.T) {
	body := []byte("payload=%7B%7D")
	ts := fmt.Sprintf("%d", time.Now().Add(-10*time.Minute).Unix())
	headers := map[string]string{
		"x-slack-request-timestamp": ts,
		"x-slack-signature":         slackSign(ts, body),
	}
	if err := verifySignature(headers, body, testSecret); err == nil {
		t.Fatal("expected error for stale timestamp (replay window)")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/jrsue/dev/repos/platform/alerter/packages/responder && go test ./cmd/ -run TestVerifySignature -v`
Expected: FAIL — `undefined: verifySignature`.

- [ ] **Step 3: Implement**

`alerter/packages/responder/cmd/verify.go`:

```go
package main

import (
	"net/http"

	"github.com/slack-go/slack"
)

// verifySignature validates Slack's request signature and rejects stale
// requests (>5 min). slack.NewSecretsVerifier enforces the timestamp window
// and HMAC comparison; we only adapt the Function URL header map to http.Header.
func verifySignature(headers map[string]string, body []byte, signingSecret string) error {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v) // http.Header canonicalises keys; Function URL sends them lowercased
	}
	sv, err := slack.NewSecretsVerifier(h, signingSecret)
	if err != nil {
		return err
	}
	if _, err := sv.Write(body); err != nil {
		return err
	}
	return sv.Ensure()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/jrsue/dev/repos/platform/alerter/packages/responder && go test ./cmd/ -run TestVerifySignature -v && gofmt -l .`
Expected: all three PASS; `gofmt -l` prints nothing.

- [ ] **Step 5: Commit** (user-gated)

```bash
git add alerter/packages/responder/cmd/verify.go alerter/packages/responder/cmd/verify_test.go
git commit -m "feat(responder): verify Slack request signatures"
```

---

## Task 8: Operator allow-list

**Files:**
- Create: `alerter/packages/responder/cmd/authz.go`, `alerter/packages/responder/cmd/authz_test.go`

**Interfaces:**
- Produces: `func parseOperators(csv string) map[string]struct{}` and `func isAllowed(allow map[string]struct{}, userID string) bool`.

- [ ] **Step 1: Write the failing test**

`alerter/packages/responder/cmd/authz_test.go`:

```go
package main

import "testing"

func TestParseOperatorsAndAllow(t *testing.T) {
	allow := parseOperators(" U1 , U2 ,, U3 ") // tolerate spaces + empty entries
	if len(allow) != 3 {
		t.Fatalf("expected 3 operators, got %d", len(allow))
	}
	if !isAllowed(allow, "U2") {
		t.Fatal("U2 should be allowed")
	}
	if isAllowed(allow, "U9") {
		t.Fatal("U9 should NOT be allowed")
	}
}

func TestIsAllowed_EmptyListDeniesAll(t *testing.T) {
	if isAllowed(parseOperators(""), "U1") {
		t.Fatal("empty allow-list must deny everyone")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/jrsue/dev/repos/platform/alerter/packages/responder && go test ./cmd/ -run "TestParseOperators|TestIsAllowed" -v`
Expected: FAIL — `undefined: parseOperators`.

- [ ] **Step 3: Implement**

`alerter/packages/responder/cmd/authz.go`:

```go
package main

import "strings"

// parseOperators turns the comma-separated SSM value into a set, tolerating
// surrounding spaces and empty entries.
func parseOperators(csv string) map[string]struct{} {
	allow := map[string]struct{}{}
	for _, id := range strings.Split(csv, ",") {
		if id = strings.TrimSpace(id); id != "" {
			allow[id] = struct{}{}
		}
	}
	return allow
}

func isAllowed(allow map[string]struct{}, userID string) bool {
	_, ok := allow[userID]
	return ok
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/jrsue/dev/repos/platform/alerter/packages/responder && go test ./cmd/ -run "TestParseOperators|TestIsAllowed" -v && gofmt -l .`
Expected: PASS; `gofmt -l` prints nothing.

- [ ] **Step 5: Commit** (user-gated)

```bash
git add alerter/packages/responder/cmd/authz.go alerter/packages/responder/cmd/authz_test.go
git commit -m "feat(responder): operator allow-list"
```

---

## Task 9: `response_url` message builders

**Files:**
- Create: `alerter/packages/responder/cmd/respond.go`, `alerter/packages/responder/cmd/respond_test.go`

**Interfaces:**
- Produces:
  - `func confirmationMessage(original slack.Blocks, actionLabel, userName string) *slack.WebhookMessage` — `replace_original`, original blocks minus any actions block, plus a confirmation context line.
  - `func rejectionMessage(text string) *slack.WebhookMessage` — ephemeral, `replace_original:false`.

- [ ] **Step 1: Write the failing test**

`alerter/packages/responder/cmd/respond_test.go`:

```go
package main

import (
	"testing"

	"github.com/slack-go/slack"
)

func TestConfirmationMessage_DropsActionsAddsContext(t *testing.T) {
	original := slack.Blocks{BlockSet: []slack.Block{
		slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, "Approve deploy?", false, false), nil, nil),
		slack.NewActionBlock("req-1", slack.NewButtonBlockElement("approve", "{}",
			slack.NewTextBlockObject(slack.PlainTextType, "OK", false, false))),
	}}
	msg := confirmationMessage(original, "OK", "jsue")

	if !msg.ReplaceOriginal {
		t.Fatal("confirmation must replace the original message")
	}
	for _, b := range msg.Blocks.BlockSet {
		if b.BlockType() == slack.MBTAction {
			t.Fatal("actions block must be removed so buttons can't be re-clicked")
		}
	}
	// Original content is preserved (still one section) + a confirmation context line.
	var sections, contexts int
	for _, b := range msg.Blocks.BlockSet {
		switch b.BlockType() {
		case slack.MBTSection:
			sections++
		case slack.MBTContext:
			contexts++
		}
	}
	if sections != 1 || contexts != 1 {
		t.Fatalf("expected 1 section + 1 context, got %d/%d", sections, contexts)
	}
}

func TestRejectionMessage_IsEphemeral(t *testing.T) {
	msg := rejectionMessage("nope")
	if msg.ResponseType != "ephemeral" {
		t.Fatalf("expected ephemeral, got %q", msg.ResponseType)
	}
	if msg.ReplaceOriginal {
		t.Fatal("rejection must NOT replace the original (buttons stay for authorised users)")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/jrsue/dev/repos/platform/alerter/packages/responder && go test ./cmd/ -run "TestConfirmationMessage|TestRejectionMessage" -v`
Expected: FAIL — `undefined: confirmationMessage`.

- [ ] **Step 3: Implement**

`alerter/packages/responder/cmd/respond.go`:

```go
package main

import (
	"fmt"

	"github.com/slack-go/slack"
)

// confirmationMessage replaces the original alert: it keeps the original blocks
// but strips the actions block (so buttons can't be re-clicked) and appends a
// context line naming who acted. This is the Level-1 stateless double-click guard.
func confirmationMessage(original slack.Blocks, actionLabel, userName string) *slack.WebhookMessage {
	kept := make([]slack.Block, 0, len(original.BlockSet)+1)
	for _, b := range original.BlockSet {
		if b.BlockType() == slack.MBTAction {
			continue // drop buttons
		}
		kept = append(kept, b)
	}
	kept = append(kept, slack.NewContextBlock("",
		slack.NewTextBlockObject(slack.MarkdownType,
			fmt.Sprintf(":white_check_mark: *%s* by <@%s>", actionLabel, userName), false, false)))

	return &slack.WebhookMessage{
		ReplaceOriginal: true,
		Blocks:          &slack.Blocks{BlockSet: kept},
	}
}

// rejectionMessage is a private notice to an unauthorised clicker. It does not
// touch the shared message, so the buttons remain for an authorised operator.
func rejectionMessage(text string) *slack.WebhookMessage {
	return &slack.WebhookMessage{
		ResponseType:    "ephemeral",
		ReplaceOriginal: false,
		Text:            text,
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/jrsue/dev/repos/platform/alerter/packages/responder && go test ./cmd/ -run "TestConfirmationMessage|TestRejectionMessage" -v && gofmt -l .`
Expected: PASS; `gofmt -l` prints nothing.

- [ ] **Step 5: Commit** (user-gated)

```bash
git add alerter/packages/responder/cmd/respond.go alerter/packages/responder/cmd/respond_test.go
git commit -m "feat(responder): response_url confirmation + ephemeral rejection builders"
```

---

## Task 10: Wire the responder handler (init, parse, authorise, publish, respond)

**Files:**
- Modify: `alerter/packages/responder/cmd/main.go`

**Interfaces:**
- Consumes: `verifySignature`, `decodeButtonValue`, `parseOperators`/`isAllowed`, `confirmationMessage`/`rejectionMessage`.
- Produces: the full Function URL handler; `responsePayload` JSON published to SNS.

- [ ] **Step 1: Write the failing test for the published payload shape**

`alerter/packages/responder/cmd/publish_test.go`:

```go
package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildResponsePayload(t *testing.T) {
	c := clickContext{Source: "idp", CallbackID: "req-1", Payload: "tok"}
	b, err := buildResponsePayload(c, "approve", "U1", "jsue", "C05", "169.1")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"source", "callbackId", "action", "payload", "user", "channel", "ts"} {
		if _, ok := got[k]; !ok {
			t.Fatalf("missing key %q in %s", k, b)
		}
	}
	if !strings.Contains(string(b), `"action":"approve"`) {
		t.Fatalf("action not set: %s", b)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/jrsue/dev/repos/platform/alerter/packages/responder && go test ./cmd/ -run TestBuildResponsePayload -v`
Expected: FAIL — `undefined: buildResponsePayload`.

- [ ] **Step 3: Implement the full handler**

Replace `alerter/packages/responder/cmd/main.go`:

```go
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/slack-go/slack"
)

// Env vars hold SSM parameter NAMES (fetched at cold start) and the topic ARN.
var (
	signingSecretParam = os.Getenv("SLACK_SIGNING_SECRET") // SSM name
	operatorsParam     = os.Getenv("SLACK_OPERATORS")      // SSM name
	responsesTopicArn  = os.Getenv("RESPONSES_TOPIC_ARN")

	signingSecret string
	operators     map[string]struct{}
	snsClient     *sns.Client
)

// responsePayload is the SNS body producers consume.
type responsePayload struct {
	Source     string    `json:"source"`
	CallbackID string    `json:"callbackId"`
	Action     string    `json:"action"`
	Payload    string    `json:"payload,omitempty"`
	User       slackUser `json:"user"`
	Channel    string    `json:"channel"`
	Ts         string    `json:"ts"`
}

type slackUser struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func buildResponsePayload(c clickContext, action, userID, userName, channel, ts string) ([]byte, error) {
	return json.Marshal(responsePayload{
		Source: c.Source, CallbackID: c.CallbackID, Action: action, Payload: c.Payload,
		User: slackUser{ID: userID, Name: userName}, Channel: channel, Ts: ts,
	})
}

func getSSMParam(ssmClient *ssm.Client, name string) string {
	withDecryption := true
	out, err := ssmClient.GetParameter(context.Background(), &ssm.GetParameterInput{
		Name: &name, WithDecryption: &withDecryption,
	})
	if err != nil {
		log.Fatal().Err(err).Str("parameter", name).Msg("Failed to get SSM parameter")
	}
	return *out.Parameter.Value
}

// ack returns 200 so Slack never retries; the button was already consumed on
// the first successful click, so re-delivery would only double-publish.
func ack() (events.LambdaFunctionURLResponse, error) {
	return events.LambdaFunctionURLResponse{StatusCode: 200}, nil
}

func handler(ctx context.Context, req events.LambdaFunctionURLRequest) (events.LambdaFunctionURLResponse, error) {
	body := []byte(req.Body)
	if req.IsBase64Encoded {
		decoded, err := base64.StdEncoding.DecodeString(req.Body)
		if err != nil {
			log.Error().Err(err).Msg("Failed to decode base64 body")
			return events.LambdaFunctionURLResponse{StatusCode: 400}, nil
		}
		body = decoded
	}

	// Gate 1: the request must be genuinely from Slack and fresh.
	if err := verifySignature(req.Headers, body, signingSecret); err != nil {
		log.Warn().Err(err).Msg("Slack signature verification failed")
		return events.LambdaFunctionURLResponse{StatusCode: 401}, nil
	}

	// Slack sends application/x-www-form-urlencoded with payload=<json>.
	form, err := url.ParseQuery(string(body))
	if err != nil {
		log.Error().Err(err).Msg("Failed to parse form body")
		return events.LambdaFunctionURLResponse{StatusCode: 400}, nil
	}
	var cb slack.InteractionCallback
	if err := json.Unmarshal([]byte(form.Get("payload")), &cb); err != nil {
		log.Error().Err(err).Msg("Failed to parse interaction payload")
		return events.LambdaFunctionURLResponse{StatusCode: 400}, nil
	}

	actions := cb.ActionCallback.BlockActions
	if len(actions) == 0 {
		log.Warn().Msg("Interaction has no block actions; ignoring")
		return ack()
	}
	ba := actions[0]

	clickCtx, err := decodeButtonValue(ba.Value)
	if err != nil {
		log.Error().Err(err).Msg("Failed to decode button value; ignoring")
		return ack()
	}

	// Gate 2: only allow-listed operators fire the action.
	if !isAllowed(operators, cb.User.ID) {
		log.Warn().Str("user", cb.User.ID).Str("callbackId", clickCtx.CallbackID).Msg("Unauthorised click")
		if err := slack.PostWebhookContext(ctx, cb.ResponseURL,
			rejectionMessage(":x: You're not authorized to act on this alert.")); err != nil {
			log.Error().Err(err).Msg("Failed to post rejection")
		}
		return ack()
	}

	// Relay the decision to producers.
	payload, err := buildResponsePayload(clickCtx, ba.ActionID, cb.User.ID, cb.User.Name, cb.Channel.ID, cb.Message.Timestamp)
	if err != nil {
		log.Error().Err(err).Msg("Failed to build response payload")
		return ack()
	}
	if _, err := snsClient.Publish(ctx, &sns.PublishInput{
		TopicArn: &responsesTopicArn,
		Message:  aws.String(string(payload)),
		// source attribute lets producers filter-policy their subscription.
		MessageAttributes: map[string]snstypes.MessageAttributeValue{
			"source": {DataType: aws.String("String"), StringValue: aws.String(clickCtx.Source)},
		},
	}); err != nil {
		// Log and still ack: retries risk double-publishing.
		log.Error().Err(err).Str("callbackId", clickCtx.CallbackID).Msg("Failed to publish response")
		return ack()
	}

	// Consume the buttons + confirm who acted.
	if err := slack.PostWebhookContext(ctx, cb.ResponseURL,
		confirmationMessage(cb.Message.Blocks, ba.Text.Text, cb.User.Name)); err != nil {
		log.Error().Err(err).Msg("Failed to update original message")
	}

	log.Info().Str("action", ba.ActionID).Str("callbackId", clickCtx.CallbackID).
		Str("user", cb.User.ID).Msg("Decision relayed")
	return ack()
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to load AWS SDK config")
	}
	ssmClient := ssm.NewFromConfig(cfg)
	signingSecret = getSSMParam(ssmClient, signingSecretParam)
	operators = parseOperators(getSSMParam(ssmClient, operatorsParam))
	snsClient = sns.NewFromConfig(cfg)

	lambda.Start(handler)
}
```

- [ ] **Step 4: Run tests + build**

Run: `cd /Users/jrsue/dev/repos/platform/alerter/packages/responder && go mod tidy && go test ./... && make build && gofmt -l .`
Expected: all tests PASS; `bin/bootstrap` builds; `gofmt -l` prints nothing.

> If `cb.Message.Timestamp` does not resolve against the pinned slack-go version, use `cb.Container.MessageTs` (both denote the acted-on message ts). Verify with `go build` before proceeding.

- [ ] **Step 5: Commit** (user-gated)

```bash
git add alerter/packages/responder/cmd
git commit -m "feat(responder): wire signature check, authz, publish, and message update"
```

---

## Task 11: Terraform — responses topic, responder Lambda, Function URL, IAM, outputs

> **Post-implementation amendments (applied):**
> - `terraform-modules` ref bumped **v1.6.0 → v1.8.0** on all module sources (lambda-function ×2, lambda-trigger-sns).
> - Both Lambda modules consolidated into **`functions.tf`** (notifier `alerter_function` + `sns_trigger`; responder `responder_function` + `aws_lambda_function_url` + `aws_lambda_permission`). No standalone `responder.tf`; the notifier modules moved out of `main.tf`.
> - The topic-ARN discovery **`aws_ssm_parameter "responses_topic_arn"` was dropped** — producers read the `responses_topic_arn` output or resolve `data "aws_sns_topic" { name = "alerting-responses" }` in their own stack.
> - Lambda env vars are unchanged: they carry SSM parameter **names** (not secret values); Lambdas fetch the values from SSM at startup.

**Files:**
- Modify: `alerter/packages/infrastructure/sns.tf`, `alerter/packages/infrastructure/iam.tf`, `alerter/packages/infrastructure/main.tf`
- Create: `alerter/packages/infrastructure/functions.tf`, `alerter/packages/infrastructure/outputs.tf`

**Interfaces:**
- Consumes: `module.alerter_function` (existing), `data.aws_caller_identity.current`, `local.slack_token_param_name`.
- Produces: `aws_sns_topic.alerting_responses`, `aws_lambda_function_url.responder`, outputs `responder_function_url`, `responses_topic_arn`.

- [ ] **Step 1: Add the responses topic, its subscribe policy, ARN SSM param, and locals**

Append to `alerter/packages/infrastructure/sns.tf`:

```hcl
# Decisions from button clicks. The alerter owns this topic; producers subscribe
# their own Lambda/SQS (with a {"source":[...]} filter policy) from their stacks.
resource "aws_sns_topic" "alerting_responses" {
  name = "alerting-responses"
}

# Same-account producers may self-subscribe without the alerter knowing them.
data "aws_iam_policy_document" "responses_topic_policy" {
  statement {
    sid     = "AllowAccountSubscribe"
    effect  = "Allow"
    actions = ["sns:Subscribe"]
    principals {
      type        = "AWS"
      identifiers = [data.aws_caller_identity.current.account_id]
    }
    resources = [aws_sns_topic.alerting_responses.arn]
  }
}

resource "aws_sns_topic_policy" "alerting_responses" {
  arn    = aws_sns_topic.alerting_responses.arn
  policy = data.aws_iam_policy_document.responses_topic_policy.json
}
```

> (Amended: no `aws_ssm_parameter` for the topic ARN — producers use the
> `responses_topic_arn` output or a `data "aws_sns_topic"` lookup.)

Add the two new SSM param names to `locals` in `main.tf`:

```hcl
locals {
  slack_token_param_name          = "slack.alerting.token"
  slack_signing_secret_param_name = "slack.alerting.signing_secret"
  slack_operators_param_name      = "slack.alerting.operators"
}
```

- [ ] **Step 2: Add the responder IAM policy**

Append to `alerter/packages/infrastructure/iam.tf`:

```hcl
# Responder: read its two SSM secrets and publish decisions to the responses topic.
data "aws_iam_policy_document" "responder" {
  statement {
    effect  = "Allow"
    actions = ["ssm:GetParameter"]
    resources = [
      "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/${local.slack_signing_secret_param_name}",
      "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/${local.slack_operators_param_name}",
    ]
  }
  statement {
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerting_responses.arn]
  }
}

resource "aws_iam_policy" "responder" {
  name        = "platform-notifier-responder-policy"
  description = "Allow responder Lambda to read SSM secrets and publish responses"
  policy      = data.aws_iam_policy_document.responder.json
}
```

- [ ] **Step 3: Add the responder Lambda + Function URL**

Add to `alerter/packages/infrastructure/functions.tf` (alongside the notifier modules):

```hcl
module "responder_function" {
  source        = "github.com/Maev4l/terraform-modules//modules/lambda-function?ref=v1.8.0"
  function_name = "platform-notifier-responder"
  zip = {
    filename = "../responder/dist/responder.zip"
    runtime  = "provided.al2023"
    handler  = "bootstrap"
    hash     = filebase64sha256("../responder/bin/bootstrap")
  }
  architecture = "arm64"

  environment_variables = {
    "SLACK_SIGNING_SECRET" : local.slack_signing_secret_param_name # SSM name
    "SLACK_OPERATORS" : local.slack_operators_param_name           # SSM name
    "RESPONSES_TOPIC_ARN" : aws_sns_topic.alerting_responses.arn
  }

  additional_policy_arns = [aws_iam_policy.responder.arn]
}

# Public HTTPS endpoint for Slack's interactivity request URL. Security is the
# Slack request signature (verified in-code), so no AWS auth on the URL itself.
resource "aws_lambda_function_url" "responder" {
  function_name      = module.responder_function.function_name
  authorization_type = "NONE"
}

# AuthType NONE still requires an explicit invoke permission.
resource "aws_lambda_permission" "responder_url" {
  statement_id           = "AllowFunctionURLInvoke"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = module.responder_function.function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}
```

- [ ] **Step 4: Add outputs**

Create `alerter/packages/infrastructure/outputs.tf`:

```hcl
output "responder_function_url" {
  description = "Set this as the Slack app Interactivity Request URL"
  value       = aws_lambda_function_url.responder.function_url
}

output "responses_topic_arn" {
  description = "SNS topic producers subscribe to for button decisions"
  value       = aws_sns_topic.alerting_responses.arn
}
```

- [ ] **Step 5: Package both functions, then validate the Terraform**

Run:
```bash
make -C /Users/jrsue/dev/repos/platform/alerter/packages/notifier package
make -C /Users/jrsue/dev/repos/platform/alerter/packages/responder package
terraform -chdir=/Users/jrsue/dev/repos/platform/alerter/packages/infrastructure init -backend=false
terraform -chdir=/Users/jrsue/dev/repos/platform/alerter/packages/infrastructure validate
```
Expected: both zips build; `Success! The configuration is valid.`

- [ ] **Step 6: Commit** (user-gated)

```bash
git add alerter/packages/infrastructure
git commit -m "feat(alerter-infra): responses topic, responder lambda, function URL, IAM"
```

---

## Task 12: Root Makefile + README/docs

**Files:**
- Modify: `alerter/Makefile`, `alerter/README.md`

**Interfaces:** none (build orchestration + docs).

- [ ] **Step 1: Rewrite the root Makefile to build both packages**

`alerter/Makefile`:

```make
.PHONY: backend-deploy infra-plan infra-apply

NOTIFIER  := packages/notifier
RESPONDER := packages/responder
INFRA     := packages/infrastructure

# Full deploy: package both zips, then apply the infra.
backend-deploy:
	$(MAKE) -C $(NOTIFIER) package
	$(MAKE) -C $(RESPONDER) package
	$(MAKE) infra-apply

infra-plan:
	$(MAKE) -C $(NOTIFIER) package
	$(MAKE) -C $(RESPONDER) package
	terraform -chdir=$(INFRA) plan

infra-apply:
	terraform -chdir=$(INFRA) apply -auto-approve
```

(`infra-plan` now packages first so `filebase64sha256` on the binaries resolves.)

- [ ] **Step 2: Update the README**

Add to `alerter/README.md`: (a) the new `packages/` layout, (b) the interactive contract, (c) the response contract, (d) one-time Slack setup. Append:

````markdown
## Interactive alerts (buttons)

Attach buttons by adding an `interactive` block to the message:

```json
{
  "target": "slack",
  "source": "idp",
  "sourceDescription": "IdP",
  "content": "Approve deploy to **prod**?",
  "interactive": {
    "callbackId": "deploy-123",
    "payload": "opaque-token-echoed-back",
    "actions": [
      { "id": "approve", "label": "OK", "style": "primary" },
      { "id": "reject",  "label": "Cancel", "style": "danger" }
    ]
  }
}
```

- `id` is echoed back as the decision's `action`. `style` (`primary`/`danger`) is the producer's choice.
- Keep `payload` small — it rides inside the Slack button value (2000-char cap).

### Response contract (SNS topic `alerting-responses`)

On a click by an allow-listed operator, the responder publishes (with a `source` message attribute):

```json
{
  "source": "idp", "callbackId": "deploy-123", "action": "approve",
  "payload": "opaque-token-echoed-back",
  "user": { "id": "U123", "name": "jsue" }, "channel": "C05...", "ts": "169..."
}
```

Subscribe your own Lambda/SQS to the topic with a filter policy `{"source":["<your-source>"]}`.
Discover the topic ARN from the `responses_topic_arn` Terraform output, or resolve it with a
`data "aws_sns_topic" { name = "alerting-responses" }` lookup in your own stack.

### One-time Slack setup

1. `terraform output responder_function_url` → set it as **Interactivity → Request URL** in the Slack app.
2. SSM params (SecureString): `slack.alerting.signing_secret` (app signing secret), `slack.alerting.operators` (comma-separated `U…` user IDs).
````

- [ ] **Step 3: Verify docs build (lint markdown is optional) and Makefile targets resolve**

Run: `make -C /Users/jrsue/dev/repos/platform/alerter infra-plan` is **not** run here (needs AWS creds/state). Instead dry-check the Makefile: `make -C /Users/jrsue/dev/repos/platform/alerter -n backend-deploy`
Expected: prints the notifier package, responder package, and terraform apply commands with no error.

- [ ] **Step 4: Commit** (user-gated)

```bash
git add alerter/Makefile alerter/README.md
git commit -m "docs(alerter): packages layout, interactive + response contracts, Slack setup"
```

---

## Task 13: Release `notifications v1.2.0` — ✅ DONE

Brought forward and completed (see Task 2). The module is tagged and pushed; no `replace`
directives were introduced, so there is nothing to unwind. Downstream go.mod bumps happen
in-place: notifier in Task 4 Step 0, responder in Task 5 Step 1.

---

## Self-Review

**Spec coverage:**
- Generic/configurable action, SNS responses topic → Tasks 10, 11. ✅
- Message contract `Interactive`/`Action` → Task 2. ✅
- Stateless button context (`{"s","c","p"}`, ≤2000) → Tasks 4, 6. ✅
- Response delivery + `source` attribute + producer-side subscribe policy → Tasks 10, 11. ✅
- Authorization: signature (≤5 min) + allow-list → Tasks 7, 8, 10. ✅
- Ephemeral rejection; success replace_original dropping buttons → Task 9. ✅
- Level-1 stateless double-click guard → Task 9 (confirmationMessage drops actions). ✅
- Lambda Function URL, no bot token on responder → Tasks 5, 10, 11. ✅
- `packages/{notifier,responder,infrastructure}` layout → Task 1. ✅
- Remove Target abstraction, no producer changes → Task 3. ✅
- SSM params, Slack setup docs → Tasks 11, 12. ✅
- `notifications v1.2.0` release → done ahead of plan (Tasks 2 & 13 complete); go.mod bumps in Task 4 Step 0 (notifier) + Task 5 (responder). ✅
- Error-handling table (401/400/200 behaviors) → Task 10 handler. ✅

**Placeholder scan:** none — every code/step is concrete.

**Type consistency:** `buttonContext{s,c,p}` (notifier) ↔ `clickContext{s,c,p}` (responder) share the JSON shape; `buildResponsePayload` field set matches the README response contract; `confirmationMessage`/`rejectionMessage` signatures match their call sites in Task 10.

**Known version-sensitive spot:** `cb.Message.Timestamp` vs `cb.Container.MessageTs` (Task 10, Step 4 note) — resolved at build time against pinned slack-go v0.27.0.
