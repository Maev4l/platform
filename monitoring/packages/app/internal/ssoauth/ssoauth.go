// Package ssoauth implements the IAM Identity Center OIDC device-authorization
// flow without requiring the AWS CLI. It caches the resulting SSO access token
// on disk and derives short-lived role credentials on demand.
package ssoauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	oidctypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
	"github.com/pkg/browser"
	"github.com/rs/zerolog/log"
)

// Config holds the parameters needed to perform the SSO device-authorization
// flow and to obtain role credentials from IAM Identity Center.
type Config struct {
	StartURL  string
	SSORegion string
	AccountID string
	RoleName  string
}

// cachedToken is the on-disk representation of a short-lived SSO access token.
type cachedToken struct {
	AccessToken string    `json:"accessToken"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

// valid returns true when the token is non-empty and not yet expired.
func (t cachedToken) valid() bool { return t.AccessToken != "" && time.Now().Before(t.ExpiresAt) }

// cachePath resolves (and creates if needed) the directory that holds sso.json.
func cachePath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	d := filepath.Join(dir, "monitoring")
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(d, "sso.json"), nil
}

// loadToken deserializes a cachedToken from the given file path.
func loadToken(path string) (cachedToken, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return cachedToken{}, err
	}
	var t cachedToken
	return t, json.Unmarshal(b, &t)
}

// saveToken serializes the token to disk with mode 0600 (owner-read/write only)
// so the access token is not world-readable.
func saveToken(path string, t cachedToken) error {
	b, _ := json.Marshal(t)
	return os.WriteFile(path, b, 0o600)
}

// Login returns an AWS CredentialsProvider backed by SSO role credentials.
// It first attempts to reuse a cached SSO access token; on a cache miss or
// expiry it runs the full device-authorization flow and caches the new token.
func Login(ctx context.Context, c Config) (aws.CredentialsProvider, error) {
	path, err := cachePath()
	if err != nil {
		return nil, err
	}

	tok, err := loadToken(path)
	if err != nil || !tok.valid() {
		// Cache miss or expired — run the interactive device flow.
		tok, err = deviceFlow(ctx, c)
		if err != nil {
			return nil, err
		}
		// Best-effort cache write: a failure here is non-fatal; the user will
		// just need to re-authenticate next time.
		if err := saveToken(path, tok); err != nil {
			log.Warn().Err(err).Msg("could not cache SSO token")
		}
	}

	// SSO and SSOOIDC calls to IdC are unauthenticated at the HTTP level —
	// the SSO access token is passed as a header, not as AWS SigV4 credentials.
	ssoClient := sso.New(sso.Options{
		Region:      c.SSORegion,
		Credentials: aws.AnonymousCredentials{},
	})
	provider := &roleProvider{
		client:    ssoClient,
		accountID: c.AccountID,
		roleName:  c.RoleName,
		token:     tok.AccessToken,
	}
	// Wrap in CredentialsCache so role credentials are refreshed automatically
	// before expiry without re-entering the device flow.
	return aws.NewCredentialsCache(provider), nil
}

// deviceFlow performs the OIDC device-authorization grant:
//  1. RegisterClient — obtain a public client registration.
//  2. StartDeviceAuthorization — obtain a device code and verification URL.
//  3. Open the browser to the verification URL.
//  4. Poll CreateToken until the user approves or the context is cancelled.
func deviceFlow(ctx context.Context, c Config) (cachedToken, error) {
	// SSOOIDC calls are unauthenticated — the bearer token replaces SigV4.
	oidcClient := ssooidc.New(ssooidc.Options{
		Region:      c.SSORegion,
		Credentials: aws.AnonymousCredentials{},
	})

	reg, err := oidcClient.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName: aws.String("monitoring"),
		ClientType: aws.String("public"),
	})
	if err != nil {
		return cachedToken{}, fmt.Errorf("register client: %w", err)
	}

	dev, err := oidcClient.StartDeviceAuthorization(ctx, &ssooidc.StartDeviceAuthorizationInput{
		ClientId:     reg.ClientId,
		ClientSecret: reg.ClientSecret,
		StartUrl:     aws.String(c.StartURL),
	})
	if err != nil {
		return cachedToken{}, fmt.Errorf("start device auth: %w", err)
	}

	log.Info().Msgf("Opening browser to approve sign-in. If it doesn't open, visit: %s", aws.ToString(dev.VerificationUriComplete))
	_ = browser.OpenURL(aws.ToString(dev.VerificationUriComplete))

	// Use the interval suggested by the server; fall back to 5 s if absent.
	interval := time.Duration(dev.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	for {
		out, err := oidcClient.CreateToken(ctx, &ssooidc.CreateTokenInput{
			ClientId:     reg.ClientId,
			ClientSecret: reg.ClientSecret,
			GrantType:    aws.String("urn:ietf:params:oauth:grant-type:device_code"),
			DeviceCode:   dev.DeviceCode,
		})
		if err == nil {
			return cachedToken{
				AccessToken: aws.ToString(out.AccessToken),
				ExpiresAt:   time.Now().Add(time.Duration(out.ExpiresIn) * time.Second),
			}, nil
		}

		var pending *oidctypes.AuthorizationPendingException
		var slow *oidctypes.SlowDownException
		switch {
		case errors.As(err, &pending):
			// User hasn't approved yet — wait the prescribed interval.
			time.Sleep(interval)
		case errors.As(err, &slow):
			// Server asked us to back off — add 5 s per RFC 8628 §3.5.
			interval += 5 * time.Second
			time.Sleep(interval)
		default:
			return cachedToken{}, fmt.Errorf("create token: %w", err)
		}

		// Respect context cancellation even while sleeping.
		if ctx.Err() != nil {
			return cachedToken{}, ctx.Err()
		}
	}
}

// roleProvider implements aws.CredentialsProvider by exchanging the SSO
// access token for short-lived role credentials on each Retrieve call.
// CredentialsCache (wrapping this) ensures Retrieve is not called more often
// than necessary.
type roleProvider struct {
	client    *sso.Client
	accountID string
	roleName  string
	token     string
}

// Retrieve calls sso:GetRoleCredentials and maps the response to aws.Credentials.
// The Expiration field in the SSO response is Unix milliseconds.
func (p *roleProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	out, err := p.client.GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{
		AccessToken: aws.String(p.token),
		AccountId:   aws.String(p.accountID),
		RoleName:    aws.String(p.roleName),
	})
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("get role credentials: %w", err)
	}
	rc := out.RoleCredentials
	return aws.Credentials{
		AccessKeyID:     aws.ToString(rc.AccessKeyId),
		SecretAccessKey: aws.ToString(rc.SecretAccessKey),
		SessionToken:    aws.ToString(rc.SessionToken),
		CanExpire:       true,
		// SSO returns expiration as Unix milliseconds.
		Expires: time.UnixMilli(rc.Expiration),
	}, nil
}
