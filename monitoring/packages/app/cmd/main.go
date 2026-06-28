package main

import (
	"fmt"
	"net"
	"os"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/gin-gonic/gin"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/v2"
	"github.com/pkg/browser"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	athenacli "isnan.eu/monitoring/internal/athena"
	"isnan.eu/monitoring/internal/cache"
	"isnan.eu/monitoring/internal/config"
	"isnan.eu/monitoring/internal/geo"
	"isnan.eu/monitoring/internal/handlers"
	"isnan.eu/monitoring/internal/ssoauth"
)

func main() {
	log.Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
	gin.SetMode(gin.ReleaseMode) // keep logs clean zerolog JSON (no Gin debug banner)
	if err := newRootCmd().Execute(); err != nil {
		log.Fatal().Err(err).Msg("monitoring")
	}
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "monitoring",
		Short:         "CloudFront access-log analytics dashboard (local)",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          run,
	}
	f := cmd.Flags()
	f.String("sso-start-url", "", "IAM Identity Center start URL")
	f.String("sso-region", "", "IAM Identity Center region")
	f.String("account-id", "", "AWS account id")
	f.String("sso-role", "", "IdC permission-set / role name")
	// Port 0 → OS assigns a free port (no collisions). Dev passes 127.0.0.1:8080
	// so Vite's /api proxy can find it.
	f.String("addr", "127.0.0.1:0", "listen address (host:port; port 0 = auto-select)")
	return cmd
}

// cliEnvMap maps process env vars to the CLI flag keys koanf merges them into.
var cliEnvMap = map[string]string{
	"MONITORING_SSO_START_URL": "sso-start-url",
	"MONITORING_SSO_REGION":    "sso-region",
	"AWS_ACCOUNT_ID":           "account-id",
	"MONITORING_SSO_ROLE":      "sso-role",
	"ADDR":                     "addr",
}

func run(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()

	// koanf merges env vars with CLI flags. Passing the koanf instance to the
	// posflag provider makes an explicitly-set flag win, else the env var, else
	// the flag default.
	k := koanf.New(".")
	_ = k.Load(env.Provider("", ".", func(s string) string { return cliEnvMap[s] }), nil)
	_ = k.Load(posflag.Provider(cmd.Flags(), ".", k), nil)

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	// 1. Authenticate with IAM Identity Center (device flow on cold cache).
	creds, err := ssoauth.Login(ctx, ssoauth.Config{
		StartURL:  k.String("sso-start-url"),
		SSORegion: k.String("sso-region"),
		AccountID: k.String("account-id"),
		RoleName:  k.String("sso-role"),
	})
	if err != nil {
		return fmt.Errorf("sso login: %w", err)
	}

	// 2. AWS config (Athena region) using the IdC credentials.
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.Region),
		awsconfig.WithCredentialsProvider(creds),
	)
	if err != nil {
		return fmt.Errorf("aws config: %w", err)
	}

	// 3. GeoIP — auto-update at startup (default on), then open; tolerate no DB.
	// When credentials are absent or the download fails the binary keeps running
	// with an empty resolver; the world view still works off c-country.
	if cfg.GeoIPAutoUpdate && cfg.GeoIPLicenseKey != "" {
		if _, err := geo.Update(ctx, cfg.GeoIPLicenseKey, cfg.GeoIPPath); err != nil {
			log.Warn().Err(err).Msg("geoip update failed; using existing DB if present")
		}
	}
	resolver := geo.New()
	if r, err := geo.Open(cfg.GeoIPPath); err != nil {
		log.Warn().Err(err).Str("path", cfg.GeoIPPath).Msg("geoip DB unavailable; country drill-down disabled")
	} else {
		resolver = r
	}
	defer resolver.Close()

	q := athenacli.New(athena.NewFromConfig(awsCfg), cfg.Database, cfg.Workgroup)
	api := &handlers.API{Cfg: cfg, Q: q, Geo: resolver, Cache: cache.New(5 * time.Minute)}

	r := gin.New()
	r.Use(gin.Recovery())
	api.Register(r)

	// 4. Bind first to learn the actual (possibly auto-assigned) port, open the
	//    browser to it, then serve on that listener.
	addr := k.String("addr")
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	url := "http://" + ln.Addr().String()
	go func() {
		time.Sleep(300 * time.Millisecond)
		log.Info().Msgf("opening %s", url)
		_ = browser.OpenURL(url)
	}()

	log.Info().Msgf("serving on %s", url)
	return r.RunListener(ln)
}
