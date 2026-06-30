package main

import (
	"fmt"
	"net"
	"os"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/aws/aws-sdk-go-v2/service/glue"
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
	"isnan.eu/monitoring/internal/catalog"
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

	// 3. Discover log sources from the Glue catalog (the tables `terraform apply`
	// created) using the credentials just obtained — the catalog is the single
	// source of truth. An explicit LOG_SOURCES (parsed by config.Load) still wins,
	// as an override for tests or querying a subset.
	if len(cfg.Sources) == 0 {
		srcs, err := catalog.Discover(ctx, glue.NewFromConfig(awsCfg), cfg.Database)
		if err != nil {
			return fmt.Errorf("discover log sources: %w", err)
		}
		for _, s := range srcs {
			cfg.Sources[s.Name] = s
		}
		log.Info().Int("count", len(srcs)).Str("database", cfg.Database).Msg("discovered log sources from Glue catalog")
	}

	// 4. GeoIP — auto-update at startup (default on), then open; tolerate no DB.
	// The geo map resolves IPs via this DB, so without it the map is empty
	// (KPIs/histogram still work). Log the state clearly either way.
	if !cfg.GeoIPAutoUpdate || cfg.GeoIPLicenseKey == "" {
		log.Warn().Bool("autoUpdate", cfg.GeoIPAutoUpdate).Bool("licenseKeySet", cfg.GeoIPLicenseKey != "").
			Msg("geoip auto-update skipped (need GEOIP_AUTO_UPDATE=true + GEOIP_LICENSE_KEY); will use an existing DB if present")
	} else {
		if _, err := geo.Update(ctx, cfg.GeoIPLicenseKey, "GeoLite2-City", cfg.GeoIPPath); err != nil {
			log.Warn().Err(err).Msg("geoip city download failed; will use an existing DB if present")
		}
		// AS-org DB: same license key + gate as City; best-effort (org is optional).
		if _, err := geo.Update(ctx, cfg.GeoIPLicenseKey, "GeoLite2-ASN", cfg.GeoIPASNPath); err != nil {
			log.Warn().Err(err).Msg("geoip ASN download failed; AS org will be blank")
		}
	}
	resolver := geo.New()
	if r, err := geo.Open(cfg.GeoIPPath); err != nil {
		log.Warn().Err(err).Str("path", cfg.GeoIPPath).Msg("geoip DB NOT loaded → the world map will be empty; set GEOIP_LICENSE_KEY or place a .mmdb at GEOIP_DB_PATH")
	} else {
		resolver = r
		log.Info().Str("path", cfg.GeoIPPath).Msg("geoip database loaded")
	}
	// Attach the ASN reader so the callers list can show each IP's AS org.
	// Independent of the City DB — tolerated if absent (org just stays blank).
	if err := resolver.LoadASN(cfg.GeoIPASNPath); err != nil {
		log.Warn().Err(err).Str("path", cfg.GeoIPASNPath).Msg("geoip ASN DB NOT loaded → AS org will be blank; set GEOIP_LICENSE_KEY or place a .mmdb at GEOIP_ASN_DB_PATH")
	} else {
		log.Info().Str("path", cfg.GeoIPASNPath).Msg("geoip ASN database loaded")
	}
	defer resolver.Close()

	q := athenacli.New(athena.NewFromConfig(awsCfg), cfg.Database, cfg.Workgroup)
	api := &handlers.API{Cfg: cfg, Q: q, Geo: resolver, Cache: cache.New(5 * time.Minute)}

	r := gin.New()
	r.Use(gin.Recovery())
	api.Register(r)

	// 5. Bind first to learn the actual (possibly auto-assigned) port, open the
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
