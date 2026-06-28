package main

import (
	"os"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"isnan.eu/monitoring/internal/handlers"
	"isnan.eu/monitoring/internal/web"
)

func main() {
	log.Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
	r := gin.New()
	r.Use(gin.Recovery())
	r.GET("/api/health", handlers.Health)
	r.NoRoute(gin.WrapH(web.Handler())) // serve embedded SPA for everything else

	addr := "127.0.0.1:8080"
	log.Info().Msgf("serving on http://%s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatal().Err(err).Msg("server exited")
	}
}
