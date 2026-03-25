package analytics

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"

	"github.com/agentgate/agentgate/config"
)

//go:embed ui/*
var uiAssets embed.FS

// StartAdminServer boots the embedded dashboard and API on localhost explicitly.
func StartAdminServer(ctx context.Context, getConfig func() *config.Config, configPath string, reloadFunc func() error) {
	uiFs, err := fs.Sub(uiAssets, "ui")
	if err != nil {
		log.Fatalf("[Analytics] Failed to mount embedded UI filesystem: %v", err)
	}

	mux := http.NewServeMux()

	// ── Serve API Endpoints ───────────────────────────────────────────────────
	mux.HandleFunc("/api/stats", HandleStats)
	mux.HandleFunc("/api/heatmap", HandleHeatmap)
	mux.HandleFunc("/api/history", HandleHistory)
	mux.HandleFunc("/api/config", HandleConfig(getConfig))
	mux.HandleFunc("/api/stream", HandleSSEStream)
	mux.HandleFunc("/api/discover", HandleDiscover)
	mux.HandleFunc("/api/config/save", HandleConfigSave(configPath, reloadFunc))

	// ── Serve Embedded UI ─────────────────────────────────────────────────────
	// Fallback to exactly serving index.html natively
	mux.Handle("/", http.FileServer(http.FS(uiFs)))

	cfg := getConfig()
	addr := fmt.Sprintf("127.0.0.1:%d", cfg.Network.AdminPort)
	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		log.Printf("[Analytics] Embed Dashboard running on http://%s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[Analytics] Admin Server error: %v", err)
		}
	}()

	// Graceful termination
	<-ctx.Done()
	srv.Shutdown(context.Background())
}
