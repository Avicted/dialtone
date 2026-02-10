package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Avicted/dialtone/internal/auth"
	"github.com/Avicted/dialtone/internal/channel"
	"github.com/Avicted/dialtone/internal/config"
	"github.com/Avicted/dialtone/internal/device"
	"github.com/Avicted/dialtone/internal/httpapi"
	"github.com/Avicted/dialtone/internal/securelog"
	"github.com/Avicted/dialtone/internal/serverinvite"
	"github.com/Avicted/dialtone/internal/storage"
	"github.com/Avicted/dialtone/internal/user"
	"github.com/Avicted/dialtone/internal/ws"
)

func main() {
	if err := run(); err != nil {
		securelog.Error("server.run", err)
		log.Printf("fatal: server error")
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		return fmt.Errorf("config load failed: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("config invalid: %w", err)
	}

	storeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	store, err := storage.NewPostgresStore(storeCtx, cfg.DBURL)
	if err != nil {
		return fmt.Errorf("init store: %w", err)
	}
	migrateCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := store.Migrate(migrateCtx); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = store.Close(ctx)
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	hub := ws.NewHub(store.Broadcasts(), store.Devices(), store.Channels())
	go hub.Run(ctx)

	userService := user.NewService(store.Users(), cfg.UsernamePepper)
	deviceService := device.NewService(store.Devices())
	channelService := channel.NewService(store.Channels(), userService)
	inviteService := serverinvite.NewService(store.ServerInvites())
	authService := auth.NewService(userService, deviceService, inviteService)
	api := httpapi.NewHandler(userService, deviceService, channelService, authService, inviteService, hub, hub, cfg.AdminToken)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.Handle("/ws", ws.WithAuthValidator(http.HandlerFunc(hub.HandleWS), authService))
	api.Register(mux)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if cfg.TLSCertPath != "" && cfg.TLSKeyPath != "" {
			log.Printf("listening with TLS on %s", cfg.ListenAddr)
			errCh <- srv.ListenAndServeTLS(cfg.TLSCertPath, cfg.TLSKeyPath)
			return
		}

		log.Printf("listening on %s", cfg.ListenAddr)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		err = <-errCh
	case err = <-errCh:
	}

	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server failed: %w", err)
	}
	return nil
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
