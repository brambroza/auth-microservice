// Command authd is the central authentication service.
//
//	authd                 run the HTTP server (default)
//	authd migrate         apply database migrations and exit
//	authd create-admin    create the first platform admin
//	authd rotate-key      add a new signing key
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/brambroza/auth-microservice/internal/api"
	"github.com/brambroza/auth-microservice/internal/config"
	"github.com/brambroza/auth-microservice/internal/db"
	"github.com/brambroza/auth-microservice/internal/password"
	"github.com/brambroza/auth-microservice/internal/secret"
	"github.com/brambroza/auth-microservice/internal/store"
	"github.com/brambroza/auth-microservice/internal/token"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cmd := "serve"
	args := os.Args[1:]
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Open(ctx, cfg.DatabaseURL, cfg.DBMaxConns)
	if err != nil {
		return err
	}
	defer pool.Close()
	st := store.New(pool)
	box, err := secret.NewBox(cfg.MasterKey)
	if err != nil {
		return err
	}
	tok := token.NewManager(cfg.Issuer, cfg.Audience, cfg.AccessTTL)

	switch cmd {
	case "migrate":
		return db.Migrate(ctx, pool)

	case "rotate-key":
		if err := db.Migrate(ctx, pool); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		if err := api.LoadKeys(ctx, st, box, tok, true); err != nil {
			return err
		}
		log.Info("signing key rotated; running instances pick it up within a minute")
		return nil

	case "create-admin":
		if err := db.Migrate(ctx, pool); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		return createAdmin(ctx, st, args)

	case "serve":
		if cfg.AutoMigrate {
			if err := db.Migrate(ctx, pool); err != nil {
				return fmt.Errorf("migrate: %w", err)
			}
		}
		if err := api.LoadKeys(ctx, st, box, tok, false); err != nil {
			return fmt.Errorf("load signing keys: %w", err)
		}
		// Pick up keys rotated by another instance or by "authd rotate-key".
		go func() {
			t := time.NewTicker(time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if err := api.LoadKeys(ctx, st, box, tok, false); err != nil && ctx.Err() == nil {
						log.Error("reload signing keys", "err", err)
					}
				}
			}
		}()

		srv, err := api.New(cfg, st, tok, box, log)
		if err != nil {
			return err
		}
		httpSrv := &http.Server{
			Addr:              cfg.HTTPAddr,
			Handler:           srv.Handler(),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		errc := make(chan error, 1)
		go func() { errc <- httpSrv.ListenAndServe() }()
		log.Info("listening", "addr", cfg.HTTPAddr, "issuer", cfg.Issuer)

		select {
		case err := <-errc:
			return err
		case <-ctx.Done():
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		log.Info("stopped")
		return nil

	default:
		return fmt.Errorf("unknown command %q (use: serve, migrate, create-admin, rotate-key)", cmd)
	}
}

// createAdmin reads the password from AUTH_ADMIN_PASSWORD or from stdin, so it
// never appears in shell history or the process list.
func createAdmin(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("create-admin", flag.ContinueOnError)
	email := fs.String("email", "", "admin email")
	name := fs.String("name", "Platform Admin", "display name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !strings.Contains(*email, "@") {
		return errors.New("create-admin: -email is required")
	}
	pw := os.Getenv("AUTH_ADMIN_PASSWORD")
	if pw == "" {
		fmt.Fprint(os.Stderr, "Password: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("read password: %w", err)
		}
		pw = strings.TrimRight(line, "\r\n")
	}
	if err := password.Validate(pw); err != nil {
		return err
	}
	hash, err := password.Hash(pw)
	if err != nil {
		return err
	}
	u, err := st.CreateUser(ctx, strings.ToLower(strings.TrimSpace(*email)), hash, *name, true)
	if errors.Is(err, store.ErrConflict) {
		return errors.New("create-admin: a user with this email already exists")
	}
	if err != nil {
		return err
	}
	fmt.Printf("created platform admin %s (%s)\n", u.Email, u.ID)
	return nil
}
