// Package api is the HTTP layer of the auth service.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/brambroza/auth-microservice/internal/config"
	"github.com/brambroza/auth-microservice/internal/password"
	"github.com/brambroza/auth-microservice/internal/secret"
	"github.com/brambroza/auth-microservice/internal/store"
	"github.com/brambroza/auth-microservice/internal/token"
)

type Server struct {
	cfg config.Config
	st  *store.Store
	tok *token.Manager
	box *secret.Box
	log *slog.Logger
	lim *limiter
	now func() time.Time
	// dummyHash is verified when the email is unknown, so the response time
	// does not reveal whether an account exists.
	dummyHash string
}

func New(cfg config.Config, st *store.Store, tok *token.Manager, box *secret.Box, log *slog.Logger) (*Server, error) {
	dummy, err := password.Hash(secret.NewToken())
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, st: st, tok: tok, box: box, log: log, lim: newLimiter(), now: time.Now, dummyHash: dummy}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /.well-known/jwks.json", s.jwks)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)

	mux.HandleFunc("POST /v1/auth/login", s.login)
	mux.HandleFunc("POST /v1/auth/mfa/verify", s.mfaVerify)
	mux.HandleFunc("POST /v1/auth/refresh", s.refresh)
	mux.HandleFunc("POST /v1/auth/logout", s.logout)
	mux.Handle("POST /v1/auth/switch-tenant", s.authed(s.switchTenant))
	mux.Handle("POST /v1/auth/password", s.authed(s.changePassword))
	mux.Handle("GET /v1/me", s.authed(s.me))

	mux.Handle("POST /v1/mfa/totp/enroll", s.authed(s.totpEnroll))
	mux.Handle("POST /v1/mfa/totp/activate", s.authed(s.totpActivate))
	mux.Handle("POST /v1/mfa/totp/disable", s.authed(s.totpDisable))
	mux.Handle("POST /v1/mfa/recovery-codes", s.authed(s.recoveryRegenerate))

	mux.Handle("POST /v1/admin/tenants", s.admin(s.adminCreateTenant))
	mux.Handle("POST /v1/admin/users", s.admin(s.adminCreateUser))
	mux.Handle("POST /v1/admin/memberships", s.admin(s.adminAddMembership))
	mux.Handle("DELETE /v1/admin/memberships", s.admin(s.adminRemoveMembership))
	mux.Handle("POST /v1/admin/users/{id}/mfa/reset", s.admin(s.adminResetMFA))
	mux.Handle("POST /v1/admin/users/{id}/revoke-sessions", s.admin(s.adminRevokeSessions))

	return s.common(mux)
}

// ---------- middleware ----------

func (s *Server) common(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if origin := r.Header.Get("Origin"); origin != "" && slices.Contains(s.cfg.CORSOrigins, origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Max-Age", "600")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		next.ServeHTTP(w, r)
	})
}

// authCtx is what an authenticated handler receives.
type authCtx struct {
	User    store.User
	Session store.Session
	Claims  *token.Claims
}

type authedHandler func(http.ResponseWriter, *http.Request, *authCtx)

// authed verifies the bearer token and that its session is still alive.
// Downstream systems only verify the signature; this service also checks the
// session so that logout takes effect here immediately.
func (s *Server) authed(h authedHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || raw == "" {
			fail(w, http.StatusUnauthorized, "unauthorized", "missing bearer token")
			return
		}
		claims, err := s.tok.Verify(raw)
		if err != nil {
			fail(w, http.StatusUnauthorized, "invalid_token", "access token is invalid or expired")
			return
		}
		sess, err := s.st.SessionByID(r.Context(), claims.SID)
		if err != nil || sess.RevokedAt != nil || sess.UserID != claims.Subject {
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				s.internal(w, r, err)
				return
			}
			fail(w, http.StatusUnauthorized, "invalid_token", "session has ended")
			return
		}
		u, err := s.st.UserByID(r.Context(), sess.UserID)
		if err != nil || !u.IsActive {
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				s.internal(w, r, err)
				return
			}
			fail(w, http.StatusUnauthorized, "invalid_token", "account is disabled")
			return
		}
		h(w, r, &authCtx{User: u, Session: sess, Claims: claims})
	})
}

func (s *Server) admin(h authedHandler) http.Handler {
	return s.authed(func(w http.ResponseWriter, r *http.Request, a *authCtx) {
		if !a.User.IsPlatformAdmin {
			fail(w, http.StatusForbidden, "forbidden", "platform admin only")
			return
		}
		h(w, r, a)
	})
}

// ---------- helpers ----------

type apiError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, apiError{Error: code, Message: msg})
}

func (s *Server) internal(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("internal error", "path", r.URL.Path, "err", err)
	fail(w, http.StatusInternalServerError, "internal_error", "something went wrong")
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "request body must be valid JSON")
		return false
	}
	return true
}

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func isUUID(s string) bool { return uuidRe.MatchString(s) }

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		// The right-most entry is the one our own gateway appended.
		if parts := strings.Split(r.Header.Get("X-Forwarded-For"), ","); len(parts) > 0 {
			if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func userAgent(r *http.Request) string {
	ua := r.UserAgent()
	if len(ua) > 300 {
		ua = ua[:300]
	}
	return ua
}

func (s *Server) audit(r *http.Request, event string, userID string, tenantID *string, detail map[string]any) {
	var uid *string
	if userID != "" {
		uid = &userID
	}
	// Detached from the request context so the record survives a client disconnect.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 3*time.Second)
	defer cancel()
	if err := s.st.Audit(ctx, event, uid, tenantID, s.clientIP(r), userAgent(r), detail); err != nil {
		s.log.Error("audit write failed", "event", event, "err", err)
	}
}

// ---------- rate limiter ----------

// limiter is a fixed-window counter held in memory. It is per instance: with
// several instances behind a load balancer the effective limit is multiplied,
// which is acceptable next to the per-account lockout stored in the database.
type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	count int
	reset time.Time
}

func newLimiter() *limiter { return &limiter{buckets: map[string]*bucket{}} }

func (l *limiter) allow(key string, max int, window time.Duration, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buckets) > 50000 {
		for k, b := range l.buckets {
			if now.After(b.reset) {
				delete(l.buckets, k)
			}
		}
	}
	b, ok := l.buckets[key]
	if !ok || now.After(b.reset) {
		l.buckets[key] = &bucket{count: 1, reset: now.Add(window)}
		return true
	}
	b.count++
	return b.count <= max
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.st.Ping(ctx); err != nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", "database unreachable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(s.tok.JWKS())
}

// discovery publishes just enough metadata for JWT middleware to find the
// issuer and keys on its own (for example ASP.NET Core's "Authority" setting).
// The interactive OIDC endpoints (authorize, token, userinfo) are not
// implemented yet, so they are deliberately absent.
func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.cfg.Issuer,
		"jwks_uri":                              s.cfg.Issuer + "/.well-known/jwks.json",
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"subject_types_supported":               []string{"public"},
		"response_types_supported":              []string{},
	})
}
