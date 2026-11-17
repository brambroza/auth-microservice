package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brambroza/auth-microservice/internal/config"
	"github.com/brambroza/auth-microservice/internal/db"
	"github.com/brambroza/auth-microservice/internal/password"
	"github.com/brambroza/auth-microservice/internal/secret"
	"github.com/brambroza/auth-microservice/internal/store"
	"github.com/brambroza/auth-microservice/internal/token"
	"github.com/brambroza/auth-microservice/internal/totp"
)

// These tests need a real PostgreSQL. Set TEST_DATABASE_URL to run them, e.g.
//
//	TEST_DATABASE_URL=postgres://auth:auth@localhost:5432/auth_test go test ./...
//
// Each test works in its own throwaway schema.
type env struct {
	t   *testing.T
	srv *Server
	st  *store.Store
	ts  *httptest.Server
}

const testPassword = "correct horse battery"

func newEnv(t *testing.T, tweak func(*config.Config)) *env {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	schema := fmt.Sprintf("t_%d", time.Now().UnixNano())

	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	pcfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	pcfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, pcfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
		admin.Close()
	})
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	// Running it twice must be a no-op.
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{
		Issuer: "https://auth.test", Audience: "goalong", MasterKey: bytes.Repeat([]byte{7}, 32),
		AccessTTL: 10 * time.Minute, RefreshTTL: time.Hour, SessionMax: 24 * time.Hour, ChallengeTTL: 5 * time.Minute,
		MaxFailedLogins: 10, LockDuration: 15 * time.Minute, LoginRatePerMin: 1000,
	}
	if tweak != nil {
		tweak(&cfg)
	}
	st := store.New(pool)
	box, err := secret.NewBox(cfg.MasterKey)
	if err != nil {
		t.Fatal(err)
	}
	tok := token.NewManager(cfg.Issuer, cfg.Audience, cfg.AccessTTL)
	if err := LoadKeys(ctx, st, box, tok, false); err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg, st, tok, box, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &env{t: t, srv: srv, st: st, ts: ts}
}

func (e *env) user(email string, admin bool) store.User {
	e.t.Helper()
	h, err := password.Hash(testPassword)
	if err != nil {
		e.t.Fatal(err)
	}
	u, err := e.st.CreateUser(context.Background(), email, h, "Test", admin)
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

// call sends a JSON request and decodes the JSON response into a map.
func (e *env) call(method, path, bearer string, body any) (int, map[string]any) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.ts.URL+path, rd)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			e.t.Fatalf("%s %s: non-JSON response %q", method, path, raw)
		}
	}
	return resp.StatusCode, out
}

func (e *env) want(status int, got int, body map[string]any) {
	e.t.Helper()
	if got != status {
		e.t.Fatalf("status = %d, want %d; body = %v", got, status, body)
	}
}

func (e *env) login(email string, extra map[string]any) map[string]any {
	e.t.Helper()
	in := map[string]any{"email": email, "password": testPassword}
	for k, v := range extra {
		in[k] = v
	}
	code, out := e.call("POST", "/v1/auth/login", "", in)
	e.want(200, code, out)
	return out
}

func (e *env) claims(access any) *token.Claims {
	e.t.Helper()
	c, err := e.srv.tok.Verify(access.(string))
	if err != nil {
		e.t.Fatalf("verify access token: %v", err)
	}
	return c
}

// advance moves the server clock so the next TOTP code falls in a new time step.
func (e *env) advance(d time.Duration) {
	prev := e.srv.now
	e.srv.now = func() time.Time { return prev().Add(d) }
}

func (e *env) code(secretB32 string) string {
	e.t.Helper()
	c, err := totp.Code(secretB32, totp.Step(e.srv.now()))
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

// enableTOTP enrolls and activates TOTP, returning the secret and recovery codes.
func (e *env) enableTOTP(access string) (string, []any) {
	e.t.Helper()
	code, out := e.call("POST", "/v1/mfa/totp/enroll", access, nil)
	e.want(200, code, out)
	sec := out["secret"].(string)
	code, out = e.call("POST", "/v1/mfa/totp/activate", access, map[string]any{"code": e.code(sec)})
	e.want(200, code, out)
	return sec, out["recovery_codes"].([]any)
}

func TestLoginRefreshRotationAndReuse(t *testing.T) {
	e := newEnv(t, nil)
	u := e.user("a@example.com", false)

	code, out := e.call("POST", "/v1/auth/login", "", map[string]any{"email": "a@example.com", "password": "wrong password!"})
	e.want(401, code, out)
	code, out = e.call("POST", "/v1/auth/login", "", map[string]any{"email": "nobody@example.com", "password": testPassword})
	e.want(401, code, out)

	// Email matching ignores case.
	tokens := e.login("A@Example.com", nil)
	c := e.claims(tokens["access_token"])
	if c.Subject != u.ID || c.Issuer != "https://auth.test" || len(c.AMR) != 1 || c.AMR[0] != "pwd" {
		t.Fatalf("unexpected claims: %+v", c)
	}

	code, me := e.call("GET", "/v1/me", tokens["access_token"].(string), nil)
	e.want(200, code, me)
	if me["email"] != "a@example.com" {
		t.Fatalf("me = %v", me)
	}

	first := tokens["refresh_token"].(string)
	code, rotated := e.call("POST", "/v1/auth/refresh", "", map[string]any{"refresh_token": first})
	e.want(200, code, rotated)
	second := rotated["refresh_token"].(string)
	if second == first {
		t.Fatal("refresh token was not rotated")
	}

	// Replaying the old token must kill the session, including the new token.
	code, out = e.call("POST", "/v1/auth/refresh", "", map[string]any{"refresh_token": first})
	e.want(401, code, out)
	code, out = e.call("POST", "/v1/auth/refresh", "", map[string]any{"refresh_token": second})
	e.want(401, code, out)
	code, out = e.call("GET", "/v1/me", rotated["access_token"].(string), nil)
	e.want(401, code, out)

	// Logout ends the session.
	tokens = e.login("a@example.com", nil)
	code, out = e.call("POST", "/v1/auth/logout", "", map[string]any{"refresh_token": tokens["refresh_token"]})
	e.want(204, code, out)
	code, out = e.call("POST", "/v1/auth/refresh", "", map[string]any{"refresh_token": tokens["refresh_token"]})
	e.want(401, code, out)

	code, out = e.call("GET", "/v1/me", "not-a-token", nil)
	e.want(401, code, out)
}

func TestTOTPLoginReplayAndRecoveryCodes(t *testing.T) {
	e := newEnv(t, nil)
	e.user("b@example.com", false)
	tokens := e.login("b@example.com", nil)
	access := tokens["access_token"].(string)
	sec, recovery := e.enableTOTP(access)
	if len(recovery) != recoveryCodeCount {
		t.Fatalf("got %d recovery codes", len(recovery))
	}

	// The session that enrolled is upgraded to multi-factor at its next refresh.
	code, out := e.call("POST", "/v1/auth/refresh", "", map[string]any{"refresh_token": tokens["refresh_token"]})
	e.want(200, code, out)
	if c := e.claims(out["access_token"]); len(c.AMR) != 3 {
		t.Fatalf("amr after enrollment = %v", c.AMR)
	}

	// Password alone no longer yields tokens.
	step1 := e.login("b@example.com", nil)
	if step1["mfa_required"] != true || step1["access_token"] != nil {
		t.Fatalf("expected an MFA challenge, got %v", step1)
	}
	mfaToken := step1["mfa_token"]

	// The code used for activation belongs to a spent time step.
	code, out = e.call("POST", "/v1/auth/mfa/verify", "", map[string]any{"mfa_token": mfaToken, "code": e.code(sec)})
	e.want(401, code, out)
	code, out = e.call("POST", "/v1/auth/mfa/verify", "", map[string]any{"mfa_token": mfaToken, "code": "000000"})
	e.want(401, code, out)

	e.advance(31 * time.Second)
	good := e.code(sec)
	code, out = e.call("POST", "/v1/auth/mfa/verify", "", map[string]any{"mfa_token": mfaToken, "code": good})
	e.want(200, code, out)
	c := e.claims(out["access_token"])
	if fmt.Sprint(c.AMR) != "[pwd otp mfa]" {
		t.Fatalf("amr = %v", c.AMR)
	}

	// A challenge works once, and so does a code.
	code, out = e.call("POST", "/v1/auth/mfa/verify", "", map[string]any{"mfa_token": mfaToken, "code": good})
	e.want(401, code, out)
	step1 = e.login("b@example.com", nil)
	code, out = e.call("POST", "/v1/auth/mfa/verify", "", map[string]any{"mfa_token": step1["mfa_token"], "code": good})
	e.want(401, code, out)

	// Recovery code: accepted once, in any letter case.
	rc := recovery[0].(string)
	code, out = e.call("POST", "/v1/auth/mfa/verify", "", map[string]any{"mfa_token": step1["mfa_token"], "method": "recovery_code", "code": rc})
	e.want(200, code, out)
	if c := e.claims(out["access_token"]); fmt.Sprint(c.AMR) != "[pwd rc mfa]" {
		t.Fatalf("amr = %v", c.AMR)
	}
	step1 = e.login("b@example.com", nil)
	code, out = e.call("POST", "/v1/auth/mfa/verify", "", map[string]any{"mfa_token": step1["mfa_token"], "method": "recovery_code", "code": rc})
	e.want(401, code, out)

	// Disabling needs password and a fresh code.
	access = out2access(e, sec, step1["mfa_token"])
	code, out = e.call("POST", "/v1/mfa/totp/disable", access, map[string]any{"password": "wrong password!", "code": "000000"})
	e.want(401, code, out)
	e.advance(31 * time.Second)
	code, out = e.call("POST", "/v1/mfa/totp/disable", access, map[string]any{"password": testPassword, "code": e.code(sec)})
	e.want(204, code, out)
	if again := e.login("b@example.com", nil); again["access_token"] == nil {
		t.Fatalf("expected tokens after disabling MFA, got %v", again)
	}
}

// out2access finishes a pending challenge with a fresh TOTP code.
func out2access(e *env, sec string, mfaToken any) string {
	e.t.Helper()
	e.advance(31 * time.Second)
	code, out := e.call("POST", "/v1/auth/mfa/verify", "", map[string]any{"mfa_token": mfaToken, "code": e.code(sec)})
	e.want(200, code, out)
	return out["access_token"].(string)
}

func TestChallengeAttemptLimit(t *testing.T) {
	e := newEnv(t, nil)
	e.user("c@example.com", false)
	sec, _ := e.enableTOTP(e.login("c@example.com", nil)["access_token"].(string))
	e.advance(31 * time.Second)

	ch := e.login("c@example.com", nil)["mfa_token"]
	for range maxChallengeAttempts {
		code, out := e.call("POST", "/v1/auth/mfa/verify", "", map[string]any{"mfa_token": ch, "code": "000000"})
		e.want(401, code, out)
	}
	// Even the right code is refused once the attempts are spent.
	code, out := e.call("POST", "/v1/auth/mfa/verify", "", map[string]any{"mfa_token": ch, "code": e.code(sec)})
	e.want(401, code, out)
	if out["error"] != "invalid_challenge" {
		t.Fatalf("error = %v", out["error"])
	}
}

func TestAccountLockout(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.MaxFailedLogins = 3 })
	e.user("d@example.com", false)
	for range 3 {
		code, out := e.call("POST", "/v1/auth/login", "", map[string]any{"email": "d@example.com", "password": "wrong password!"})
		e.want(401, code, out)
	}
	code, out := e.call("POST", "/v1/auth/login", "", map[string]any{"email": "d@example.com", "password": testPassword})
	e.want(429, code, out)
	if out["error"] != "account_locked" {
		t.Fatalf("error = %v", out["error"])
	}
}

func TestRateLimit(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.LoginRatePerMin = 2 })
	for i := range 3 {
		code, out := e.call("POST", "/v1/auth/login", "", map[string]any{"email": "x@example.com", "password": "whatever-pass"})
		if i < 2 {
			e.want(401, code, out)
		} else {
			e.want(429, code, out)
		}
	}
}

func TestTenantsRolesAndAdmin(t *testing.T) {
	e := newEnv(t, nil)
	e.user("root@example.com", true)
	e.user("plain@example.com", false)
	adminTok := e.login("root@example.com", nil)["access_token"].(string)
	plainTok := e.login("plain@example.com", nil)["access_token"].(string)

	code, out := e.call("POST", "/v1/admin/tenants", plainTok, map[string]any{"slug": "acme", "name": "ACME"})
	e.want(403, code, out)

	code, out = e.call("POST", "/v1/admin/tenants", adminTok, map[string]any{"slug": "acme", "name": "ACME"})
	e.want(201, code, out)
	code, out = e.call("POST", "/v1/admin/tenants", adminTok, map[string]any{"slug": "acme", "name": "ACME"})
	e.want(409, code, out)
	code, out = e.call("POST", "/v1/admin/tenants", adminTok, map[string]any{"slug": "strict", "name": "Strict Co", "require_mfa": true})
	e.want(201, code, out)

	code, out = e.call("POST", "/v1/admin/users", adminTok, map[string]any{"email": "w@example.com", "password": "short"})
	e.want(400, code, out)
	code, out = e.call("POST", "/v1/admin/users", adminTok, map[string]any{"email": "W@example.com", "password": testPassword, "display_name": "Worker"})
	e.want(201, code, out)
	uid := out["id"].(string)

	for _, m := range []map[string]any{
		{"user_id": uid, "tenant": "acme", "app": "wms", "role": "admin"},
		{"user_id": uid, "tenant": "acme", "app": "hrm", "role": "viewer"},
		{"user_id": uid, "tenant": "strict", "app": "wms", "role": "operator"},
	} {
		code, out = e.call("POST", "/v1/admin/memberships", adminTok, m)
		e.want(204, code, out)
	}

	// Two tenants and none chosen: the session starts without one.
	tokens := e.login("w@example.com", nil)
	if c := e.claims(tokens["access_token"]); c.TenantID != "" || len(c.Roles) != 0 {
		t.Fatalf("expected no tenant, got %+v", c)
	}
	code, out = e.call("POST", "/v1/auth/login", "", map[string]any{"email": "w@example.com", "password": testPassword, "tenant": "nope"})
	e.want(403, code, out)

	tokens = e.login("w@example.com", map[string]any{"tenant": "acme"})
	c := e.claims(tokens["access_token"])
	if c.Tenant != "acme" || fmt.Sprint(c.Roles) != "[hrm:viewer wms:admin]" {
		t.Fatalf("claims = %+v", c)
	}

	// A tenant that requires MFA withholds roles until the user enrolls.
	code, out = e.call("POST", "/v1/auth/switch-tenant", tokens["access_token"].(string), map[string]any{"tenant": "strict"})
	e.want(200, code, out)
	c = e.claims(out["access_token"])
	if c.Tenant != "strict" || !c.MFAEnrollmentRequired || len(c.Roles) != 0 {
		t.Fatalf("claims = %+v", c)
	}
	e.enableTOTP(out["access_token"].(string))
	code, out = e.call("POST", "/v1/auth/refresh", "", map[string]any{"refresh_token": tokens["refresh_token"]})
	e.want(200, code, out)
	c = e.claims(out["access_token"])
	if c.MFAEnrollmentRequired || fmt.Sprint(c.Roles) != "[wms:operator]" {
		t.Fatalf("claims after enrollment = %+v", c)
	}

	// Removing a role shows up at the next refresh.
	code, out2 := e.call("DELETE", "/v1/admin/memberships", adminTok, map[string]any{"user_id": uid, "tenant": "strict", "app": "wms", "role": "operator"})
	e.want(204, code, out2)
	code, out = e.call("POST", "/v1/auth/refresh", "", map[string]any{"refresh_token": out["refresh_token"]})
	e.want(200, code, out)
	if c = e.claims(out["access_token"]); len(c.Roles) != 0 {
		t.Fatalf("roles after removal = %v", c.Roles)
	}

	// Admin MFA reset signs the user out and removes the factor.
	code, out2 = e.call("POST", "/v1/admin/users/"+uid+"/mfa/reset", adminTok, nil)
	e.want(204, code, out2)
	code, out2 = e.call("POST", "/v1/auth/refresh", "", map[string]any{"refresh_token": out["refresh_token"]})
	e.want(401, code, out2)
	if again := e.login("w@example.com", map[string]any{"tenant": "acme"}); again["access_token"] == nil {
		t.Fatalf("expected tokens after MFA reset, got %v", again)
	}
	code, out2 = e.call("POST", "/v1/admin/users/not-a-uuid/mfa/reset", adminTok, nil)
	e.want(400, code, out2)
}

func TestChangePasswordSignsOutOtherSessions(t *testing.T) {
	e := newEnv(t, nil)
	e.user("p@example.com", false)
	other := e.login("p@example.com", nil)
	mine := e.login("p@example.com", nil)
	access := mine["access_token"].(string)

	code, out := e.call("POST", "/v1/auth/password", access, map[string]any{"current_password": testPassword, "new_password": "short"})
	e.want(400, code, out)
	code, out = e.call("POST", "/v1/auth/password", access, map[string]any{"current_password": "wrong password!", "new_password": "a brand new password"})
	e.want(401, code, out)
	code, out = e.call("POST", "/v1/auth/password", access, map[string]any{"current_password": testPassword, "new_password": "a brand new password"})
	e.want(204, code, out)

	code, out = e.call("POST", "/v1/auth/refresh", "", map[string]any{"refresh_token": other["refresh_token"]})
	e.want(401, code, out)
	code, out = e.call("POST", "/v1/auth/refresh", "", map[string]any{"refresh_token": mine["refresh_token"]})
	e.want(200, code, out)
	code, out = e.call("POST", "/v1/auth/login", "", map[string]any{"email": "p@example.com", "password": testPassword})
	e.want(401, code, out)
}

// TestJWKSVerifiesTokens checks what a downstream system does: fetch the JWKS,
// rebuild the public key, verify a token with no access to this service's internals.
func TestJWKSVerifiesTokens(t *testing.T) {
	e := newEnv(t, nil)
	e.user("j@example.com", false)
	access := e.login("j@example.com", nil)["access_token"].(string)

	resp, err := http.Get(e.ts.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc struct {
		Keys []struct{ Kty, Crv, Alg, Kid, X, Y string }
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Keys) != 1 || doc.Keys[0].Kty != "EC" || doc.Keys[0].Crv != "P-256" {
		t.Fatalf("jwks = %+v", doc)
	}
	x, _ := base64.RawURLEncoding.DecodeString(doc.Keys[0].X)
	y, _ := base64.RawURLEncoding.DecodeString(doc.Keys[0].Y)
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}

	parsed, err := jwt.Parse(access, func(tk *jwt.Token) (any, error) {
		if tk.Header["kid"] != doc.Keys[0].Kid {
			return nil, fmt.Errorf("kid mismatch")
		}
		return pub, nil
	}, jwt.WithValidMethods([]string{"ES256"}), jwt.WithIssuer("https://auth.test"), jwt.WithAudience("goalong"))
	if err != nil || !parsed.Valid {
		t.Fatalf("downstream verification failed: %v", err)
	}

	code, meta := e.call("GET", "/.well-known/openid-configuration", "", nil)
	e.want(200, code, meta)
	if meta["issuer"] != "https://auth.test" || meta["jwks_uri"] != "https://auth.test/.well-known/jwks.json" {
		t.Fatalf("discovery = %v", meta)
	}

	// Rotation: the new key signs, the old one still verifies.
	ctx := context.Background()
	if err := LoadKeys(ctx, e.st, e.srv.box, e.srv.tok, true); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.tok.Verify(access); err != nil {
		t.Fatalf("token signed by the previous key was rejected: %v", err)
	}
	fresh := e.login("j@example.com", nil)["access_token"].(string)
	if _, err := jwt.Parse(fresh, func(*jwt.Token) (any, error) { return pub, nil }, jwt.WithValidMethods([]string{"ES256"})); err == nil {
		t.Fatal("new token should be signed by the new key")
	}
}
