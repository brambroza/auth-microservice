// Package store contains every SQL statement the service runs.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound    = errors.New("store: not found")
	ErrConflict    = errors.New("store: already exists")
	ErrTokenReused = errors.New("store: refresh token reused")
	ErrExpired     = errors.New("store: expired or revoked")
)

type Store struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

func isUnique(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// ---------- users ----------

type User struct {
	ID              string
	Email           string
	PasswordHash    string
	DisplayName     string
	IsPlatformAdmin bool
	IsActive        bool
	LockedUntil     *time.Time
}

const userCols = `id::text, email, password_hash, display_name, is_platform_admin, is_active, locked_until`

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.DisplayName, &u.IsPlatformAdmin, &u.IsActive, &u.LockedUntil)
	return u, notFound(err)
}

func (s *Store) CreateUser(ctx context.Context, email, hash, name string, admin bool) (User, error) {
	u, err := scanUser(s.pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, display_name, is_platform_admin)
		 VALUES ($1, $2, $3, $4) RETURNING `+userCols, email, hash, name, admin))
	if isUnique(err) {
		return u, ErrConflict
	}
	return u, err
}

func (s *Store) UserByEmail(ctx context.Context, email string) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE lower(email) = lower($1)`, email))
}

func (s *Store) UserByID(ctx context.Context, id string) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id = $1`, id))
}

// RecordLoginFailure counts a wrong password and locks the account once the
// limit is reached. The counter restarts after a lock.
func (s *Store) RecordLoginFailure(ctx context.Context, id string, max int, lockFor time.Duration) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET
		   locked_until  = CASE WHEN failed_logins + 1 >= $2 THEN now() + make_interval(secs => $3) ELSE locked_until END,
		   failed_logins = CASE WHEN failed_logins + 1 >= $2 THEN 0 ELSE failed_logins + 1 END
		 WHERE id = $1`, id, max, lockFor.Seconds())
	return err
}

func (s *Store) ResetLoginFailures(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1 AND (failed_logins <> 0 OR locked_until IS NOT NULL)`, id)
	return err
}

func (s *Store) UpdatePassword(ctx context.Context, id, hash string, changed bool) error {
	q := `UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1`
	if changed {
		q = `UPDATE users SET password_hash = $2, updated_at = now(), password_changed_at = now() WHERE id = $1`
	}
	_, err := s.pool.Exec(ctx, q, id, hash)
	return err
}

// ---------- tenants and memberships ----------

type Tenant struct {
	ID         string `json:"id"`
	Slug       string `json:"slug"`
	Name       string `json:"name"`
	RequireMFA bool   `json:"require_mfa"`
}

const tenantCols = `t.id::text, t.slug, t.name, t.require_mfa`

func scanTenant(row pgx.Row) (Tenant, error) {
	var t Tenant
	err := row.Scan(&t.ID, &t.Slug, &t.Name, &t.RequireMFA)
	return t, notFound(err)
}

func (s *Store) CreateTenant(ctx context.Context, slug, name string, requireMFA bool) (Tenant, error) {
	t, err := scanTenant(s.pool.QueryRow(ctx,
		`INSERT INTO tenants AS t (slug, name, require_mfa) VALUES ($1, $2, $3) RETURNING `+tenantCols, slug, name, requireMFA))
	if isUnique(err) {
		return t, ErrConflict
	}
	return t, err
}

func (s *Store) TenantBySlug(ctx context.Context, slug string) (Tenant, error) {
	return scanTenant(s.pool.QueryRow(ctx, `SELECT `+tenantCols+` FROM tenants t WHERE t.slug = $1`, slug))
}

func (s *Store) TenantByID(ctx context.Context, id string) (Tenant, error) {
	return scanTenant(s.pool.QueryRow(ctx, `SELECT `+tenantCols+` FROM tenants t WHERE t.id = $1`, id))
}

// UserTenants lists the tenants a user belongs to.
func (s *Store) UserTenants(ctx context.Context, userID string) ([]Tenant, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+tenantCols+` FROM tenants t
		 WHERE EXISTS (SELECT 1 FROM memberships m WHERE m.tenant_id = t.id AND m.user_id = $1)
		 ORDER BY t.slug`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Tenant{}
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Roles returns the user's roles in one tenant as "app:role" strings.
func (s *Store) Roles(ctx context.Context, userID, tenantID string) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT app || ':' || role FROM memberships WHERE user_id = $1 AND tenant_id = $2 ORDER BY 1`, userID, tenantID)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if out == nil {
		out = []string{}
	}
	return out, err
}

func (s *Store) AddMembership(ctx context.Context, userID, tenantID, app, role string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO memberships (user_id, tenant_id, app, role) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
		userID, tenantID, app, role)
	return err
}

func (s *Store) RemoveMembership(ctx context.Context, userID, tenantID, app, role string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM memberships WHERE user_id = $1 AND tenant_id = $2 AND app = $3 AND role = $4`,
		userID, tenantID, app, role)
	return err
}

// ---------- login challenges (password accepted, second factor pending) ----------

type Challenge struct {
	ID       string
	UserID   string
	TenantID *string
}

func (s *Store) CreateChallenge(ctx context.Context, hash []byte, userID string, tenantID *string, ip, ua string, ttl time.Duration) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO login_challenges (token_hash, user_id, tenant_id, ip, user_agent, expires_at)
		 VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))`,
		hash, userID, tenantID, ip, ua, ttl.Seconds())
	return err
}

// AttemptChallenge counts one verification attempt and returns the challenge
// if it is still usable. The attempt is counted before the code is checked,
// so parallel guesses cannot exceed the limit.
func (s *Store) AttemptChallenge(ctx context.Context, hash []byte, maxAttempts int) (Challenge, error) {
	var c Challenge
	err := s.pool.QueryRow(ctx,
		`UPDATE login_challenges SET attempts = attempts + 1
		 WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now() AND attempts < $2
		 RETURNING id::text, user_id::text, tenant_id::text`, hash, maxAttempts).Scan(&c.ID, &c.UserID, &c.TenantID)
	return c, notFound(err)
}

// ConsumeChallenge marks the challenge used. It fails if another request got there first.
func (s *Store) ConsumeChallenge(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE login_challenges SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}

// ---------- second factors ----------

type Factor struct {
	ID        string
	UserID    string
	SecretEnc []byte
	Confirmed bool
}

// TOTPFactor returns the user's TOTP factor, whether pending or confirmed.
func (s *Store) TOTPFactor(ctx context.Context, userID string) (Factor, error) {
	var f Factor
	err := s.pool.QueryRow(ctx,
		`SELECT id::text, user_id::text, secret_enc, confirmed_at IS NOT NULL
		 FROM mfa_factors WHERE user_id = $1 AND type = 'totp'`, userID).Scan(&f.ID, &f.UserID, &f.SecretEnc, &f.Confirmed)
	return f, notFound(err)
}

// CreatePendingTOTP stores a new unconfirmed secret, replacing an earlier
// unconfirmed one. It returns ErrConflict if TOTP is already active.
// seal receives the new factor ID so the ciphertext can be bound to its row.
func (s *Store) CreatePendingTOTP(ctx context.Context, userID string, seal func(factorID string) []byte) error {
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM mfa_factors WHERE user_id = $1 AND type = 'totp' AND confirmed_at IS NULL`, userID); err != nil {
			return err
		}
		var id string
		if err := tx.QueryRow(ctx, `INSERT INTO mfa_factors (user_id, type, name) VALUES ($1, 'totp', 'Authenticator app') RETURNING id::text`, userID).Scan(&id); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE mfa_factors SET secret_enc = $2 WHERE id = $1`, id, seal(id))
		return err
	})
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

// UseTOTPStep records a time step as spent. It returns false if this step, or
// a later one, was already used, which blocks replay of an observed code.
func (s *Store) UseTOTPStep(ctx context.Context, factorID string, step int64, confirm bool) (bool, error) {
	q := `UPDATE mfa_factors SET last_used_step = $2, last_used_at = now() WHERE id = $1 AND last_used_step < $2`
	if confirm {
		q = `UPDATE mfa_factors SET last_used_step = $2, last_used_at = now(), confirmed_at = now() WHERE id = $1 AND last_used_step < $2 AND confirmed_at IS NULL`
	}
	tag, err := s.pool.Exec(ctx, q, factorID, step)
	return tag.RowsAffected() == 1, err
}

// DeleteMFA removes every second factor and recovery code of a user.
func (s *Store) DeleteMFA(ctx context.Context, userID string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM mfa_factors WHERE user_id = $1`, userID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM recovery_codes WHERE user_id = $1`, userID)
		return err
	})
}

func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID string, hashes [][]byte) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM recovery_codes WHERE user_id = $1`, userID); err != nil {
			return err
		}
		for _, h := range hashes {
			if _, err := tx.Exec(ctx, `INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)`, userID, h); err != nil {
				return err
			}
		}
		return nil
	})
}

// UseRecoveryCode spends a code. Each code works once.
func (s *Store) UseRecoveryCode(ctx context.Context, userID string, hash []byte) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE recovery_codes SET used_at = now() WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL`, userID, hash)
	return tag.RowsAffected() == 1, err
}

func (s *Store) RecoveryCodesLeft(ctx context.Context, userID string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL`, userID).Scan(&n)
	return n, err
}

// ---------- sessions and refresh tokens ----------

type Session struct {
	ID        string
	UserID    string
	TenantID  *string
	AMR       []string
	AuthTime  time.Time
	CreatedAt time.Time
	RevokedAt *time.Time
}

const sessionCols = `id::text, user_id::text, tenant_id::text, amr, auth_time, created_at, revoked_at`

func scanSession(row pgx.Row) (Session, error) {
	var x Session
	err := row.Scan(&x.ID, &x.UserID, &x.TenantID, &x.AMR, &x.AuthTime, &x.CreatedAt, &x.RevokedAt)
	return x, notFound(err)
}

// CreateSession opens a session and stores its first refresh token.
func (s *Store) CreateSession(ctx context.Context, userID string, tenantID *string, amr []string, ip, ua string, refreshHash []byte, refreshTTL time.Duration) (Session, error) {
	var sess Session
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		sess, err = scanSession(tx.QueryRow(ctx,
			`INSERT INTO sessions (user_id, tenant_id, amr, ip, user_agent) VALUES ($1, $2, $3, $4, $5) RETURNING `+sessionCols,
			userID, tenantID, amr, ip, ua))
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO refresh_tokens (session_id, token_hash, expires_at) VALUES ($1, $2, now() + make_interval(secs => $3))`,
			sess.ID, refreshHash, refreshTTL.Seconds())
		return err
	})
	return sess, err
}

func (s *Store) SessionByID(ctx context.Context, id string) (Session, error) {
	return scanSession(s.pool.QueryRow(ctx, `SELECT `+sessionCols+` FROM sessions WHERE id = $1`, id))
}

func (s *Store) SessionByRefreshHash(ctx context.Context, hash []byte) (Session, error) {
	return scanSession(s.pool.QueryRow(ctx,
		`SELECT `+sessionCols+` FROM sessions WHERE id = (SELECT session_id FROM refresh_tokens WHERE token_hash = $1)`, hash))
}

func (s *Store) RevokeSession(ctx context.Context, id, reason string) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET revoked_at = now(), revoke_reason = $2 WHERE id = $1 AND revoked_at IS NULL`, id, reason)
	return err
}

// RevokeUserSessions ends all of a user's sessions except keepID (pass "" to end all).
func (s *Store) RevokeUserSessions(ctx context.Context, userID, keepID, reason string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE sessions SET revoked_at = now(), revoke_reason = $3
		 WHERE user_id = $1 AND revoked_at IS NULL AND ($2 = '' OR id::text <> $2)`, userID, keepID, reason)
	return err
}

func (s *Store) SetSessionTenant(ctx context.Context, id, tenantID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET tenant_id = $2 WHERE id = $1`, id, tenantID)
	return err
}

func (s *Store) SetSessionAMR(ctx context.Context, id string, amr []string) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET amr = $2, auth_time = now() WHERE id = $1`, id, amr)
	return err
}

// RotateRefreshToken swaps a refresh token for a new one. If the presented
// token was already rotated, someone is replaying it (a stolen token, or a
// client bug), so the whole session is revoked and ErrTokenReused returned.
func (s *Store) RotateRefreshToken(ctx context.Context, oldHash, newHash []byte, ttl, sessionMax time.Duration) (Session, error) {
	var sess Session
	var reused bool
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var tokenID, sessionID string
		var usedAt *time.Time
		var expired bool
		err := tx.QueryRow(ctx,
			`SELECT id::text, session_id::text, used_at, expires_at <= now()
			 FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE`, oldHash).Scan(&tokenID, &sessionID, &usedAt, &expired)
		if err != nil {
			return notFound(err)
		}
		sess, err = scanSession(tx.QueryRow(ctx, `SELECT `+sessionCols+` FROM sessions WHERE id = $1 FOR UPDATE`, sessionID))
		if err != nil {
			return err
		}
		if sess.RevokedAt != nil {
			return ErrExpired
		}
		if usedAt != nil {
			reused = true
			_, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = now(), revoke_reason = 'refresh_token_reuse' WHERE id = $1`, sessionID)
			return err
		}
		if expired {
			return ErrExpired
		}
		// The new token never outlives the session's absolute lifetime.
		tag, err := tx.Exec(ctx,
			`INSERT INTO refresh_tokens (session_id, token_hash, expires_at)
			 SELECT $1, $2, least(now() + make_interval(secs => $3), $4::timestamptz + make_interval(secs => $5))
			 WHERE $4::timestamptz + make_interval(secs => $5) > now()`,
			sessionID, newHash, ttl.Seconds(), sess.CreatedAt, sessionMax.Seconds())
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrExpired
		}
		if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET used_at = now() WHERE id = $1`, tokenID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE sessions SET last_seen_at = now() WHERE id = $1`, sessionID)
		return err
	})
	if err == nil && reused {
		return sess, ErrTokenReused
	}
	return sess, err
}

// ---------- signing keys ----------

type KeyRow struct {
	KID        string
	PrivateEnc []byte
	CreatedAt  time.Time
}

// SigningKeys returns the keys that are still published.
func (s *Store) SigningKeys(ctx context.Context) ([]KeyRow, error) {
	rows, err := s.pool.Query(ctx, `SELECT kid, private_key_enc, created_at FROM signing_keys WHERE retired_at IS NULL ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (KeyRow, error) {
		var k KeyRow
		err := r.Scan(&k.KID, &k.PrivateEnc, &k.CreatedAt)
		return k, err
	})
}

const keyLockID = 7260411902

// EnsureSigningKey inserts the key produced by gen when none exists (or always,
// when rotate is true). An advisory lock stops two instances from racing.
// On rotation only the newest two keys stay published.
func (s *Store) EnsureSigningKey(ctx context.Context, rotate bool, gen func() (kid string, enc []byte, err error)) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(keyLockID)); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM signing_keys WHERE retired_at IS NULL`).Scan(&n); err != nil {
			return err
		}
		if n > 0 && !rotate {
			return nil
		}
		kid, enc, err := gen()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO signing_keys (kid, private_key_enc) VALUES ($1, $2)`, kid, enc); err != nil {
			return err
		}
		_, err = tx.Exec(ctx,
			`UPDATE signing_keys SET retired_at = now()
			 WHERE retired_at IS NULL AND kid NOT IN (SELECT kid FROM signing_keys WHERE retired_at IS NULL ORDER BY created_at DESC LIMIT 2)`)
		return err
	})
}

// ---------- audit ----------

// Audit writes a security event. Callers log, but do not fail the request, on error.
func (s *Store) Audit(ctx context.Context, event string, userID, tenantID *string, ip, ua string, detail map[string]any) error {
	if detail == nil {
		detail = map[string]any{}
	}
	b, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO audit_logs (event, user_id, tenant_id, ip, user_agent, detail) VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
		event, userID, tenantID, ip, ua, string(b))
	return err
}
