package api

import (
	"context"
	"errors"
	"net/http"
	"net/mail"
	"slices"
	"strings"
	"time"

	"github.com/brambroza/auth-microservice/internal/password"
	"github.com/brambroza/auth-microservice/internal/secret"
	"github.com/brambroza/auth-microservice/internal/store"
	"github.com/brambroza/auth-microservice/internal/token"
	"github.com/brambroza/auth-microservice/internal/totp"
)

const maxChallengeAttempts = 5

type tokenResponse struct {
	AccessToken           string `json:"access_token"`
	TokenType             string `json:"token_type"`
	ExpiresIn             int    `json:"expires_in"`
	RefreshToken          string `json:"refresh_token,omitempty"`
	MFAEnrollmentRequired bool   `json:"mfa_enrollment_required,omitempty"`
}

func normalizeEmail(e string) (string, bool) {
	e = strings.ToLower(strings.TrimSpace(e))
	if len(e) > 254 {
		return "", false
	}
	a, err := mail.ParseAddress(e)
	if err != nil || a.Address != e {
		return "", false
	}
	return e, true
}

// accessToken builds the JWT for a session. Roles are read fresh each time,
// so a role change reaches clients at their next refresh.
func (s *Server) accessToken(ctx context.Context, u store.User, sess store.Session) (tokenResponse, error) {
	c := token.Claims{
		Email:    u.Email,
		AMR:      sess.AMR,
		AuthTime: sess.AuthTime.Unix(),
		SID:      sess.ID,
	}
	c.Subject = u.ID
	var pending bool
	if sess.TenantID != nil {
		t, err := s.st.TenantByID(ctx, *sess.TenantID)
		if err != nil {
			return tokenResponse{}, err
		}
		c.TenantID, c.Tenant = t.ID, t.Slug
		if t.RequireMFA && !slices.Contains(sess.AMR, "mfa") {
			pending = true
		} else if c.Roles, err = s.st.Roles(ctx, u.ID, t.ID); err != nil {
			return tokenResponse{}, err
		}
	}
	c.MFAEnrollmentRequired = pending
	signed, err := s.tok.Issue(c, s.now())
	if err != nil {
		return tokenResponse{}, err
	}
	return tokenResponse{
		AccessToken: signed, TokenType: "Bearer",
		ExpiresIn: int(s.tok.TTL().Seconds()), MFAEnrollmentRequired: pending,
	}, nil
}

// startSession opens a session and returns the first token pair.
func (s *Server) startSession(r *http.Request, u store.User, tenantID *string, amr []string) (tokenResponse, error) {
	refresh := secret.NewToken()
	sess, err := s.st.CreateSession(r.Context(), u.ID, tenantID, amr, s.clientIP(r), userAgent(r), secret.Hash(refresh), s.cfg.RefreshTTL)
	if err != nil {
		return tokenResponse{}, err
	}
	resp, err := s.accessToken(r.Context(), u, sess)
	if err != nil {
		return tokenResponse{}, err
	}
	resp.RefreshToken = refresh
	return resp, nil
}

// resolveTenant picks the tenant for a sign-in. With no slug given, a user
// who belongs to exactly one tenant lands in it; otherwise the session starts
// without a tenant and the client calls /v1/auth/switch-tenant.
func (s *Server) resolveTenant(ctx context.Context, userID, slug string) (*string, []store.Tenant, error) {
	tenants, err := s.st.UserTenants(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	if slug == "" {
		if len(tenants) == 1 {
			return &tenants[0].ID, tenants, nil
		}
		return nil, tenants, nil
	}
	for _, t := range tenants {
		if t.Slug == slug {
			return &t.ID, tenants, nil
		}
	}
	return nil, tenants, store.ErrNotFound
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Tenant   string `json:"tenant"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !s.lim.allow("login:"+s.clientIP(r), s.cfg.LoginRatePerMin, time.Minute, s.now()) {
		fail(w, http.StatusTooManyRequests, "rate_limited", "too many attempts, try again shortly")
		return
	}
	ctx := r.Context()
	email, ok := normalizeEmail(in.Email)
	if !ok || in.Password == "" || len(in.Password) > 256 {
		fail(w, http.StatusUnauthorized, "invalid_credentials", "email or password is incorrect")
		return
	}

	u, err := s.st.UserByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) {
		_, _, _ = password.Verify(in.Password, s.dummyHash)
		s.audit(r, "login.failed", "", nil, map[string]any{"reason": "unknown_email"})
		fail(w, http.StatusUnauthorized, "invalid_credentials", "email or password is incorrect")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if u.LockedUntil != nil && u.LockedUntil.After(s.now()) {
		s.audit(r, "login.failed", u.ID, nil, map[string]any{"reason": "locked"})
		fail(w, http.StatusTooManyRequests, "account_locked", "too many failed attempts, try again later")
		return
	}
	match, rehash, err := password.Verify(in.Password, u.PasswordHash)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if !match || !u.IsActive {
		if !match {
			if err := s.st.RecordLoginFailure(ctx, u.ID, s.cfg.MaxFailedLogins, s.cfg.LockDuration); err != nil {
				s.log.Error("record login failure", "err", err)
			}
		}
		reason := "bad_password"
		if match {
			reason = "disabled"
		}
		s.audit(r, "login.failed", u.ID, nil, map[string]any{"reason": reason})
		fail(w, http.StatusUnauthorized, "invalid_credentials", "email or password is incorrect")
		return
	}
	if err := s.st.ResetLoginFailures(ctx, u.ID); err != nil {
		s.log.Error("reset login failures", "err", err)
	}
	if rehash {
		if h, err := password.Hash(in.Password); err == nil {
			_ = s.st.UpdatePassword(ctx, u.ID, h, false)
		}
	}

	tenantID, _, err := s.resolveTenant(ctx, u.ID, in.Tenant)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusForbidden, "tenant_not_allowed", "you are not a member of this tenant")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}

	// Second factor enrolled: stop here and hand back a short-lived challenge
	// instead of tokens.
	f, err := s.st.TOTPFactor(ctx, u.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internal(w, r, err)
		return
	}
	if err == nil && f.Confirmed {
		mfaToken := secret.NewToken()
		if err := s.st.CreateChallenge(ctx, secret.Hash(mfaToken), u.ID, tenantID, s.clientIP(r), userAgent(r), s.cfg.ChallengeTTL); err != nil {
			s.internal(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"mfa_required": true,
			"mfa_token":    mfaToken,
			"methods":      []string{"totp", "recovery_code"},
			"expires_in":   int(s.cfg.ChallengeTTL.Seconds()),
		})
		return
	}

	resp, err := s.startSession(r, u, tenantID, []string{"pwd"})
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.audit(r, "login.success", u.ID, tenantID, map[string]any{"amr": []string{"pwd"}})
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) mfaVerify(w http.ResponseWriter, r *http.Request) {
	var in struct {
		MFAToken string `json:"mfa_token"`
		Method   string `json:"method"`
		Code     string `json:"code"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !s.lim.allow("mfa:"+s.clientIP(r), s.cfg.LoginRatePerMin, time.Minute, s.now()) {
		fail(w, http.StatusTooManyRequests, "rate_limited", "too many attempts, try again shortly")
		return
	}
	ctx := r.Context()
	ch, err := s.st.AttemptChallenge(ctx, secret.Hash(in.MFAToken), maxChallengeAttempts)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusUnauthorized, "invalid_challenge", "sign-in expired or too many wrong codes, please sign in again")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	u, err := s.st.UserByID(ctx, ch.UserID)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if !u.IsActive {
		fail(w, http.StatusUnauthorized, "invalid_challenge", "sign-in expired, please sign in again")
		return
	}

	var amr []string
	switch in.Method {
	case "", "totp":
		ok, err := s.checkTOTP(ctx, u.ID, in.Code)
		if err != nil {
			s.internal(w, r, err)
			return
		}
		if ok {
			amr = []string{"pwd", "otp", "mfa"}
		}
	case "recovery_code":
		ok, err := s.st.UseRecoveryCode(ctx, u.ID, secret.Hash(normalizeRecoveryCode(in.Code)))
		if err != nil {
			s.internal(w, r, err)
			return
		}
		if ok {
			amr = []string{"pwd", "rc", "mfa"}
		}
	default:
		fail(w, http.StatusBadRequest, "bad_request", "method must be totp or recovery_code")
		return
	}
	if amr == nil {
		s.audit(r, "mfa.failed", u.ID, ch.TenantID, map[string]any{"method": in.Method})
		fail(w, http.StatusUnauthorized, "invalid_code", "the code is incorrect")
		return
	}
	if err := s.st.ConsumeChallenge(ctx, ch.ID); err != nil {
		fail(w, http.StatusUnauthorized, "invalid_challenge", "sign-in expired, please sign in again")
		return
	}
	resp, err := s.startSession(r, u, ch.TenantID, amr)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.audit(r, "login.success", u.ID, ch.TenantID, map[string]any{"amr": amr})
	writeJSON(w, http.StatusOK, resp)
}

// checkTOTP verifies a code against the user's confirmed factor and spends its time step.
func (s *Server) checkTOTP(ctx context.Context, userID, code string) (bool, error) {
	f, err := s.st.TOTPFactor(ctx, userID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !f.Confirmed) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	sec, err := s.box.Open(f.SecretEnc, "totp:"+f.ID)
	if err != nil {
		return false, err
	}
	step, ok := totp.Match(string(sec), code, s.now())
	if !ok {
		return false, nil
	}
	return s.st.UseTOTPStep(ctx, f.ID, step, false)
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	next := secret.NewToken()
	sess, err := s.st.RotateRefreshToken(ctx, secret.Hash(in.RefreshToken), secret.Hash(next), s.cfg.RefreshTTL, s.cfg.SessionMax)
	switch {
	case errors.Is(err, store.ErrTokenReused):
		s.audit(r, "refresh.reuse_detected", sess.UserID, sess.TenantID, map[string]any{"session_id": sess.ID})
		fail(w, http.StatusUnauthorized, "invalid_refresh_token", "session has ended, please sign in again")
		return
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrExpired):
		fail(w, http.StatusUnauthorized, "invalid_refresh_token", "session has ended, please sign in again")
		return
	case err != nil:
		s.internal(w, r, err)
		return
	}
	u, err := s.st.UserByID(ctx, sess.UserID)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if !u.IsActive {
		_ = s.st.RevokeSession(ctx, sess.ID, "user_disabled")
		fail(w, http.StatusUnauthorized, "invalid_refresh_token", "session has ended, please sign in again")
		return
	}
	resp, err := s.accessToken(ctx, u, sess)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	resp.RefreshToken = next
	writeJSON(w, http.StatusOK, resp)
}

// logout ends the session that owns the refresh token. It always answers 204
// so it cannot be used to probe for valid tokens.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !decode(w, r, &in) {
		return
	}
	sess, err := s.st.SessionByRefreshHash(r.Context(), secret.Hash(in.RefreshToken))
	if err == nil {
		if err := s.st.RevokeSession(r.Context(), sess.ID, "logout"); err != nil {
			s.internal(w, r, err)
			return
		}
		s.audit(r, "logout", sess.UserID, sess.TenantID, nil)
	} else if !errors.Is(err, store.ErrNotFound) {
		s.internal(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) switchTenant(w http.ResponseWriter, r *http.Request, a *authCtx) {
	var in struct {
		Tenant string `json:"tenant"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Tenant == "" {
		fail(w, http.StatusBadRequest, "bad_request", "tenant is required")
		return
	}
	tenantID, _, err := s.resolveTenant(r.Context(), a.User.ID, in.Tenant)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusForbidden, "tenant_not_allowed", "you are not a member of this tenant")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if err := s.st.SetSessionTenant(r.Context(), a.Session.ID, *tenantID); err != nil {
		s.internal(w, r, err)
		return
	}
	a.Session.TenantID = tenantID
	resp, err := s.accessToken(r.Context(), a.User, a.Session)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, a *authCtx) {
	var in struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !s.lim.allow("pw:"+a.User.ID, 10, time.Minute, s.now()) {
		fail(w, http.StatusTooManyRequests, "rate_limited", "too many attempts, try again shortly")
		return
	}
	if ok, _, err := password.Verify(in.CurrentPassword, a.User.PasswordHash); err != nil || !ok {
		fail(w, http.StatusUnauthorized, "invalid_credentials", "current password is incorrect")
		return
	}
	if err := password.Validate(in.NewPassword); err != nil {
		fail(w, http.StatusBadRequest, "weak_password", err.Error())
		return
	}
	hash, err := password.Hash(in.NewPassword)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if err := s.st.UpdatePassword(r.Context(), a.User.ID, hash, true); err != nil {
		s.internal(w, r, err)
		return
	}
	// Every other device is signed out; this session stays.
	if err := s.st.RevokeUserSessions(r.Context(), a.User.ID, a.Session.ID, "password_changed"); err != nil {
		s.internal(w, r, err)
		return
	}
	s.audit(r, "password.changed", a.User.ID, a.Session.TenantID, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request, a *authCtx) {
	ctx := r.Context()
	tenants, err := s.st.UserTenants(ctx, a.User.ID)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	f, err := s.st.TOTPFactor(ctx, a.User.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internal(w, r, err)
		return
	}
	totpEnabled := err == nil && f.Confirmed
	left, err := s.st.RecoveryCodesLeft(ctx, a.User.ID)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":                a.User.ID,
		"email":             a.User.Email,
		"display_name":      a.User.DisplayName,
		"is_platform_admin": a.User.IsPlatformAdmin,
		"current_tenant":    a.Claims.Tenant,
		"roles":             a.Claims.Roles,
		"tenants":           tenants,
		"mfa": map[string]any{
			"totp_enabled":        totpEnabled,
			"recovery_codes_left": left,
		},
	})
}
