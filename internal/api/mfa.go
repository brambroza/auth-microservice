package api

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/brambroza/auth-microservice/internal/password"
	"github.com/brambroza/auth-microservice/internal/secret"
	"github.com/brambroza/auth-microservice/internal/store"
	"github.com/brambroza/auth-microservice/internal/totp"
)

const recoveryCodeCount = 10

// newRecoveryCodes returns codes such as "K7QW-2M9X-PD4T" (60 bits each).
func newRecoveryCodes() (plain []string, hashes [][]byte) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	for range recoveryCodeCount {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			panic(err)
		}
		raw := enc.EncodeToString(b)[:12]
		plain = append(plain, raw[:4]+"-"+raw[4:8]+"-"+raw[8:])
		hashes = append(hashes, secret.Hash(raw))
	}
	return plain, hashes
}

func normalizeRecoveryCode(c string) string {
	c = strings.ToUpper(strings.TrimSpace(c))
	c = strings.ReplaceAll(c, "-", "")
	return strings.ReplaceAll(c, " ", "")
}

// totpEnroll creates an unconfirmed secret. Nothing is enforced at sign-in
// until the user proves the authenticator works via totpActivate.
func (s *Server) totpEnroll(w http.ResponseWriter, r *http.Request, a *authCtx) {
	sec := totp.NewSecret()
	err := s.st.CreatePendingTOTP(r.Context(), a.User.ID, func(factorID string) []byte {
		return s.box.Seal([]byte(sec), "totp:"+factorID)
	})
	if errors.Is(err, store.ErrConflict) {
		fail(w, http.StatusConflict, "already_enabled", "two-factor authentication is already enabled")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"secret":      sec,
		"otpauth_url": totp.URI(s.cfg.Audience, a.User.Email, sec),
	})
}

func (s *Server) totpActivate(w http.ResponseWriter, r *http.Request, a *authCtx) {
	var in struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !s.lim.allow("totp:"+a.User.ID, 10, time.Minute, s.now()) {
		fail(w, http.StatusTooManyRequests, "rate_limited", "too many attempts, try again shortly")
		return
	}
	ctx := r.Context()
	f, err := s.st.TOTPFactor(ctx, a.User.ID)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusConflict, "not_enrolled", "start enrollment first")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if f.Confirmed {
		fail(w, http.StatusConflict, "already_enabled", "two-factor authentication is already enabled")
		return
	}
	sec, err := s.box.Open(f.SecretEnc, "totp:"+f.ID)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	step, ok := totp.Match(string(sec), in.Code, s.now())
	if ok {
		ok, err = s.st.UseTOTPStep(ctx, f.ID, step, true)
		if err != nil {
			s.internal(w, r, err)
			return
		}
	}
	if !ok {
		fail(w, http.StatusUnauthorized, "invalid_code", "the code is incorrect")
		return
	}
	plain, hashes := newRecoveryCodes()
	if err := s.st.ReplaceRecoveryCodes(ctx, a.User.ID, hashes); err != nil {
		s.internal(w, r, err)
		return
	}
	// The user has just proven possession of the factor, so this session counts
	// as multi-factor from now on. The client should refresh to get new claims.
	if !slices.Contains(a.Session.AMR, "mfa") {
		if err := s.st.SetSessionAMR(ctx, a.Session.ID, append(slices.Clone(a.Session.AMR), "otp", "mfa")); err != nil {
			s.internal(w, r, err)
			return
		}
	}
	s.audit(r, "mfa.totp.enabled", a.User.ID, a.Session.TenantID, nil)
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": plain})
}

// totpDisable needs both the password and a current code, so a stolen access
// token alone cannot strip the second factor.
func (s *Server) totpDisable(w http.ResponseWriter, r *http.Request, a *authCtx) {
	var in struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !s.lim.allow("totp:"+a.User.ID, 10, time.Minute, s.now()) {
		fail(w, http.StatusTooManyRequests, "rate_limited", "too many attempts, try again shortly")
		return
	}
	if ok, _, err := password.Verify(in.Password, a.User.PasswordHash); err != nil || !ok {
		fail(w, http.StatusUnauthorized, "invalid_credentials", "password is incorrect")
		return
	}
	ok, err := s.checkTOTP(r.Context(), a.User.ID, in.Code)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if !ok {
		fail(w, http.StatusUnauthorized, "invalid_code", "the code is incorrect")
		return
	}
	if err := s.st.DeleteMFA(r.Context(), a.User.ID); err != nil {
		s.internal(w, r, err)
		return
	}
	s.audit(r, "mfa.totp.disabled", a.User.ID, a.Session.TenantID, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) recoveryRegenerate(w http.ResponseWriter, r *http.Request, a *authCtx) {
	var in struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !s.lim.allow("totp:"+a.User.ID, 10, time.Minute, s.now()) {
		fail(w, http.StatusTooManyRequests, "rate_limited", "too many attempts, try again shortly")
		return
	}
	ok, err := s.checkTOTP(r.Context(), a.User.ID, in.Code)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if !ok {
		fail(w, http.StatusUnauthorized, "invalid_code", "the code is incorrect")
		return
	}
	plain, hashes := newRecoveryCodes()
	if err := s.st.ReplaceRecoveryCodes(r.Context(), a.User.ID, hashes); err != nil {
		s.internal(w, r, err)
		return
	}
	s.audit(r, "mfa.recovery_codes.regenerated", a.User.ID, a.Session.TenantID, nil)
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": plain})
}
