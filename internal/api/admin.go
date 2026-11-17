package api

import (
	"errors"
	"net/http"
	"regexp"

	"github.com/brambroza/auth-microservice/internal/password"
	"github.com/brambroza/auth-microservice/internal/store"
)

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

func (s *Server) adminCreateTenant(w http.ResponseWriter, r *http.Request, a *authCtx) {
	var in struct {
		Slug       string `json:"slug"`
		Name       string `json:"name"`
		RequireMFA bool   `json:"require_mfa"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !slugRe.MatchString(in.Slug) || in.Name == "" {
		fail(w, http.StatusBadRequest, "bad_request", "slug must be lowercase letters, digits or dashes; name is required")
		return
	}
	t, err := s.st.CreateTenant(r.Context(), in.Slug, in.Name, in.RequireMFA)
	if errors.Is(err, store.ErrConflict) {
		fail(w, http.StatusConflict, "already_exists", "a tenant with this slug already exists")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.audit(r, "admin.tenant.created", a.User.ID, &t.ID, map[string]any{"slug": t.Slug})
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) adminCreateUser(w http.ResponseWriter, r *http.Request, a *authCtx) {
	var in struct {
		Email       string `json:"email"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
	}
	if !decode(w, r, &in) {
		return
	}
	email, ok := normalizeEmail(in.Email)
	if !ok {
		fail(w, http.StatusBadRequest, "bad_request", "email is not valid")
		return
	}
	if err := password.Validate(in.Password); err != nil {
		fail(w, http.StatusBadRequest, "weak_password", err.Error())
		return
	}
	hash, err := password.Hash(in.Password)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	u, err := s.st.CreateUser(r.Context(), email, hash, in.DisplayName, false)
	if errors.Is(err, store.ErrConflict) {
		fail(w, http.StatusConflict, "already_exists", "a user with this email already exists")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.audit(r, "admin.user.created", a.User.ID, nil, map[string]any{"target_user_id": u.ID})
	writeJSON(w, http.StatusCreated, map[string]string{"id": u.ID, "email": u.Email, "display_name": u.DisplayName})
}

type membershipInput struct {
	UserID string `json:"user_id"`
	Tenant string `json:"tenant"`
	App    string `json:"app"`
	Role   string `json:"role"`
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// membershipTarget validates the input and resolves the tenant slug.
func (s *Server) membershipTarget(w http.ResponseWriter, r *http.Request) (membershipInput, store.Tenant, bool) {
	var in membershipInput
	if !decode(w, r, &in) {
		return in, store.Tenant{}, false
	}
	if !isUUID(in.UserID) || !nameRe.MatchString(in.App) || !nameRe.MatchString(in.Role) {
		fail(w, http.StatusBadRequest, "bad_request", "user_id must be a UUID; app and role must be lowercase names")
		return in, store.Tenant{}, false
	}
	if _, err := s.st.UserByID(r.Context(), in.UserID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			fail(w, http.StatusNotFound, "not_found", "user not found")
		} else {
			s.internal(w, r, err)
		}
		return in, store.Tenant{}, false
	}
	t, err := s.st.TenantBySlug(r.Context(), in.Tenant)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			fail(w, http.StatusNotFound, "not_found", "tenant not found")
		} else {
			s.internal(w, r, err)
		}
		return in, t, false
	}
	return in, t, true
}

func (s *Server) adminAddMembership(w http.ResponseWriter, r *http.Request, a *authCtx) {
	in, t, ok := s.membershipTarget(w, r)
	if !ok {
		return
	}
	if err := s.st.AddMembership(r.Context(), in.UserID, t.ID, in.App, in.Role); err != nil {
		s.internal(w, r, err)
		return
	}
	s.audit(r, "admin.membership.added", a.User.ID, &t.ID, map[string]any{"target_user_id": in.UserID, "role": in.App + ":" + in.Role})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminRemoveMembership(w http.ResponseWriter, r *http.Request, a *authCtx) {
	in, t, ok := s.membershipTarget(w, r)
	if !ok {
		return
	}
	if err := s.st.RemoveMembership(r.Context(), in.UserID, t.ID, in.App, in.Role); err != nil {
		s.internal(w, r, err)
		return
	}
	s.audit(r, "admin.membership.removed", a.User.ID, &t.ID, map[string]any{"target_user_id": in.UserID, "role": in.App + ":" + in.Role})
	w.WriteHeader(http.StatusNoContent)
}

// targetUser reads {id} from the path and loads that user.
func (s *Server) targetUser(w http.ResponseWriter, r *http.Request) (store.User, bool) {
	id := r.PathValue("id")
	if !isUUID(id) {
		fail(w, http.StatusBadRequest, "bad_request", "user id must be a UUID")
		return store.User{}, false
	}
	u, err := s.st.UserByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, "not_found", "user not found")
		return u, false
	}
	if err != nil {
		s.internal(w, r, err)
		return u, false
	}
	return u, true
}

// adminResetMFA is the lost-phone path. It removes the user's second factors
// and signs them out everywhere. The audit trail records who did it.
func (s *Server) adminResetMFA(w http.ResponseWriter, r *http.Request, a *authCtx) {
	u, ok := s.targetUser(w, r)
	if !ok {
		return
	}
	if err := s.st.DeleteMFA(r.Context(), u.ID); err != nil {
		s.internal(w, r, err)
		return
	}
	if err := s.st.RevokeUserSessions(r.Context(), u.ID, "", "mfa_reset"); err != nil {
		s.internal(w, r, err)
		return
	}
	s.audit(r, "admin.mfa.reset", a.User.ID, nil, map[string]any{"target_user_id": u.ID})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminRevokeSessions(w http.ResponseWriter, r *http.Request, a *authCtx) {
	u, ok := s.targetUser(w, r)
	if !ok {
		return
	}
	if err := s.st.RevokeUserSessions(r.Context(), u.ID, "", "admin_revoked"); err != nil {
		s.internal(w, r, err)
		return
	}
	s.audit(r, "admin.sessions.revoked", a.User.ID, nil, map[string]any{"target_user_id": u.ID})
	w.WriteHeader(http.StatusNoContent)
}
