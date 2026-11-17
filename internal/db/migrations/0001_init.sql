-- Core schema for the central auth service.
-- gen_random_uuid() is built in from PostgreSQL 13.

CREATE TABLE tenants (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        text NOT NULL UNIQUE,
    name        text NOT NULL,
    require_mfa boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email               text NOT NULL,
    password_hash       text NOT NULL,
    display_name        text NOT NULL DEFAULT '',
    is_platform_admin   boolean NOT NULL DEFAULT false,
    is_active           boolean NOT NULL DEFAULT true,
    failed_logins       integer NOT NULL DEFAULT 0,
    locked_until        timestamptz,
    password_changed_at timestamptz NOT NULL DEFAULT now(),
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_lower_key ON users (lower(email));

-- One user can belong to many tenants, with a coarse role per application
-- (e.g. app = 'wms', role = 'admin'). Fine-grained permissions stay in each system.
CREATE TABLE memberships (
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    tenant_id  uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    app        text NOT NULL,
    role       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, tenant_id, app, role)
);
CREATE INDEX memberships_tenant_idx ON memberships (tenant_id);

-- Second factors. 'totp' is implemented; 'webauthn' is reserved for passkeys
-- (public key + sign counter go in "credential").
CREATE TABLE mfa_factors (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    type           text NOT NULL CHECK (type IN ('totp', 'webauthn')),
    name           text NOT NULL DEFAULT '',
    secret_enc     bytea,
    credential     jsonb,
    last_used_step bigint NOT NULL DEFAULT 0,
    confirmed_at   timestamptz,
    last_used_at   timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX mfa_factors_one_totp_key ON mfa_factors (user_id) WHERE type = 'totp';
CREATE INDEX mfa_factors_user_idx ON mfa_factors (user_id);

CREATE TABLE recovery_codes (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash  bytea NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX recovery_codes_user_idx ON recovery_codes (user_id);

-- A session is one sign-in on one device. Refresh tokens rotate inside it.
CREATE TABLE sessions (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    tenant_id     uuid REFERENCES tenants (id) ON DELETE SET NULL,
    amr           text[] NOT NULL,
    auth_time     timestamptz NOT NULL DEFAULT now(),
    ip            text NOT NULL DEFAULT '',
    user_agent    text NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    revoked_at    timestamptz,
    revoke_reason text
);
CREATE INDEX sessions_user_idx ON sessions (user_id);

-- Only the SHA-256 of a refresh token is stored. used_at marks a rotated token;
-- presenting a used token again revokes the whole session.
CREATE TABLE refresh_tokens (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id uuid NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX refresh_tokens_session_idx ON refresh_tokens (session_id);

-- State between "password accepted" and "second factor accepted".
CREATE TABLE login_challenges (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash  bytea NOT NULL UNIQUE,
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    tenant_id   uuid REFERENCES tenants (id) ON DELETE CASCADE,
    attempts    integer NOT NULL DEFAULT 0,
    ip          text NOT NULL DEFAULT '',
    user_agent  text NOT NULL DEFAULT '',
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- ES256 signing keys. The private key is encrypted with AUTH_MASTER_KEY.
CREATE TABLE signing_keys (
    kid             text PRIMARY KEY,
    private_key_enc bytea NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    retired_at      timestamptz
);

CREATE TABLE audit_logs (
    id         bigserial PRIMARY KEY,
    at         timestamptz NOT NULL DEFAULT now(),
    event      text NOT NULL,
    user_id    uuid,
    tenant_id  uuid,
    ip         text NOT NULL DEFAULT '',
    user_agent text NOT NULL DEFAULT '',
    detail     jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_logs_user_idx ON audit_logs (user_id, at DESC);
CREATE INDEX audit_logs_at_idx ON audit_logs (at DESC);
