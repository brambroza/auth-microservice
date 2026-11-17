// Package token issues and verifies ES256 access tokens and publishes the
// matching public keys as a JWKS document.
package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims is the access-token payload that downstream systems read.
type Claims struct {
	jwt.RegisteredClaims
	Email    string   `json:"email,omitempty"`
	TenantID string   `json:"tenant_id,omitempty"`
	Tenant   string   `json:"tenant,omitempty"`
	Roles    []string `json:"roles"`
	// AMR lists how the user authenticated: "pwd", "otp", "rc" (recovery code), "mfa".
	AMR      []string `json:"amr"`
	AuthTime int64    `json:"auth_time"`
	SID      string   `json:"sid"`
	// MFAEnrollmentRequired is set when the tenant demands MFA and the user has
	// not enrolled yet. Roles are withheld until they do.
	MFAEnrollmentRequired bool `json:"mfa_enrollment_required,omitempty"`
}

// Key is one signing key pair.
type Key struct {
	KID       string
	Private   *ecdsa.PrivateKey
	CreatedAt time.Time
}

// NewKey generates a P-256 key with a random key ID.
func NewKey() (*Key, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	return &Key{KID: hex.EncodeToString(id), Private: priv, CreatedAt: time.Now()}, nil
}

func MarshalPrivate(k *ecdsa.PrivateKey) ([]byte, error) { return x509.MarshalPKCS8PrivateKey(k) }

func ParsePrivate(der []byte) (*ecdsa.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(*ecdsa.PrivateKey)
	if !ok || priv.Curve != elliptic.P256() {
		return nil, errors.New("token: not a P-256 private key")
	}
	return priv, nil
}

type keySet struct {
	active *Key
	public map[string]*ecdsa.PublicKey
	jwks   []byte
}

// Manager signs with the newest key and verifies against every published key.
type Manager struct {
	issuer   string
	audience string
	ttl      time.Duration
	keys     atomic.Pointer[keySet]
}

func NewManager(issuer, audience string, ttl time.Duration) *Manager {
	return &Manager{issuer: issuer, audience: audience, ttl: ttl}
}

// SetKeys replaces the key set. The newest key becomes the signing key.
func (m *Manager) SetKeys(keys []*Key) error {
	if len(keys) == 0 {
		return errors.New("token: no signing keys")
	}
	ks := &keySet{public: make(map[string]*ecdsa.PublicKey, len(keys))}
	type jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		Alg string `json:"alg"`
		Use string `json:"use"`
		Kid string `json:"kid"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	doc := struct {
		Keys []jwk `json:"keys"`
	}{}
	for _, k := range keys {
		if ks.active == nil || k.CreatedAt.After(ks.active.CreatedAt) {
			ks.active = k
		}
		pub := &k.Private.PublicKey
		ks.public[k.KID] = pub
		ecdhPub, err := pub.ECDH()
		if err != nil {
			return err
		}
		raw := ecdhPub.Bytes() // 0x04 || X (32) || Y (32)
		doc.Keys = append(doc.Keys, jwk{
			Kty: "EC", Crv: "P-256", Alg: "ES256", Use: "sig", Kid: k.KID,
			X: base64.RawURLEncoding.EncodeToString(raw[1:33]),
			Y: base64.RawURLEncoding.EncodeToString(raw[33:65]),
		})
	}
	var err error
	if ks.jwks, err = json.Marshal(doc); err != nil {
		return err
	}
	m.keys.Store(ks)
	return nil
}

// JWKS returns the public keys as a JSON Web Key Set.
func (m *Manager) JWKS() []byte { return m.keys.Load().jwks }

func (m *Manager) TTL() time.Duration { return m.ttl }

// Issue signs an access token. Registered claims (iss, aud, iat, exp, jti) are filled in here.
func (m *Manager) Issue(c Claims, now time.Time) (string, error) {
	ks := m.keys.Load()
	jti := make([]byte, 12)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	c.Issuer = m.issuer
	c.Audience = jwt.ClaimStrings{m.audience}
	c.IssuedAt = jwt.NewNumericDate(now)
	c.ExpiresAt = jwt.NewNumericDate(now.Add(m.ttl))
	c.ID = hex.EncodeToString(jti)
	if c.Roles == nil {
		c.Roles = []string{}
	}
	t := jwt.NewWithClaims(jwt.SigningMethodES256, c)
	t.Header["kid"] = ks.active.KID
	return t.SignedString(ks.active.Private)
}

// Verify checks signature, algorithm, issuer, audience and expiry.
func (m *Manager) Verify(raw string) (*Claims, error) {
	ks := m.keys.Load()
	var c Claims
	_, err := jwt.ParseWithClaims(raw, &c, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		pub, ok := ks.public[kid]
		if !ok {
			return nil, fmt.Errorf("unknown key id %q", kid)
		}
		return pub, nil
	},
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithIssuer(m.issuer),
		jwt.WithAudience(m.audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(5*time.Second),
	)
	if err != nil {
		return nil, err
	}
	return &c, nil
}
