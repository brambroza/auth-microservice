// Package totp implements RFC 6238 time-based one-time passwords with the
// parameters every authenticator app supports: SHA-1, 6 digits, 30-second steps.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	period = 30
	digits = 6
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a 160-bit secret, base32-encoded for authenticator apps.
func NewSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b32.EncodeToString(b)
}

// Step is the 30-second counter for time t.
func Step(t time.Time) int64 { return t.Unix() / period }

// Code returns the 6-digit code for a step.
func Code(secret string, step int64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("totp: bad secret: %w", err)
	}
	return hotp(key, uint64(step)), nil
}

func hotp(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", digits, v%1000000)
}

// Match checks input against the current step and one step either side, to
// tolerate clock drift. It returns the matching step so the caller can refuse
// a code that was already used.
func Match(secret, input string, now time.Time) (step int64, ok bool) {
	input = strings.ReplaceAll(strings.TrimSpace(input), " ", "")
	if len(input) != digits {
		return 0, false
	}
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return 0, false
	}
	cur := Step(now)
	for _, s := range []int64{cur, cur - 1, cur + 1} {
		if subtle.ConstantTimeCompare([]byte(hotp(key, uint64(s))), []byte(input)) == 1 {
			step, ok = s, true
		}
	}
	return step, ok
}

// URI builds the otpauth:// link that authenticator apps read from a QR code.
func URI(issuer, account, secret string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + v.Encode()
}
