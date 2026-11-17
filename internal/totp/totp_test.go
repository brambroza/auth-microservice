package totp

import (
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1 rows, truncated to 6 digits.
// The secret is the ASCII string "12345678901234567890".
const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestRFC6238Vectors(t *testing.T) {
	for unix, want := range map[int64]string{
		59:          "287082",
		1111111109:  "081804",
		1111111111:  "050471",
		1234567890:  "005924",
		2000000000:  "279037",
		20000000000: "353130",
	} {
		got, err := Code(rfcSecret, Step(time.Unix(unix, 0)))
		if err != nil || got != want {
			t.Errorf("t=%d: got %q (%v), want %q", unix, got, err, want)
		}
	}
}

func TestMatchWindow(t *testing.T) {
	now := time.Unix(1111111109, 0)
	if step, ok := Match(rfcSecret, "081 804", now); !ok || step != Step(now) {
		t.Fatalf("current step not accepted (step=%d ok=%v)", step, ok)
	}
	if _, ok := Match(rfcSecret, "081804", now.Add(30*time.Second)); !ok {
		t.Fatal("previous step should be accepted")
	}
	if _, ok := Match(rfcSecret, "081804", now.Add(90*time.Second)); ok {
		t.Fatal("a code three steps old must be rejected")
	}
	if _, ok := Match(rfcSecret, "08180", now); ok {
		t.Fatal("short code accepted")
	}
}

func TestNewSecretRoundTrip(t *testing.T) {
	s := NewSecret()
	if len(s) != 32 {
		t.Fatalf("secret length = %d", len(s))
	}
	now := time.Now()
	c, err := Code(s, Step(now))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := Match(s, c, now); !ok {
		t.Fatal("generated code did not match")
	}
}
