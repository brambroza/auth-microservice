package password

import (
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	h, err := Hash("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("unexpected format: %s", h)
	}
	if ok, rehash, err := Verify("correct horse battery", h); err != nil || !ok || rehash {
		t.Fatalf("ok=%v rehash=%v err=%v", ok, rehash, err)
	}
	if ok, _, err := Verify("wrong", h); err != nil || ok {
		t.Fatalf("wrong password accepted (err=%v)", err)
	}
	h2, _ := Hash("correct horse battery")
	if h == h2 {
		t.Fatal("salt was reused")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	// Truncated or non-PHC strings are errors, never a silent mismatch.
	weak := "$argon2id$v=19$m=1024,t=1,p=1$c29tZXNhbHRzb21lc2FsdA$"
	if _, _, err := Verify("x", weak); err == nil {
		t.Fatal("empty hash should be malformed")
	}
	if _, _, err := Verify("x", "plaintext"); err == nil {
		t.Fatal("garbage should be malformed")
	}
}

func TestValidate(t *testing.T) {
	if Validate("short") == nil {
		t.Fatal("short password accepted")
	}
	if Validate("รหัสผ่านยาวพอแล้ว") != nil {
		t.Fatal("Thai password of sufficient length rejected")
	}
	if Validate(strings.Repeat("a", 300)) == nil {
		t.Fatal("overlong password accepted")
	}
}
