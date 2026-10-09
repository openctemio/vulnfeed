package dsse

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestPAEAndEnvelopeFormat(t *testing.T) {
	if got := string(PAE("t/x", []byte("hello"))); got != "DSSEv1 3 t/x 5 hello" {
		t.Fatalf("PAE = %q", got)
	}
	_, priv := key(t)
	env, err := Sign(priv, "t/x", []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(env, &raw); err != nil {
		t.Fatal(err)
	}
	sigs, _ := raw["signatures"].([]any)
	sig, _ := sigs[0].(map[string]any)
	if raw["payloadType"] != "t/x" || raw["payload"] != "eyJhIjoxfQ==" || !strings.HasPrefix(sig["keyid"].(string), "SHA256:") || sig["sig"] == nil {
		t.Fatalf("envelope %s", env)
	}
}

func TestKeySetAndVerify(t *testing.T) {
	rootPub, root := key(t)
	pub, priv := key(t)
	now := time.Now()
	ksEnv, err := SignKeySet(root, 3, now, 90*24*time.Hour, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	ks, err := VerifyKeySet(ksEnv, KeyID(rootPub), 2, now)
	if err != nil {
		t.Fatal(err)
	}
	env, _ := Sign(priv, "t/x", []byte("payload"))
	if got, err := VerifyWith(ks, env, "t/x", 1<<10); err != nil || string(got) != "payload" {
		t.Fatalf("VerifyWith: %q %v", got, err)
	}

	otherPub, other := key(t)
	_ = otherPub
	forged, _ := Sign(other, "t/x", []byte("payload"))
	cases := map[string]func() error{
		"another root pinned": func() error { _, err := VerifyKeySet(ksEnv, KeyID(otherPub), 0, now); return err },
		"no root pinned":      func() error { _, err := VerifyKeySet(ksEnv, "", 0, now); return err },
		"rolled back":         func() error { _, err := VerifyKeySet(ksEnv, KeyID(rootPub), 4, now); return err },
		"expired":             func() error { _, err := VerifyKeySet(ksEnv, KeyID(rootPub), 0, now.Add(91*24*time.Hour)); return err },
		"not yet valid":       func() error { _, err := VerifyKeySet(ksEnv, KeyID(rootPub), 0, now.Add(-time.Hour)); return err },
		"unknown signer":      func() error { _, err := VerifyWith(ks, forged, "t/x", 1<<10); return err },
		"wrong type":          func() error { _, err := VerifyWith(ks, env, "t/y", 1<<10); return err },
		"too big":             func() error { _, err := VerifyWith(ks, env, "t/x", 10); return err },
		"tampered payload": func() error {
			var e Envelope
			_ = json.Unmarshal(env, &e)
			e.Payload = []byte("payloae")
			b, _ := json.Marshal(e)
			_, err := VerifyWith(ks, b, "t/x", 1<<10)
			return err
		},
		"key set signed by an online key": func() error {
			bad, _ := SignKeySet(priv, 1, now, time.Hour, []ed25519.PublicKey{otherPub})
			_, err := VerifyKeySet(bad, KeyID(rootPub), 0, now)
			return err
		},
	}
	for name, fn := range cases {
		if fn() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSignKeySetRefuses(t *testing.T) {
	rootPub, root := key(t)
	pub, _ := key(t)
	now := time.Now()
	for name, fn := range map[string]func() error{
		"too long": func() error {
			_, err := SignKeySet(root, 1, now, 181*24*time.Hour, []ed25519.PublicKey{pub})
			return err
		},
		"version 0":      func() error { _, err := SignKeySet(root, 0, now, time.Hour, []ed25519.PublicKey{pub}); return err },
		"no keys":        func() error { _, err := SignKeySet(root, 1, now, time.Hour, nil); return err },
		"root as online": func() error { _, err := SignKeySet(root, 1, now, time.Hour, []ed25519.PublicKey{rootPub}); return err },
		"duplicate keys": func() error { _, err := SignKeySet(root, 1, now, time.Hour, []ed25519.PublicKey{pub, pub}); return err },
		"not a root key": func() error {
			_, err := SignKeySet(ed25519.PrivateKey{1}, 1, now, time.Hour, []ed25519.PublicKey{pub})
			return err
		},
	} {
		if fn() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDecodeStrict(t *testing.T) {
	var v struct{ A int }
	if DecodeStrict([]byte(`{"A":1}`), &v) != nil || v.A != 1 {
		t.Fatal("valid")
	}
	for _, s := range []string{`{"A":1,"B":2}`, `{"A":1} {}`, `[`} {
		if DecodeStrict([]byte(s), &v) == nil {
			t.Errorf("%s accepted", s)
		}
	}
}
