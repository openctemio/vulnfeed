// Package dsse signs and verifies DSSE v1 envelopes with Ed25519, and the
// key sets that name the keys allowed to sign bundles.
//
// The envelope, pre-authentication encoding and key ids are the ones the
// OpenCTEM platform already verifies for signed jobs: JSON
// {"payloadType", "payload" (base64), "signatures": [{"keyid", "sig" (base64)}]},
// PAE "DSSEv1 <len(type)> <type> <len(body)> <body>", key id
// "SHA256:" + hex(sha256(raw public key)).
package dsse

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"
)

// Envelope is a DSSE v1 envelope.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     []byte      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Signature is one signature of an envelope.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   []byte `json:"sig"`
}

// PAE is the DSSE v1 pre-authentication encoding.
func PAE(payloadType string, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(payloadType)))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(payload)))
	b.WriteByte(' ')
	b.Write(payload)
	return b.Bytes()
}

// KeyID names a public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "SHA256:" + hex.EncodeToString(sum[:])
}

// Sign wraps payload in an envelope signed by priv.
func Sign(priv ed25519.PrivateKey, payloadType string, payload []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("dsse: an Ed25519 private key is required")
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	return json.Marshal(Envelope{
		PayloadType: payloadType,
		Payload:     payload,
		Signatures:  []Signature{{KeyID: KeyID(pub), Sig: ed25519.Sign(priv, PAE(payloadType, payload))}},
	})
}

// Open parses an envelope of the expected type (at most maxBytes) without
// checking signatures.
func Open(envelope []byte, payloadType string, maxBytes int) (*Envelope, error) {
	if len(envelope) == 0 || len(envelope) > maxBytes {
		return nil, fmt.Errorf("dsse: envelope is empty or over %d bytes", maxBytes)
	}
	var env Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, fmt.Errorf("dsse: envelope: %w", err)
	}
	if env.PayloadType != payloadType {
		return nil, fmt.Errorf("dsse: payload type %q, want %q", env.PayloadType, payloadType)
	}
	return &env, nil
}

// VerifiedBy reports whether env carries a valid signature of pub.
func (env *Envelope) VerifiedBy(pub ed25519.PublicKey) bool {
	id := KeyID(pub)
	pae := PAE(env.PayloadType, env.Payload)
	for _, s := range env.Signatures {
		if s.KeyID == id && ed25519.Verify(pub, pae, s.Sig) {
			return true
		}
	}
	return false
}

// DecodeStrict decodes JSON into v, refusing unknown fields and trailing data.
func DecodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

// Key set (offline root → online keys).
const (
	KeySetPayloadType = "application/vnd.openctem.vulnfeed.keyset+json"
	KeySetKind        = "openctem.vulnfeed.keyset/v1"
	MaxKeySetValidity = 180 * 24 * time.Hour
	MaxKeySetBytes    = 64 << 10
	MaxKeySetKeys     = 8
	maxClockSkew      = 5 * time.Minute
)

// PublicKey describes one online key.
type PublicKey struct {
	KeyID     string `json:"keyid"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

// NewPublicKey describes pub.
func NewPublicKey(pub ed25519.PublicKey) PublicKey {
	return PublicKey{KeyID: KeyID(pub), Algorithm: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(pub)}
}

// Decode returns the raw key after checking the id matches.
func (k PublicKey) Decode() (ed25519.PublicKey, error) {
	if k.Algorithm != "ed25519" {
		return nil, fmt.Errorf("key %s: unsupported algorithm %q", k.KeyID, k.Algorithm)
	}
	raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize || KeyID(raw) != k.KeyID {
		return nil, fmt.Errorf("key %s: not the 32-byte Ed25519 key of its id", k.KeyID)
	}
	return raw, nil
}

// KeySet is the list of online keys an offline root allows to sign.
type KeySet struct {
	Kind          string      `json:"kind"`
	Version       uint64      `json:"version"`
	IssuedAt      time.Time   `json:"issued_at"`
	NotAfter      time.Time   `json:"not_after"`
	Keys          []PublicKey `json:"keys"`
	RootKeyID     string      `json:"root_keyid"`
	RootPublicKey string      `json:"root_public_key"`
}

func (ks *KeySet) check() error {
	switch {
	case ks.Kind != KeySetKind:
		return fmt.Errorf("key set: kind %q", ks.Kind)
	case ks.Version == 0:
		return errors.New("key set: version must be 1 or more")
	case ks.IssuedAt.IsZero() || !ks.NotAfter.After(ks.IssuedAt) || ks.NotAfter.Sub(ks.IssuedAt) > MaxKeySetValidity:
		return fmt.Errorf("key set: validity must be positive and at most %s", MaxKeySetValidity)
	case len(ks.Keys) == 0 || len(ks.Keys) > MaxKeySetKeys:
		return fmt.Errorf("key set: 1 to %d keys", MaxKeySetKeys)
	}
	root, err := base64.StdEncoding.DecodeString(ks.RootPublicKey)
	if err != nil || len(root) != ed25519.PublicKeySize || KeyID(root) != ks.RootKeyID {
		return errors.New("key set: root_public_key is not the key of root_keyid")
	}
	seen := map[string]bool{}
	for _, k := range ks.Keys {
		if _, err := k.Decode(); err != nil {
			return fmt.Errorf("key set: %w", err)
		}
		if seen[k.KeyID] || k.KeyID == ks.RootKeyID {
			return fmt.Errorf("key set: key %s listed twice or is the root", k.KeyID)
		}
		seen[k.KeyID] = true
	}
	return nil
}

// SignKeySet signs a key set with the offline root.
func SignKeySet(root ed25519.PrivateKey, version uint64, issuedAt time.Time, validity time.Duration, keys []ed25519.PublicKey) ([]byte, error) {
	if len(root) != ed25519.PrivateKeySize {
		return nil, errors.New("key set: an Ed25519 root key is required")
	}
	rootPub, _ := root.Public().(ed25519.PublicKey)
	issuedAt = issuedAt.UTC().Truncate(time.Second)
	ks := KeySet{Kind: KeySetKind, Version: version, IssuedAt: issuedAt, NotAfter: issuedAt.Add(validity),
		RootKeyID: KeyID(rootPub), RootPublicKey: base64.StdEncoding.EncodeToString(rootPub)}
	for _, k := range keys {
		ks.Keys = append(ks.Keys, NewPublicKey(k))
	}
	if err := ks.check(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(ks)
	if err != nil {
		return nil, err
	}
	return Sign(root, KeySetPayloadType, payload)
}

// VerifyKeySet checks a key set: signed by its root, that root is the pinned
// one, valid now, and its version is not below minVersion.
func VerifyKeySet(envelope []byte, pinnedRoot string, minVersion uint64, now time.Time) (*KeySet, error) {
	env, err := Open(envelope, KeySetPayloadType, MaxKeySetBytes)
	if err != nil {
		return nil, err
	}
	var ks KeySet
	if err := DecodeStrict(env.Payload, &ks); err != nil {
		return nil, fmt.Errorf("key set: %w", err)
	}
	if err := ks.check(); err != nil {
		return nil, err
	}
	if pinnedRoot == "" || ks.RootKeyID != pinnedRoot {
		return nil, fmt.Errorf("key set: signed by root %s, the pinned root is %q", ks.RootKeyID, pinnedRoot)
	}
	root, _ := base64.StdEncoding.DecodeString(ks.RootPublicKey)
	if !env.VerifiedBy(root) {
		return nil, errors.New("key set: bad root signature")
	}
	if ks.Version < minVersion {
		return nil, fmt.Errorf("key set: version %d is below %d (rolled back)", ks.Version, minVersion)
	}
	if ks.IssuedAt.After(now.Add(maxClockSkew)) || !ks.NotAfter.After(now.Add(-maxClockSkew)) {
		return nil, fmt.Errorf("key set: not valid at %s (valid %s to %s)", now.UTC().Format(time.RFC3339),
			ks.IssuedAt.Format(time.RFC3339), ks.NotAfter.Format(time.RFC3339))
	}
	return &ks, nil
}

// VerifyWith checks envelope against the key set and returns its payload.
func VerifyWith(ks *KeySet, envelope []byte, payloadType string, maxBytes int) ([]byte, error) {
	env, err := Open(envelope, payloadType, maxBytes)
	if err != nil {
		return nil, err
	}
	for _, k := range ks.Keys {
		pub, err := k.Decode()
		if err == nil && env.VerifiedBy(pub) {
			return env.Payload, nil
		}
	}
	return nil, errors.New("dsse: not signed by a key of the key set")
}
