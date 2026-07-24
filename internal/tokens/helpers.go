package tokens

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// b64 is base64url without padding — the JOSE segment encoding.
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// split3 splits a compact JWS into its three segments.
func split3(raw string) ([]string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed jwt: want 3 segments, got %d", len(parts))
	}
	return parts, nil
}

// decodeSeg base64url-decodes a JWT segment and unmarshals its JSON.
func decodeSeg(seg string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return fmt.Errorf("segment base64: %w", err)
	}
	return json.Unmarshal(raw, v)
}

// issFromAny extracts the `iss` claim without a second JSON pass. The generic
// parse path only ever instantiates AuthClaims/ResourceClaims here.
func issFromAny(v any) string {
	switch c := v.(type) {
	case *AuthClaims:
		return c.Iss
	case *ResourceClaims:
		return c.Iss
	default:
		return ""
	}
}

// issuerThumbFromHeader resolves the issuer key named by the JWT header and
// returns its RFC 7638 thumbprint — the value a PSA pins in KeyThumbprints.
func issuerThumbFromHeader(ctx context.Context, keys JWKSResolver, iss, kid string) (string, error) {
	jwk, err := keys.Key(ctx, iss, kid)
	if err != nil {
		return "", fmt.Errorf("resolve issuer key %s/%s: %w", iss, kid, err)
	}
	return jwk.Thumbprint(), nil
}

// caipEq compares two CAIP-10 identifiers. The address segment is compared
// case-insensitively (EIP-55 checksum is presentational, not identifying).
func caipEq(a, b string) bool { return strings.EqualFold(a, b) }

// applyVouched copies gated identity claims onto the token payload.
func applyVouched(c *AuthClaims, m map[string]Vouched) {
	for name, v := range m {
		v := v
		switch name {
		case "name":
			c.Name = &v
		case "email":
			c.Email = &v
		case "kyc":
			c.KYC = &v
		}
	}
}

func containsStr(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// bigOrZero parses a decimal wei string; empty/invalid yields 0 (never nil, so
// callers can Cmp without a guard).
func bigOrZero(s string) *big.Int {
	if s == "" {
		return big.NewInt(0)
	}
	if n, ok := new(big.Int).SetString(s, 10); ok {
		return n
	}
	return big.NewInt(0)
}

// newJTI mints a random token id (128 bits, hex).
func newJTI() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
