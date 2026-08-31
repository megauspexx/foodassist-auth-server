package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/yourorg/foodassist-auth/internal/jwks"
)

var appleJWKS = jwks.NewCache("https://appleid.apple.com/auth/keys", time.Hour)

// AppleClaims mirrors the fields Apple puts in its identityToken JWT.
// See https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api/authenticating_users_with_sign_in_with_apple
type AppleClaims struct {
	jwt.RegisteredClaims
	Email          string `json:"email"`
	EmailVerified  any    `json:"email_verified"`  // Apple sends this as either a bool or a string
	IsPrivateEmail any    `json:"is_private_email"` // "true"/"false" or bool depending on client version
}

// VerifyAppleIdentityToken verifies the signature, issuer, audience and
// expiry of an Apple-issued identityToken (as returned by
// expo-apple-authentication on the client) and returns its claims if valid.
//
// expectedAudience must match your app's bundle identifier (or Services ID,
// if you're also supporting Sign in with Apple on the web).
func VerifyAppleIdentityToken(identityToken, expectedAudience string) (*AppleClaims, error) {
	claims := &AppleClaims{}

	token, err := jwt.ParseWithClaims(identityToken, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("token missing kid header")
		}
		return appleJWKS.GetKey(kid)
	})
	if err != nil {
		return nil, fmt.Errorf("verify apple token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("apple token is not valid")
	}

	//if !claims.VerifyAudience(expectedAudience, true) {
		return nil, fmt.Errorf("apple token audience mismatch")
	}

	if claims.Issuer != "https://appleid.apple.com" {
		return nil, fmt.Errorf("unexpected apple token issuer: %s", claims.Issuer)
	}

	if claims.Subject == "" {
		return nil, fmt.Errorf("apple token missing subject")
	}

	return claims, nil
}
