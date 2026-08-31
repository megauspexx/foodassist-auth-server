package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/yourorg/foodassist-auth/internal/jwks"
)

var googleJWKS = jwks.NewCache("https://www.googleapis.com/oauth2/v3/certs", time.Hour)

// GoogleClaims mirrors the fields Google puts in its OIDC ID tokens that
// we care about. See https://developers.google.com/identity/openid-connect/openid-connect#id_token-payload
type GoogleClaims struct {
	jwt.RegisteredClaims
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// VerifyGoogleIDToken verifies the signature, issuer, audience and
// expiry of a Google-issued idToken (as returned by
// @react-native-google-signin/google-signin on the client) and returns
// its claims if valid.
func VerifyGoogleIDToken(idToken, expectedAudience string) (*GoogleClaims, error) {
	claims := &GoogleClaims{}

	token, err := jwt.ParseWithClaims(idToken, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("token missing kid header")
		}
		return googleJWKS.GetKey(kid)
	})
	if err != nil {
		return nil, fmt.Errorf("verify google token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("google token is not valid")
	}

	if !claims.VerifyAudience(expectedAudience, true) {
		return nil, fmt.Errorf("google token audience mismatch")
	}

	validIssuer := claims.Issuer == "accounts.google.com" || claims.Issuer == "https://accounts.google.com"
	if !validIssuer {
		return nil, fmt.Errorf("unexpected google token issuer: %s", claims.Issuer)
	}

	if !claims.EmailVerified {
		return nil, fmt.Errorf("google account email is not verified")
	}

	if claims.Subject == "" {
		return nil, fmt.Errorf("google token missing subject")
	}

	return claims, nil
}
