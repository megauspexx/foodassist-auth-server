package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SessionClaims is the payload of the app's own session JWT, issued after
// a Google or Apple token has been verified.
type SessionClaims struct {
	jwt.RegisteredClaims
	UserID   string `json:"uid"`
	Provider string `json:"provider"`
}

// SessionManager issues and validates the app's own HS256 session tokens.
// Use ParseToken in your auth middleware to protect other routes later.
type SessionManager struct {
	secret []byte
	ttl    time.Duration
}

func NewSessionManager(secret string, ttl time.Duration) *SessionManager {
	return &SessionManager{secret: []byte(secret), ttl: ttl}
}

func (m *SessionManager) IssueToken(userID, provider string) (string, error) {
	now := time.Now()
	claims := SessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.ttl)),
			Subject:   userID,
		},
		UserID:   userID,
		Provider: provider,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secret)
}

// ParseToken validates a session token issued by IssueToken. Wire this into
// an auth middleware once you add routes that require a logged-in user.
func (m *SessionManager) ParseToken(tokenStr string) (*SessionClaims, error) {
	claims := &SessionClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.secret, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("session token is not valid")
	}
	return claims, nil
}
