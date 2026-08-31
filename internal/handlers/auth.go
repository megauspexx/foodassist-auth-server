package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/yourorg/foodassist-auth/internal/auth"
	"github.com/yourorg/foodassist-auth/internal/store"
)

// AuthHandler wires token verification + user storage + session issuance
// together for both providers.
type AuthHandler struct {
	GoogleClientID string
	AppleBundleID  string
	Sessions       *auth.SessionManager
	Users          store.Store
}

type userResponse struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Provider string `json:"provider"`
}

type authResponse struct {
	Token string       `json:"token"`
	User  userResponse `json:"user"`
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// --- POST /auth/google ---
// Body: {"idToken": "<google id token from the client>"}

type googleAuthRequest struct {
	IDToken string `json:"idToken"`
}

func (h *AuthHandler) Google(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req googleAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.IDToken == "" {
		writeError(w, http.StatusBadRequest, "idToken is required")
		return
	}

	claims, err := auth.VerifyGoogleIDToken(req.IDToken, h.GoogleClientID)
	if err != nil {
		log.Printf("google auth failed: %v", err)
		writeError(w, http.StatusUnauthorized, "invalid google token")
		return
	}

	user, err := h.Users.FindOrCreate("google", claims.Subject, claims.Email, claims.Name)
	if err != nil {
		log.Printf("store error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	sessionToken, err := h.Sessions.IssueToken(user.ID, "google")
	if err != nil {
		log.Printf("session issue error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, authResponse{
		Token: sessionToken,
		User: userResponse{
			ID:       user.ID,
			Name:     user.Name,
			Email:    user.Email,
			Provider: "google",
		},
	})
}

// --- POST /auth/apple ---
// Body: {"identityToken": "...", "userId": "...", "email": "...", "name": "..."}
// email/name come straight from the client because Apple only includes
// them in the token payload on the user's very first sign-in.

type appleAuthRequest struct {
	IdentityToken string `json:"identityToken"`
	UserID        string `json:"userId"`
	Email         string `json:"email"`
	Name          string `json:"name"`
}

func (h *AuthHandler) Apple(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req appleAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.IdentityToken == "" {
		writeError(w, http.StatusBadRequest, "identityToken is required")
		return
	}

	claims, err := auth.VerifyAppleIdentityToken(req.IdentityToken, h.AppleBundleID)
	if err != nil {
		log.Printf("apple auth failed: %v", err)
		writeError(w, http.StatusUnauthorized, "invalid apple token")
		return
	}

	email := claims.Email
	if email == "" {
		email = req.Email
	}

	user, err := h.Users.FindOrCreate("apple", claims.Subject, email, req.Name)
	if err != nil {
		log.Printf("store error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	sessionToken, err := h.Sessions.IssueToken(user.ID, "apple")
	if err != nil {
		log.Printf("session issue error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, authResponse{
		Token: sessionToken,
		User: userResponse{
			ID:       user.ID,
			Name:     user.Name,
			Email:    user.Email,
			Provider: "apple",
		},
	})
}
