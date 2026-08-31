package main

import (
	"log"
	"net/http"
	"time"

	"github.com/yourorg/foodassist-auth/internal/auth"
	"github.com/yourorg/foodassist-auth/internal/config"
	"github.com/yourorg/foodassist-auth/internal/handlers"
	"github.com/yourorg/foodassist-auth/internal/store"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	sessions := auth.NewSessionManager(cfg.JWTSecret, cfg.SessionTTL)
	users := store.NewMemoryStore() // TODO: swap for a real DB-backed store.Store implementation

	h := &handlers.AuthHandler{
		GoogleClientID: cfg.GoogleClientID,
		AppleBundleID:  cfg.AppleBundleID,
		Sessions:       sessions,
		Users:          users,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/google", withLogging(h.Google))
	mux.HandleFunc("/auth/apple", withLogging(h.Apple))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	addr := ":" + cfg.Port
	log.Printf("foodassist-auth listening on %s", addr)
	if err := http.ListenAndServe(addr, corsMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}

func withLogging(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next(w, r)
		log.Printf("%s %s %v", r.Method, r.URL.Path, time.Since(start))
	}
}

// corsMiddleware allows the Expo app (and its dev server) to call this API
// directly from a mobile client. Tighten Access-Control-Allow-Origin to
// your actual app/web origins before going to production.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}
