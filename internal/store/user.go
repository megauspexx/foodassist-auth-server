// Package store holds the user persistence layer. MemoryStore below is a
// placeholder so the server runs standalone during development; swap it
// for a Postgres/MySQL-backed implementation of the Store interface when
// you're ready — nothing else in the codebase needs to change.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

type User struct {
	ID         string
	Provider   string // "google" or "apple"
	ProviderID string // the provider's stable subject/user id
	Email      string
	Name       string
	CreatedAt  time.Time
}

// Store is the persistence interface auth handlers depend on.
type Store interface {
	// FindOrCreate looks up a user by (provider, providerID), creating one
	// if it doesn't exist yet. email/name may be empty (Apple only sends
	// them on the very first sign-in) and, if non-empty, refresh the
	// stored values.
	FindOrCreate(provider, providerID, email, name string) (*User, error)
}

type MemoryStore struct {
	mu    sync.Mutex
	byKey map[string]*User // key: provider + ":" + providerID
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{byKey: make(map[string]*User)}
}

func (s *MemoryStore) FindOrCreate(provider, providerID, email, name string) (*User, error) {
	key := provider + ":" + providerID

	s.mu.Lock()
	defer s.mu.Unlock()

	if u, ok := s.byKey[key]; ok {
		if email != "" {
			u.Email = email
		}
		if name != "" {
			u.Name = name
		}
		return u, nil
	}

	id, err := newID()
	if err != nil {
		return nil, err
	}

	u := &User{
		ID:         id,
		Provider:   provider,
		ProviderID: providerID,
		Email:      email,
		Name:       name,
		CreatedAt:  time.Now(),
	}
	s.byKey[key] = u
	return u, nil
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate user id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
