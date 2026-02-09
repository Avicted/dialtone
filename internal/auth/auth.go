package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/Avicted/dialtone/internal/device"
	"github.com/Avicted/dialtone/internal/user"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidInput = errors.New("invalid input")
	ErrUnauthorized = errors.New("unauthorized")
	ErrTokenExpired = errors.New("token expired")
)

type Session struct {
	Token     string
	UserID    user.ID
	DeviceID  device.ID
	Username  string
	ExpiresAt time.Time
}

type Service struct {
	users    *user.Service
	devices  *device.Service
	tokens   *tokenStore
	now      func() time.Time
	tokenTTL time.Duration
}

func NewService(users *user.Service, devices *device.Service) *Service {
	return &Service{
		users:    users,
		devices:  devices,
		tokens:   newTokenStore(),
		now:      time.Now,
		tokenTTL: 24 * time.Hour,
	}
}

func (s *Service) Register(ctx context.Context, username, password, publicKey string) (user.User, device.Device, Session, error) {
	if s.users == nil || s.devices == nil {
		return user.User{}, device.Device{}, Session{}, errors.New("services are required")
	}
	name := normalizeUsername(username)
	if name == "" {
		return user.User{}, device.Device{}, Session{}, ErrInvalidInput
	}
	if strings.TrimSpace(password) == "" || len(password) < 8 {
		return user.User{}, device.Device{}, Session{}, ErrInvalidInput
	}
	if strings.TrimSpace(publicKey) == "" {
		return user.User{}, device.Device{}, Session{}, ErrInvalidInput
	}

	hash, err := hashPassword(password)
	if err != nil {
		return user.User{}, device.Device{}, Session{}, err
	}

	createdUser, err := s.users.CreateWithPassword(ctx, name, hash)
	if err != nil {
		return user.User{}, device.Device{}, Session{}, err
	}

	createdDevice, err := s.devices.Create(ctx, createdUser.ID, publicKey)
	if err != nil {
		return user.User{}, device.Device{}, Session{}, err
	}

	session, err := s.issue(createdUser.ID, createdDevice.ID, name)
	if err != nil {
		return user.User{}, device.Device{}, Session{}, err
	}
	return createdUser, createdDevice, session, nil
}

func (s *Service) Login(ctx context.Context, username, password, publicKey string) (user.User, device.Device, Session, error) {
	if s.users == nil || s.devices == nil {
		return user.User{}, device.Device{}, Session{}, errors.New("services are required")
	}
	name := normalizeUsername(username)
	if name == "" {
		return user.User{}, device.Device{}, Session{}, ErrInvalidInput
	}
	if strings.TrimSpace(password) == "" || len(password) < 8 {
		return user.User{}, device.Device{}, Session{}, ErrInvalidInput
	}
	if strings.TrimSpace(publicKey) == "" {
		return user.User{}, device.Device{}, Session{}, ErrInvalidInput
	}

	found, err := s.users.GetByUsername(ctx, name)
	if err != nil {
		return user.User{}, device.Device{}, Session{}, ErrUnauthorized
	}
	if found.PasswordHash == "" {
		return user.User{}, device.Device{}, Session{}, ErrUnauthorized
	}
	if err := checkPassword(found.PasswordHash, password); err != nil {
		return user.User{}, device.Device{}, Session{}, ErrUnauthorized
	}

	createdDevice, err := s.devices.GetByUserAndPublicKey(ctx, found.ID, publicKey)
	if err != nil {
		if !errors.Is(err, device.ErrNotFound) {
			return user.User{}, device.Device{}, Session{}, err
		}
		createdDevice, err = s.devices.Create(ctx, found.ID, publicKey)
		if err != nil {
			return user.User{}, device.Device{}, Session{}, err
		}
	}

	session, err := s.issue(found.ID, createdDevice.ID, name)
	if err != nil {
		return user.User{}, device.Device{}, Session{}, err
	}
	return found, createdDevice, session, nil
}

func (s *Service) ValidateToken(token string) (Session, error) {
	if strings.TrimSpace(token) == "" {
		return Session{}, ErrUnauthorized
	}
	return s.tokens.validate(s.now(), token)
}

func (s *Service) issue(userID user.ID, deviceID device.ID, username string) (Session, error) {
	value, err := randomToken()
	if err != nil {
		return Session{}, err
	}
	expires := s.now().Add(s.tokenTTL)
	session := Session{
		Token:     value,
		UserID:    userID,
		DeviceID:  deviceID,
		Username:  username,
		ExpiresAt: expires,
	}
	s.tokens.store(session)
	return session, nil
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func checkPassword(hashed, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func normalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

type tokenStore struct {
	mu       sync.Mutex
	sessions map[string]Session
}

func newTokenStore() *tokenStore {
	return &tokenStore{sessions: make(map[string]Session)}
}

func (t *tokenStore) store(session Session) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessions[session.Token] = session
}

func (t *tokenStore) validate(now time.Time, token string) (Session, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	session, ok := t.sessions[token]
	if !ok {
		return Session{}, ErrUnauthorized
	}
	if !session.ExpiresAt.IsZero() && now.After(session.ExpiresAt) {
		delete(t.sessions, token)
		return Session{}, ErrTokenExpired
	}
	return session, nil
}
