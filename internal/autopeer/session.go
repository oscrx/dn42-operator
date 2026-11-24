package autopeer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// Cookies seals small JSON values into encrypted, authenticated cookies
// (AES-256-GCM). Nothing is stored server side.
type Cookies struct {
	aead   cipher.AEAD
	Secure bool
}

// NewCookies uses a 32-byte key.
func NewCookies(key []byte, secure bool) (*Cookies, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("cookie key must be 32 bytes, got %d", len(key))
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return &Cookies{aead: a, Secure: secure}, nil
}

// ReadKeyFile reads a base64-encoded key (e.g. 32 random bytes, base64).
func ReadKeyFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// One format, base64: raw bytes that happened to be 32 characters long
	// would otherwise be read differently than their base64 decoding.
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("%s: not base64: %w", path, err)
	}
	return k, nil
}

type sealed struct {
	Exp  int64           `json:"e"`
	Data json.RawMessage `json:"d"`
}

// Set seals v under name for ttl.
func (c *Cookies) Set(w http.ResponseWriter, name string, v any, ttl time.Duration) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	plain, err := json.Marshal(sealed{Exp: time.Now().Add(ttl).Unix(), Data: data})
	if err != nil {
		return err
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	// The cookie name is authenticated too, so a value can't be moved
	// from one cookie to another.
	ct := c.aead.Seal(nonce, nonce, plain, []byte(name))
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: base64.RawURLEncoding.EncodeToString(ct), Path: "/",
		MaxAge: int(ttl.Seconds()), HttpOnly: true, Secure: c.Secure, SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// Get opens the cookie into v; an expired or tampered cookie is an error.
func (c *Cookies) Get(r *http.Request, name string, v any) error {
	ck, err := r.Cookie(name)
	if err != nil {
		return err
	}
	ct, err := base64.RawURLEncoding.DecodeString(ck.Value)
	if err != nil || len(ct) < c.aead.NonceSize() {
		return errors.New("bad cookie")
	}
	plain, err := c.aead.Open(nil, ct[:c.aead.NonceSize()], ct[c.aead.NonceSize():], []byte(name))
	if err != nil {
		return errors.New("bad cookie")
	}
	var s sealed
	if err := json.Unmarshal(plain, &s); err != nil {
		return err
	}
	if time.Now().Unix() > s.Exp {
		return errors.New("cookie expired")
	}
	return json.Unmarshal(s.Data, v)
}

// Clear removes a cookie.
func (c *Cookies) Clear(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: c.Secure, SameSite: http.SameSiteLaxMode})
}

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
