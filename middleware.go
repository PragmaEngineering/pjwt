// a simple middleware for handling JWT Tokens in Pragma Go backends
package pjwt

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var SECRET_KEY []byte

func init() {
	key := os.Getenv("PRAGMA_JWT_SECRET_KEY")
	if key == "" {
		panic("JWT Secret not found in environment")
	}
	SECRET_KEY = []byte(key)
}

type Adapter func(http.Handler) http.Handler

func SetAuthContext() Adapter {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			v := r.Header.Get("Authorization")
			if !strings.Contains(v, "bearer") {
				h.ServeHTTP(w, r)
				return
			}

			tokenString := strings.SplitAfter(v, " ")[1]
			token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", t.Header["alg"])
				}

				return []byte(SECRET_KEY), nil
			})
			if err != nil {
				panic(err)
			}

			if !token.Valid {
				panic(err)
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				// TODO
				panic("something not ok")
			}

			ctx := context.WithValue(r.Context(), "user_id", claims["user_id"])

			h.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// create a claims token
func NewClaims(uid string) *jwt.Token {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": uid,
		"exp":     time.Now().Add(time.Hour * time.Duration(12)).Unix(),
		"iat":     time.Now().Unix(),
	})
}

// create a signed claims string
func NewSignedString(uid string) (string, error) {
	return NewClaims(uid).SignedString(SECRET_KEY)
}

func UserIDFromContext(ctx context.Context) (string, bool) {
	uid, ok := ctx.Value("user_id").(string)
	if uid == "" {
		ok = false
	}
	return uid, ok
}
