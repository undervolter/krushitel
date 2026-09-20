package dhip

// Верификация dummy-юзера: хеш Console-логина содержит username, поэтому
// VerifyLogin обязан логиниться под созданным юзером, а не под admin.

import (
	"crypto/md5"
	"fmt"
	"strings"
	"testing"
	"time"
)

func md5upper(s string) string {
	h := md5.Sum([]byte(s))
	return strings.ToUpper(fmt.Sprintf("%x", h))
}

// Test_VerifyLogin_username_hash — сервер принимает Console-логин только
// под pwnedadmin с корректным хешем (user:realm:pwd → user:random:h1).
func Test_VerifyLogin_username_hash(t *testing.T) {
	const (
		wantUser = "pwnedadmin"
		wantPass = "PwnedByK1"
		realm    = "Login to 5L04507PAJ01B96"
		random   = "1705806535"
	)

	var lastUser, lastClientType string
	srv := newFakeDhipServer(t, func(method string, params map[string]any, id int) (bool, map[string]any) {
		if method != "global.login" {
			return false, nil
		}
		lastUser, _ = params["userName"].(string)
		lastClientType, _ = params["clientType"].(string)

		switch params["clientType"] {
		case "Web3.0":
			if params["password"] == "" {
				return false, map[string]any{
					"session": float64(7), "realm": realm, "random": random,
				}
			}
			return false, nil
		case "Console":
			h1 := md5upper(wantUser + ":" + realm + ":" + wantPass)
			h2 := md5upper(wantUser + ":" + random + ":" + h1)
			if params["userName"] == wantUser && params["password"] == h2 {
				return true, map[string]any{"session": float64(7)}
			}
			return false, nil
		}
		return false, nil
	})

	if err := VerifyLogin(srv.addr(), wantUser, wantPass, 3*time.Second); err != nil {
		t.Fatalf("VerifyLogin(pwnedadmin): %v", err)
	}
	if lastUser != wantUser {
		t.Fatalf("сервер видел userName=%q, want %q", lastUser, wantUser)
	}
	if lastClientType != "Console" {
		t.Fatalf("clientType=%q, want Console (полные права)", lastClientType)
	}

	// Старый баг: верификация под admin должна провалиться — юзер не admin.
	if err := VerifyLogin(srv.addr(), "admin", wantPass, 3*time.Second); err == nil {
		t.Fatal("VerifyLogin(admin) прошёл — username-хеш не проверяется!")
	}
}
