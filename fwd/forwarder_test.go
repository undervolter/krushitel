package fwd

import (
	"os"
	"reflect"
	"testing"
)

func TestDefaultCreds(t *testing.T) {
	origLogin, origPass := getDefaultCreds()
	defer SetDefaultCreds(origLogin, origPass)

	SetDefaultCreds("superadmin", []string{"pass1", "pass2", "custom:pass3"})

	login, passes := getDefaultCreds()
	if login != "superadmin" {
		t.Fatalf("expected login superadmin, got %s", login)
	}
	expected := []string{"pass1", "pass2", "custom:pass3"}
	if !reflect.DeepEqual(passes, expected) {
		t.Fatalf("expected passes %v, got %v", expected, passes)
	}
}

func TestForwarderCredsFields(t *testing.T) {
	f := &Forwarder{
		User:  "admin",
		Pass:  "admin123",
		Dtype: 1,
	}
	if f.User != "admin" || f.Pass != "admin123" || f.Dtype != 1 {
		t.Fatalf("Forwarder creds mismatch: %s:%s dtype=%d", f.User, f.Pass, f.Dtype)
	}

	b := Binding{
		Serial: "4H01557PAZ14C8F",
		Tunnel: fwdTunnel{f: f},
		Login:  f.User,
		Pass:   f.Pass,
		Dtype:  f.Dtype,
	}
	if b.Login != "admin" || b.Pass != "admin123" || b.Dtype != 1 {
		t.Fatalf("Binding creds mismatch: %s:%s dtype=%d", b.Login, b.Pass, b.Dtype)
	}
}

func TestLoadPasswordsFromFile(t *testing.T) {
	tmp, err := os.CreateTemp("", "krushitel_pass_*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	content := "# comment line\nadmin\n\nadmin123\n// another comment\nroot:toor\n"
	if _, err := tmp.WriteString(content); err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	list, err := LoadPasswordsFromFile(tmp.Name())
	if err != nil {
		t.Fatalf("LoadPasswordsFromFile failed: %v", err)
	}
	expected := []string{"admin", "admin123", "root:toor"}
	if !reflect.DeepEqual(list, expected) {
		t.Fatalf("got %v, want %v", list, expected)
	}
}

