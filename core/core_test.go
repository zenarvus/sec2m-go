package core

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

const (
	testFastKDParams = "argon2id-16-1-8-1" // Low iteration and memory settings for fast unit test execution
	testPassword     = "SecretPassword123!"
	testNewPassword  = "NewStrongerPassword456!"
)

// Tests front coding prefix compression and decompression.
func TestFrontCodeDecode(t *testing.T) {
	tests := []struct { prev string; curr string; expected string
	}{
		{"", "app/config/db", "app/config/db"},
		{"app/config/db", "app/config/env", "app/config/env"},
		{"app/config/env", "app/logs/sys", "app/logs/sys"},
		{"app/logs/sys", "zebra", "zebra"},
	}

	prev := ""
	for _, tt := range tests {
		compressed := FrontCode(prev, tt.curr)
		decoded, err := FrontDecode(prev, compressed)
		if err != nil {
			t.Fatalf("FrontDecode failed for '%s' with prev '%s': %v", tt.curr, prev, err)
		}
		if decoded != tt.expected {
			t.Errorf("Expected decoded '%s', got '%s'", tt.expected, decoded)
		}
		prev = tt.curr
	}

	// Test decoding error cases
	_, err := FrontDecode("short", []byte{0x0a, 'x'}) // Prefix len 10 > prev len 5
	if err == nil {
		t.Error("Expected error when prefix length exceeds previous string length, got nil")
	}
}

// Verifies memory clearing functionality.
func TestZeroBytes(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5, 255, 128}
	ZeroBytes(data)
	for i, b := range data {
		if b != 0 { t.Errorf("Byte at index %d was not zeroed, got %d", i, b) }
	}

	// Ensure calling on nil does not panic
	ZeroBytes(nil)
}

// Tests direct encryption and decryption across supported algorithms.
func TestLowLevelEncryption(t *testing.T) {
	algorithms := []struct { name string; algo uint64
	}{
		{"AES_CBC_256", Encrypt_AES_CBC_256},
		{"CHACHA20", Encrypt_CHACHA20},
	}

	key := make([]byte, 32)
	copy(key, []byte("01234567890123456789012345678901"))
	plaintext := []byte("Sensitive data to be encrypted")

	for _, tc := range algorithms {
		t.Run(tc.name, func(t *testing.T) {
			nonce, ciphertext, err := encryptData(plaintext, key, nil, tc.algo)
			if err != nil {
				t.Fatalf("encryptData failed: %v", err)
			}

			decrypted, err := unencryptData(ciphertext, nonce, key, tc.algo)
			if err != nil {
				t.Fatalf("unencryptData failed: %v", err)
			}

			if !bytes.Equal(plaintext, decrypted) {
				t.Errorf("Decrypted data mismatch. Got %s, expected %s", decrypted, plaintext)
			}
		})
	}
}

// Tests vault initialization, lock files, and loading with correct/wrong passwords.
func TestInitAndLoadSession(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "test_vault.sdb")

	// Initialize vault session
	sess, err := InitSession(vaultPath, []byte(testPassword), testFastKDParams, "aes-cbc-256", "sha2-256")
	if err != nil {
		t.Fatalf("InitSession failed: %v", err)
	}

	// Check lock file existence
	lockPath := vaultPath + ".lock"
	if _, err := os.Stat(lockPath); os.IsNotExist(err) { t.Errorf("Lock file does not exist after InitSession") }

	// Destroy session (removes lock file)
	sess.Destroy()
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) { t.Errorf("Lock file still exists after Destroy()") }

	// Try to initialize over existing lock file collision
	if err := os.WriteFile(lockPath, []byte("lock"), 0600); err != nil {
		t.Fatalf("Failed to create dummy lock file: %v", err)
	}
	_, err = InitSession(vaultPath, []byte(testPassword), testFastKDParams, "aes-cbc-256", "sha2-256")
	if err == nil { t.Errorf("Expected InitSession to fail when lock file already exists") }
	os.Remove(lockPath)

	// Load session with correct password
	loadedSess, err := LoadSession(vaultPath, []byte(testPassword))
	if err != nil { t.Fatalf("LoadSession failed with correct password: %v", err) }
	loadedSess.Destroy()

	// Load session with incorrect password
	_, err = LoadSession(vaultPath, []byte("WrongPassword"))
	if err == nil { t.Errorf("Expected LoadSession to fail with wrong password") }
}

// TestSessionEntryCRUD tests Put, Get, Update, Rm, Mv operations inside a session.
func TestSessionEntryCRUD(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "crud_vault.sdb")

	sess, err := InitSession(vaultPath, []byte(testPassword), testFastKDParams, "xchacha20", "sha3-256")
	if err != nil { t.Fatalf("InitSession failed: %v", err) }
	defer sess.Destroy()

	// Put
	key := "/services/db/password"
	val := []byte("mypassword123") // we clone it because sess zeroes it after insertion
	if err := sess.Put(key, nil, bytes.Clone(val)); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Get
	gotVal, err := sess.Get(key)
	if err != nil { t.Fatalf("Get failed: %v", err) }
	if !bytes.Equal(gotVal, []byte("mypassword123")) {
		t.Errorf("Get returned %s, expected mypassword123", gotVal)
	}

	// Update
	newVal := []byte("updated_password_456")
	if err := sess.Update(key, bytes.Clone(newVal)); err != nil { t.Fatalf("Update failed: %v", err) }

	gotVal, err = sess.Get(key)
	if err != nil { t.Fatalf("Get after update failed: %v", err) }

	if !bytes.Equal(gotVal, newVal) {
		t.Errorf("Get after update returned %s, expected %s", gotVal, newVal)
	}

	// Move (Mv)
	newKey := "/services/db/master_password"
	if err := sess.Mv(key, newKey); err != nil {
		t.Fatalf("Mv failed: %v", err)
	}

	// Old key should be gone
	if _, err := sess.Get(key); err == nil {
		t.Errorf("Expected error getting moved old key, got nil")
	}

	// New key should exist
	gotVal, err = sess.Get(newKey)
	if err != nil || !bytes.Equal(gotVal, newVal) {
		t.Errorf("Get moved key failed or value mismatched: %v", err)
	}

	// Remove (Rm)
	if err := sess.Rm(newKey); err != nil {
		t.Fatalf("Rm failed: %v", err)
	}
	if _, err := sess.Get(newKey); err == nil {
		t.Errorf("Expected error getting removed key, got nil")
	}
}

// TestSessionNavigationAndListing tests Cd, Ls, Lsall, and Rmd directory operations.
func TestSessionNavigationAndListing(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "nav_vault.sdb")

	sess, err := InitSession(vaultPath, []byte(testPassword), testFastKDParams, "aes-cbc-256", "blake3-256")
	if err != nil {
		t.Fatalf("InitSession failed: %v", err)
	}
	defer sess.Destroy()

	// Populate entries
	entries := map[string]string{
		"/env/prod/db": "proddb",
		"/env/prod/api": "prodapi",
		"/env/dev/db": "devdb",
		"/global/apiKey": "key123",
	}

	for k, v := range entries {
		if err := sess.Put(k, nil, []byte(v)); err != nil {
			t.Fatalf("Failed to put key %s: %v", k, err)
		}
	}

	// Test Ls at root
	folders, files, err := sess.Ls("/")
	if err != nil { t.Fatalf("Ls '/' failed: %v", err) }
	if len(folders) != 2 || len(files) != 0 { // env, global
		t.Errorf("Unexpected root Ls output: folders=%v, files=%v", folders, files)
	}

	// Test Cd and relative operations
	if err := sess.Cd("/env/prod"); err != nil { t.Fatalf("Cd '/env/prod' failed: %v", err) }
	if sess.Pwd != "/env/prod/" { t.Errorf("Expected pwd '/env/prod/', got '%s'", sess.Pwd) }

	folders, files, err = sess.Ls("") // Current PWD
	if err != nil { t.Fatalf("Ls PWD failed: %v", err) }
	if len(files) != 2 { // db, api
		t.Errorf("Expected 2 files in /env/prod/, got %d: %v", len(files), files)
	}

	// Test Lsall
	allEntries, err := sess.Lsall("/env/")
	if err != nil { t.Fatalf("Lsall failed: %v", err) }
	if len(allEntries) != 3 { // prod/db, prod/api, dev/db
		t.Errorf("Expected 3 entries in Lsall('/env/'), got %d: %v", len(allEntries), allEntries)
	}

	// Test Rmd
	if err := sess.Rmd("/env/dev/"); err != nil { t.Fatalf("Rmd failed: %v", err) }
	if _, err := sess.Get("/env/dev/db"); err == nil {
		t.Errorf("Expected key /env/dev/db to be removed after Rmd")
	}
}

// TestVaultChange tests re-encrypting the vault with new settings and passwords.
func TestVaultChange(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "change_vault.sdb")

	// Create vault with AES-CBC-256 and SHA2-256
	sess, err := InitSession(vaultPath, []byte(testPassword), testFastKDParams, "aes-cbc-256", "sha2-256")
	if err != nil { t.Fatalf("InitSession failed: %v", err) }

	key := "/secret/token"
	val := []byte("super-secret-token")
	if err := sess.Put(key, nil, bytes.Clone(val)); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if err := sess.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Change password and cipher suite to XChaCha20 and SHA3-256
	err = sess.VaultChange(
		[]byte(testPassword),
		[]byte(testNewPassword),
		testFastKDParams,
		"xchacha20", "sha3-256",
	)
	if err != nil { t.Fatalf("VaultChange failed: %v", err) }
	sess.Destroy()

	// Ensure original password can no longer load the file
	_, err = LoadSession(vaultPath, []byte(testPassword))
	if err == nil { t.Errorf("Expected error when loading vault with old password after VaultChange") }

	// Load vault with new password and verify secret contents
	newSess, err := LoadSession(vaultPath, []byte(testNewPassword))
	if err != nil { t.Fatalf("LoadSession failed with new password: %v", err) }
	defer newSess.Destroy()

	retrievedVal, err := newSess.Get(key)
	if err != nil { t.Fatalf("Get key after VaultChange failed: %v", err) }
	if !bytes.Equal(retrievedVal, val) {
		t.Errorf("Retrieved value mismatch. Got %s, expected %s", retrievedVal, val)
	}
}
