/*
sec2m-go: CLI based secrets manager
Copyright (C) 2026  zenarvus (rem)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package core

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20"

	"github.com/zenarvus/compack/go"
	"github.com/zenarvus/polyformats/polysha/go"
	"github.com/zenarvus/sec2m-go/platforms"
	"golang.org/x/crypto/argon2"
)

// POSIX portable filepaths.
var pathRegexp = regexp.MustCompile(`^/?([a-zA-Z0-9._\-]+/?)*$`) // Regexp that matches path like strings. Must not contain "/" at the end)
// Filepaths must be absolute and must NOT contain a slash at the end.
// Dirpaths must be absolute and must contain a slash at the end

const (
	Derive_ARGON2ID = 2 // Argon2id with custom parameters

	Encrypt_AES_CBC_256 = 1
	Encrypt_CHACHA20 = 2

	Hash_SHA2_256 = polysha.TYPE_SHA2_256
	Hash_SHA3_256 = polysha.TYPE_SHA3_256
	Hash_SHA3_384 = polysha.TYPE_SHA3_384
	Hash_SHA3_512 = polysha.TYPE_SHA3_512
	Hash_Blake3 = polysha.TYPE_BLAKE3_256
)

var algoStrToNumMap = map[string]uint64{
	"argon2id": Derive_ARGON2ID, // For consistency. Isn't used.

	"aes-cbc-256": Encrypt_AES_CBC_256,
	"xchacha20": Encrypt_CHACHA20,

	"sha2-256": uint64(Hash_SHA2_256),
	"sha3-256": uint64(Hash_SHA3_256),
	"sha3-384": uint64(Hash_SHA3_384),
	"sha3-512": uint64(Hash_SHA3_512),
	"blake3-256": uint64(Hash_Blake3),
}

var encAlgoToKeylen = map[uint64]int{
	Encrypt_CHACHA20: 32,
	Encrypt_AES_CBC_256: 32,
}

/////////////////////////////////////////////

type File struct {
	Version uint64 `cmpck:"1"` // Version of the file.
	Header []byte `cmpck:"2"` // Info about the algorithms, nonce and salt.
	Body []byte `cmpck:"3"` // The encrypted entry list.
	Signature []byte `cmpck:"4"` // The HMAC signature of the version, header and encrypted body.
}
type UnmarshaledHeader struct {
	KDAlgo uint64 `cmpck:"1"` // The key derivation algorithm used. Like argon2id.
	KDSalt []byte `cmpck:"2"` // The random salt used in key derivation. Permanent for the vault.
	KDParams []byte `cmpck:"3"` // Parameters used in key derivation

	SEAlgo uint64 `cmpck:"4"`  // The symmetric encryption algorithm used. Like aes-cbc.
	SENonce []byte `cmpck:"5"` // The random nonce used in outer symmetric encryption (whole body). Changes in every save.

	HashAlgo uint64 `cmpck:"6"`  // Hash algorithm used in signatures and key derivation
}
type UnencryptedBody struct {
	Entries []Entry `cmpck:"1"`
}
type Entry struct {
	Path string `cmpck:"1"` // The path of the entry
	Value []byte `cmpck:"2"`  // The value encrypted with inner key
	Nonce []byte `cmpck:"3"` // The nonce used to encrypt the value
	MTime []byte `cmpck:"4"` // The modification time of the entry (uint64 unix epoch milliseconds [little endian])
}
type Argon2IDParams struct {
	Iterations uint32 `cmpck:"1"` // Iterations
	Memory uint32 `cmpc:"2"` // Required memory in megabytes
	Threads uint32 `cmpck:"3"` // Parallel threads used while deriving keys
}

///////////////////////////////////////////////

type Session struct {
	Version uint64
	Filepath string // The file of the session.
	Header UnmarshaledHeader

	SessionKey []byte // The random session key used to encrypt OutEncKey, InnEncKey and MacKey.

	Signature []byte
	
	EncryptedOutEncKey []byte // The secret hash derived from the plaintext password using argon2id. It's used for encryption and decryption.
	OutEncKeyNonce []byte

	EncryptedInnEncKey []byte
	InnEncKeyNonce []byte

	EncryptedMacKey []byte // The secret hash derived from the plaintext password using argon2id. It's used for the MAC signature.
	MacKeyNonce []byte

	Pwd string // The current working directory in entries. For navigation in the pseudo filesystem.

	EntryMap map[string]*Entry // Entry.Path -> Entry map
}

/////////////////////////////////////////////

// Delete the session and remove the lock key
func (s *Session) Destroy() {
	ZeroBytes(s.SessionKey)
	ZeroBytes(s.EncryptedOutEncKey)
	ZeroBytes(s.EncryptedInnEncKey)
	ZeroBytes(s.EncryptedMacKey)
	for _, v := range s.EntryMap {
		ZeroBytes(v.Value)
	}
	os.Remove(s.Filepath+".lock")
}

// InitSession creates a brand new vault file with given parameters.
func InitSession(
	filepath string,
	password []byte,
	kdAlgoStr, seAlgoStr, hashAlgoStr string,
) (*Session, error) {
	// Try to create a lock file. Exit if it already exists or gives an error.
	file, err := os.OpenFile(filepath+".lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		if os.IsExist(err) { return nil, errors.New("a lock file for this vault already exists") }
		return nil, err
	}
	file.Close()

	kdAlgo, salt, kdParams, err := getKeyDerivationParams(kdAlgoStr)
	if err != nil {return nil, err}

	seAlgo := algoStrToNumMap[seAlgoStr]
	hashAlgo := algoStrToNumMap[hashAlgoStr]

	sess := &Session{
		Filepath: filepath,
		Version: 1,
		Header: UnmarshaledHeader{
			KDAlgo: kdAlgo,
			KDParams: kdParams,
			KDSalt: salt, // Salt is permanent for this file. It's needed for key derivation.
			SEAlgo: seAlgo,
			HashAlgo: hashAlgo,
			// SENonce is created in sess.Save() and changed on every save. It's only needed for decrypting files.
		},
		EntryMap: make(map[string]*Entry),

		Pwd: "/",
	}

	derivedKey, err := deriveKey(password, salt, sess.Header.KDAlgo, sess.Header.SEAlgo, sess.Header.KDParams)
	if err != nil { return nil, err }

	sessionKey, outenckey, innenckey, mackey, err := getVaultKeys(
		derivedKey, polysha.SHAType(sess.Header.HashAlgo), sess.Header.SEAlgo,
	)
	if err != nil {
		ZeroBytes(derivedKey)
		return nil, err
	}
	// Lock the session key to the memory
	err = platforms.LockMemory(sessionKey)
	if err != nil {
		ZeroBytes(sessionKey)
		ZeroBytes(outenckey)
		ZeroBytes(innenckey)
		ZeroBytes(mackey)
		return nil, err
	}

	sess.SessionKey = sessionKey

	ZeroBytes(derivedKey)

	encOutNonce,encOutEncKey,err := encryptData(outenckey, sess.SessionKey, sess.Header.SEAlgo)
	if err != nil {return nil, err}

	sess.EncryptedOutEncKey = encOutEncKey
	sess.OutEncKeyNonce = encOutNonce

	encInnNonce,encInnEncKey,err := encryptData(innenckey, sess.SessionKey, sess.Header.SEAlgo)
	if err != nil {return nil, err}

	sess.EncryptedInnEncKey = encInnEncKey
	sess.InnEncKeyNonce = encInnNonce

	encMacNonce,encMacKey,err := encryptData(mackey, sess.SessionKey, sess.Header.SEAlgo)
	if err != nil {return nil, err}

	sess.EncryptedMacKey = encMacKey
	sess.MacKeyNonce = encMacNonce

	err = sess.Save()
	if err!= nil {
		sess.Destroy()
		return nil, err
	}

	return sess, nil
}

// Load a session from given file and password.
func LoadSession(filepath string, password []byte) (*Session, error) {

	// Try to create a lock file. Exit if it exists or gives an another error.
	file, err := os.OpenFile(filepath+".lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		if os.IsExist(err) { return nil, errors.New("a lock file for this vault already exists") }
		return nil, err
	}
	file.Close()

	var sess = &Session{
		EntryMap: make(map[string]*Entry),
		Pwd: "/",
	}
	sess.Filepath = filepath

	fileBytes, err := os.ReadFile(sess.Filepath)
	if err!=nil {return nil, err}

	var fileStruct File
	err = cmpck.Unmarshal(fileBytes, &fileStruct)
	if err != nil {return nil, err}

	if fileStruct.Version != 1 {
		return nil, errors.New("unsupported vault version")
	}

	sess.Version = fileStruct.Version
	sess.Signature = fileStruct.Signature

	err = cmpck.Unmarshal(fileStruct.Header, &sess.Header) // Copy the metadata of the file to the session.
	if err != nil {return nil, err}

	// Derive the encryption key using header parameters.
	derivedKey, err := deriveKey(
		password, sess.Header.KDSalt,
		sess.Header.KDAlgo, sess.Header.SEAlgo,
		sess.Header.KDParams,
	)
	if err != nil {return nil, err} 

	// Get vault keys from the derived key
	sessionKey, outenckey, innenckey, mackey, err := getVaultKeys(
		derivedKey, polysha.SHAType(sess.Header.HashAlgo), sess.Header.SEAlgo,
	)
	ZeroBytes(derivedKey) // Wipe derivedKey from memory. We do not need it anymore.
	if err != nil { return nil, err } // After getting keys is successful, we should destroy the session in any error to remove them from memory.

	// Lock the session key to the memory
	err = platforms.LockMemory(sessionKey)
	if err != nil {
		ZeroBytes(sessionKey)
		ZeroBytes(outenckey)
		ZeroBytes(innenckey)
		ZeroBytes(mackey)
		return nil, err
	}

	sess.SessionKey = sessionKey // Save the session key	 

	// Encrypt vault keys with session key and save to session

	encOutNonce,encOutEncKey,err := encryptData(outenckey, sess.SessionKey, sess.Header.SEAlgo)
	if err != nil {
		sess.Destroy()
		return nil, err
	}
	sess.EncryptedOutEncKey = encOutEncKey
	sess.OutEncKeyNonce = encOutNonce

	encInnNonce,encInnEncKey,err := encryptData(innenckey, sess.SessionKey, sess.Header.SEAlgo)
	ZeroBytes(innenckey) // We do not need innenckey when loading the session.
	if err != nil {
		sess.Destroy()
		return nil, err
	}
	sess.EncryptedInnEncKey = encInnEncKey
	sess.InnEncKeyNonce = encInnNonce

	encMacNonce,encMacKey,err := encryptData(mackey, sess.SessionKey, sess.Header.SEAlgo)
	if err != nil {
		sess.Destroy()
		return nil, err
	}
	sess.EncryptedMacKey = encMacKey
	sess.MacKeyNonce = encMacNonce

	// Do integrity check (Encrypt-then-MAC)
	expectedSignature, err := computeSignature(
		polysha.SHAType(sess.Header.HashAlgo),
		mackey,
		fileStruct.Version,
		fileStruct.Header,
		fileStruct.Body,
	)
	ZeroBytes(mackey) // Remove plaintext mackey from memory after using it.
	if err != nil {
		sess.Destroy() // Destroy the session to remove the encrypted key from memory.
		return nil, err
	}
	
	if subtle.ConstantTimeCompare(expectedSignature, fileStruct.Signature) != 1 {
		sess.Destroy()
		return nil, errors.New("integrity check failed: invalid password or tampered vault")
	}

	// Decrypt the body
	unencryptedBodyBytes, err := unencryptData(fileStruct.Body, sess.Header.SENonce, outenckey, sess.Header.SEAlgo)
	ZeroBytes(outenckey) // Remove plaintext outer encryption key from memory after using it.
	if err!=nil {
		sess.Destroy()
		return nil, err
	}
	// defer ZeroBytes(unencryptedBodyBytes) -> Compack uses bytes in here when parsing to structs. Deleting them will remove them from the struct fields too.

	var unencryptedBody UnencryptedBody 
	err = cmpck.Unmarshal(unencryptedBodyBytes, &unencryptedBody)
	if err!=nil {
		sess.Destroy()
		return nil, err
	}

	// Load file entries to the session.
	for _,entry := range unencryptedBody.Entries {
		sess.EntryMap[entry.Path] = &entry
	}

	return sess, nil
}

// Update the vault settings using the old password and overwrite the file.
func (s *Session) VaultChange(
	oldpass []byte, newpass []byte,
	kdAlgoStr, seAlgoStr, hashAlgoStr string,
) error {
	// Check if the old password is correct
	oldDerivedKey, err := deriveKey(
		oldpass, s.Header.KDSalt, s.Header.KDAlgo, s.Header.SEAlgo, s.Header.KDParams,
	)
	if err != nil {return err}

	// It's enough to check if inner encryption key is equal.
	// We gonna use it anyway.
	_,_,oldInnerEncKey,_,err := getVaultKeys(
		oldDerivedKey, polysha.SHAType(s.Header.HashAlgo), s.Header.SEAlgo,
	)
	ZeroBytes(oldDerivedKey);
	if err != nil { return err }

	oldEncAlgo := s.Header.SEAlgo

	// Decrypt the current inner encryption key
	expectedInnEncKey, err := unencryptData(s.EncryptedInnEncKey, s.InnEncKeyNonce, s.SessionKey, s.Header.SEAlgo)
	if err != nil {return err}

	// Compare them and give error if they do not match
	if !bytes.Equal(oldInnerEncKey, expectedInnEncKey) {
		ZeroBytes(expectedInnEncKey)
		return errors.New("provided password is incorrect")
	}
	ZeroBytes(expectedInnEncKey)

	// If we are here, the provided password is correct. Update the vault settings.

	kdAlgo, salt, kdParams, err := getKeyDerivationParams(kdAlgoStr)
	if err != nil {return err}

	seAlgo := algoStrToNumMap[seAlgoStr]
	hashAlgo := algoStrToNumMap[hashAlgoStr]

	// Update the header info of the session to the new algorithms
	s.Header.KDAlgo = kdAlgo
	s.Header.KDSalt = salt
	s.Header.KDParams = kdParams
	s.Header.SEAlgo = seAlgo
	s.Header.HashAlgo = hashAlgo

	// Generate the new keys from the new password

	derivedKey, err := deriveKey(newpass, s.Header.KDSalt, s.Header.KDAlgo, s.Header.SEAlgo, s.Header.KDParams)
	if err != nil {return err}

	newSessK, newOutEncK, newInnEncK, newMacK, err := getVaultKeys(
		derivedKey, polysha.SHAType(s.Header.HashAlgo), s.Header.SEAlgo,
	)
	ZeroBytes(derivedKey)
	if err != nil {return err}

	// Lock the session key to the memory
	err = platforms.LockMemory(newSessK)
	if err != nil {
		ZeroBytes(newSessK)
		ZeroBytes(newOutEncK)
		ZeroBytes(newInnEncK)
		ZeroBytes(newMacK)
		return err
	}

	// Update the session key
	s.SessionKey = newSessK

	// Encrypt the new outer encryption key and save to the session
	outerNonce, encOuterKey, err := encryptData(newOutEncK, s.SessionKey, s.Header.SEAlgo)
	ZeroBytes(newOutEncK) // We do not need the raw key anymore. Empty it.
	if err != nil { return err }
	s.OutEncKeyNonce = outerNonce
	s.EncryptedOutEncKey = encOuterKey

	// Encrypt the new mac key and save to the session
	macNonce, encMacKey, err := encryptData(newMacK, s.SessionKey, s.Header.SEAlgo)
	ZeroBytes(newMacK) // We do not need the raw key anymore. Empty it.
	if err != nil { return err }
	s.MacKeyNonce = macNonce
	s.EncryptedMacKey = encMacKey

	// Update the inner encryptions from old to new
	for _,entry := range s.EntryMap {
		// Decrypt the value using old parameters
		plaintextVal, err := unencryptData(entry.Value, entry.Nonce, oldInnerEncKey, oldEncAlgo)
		if err != nil {
			ZeroBytes(plaintextVal)
			return err
		}
		
		// Encrypt it with the new ones
		newValNonce, newVal, err := encryptData(plaintextVal, newInnEncK, s.Header.SEAlgo)
		if err != nil {
			ZeroBytes(plaintextVal)
			return err
		}

		entry.Value = newVal
		entry.Nonce = newValNonce

		ZeroBytes(plaintextVal)

	}

	// Encrypt the new inner encryption key and save to the session
	innerNonce, encInnerKey, err := encryptData(newInnEncK, s.SessionKey, s.Header.SEAlgo)
	ZeroBytes(newInnEncK) // We do not need the raw key anymore. Empty it.
	if err != nil { return err }
	s.InnEncKeyNonce = innerNonce
	s.EncryptedInnEncKey = encInnerKey

	// Save the session to the file with updated parameters
	err = s.Save()
	if err != nil {return err}

	return nil
}

// Save the session entries to the original file by overwriting.
func (s *Session) Save() error {
	err := s.SaveAs(s.Filepath)
	return err
}

// Save the session entries to the given file.
func (s *Session) SaveAs(filepath string) error {

	var fileStruct = &File{}

	// Create an unencryptedBody with len(s.EntryMap) capacity
	var unencryptedBody = &UnencryptedBody{ Entries: make([]Entry, 0, len(s.EntryMap)) }
	for _,entry := range s.EntryMap {
		unencryptedBody.Entries = append(unencryptedBody.Entries, *entry)
	}

	unencryptedBodyBytes, err := cmpck.Marshal(unencryptedBody, cmpck.EncOpts{Canonical:true})
	if err!=nil {return err}
	defer ZeroBytes(unencryptedBodyBytes)

	// Decrypt the outer encryption key using SessionKey
	outEncKey, err := unencryptData(s.EncryptedOutEncKey, s.OutEncKeyNonce, s.SessionKey, s.Header.SEAlgo)
	if err != nil {return err}

	// Encrypt the body using outEncKey
	nonce,encryptedData, err := encryptData(unencryptedBodyBytes, outEncKey, s.Header.SEAlgo)
	ZeroBytes(outEncKey) // Remove outenckey from memory.
	if err!=nil{return err}

	s.Header.SENonce = nonce // Set the nonce to the session.

	// Marshal the header for fileStruct
	headerBytes, err := cmpck.Marshal(s.Header, cmpck.EncOpts{Canonical:true})
	if err != nil {return err}

	// Decrypt the mac key using SessionKey
	macKey, err := unencryptData(s.EncryptedMacKey, s.MacKeyNonce, s.SessionKey, s.Header.SEAlgo)
	if err != nil {return err}

	// Compute the signature
	signature, err := computeSignature(
		polysha.SHAType(s.Header.HashAlgo),
		macKey,
		s.Version,
		headerBytes,
		encryptedData,
	)
	ZeroBytes(macKey) // Remove mackey from memory
	if err != nil { return err }

	s.Signature = signature // Update the signature of the session

	fileStruct.Version = s.Version
	fileStruct.Header = headerBytes // save the header to the fileStruct
	fileStruct.Body = encryptedData
	fileStruct.Signature = signature

	fileBytes, err := cmpck.Marshal(fileStruct, cmpck.EncOpts{Canonical:true})
	if err!=nil {return err}

	err = os.WriteFile(filepath+".tmp", fileBytes, 0600) // Only owner can read/write. First write to a temporary file.
	if err!=nil {return err}

	// If it's successful, overwrite the original file with the temporary one.
	err = os.Rename(filepath+".tmp", filepath)
	if err!=nil {return err}

	return nil
}

// Get the value using key.
func (s *Session) Get(key string) ([]byte, error) {
	// key must be a file path string.
	if !pathRegexp.MatchString(key) || strings.HasSuffix(key, "/") {
		return nil, errors.New("key must be a filepath string")
	}
	// If it does not have slash at the start, join it to the current working directory.
	if !strings.HasPrefix(key, "/") { key = filepath.Join(s.Pwd, key) }

	entry, found := s.EntryMap[key]

	if !found { return nil, errors.New("not found") }

	// Decrypt the inner encryption key
	innEncKey, err := unencryptData(s.EncryptedInnEncKey, s.InnEncKeyNonce, s.SessionKey, s.Header.SEAlgo)
	if err != nil {return nil, err}

	// Decrypt and return the value with the inner encryption key
	value, err := unencryptData(entry.Value, entry.Nonce, innEncKey, s.Header.SEAlgo)
	ZeroBytes(innEncKey)
	if err != nil {return nil,err}

	return value, nil
}

// Add a key/value pair. Give error if it already exists.
func (s *Session) Put(key string, value []byte) error {
	// key must be an absolute filepath like string. (no slash at the end)
	if !pathRegexp.MatchString(key) || strings.HasSuffix(key, "/") { return errors.New("path must be a file path string") }

	// If it does not have slash at the start, join it to the current working directory.
	if !strings.HasPrefix(key, "/") { key = filepath.Join(s.Pwd, key) }

	_,exists := s.EntryMap[key]

	if exists { return errors.New("key already exists") }

	// Decrypt the inner encryption key
	innEncKey, err := unencryptData(s.EncryptedInnEncKey, s.InnEncKeyNonce, s.SessionKey, s.Header.SEAlgo)
	if err != nil {return err}

	// Encrypt the value with the key
	nonce, chiphertext, err := encryptData(value, innEncKey, s.Header.SEAlgo)
	ZeroBytes(innEncKey)
	ZeroBytes(value)
	if err != nil {return err}

	mTime := time.Now().UTC().UnixMilli()
	var mTimeBytes = make([]byte, 8)
	binary.LittleEndian.PutUint64(mTimeBytes, uint64(mTime))

	var newEntry = &Entry{
		Path: key,
		Value: chiphertext,
		Nonce: nonce,
		MTime: mTimeBytes,
	}

	s.EntryMap[key] = newEntry

	return nil
}

// Update a key/value pair. Give error if it does not exist.
func (s *Session) Update(key string, value []byte) error {
	// path must be an absolute filepath like string. (no slash at the end)
	if !pathRegexp.MatchString(key) || strings.HasSuffix(key, "/") { return errors.New("path must be an file path string") }
	// If it does not have slash at the start, join it to the current working directory.
	if !strings.HasPrefix(key, "/") { key = filepath.Join(s.Pwd, key) }

	_,exists := s.EntryMap[key]

	if !exists { return errors.New("key does not exist") }

	// Zero the old values
	ZeroBytes(s.EntryMap[key].Value)
	ZeroBytes(s.EntryMap[key].Nonce)

	// Decrypt the inner encryption key
	innEncKey, err := unencryptData(s.EncryptedInnEncKey, s.InnEncKeyNonce, s.SessionKey, s.Header.SEAlgo)
	if err != nil {return err}

	// Encrypt the new value with the key
	nonce, chiphertext, err := encryptData(value, innEncKey, s.Header.SEAlgo)
	ZeroBytes(innEncKey)
	ZeroBytes(value)
	if err != nil {return err}

	mTime := time.Now().UTC().UnixMilli()
	var mTimeBytes = make([]byte, 8)
	binary.LittleEndian.PutUint64(mTimeBytes, uint64(mTime))

	s.EntryMap[key].Value = chiphertext
	s.EntryMap[key].Nonce = nonce
	s.EntryMap[key].MTime = mTimeBytes

	return nil
}

// Delete a field with key. Give error if it does not exists.
func (s *Session) Rm(key string) error {
	// path must be an absolute filepath like string.
	if !pathRegexp.MatchString(key) || strings.HasSuffix(key, "/") { return errors.New("path must be a file path string") }
	// If it does not have slash at the start, join it to the current working directory.
	if !strings.HasPrefix(key, "/") { key = filepath.Join(s.Pwd, key) }

	_,exists := s.EntryMap[key]

	if !exists { return errors.New("key does not exist") }

	// Zero the values
	ZeroBytes(s.EntryMap[key].Value)
	ZeroBytes(s.EntryMap[key].Nonce)

	delete(s.EntryMap, key)

	return nil
}

// Delete a dir and everything in it.
func (s *Session) Rmd(dirPath string) error {
	if dirPath == "" { return errors.New("dirpath cannot be empty.") }

	// dirPath must start and end with "/"
	if !pathRegexp.MatchString(dirPath) { return errors.New("malformed folder path. It should be POSIX portable path.") }
	// If it does not have slash at the start, join it to the current working directory.
	if !strings.HasPrefix(dirPath, "/") { dirPath = filepath.Join(s.Pwd, dirPath) }
	// if it does not have slash at the end, add it.
	if !strings.HasSuffix(dirPath, "/") { dirPath = dirPath+"/" }

	folderExists := false

	for key := range s.EntryMap {
		if strings.HasPrefix(key, dirPath) {
			folderExists = true
			
			ZeroBytes(s.EntryMap[key].Value)
			ZeroBytes(s.EntryMap[key].Nonce)
			delete(s.EntryMap, key)
		}
	}

	if !folderExists { return errors.New("no such dir exists") }

	return nil
}

func (s *Session) Mv(oldKey, newKey string) error {
	// paths must be an absolute filepath like string.
	if (!pathRegexp.MatchString(oldKey) || strings.HasSuffix(oldKey, "/")) || (!pathRegexp.MatchString(newKey) || strings.HasSuffix(newKey, "/")) {
		return errors.New("path must be a file path string")
	}
	// If it does not have slash at the start, join it to the current working directory.
	if !strings.HasPrefix(oldKey, "/") { oldKey = filepath.Join(s.Pwd, oldKey) }
	if !strings.HasPrefix(newKey, "/") { newKey = filepath.Join(s.Pwd, newKey) }

	entry,exists := s.EntryMap[oldKey]

	if !exists { return errors.New("key does not exist") }

	// Decrypt the inner encryption key
	innEncKey, err := unencryptData(s.EncryptedInnEncKey, s.InnEncKeyNonce, s.SessionKey, s.Header.SEAlgo)
	if err != nil {return err}

	// Decrypt the value with the inner encryption key.
	// Put needs it in plaintext.
	value, err := unencryptData(entry.Value, entry.Nonce, innEncKey, s.Header.SEAlgo)
	ZeroBytes(innEncKey)
	if err != nil {return err}
	defer ZeroBytes(value) // Clean even if s.Put() returns without clearing value.

	err = s.Put(newKey, value)
	if err != nil {return err}

	err = s.Rm(oldKey)
	if err != nil {return err}

	return nil
}

// Change the current working directory. If dirPath is empty, navigate to root.
func (s *Session) Cd(dirPath string) error {
	if dirPath == "" { dirPath = "/" }

	// dirPath must start and end with "/"
	if !pathRegexp.MatchString(dirPath) { return errors.New("malformed folder path. It should be POSIX portable path.") }
	// If it does not have slash at the start, join it to the current working directory.
	if !strings.HasPrefix(dirPath, "/") { dirPath = filepath.Join(s.Pwd, dirPath) }
	// if it does not have slash at the end, add it.
	if !strings.HasSuffix(dirPath, "/") { dirPath = dirPath+"/" }

	// Look if a dir like this exists
	for key := range s.EntryMap {
		if strings.HasPrefix(key, dirPath) {
			s.Pwd = dirPath
			return nil
		}
	}

	return errors.New("no such dir exists")
}

// Get the list of entry keys and folders in the given path level OR current working directory if dirPath is empty.
func (s *Session) Ls(dirPath string) ([]string, []string, error) {
	if dirPath == "" { dirPath = s.Pwd }

	// dirPath must start and end with "/"
	if !pathRegexp.MatchString(dirPath) { return nil, nil, errors.New("malformed folder path. It should be POSIX portable path.") }
	// If it does not have slash at the start, join it to the current working directory.
	if !strings.HasPrefix(dirPath, "/") { dirPath = filepath.Join(s.Pwd, dirPath) }
	// if it does not have slash at the end, add it.
	if !strings.HasSuffix(dirPath, "/") { dirPath = dirPath+"/" }

	var entries []string
	var foldersMap = make(map[string]struct{}) // We need to deduplicate the folders as multiple entries can have same folder. prefix.

	// Iterate through all entries and only process the ones with folderPath prefix
	for key := range s.EntryMap {
		if strings.HasPrefix(key, dirPath) {
			// Strip the folderPath prefix from the entry key.
			keyStrippedPrefix := strings.TrimPrefix(key, dirPath)

			// If keyStrippedPrefix does not contain any slashes, it's an entry in the current level.
			if !strings.Contains(keyStrippedPrefix, "/") {
				entries = append(entries, keyStrippedPrefix)

			// Else, it's an entry in deeper levels. Split the path by slashes and append the first string to the folders.
			} else {
				parts := strings.Split(keyStrippedPrefix, "/")

				foldersMap[parts[0]] = struct{}{}

			}
		}
	}

	var folders []string
	for folder := range foldersMap {
		folders = append(folders, folder)
	}

	return folders, entries, nil
}

func (s *Session) Lsall(dirPath string) ([]string, error) {
	if dirPath == "" { dirPath = s.Pwd }

	// dirPath must start and end with "/"
	if !pathRegexp.MatchString(dirPath) { return nil, errors.New("malformed folder path. It should be POSIX portable path.") }
	// If it does not have slash at the start, join it to the current working directory.
	if !strings.HasPrefix(dirPath, "/") { dirPath = filepath.Join(s.Pwd, dirPath) }
	// if it does not have slash at the end, add it.
	if !strings.HasSuffix(dirPath, "/") { dirPath = dirPath+"/" }

	var entries []string

	for key := range s.EntryMap {
		if strings.HasPrefix(key, dirPath) {
			entries = append(entries, strings.TrimPrefix(key, dirPath))
		}
	}

	return entries, nil
}

/////////////////////////////////////////////////////////////////

// deriveKey generates a key from password and salt, used for symmetric encryption and signature
// Returns keys in order: OutEncKey, InnEncKey, MacKey
func deriveKey(
	password []byte, salt []byte,
	kdAlgorithm uint64, seAlgorithm uint64,
	params []byte,
) ([]byte, error) {

	// Determine the key length based on the seAlgorithm
	keylen, exists := encAlgoToKeylen[seAlgorithm]
	if !exists { return nil, errors.New("unsupported encryption algorithm for key length") }

	switch kdAlgorithm {
	case Derive_ARGON2ID:
		var argon2idParams Argon2IDParams
		err := cmpck.Unmarshal(params, &argon2idParams)
		if err != nil {return nil, err}

		return argon2.IDKey(
			password, salt,
			argon2idParams.Iterations, argon2idParams.Memory*1024, uint8(argon2idParams.Threads), uint32(keylen),
		), nil
	default:
		return nil, errors.New("unsupported algorithm for key derivation")
	}
}

// getVaultKeys generates A random session key, and derives OuterEncryptionKey, InnerEncryptionKey and MacKey from the derived key using the given hash function.
func getVaultKeys(
	derivedKey []byte, hashAlgo polysha.SHAType, seAlgorithm uint64,
) ([]byte, []byte, []byte, []byte, error) {

	// Determine the key length based on the seAlgorithm
	keylen, exists := encAlgoToKeylen[seAlgorithm]
	if !exists { return nil, nil,nil,nil, errors.New("unsupported encryption algorithm for key length") }

	if keylen != 32 {
		return nil, nil, nil, nil, errors.New("currently only logic for 32 byte symmetric encryption keys is implemented")
	}

	// Create a new random session key
	sessionKey := make([]byte, keylen)
	if _, err := io.ReadFull(rand.Reader, sessionKey); err != nil {
		return nil,nil,nil,nil,err
	}

	out, err := polysha.HashRaw(hashAlgo, append([]byte("out_key"), derivedKey...))
	if err!=nil {return nil, nil, nil, nil, err}

	inn, err := polysha.HashRaw(hashAlgo, append([]byte("inn_key"), derivedKey...))
	if err!=nil {return nil, nil, nil, nil, err}

	mac, err := polysha.HashRaw(hashAlgo, append([]byte("mac_key"), derivedKey...))
	if err!=nil {return nil, nil, nil, nil, err}

	return sessionKey, out[:keylen], inn[:keylen], mac[:keylen], nil
}

func encryptData(plaintext []byte, enckey []byte, algorithm uint64) ([]byte, []byte, error) {
	switch algorithm {
	case Encrypt_AES_CBC_256:
		// Create AES block cipher
		block, err := aes.NewCipher(enckey)
		if err != nil { return nil, nil, err }

		// Generate a random nonce
		iv_nonce := make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(rand.Reader, iv_nonce); err != nil {
			return nil, nil, err
		}

		// pad the plaintext data
		pkcs7Pad := func(data []byte, blockSize int) []byte {
			padding := blockSize - (len(data) % blockSize)
			padtext := bytes.Repeat([]byte{byte(padding)}, padding)
			return append(data, padtext...)
		}
		paddedPlaintext := pkcs7Pad(plaintext, block.BlockSize())

		ciphertext := make([]byte, len(paddedPlaintext))

		// Encrypt the paddedPlaintext using iv_nonce and enckey and save to chiphertext slice.
		mode := cipher.NewCBCEncrypter(block, iv_nonce)
		mode.CryptBlocks(ciphertext, paddedPlaintext)

		return iv_nonce, ciphertext, nil

	case Encrypt_CHACHA20:
		iv_nonce := make([]byte, chacha20.NonceSizeX)
		if _, err := io.ReadFull(rand.Reader, iv_nonce); err != nil {
			return nil, nil, err
		}

		cipher, err := chacha20.NewUnauthenticatedCipher(enckey, iv_nonce)
		if err != nil {
			return nil, nil, err
		}

		ciphertext := make([]byte, len(plaintext))
		cipher.XORKeyStream(ciphertext, plaintext)

		return iv_nonce, ciphertext, nil
		
	default:
		return nil, nil, errors.New("encryptData: unsupported encryption algorithm")
	}
}

// unencryptData decrypts the chiphertext using the given nonce, secret and algorithm.
func unencryptData(ciphertext []byte, iv_nonce []byte, enckey []byte, algorithm uint64) ([]byte, error){
	switch algorithm {
	case Encrypt_AES_CBC_256:

		if len(ciphertext)%aes.BlockSize != 0 {
			return nil, errors.New("decryption failed: ciphertext length is not a multiple of block size")
		}

		// Initialize AES-CBC
		block, err := aes.NewCipher(enckey)
		if err != nil { return nil, err }

		// Decrypt to paddedPlaintext using the key and iv_nonce
		paddedPlaintext := make([]byte, len(ciphertext))
		mode := cipher.NewCBCDecrypter(block, iv_nonce)
		mode.CryptBlocks(paddedPlaintext, ciphertext)

		// Unpad the plaintext and return it.

		pkcs7Unpad := func(data []byte, blockSize int) ([]byte, error) {
			length := len(data)
			if length == 0 || length%blockSize != 0 { return nil, errors.New("invalid padding length") }

			unpadding := int(data[length-1])
			if unpadding == 0 || unpadding > blockSize { return nil, errors.New("invalid padding byte") }

			for i := length - unpadding; i < length; i++ {
				if data[i] != byte(unpadding) {
					return nil, errors.New("invalid padding pattern")
				}
			}

			return data[:(length - unpadding)], nil
		}

		plaintext, err := pkcs7Unpad(paddedPlaintext, aes.BlockSize)
		if err != nil { return nil, errors.New("decryption failed: invalid padding") }

		return plaintext, nil

	case Encrypt_CHACHA20:
		// Ensure the nonce matches xchacha20's expectations
		if len(iv_nonce) != chacha20.NonceSizeX {
			return nil, errors.New("decryption failed: invalid nonce length for XChaCha20")
		}

		cipher, err := chacha20.NewUnauthenticatedCipher(enckey, iv_nonce)
		if err != nil {
			return nil, err
		}

		// Direct XOR stream back into plaintext
		plaintext := make([]byte, len(ciphertext))
		cipher.XORKeyStream(plaintext, ciphertext)

		return plaintext, nil

	default:
		return nil, errors.New("UnencryptData: unsupported encryption algorithm")
	}
}

// Computes the HMAC signature of the version, header and body using the given hash algorithm.
func computeSignature(
	polyShaAlgo polysha.SHAType, encKey []byte,
	version uint64, headerBytes []byte, bodyBytes []byte,
) ([]byte, error) {

	canonicalBytes, err := cmpck.Marshal(File{Version:version, Header:headerBytes, Body:bodyBytes}, cmpck.EncOpts{Canonical:true})
	if err != nil {return nil, err}

	hashReturner := func() hash.Hash {
		return polysha.NewRawHasher(polyShaAlgo)
	}

	b := hmac.New(hashReturner, encKey)
	_, err = b.Write(canonicalBytes)
	if err != nil {return nil, err}

	return b.Sum(nil), nil
}

// ZeroBytes explicitly zeroes out sensitive memory slices
func ZeroBytes(b []byte) {
	if b == nil {return}
	for i := range b { b[i] = 0 }
}

///////////////////////////////

// keyDerivationString: argon2id-<saltlength>-<iterations>-<memory>-<threads>
func getKeyDerivationParams(keyDerivationString string) (uint64, []byte, []byte, error) {

	if strings.HasPrefix(keyDerivationString, "argon2id-") {
		parts := strings.Split(keyDerivationString, "-")
		if len(parts) != 5 { return 0, nil, nil, errors.New("malformed argon2id string") }

		saltlen, err := strconv.Atoi(parts[1])
		if err != nil {return 0, nil, nil, err}

		// Create a new salt
		salt := make([]byte, saltlen)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return 0, nil, nil, err
		}

		iterations, err := strconv.Atoi(parts[2])
		if err != nil {return 0, nil, nil, err}

		memory, err := strconv.Atoi(parts[3])
		if err != nil {return 0, nil, nil, err}

		threads, err := strconv.Atoi(parts[4])
		if err != nil {return 0, nil, nil, err}

		paramBytes, err := cmpck.Marshal(Argon2IDParams{
			Iterations: uint32(iterations),
			Memory: uint32(memory),
			Threads: uint32(threads),
		}, cmpck.EncOpts{Canonical:true})
		if err != nil {return 0,nil,nil,err}

		return Derive_ARGON2ID, salt, paramBytes, nil

	} else {
		return 0, nil, nil, errors.New("unsupported key derivation algorithm")
	}
}
