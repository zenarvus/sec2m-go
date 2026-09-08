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

// TODO: Write a function in securemem that converts a regular golang slice to a manually managed one by zeroing the original

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
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20"

	"github.com/zenarvus/compack/go"
	"github.com/zenarvus/polyformats/polysha/go"
	"github.com/zenarvus/sec2m-go/securemem"
	"golang.org/x/crypto/argon2"
)

// POSIX portable filepaths.
var PathRegexp = regexp.MustCompile(`^/?([a-zA-Z0-9._\-]+/?)*$`) // Regexp that matches path like strings. Must not contain "/" at the end)
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
	Entries []Entry `cmpck:"1"` // alphabetically sorted list of entries by path
}
type Entry struct {
	Path []byte `cmpck:"1"` // The front coded path of the entry (decoded in session)
	Value []byte `cmpck:"2"`  // The value encrypted with inner key
	MTime []byte `cmpck:"4"` // The modification time of the entry (uint64 unix epoch milliseconds [little endian])
}
type Argon2IDParams struct {
	Iterations uint32 `cmpck:"1"` // Iterations
	Memory uint32 `cmpck:"2"` // Required memory in megabytes
	Threads uint32 `cmpck:"3"` // Parallel threads used while deriving keys
}

///////////////////////////////////////////////

type Env struct {
	EncryptedValue []byte // Encrypted value with the session key
	Nonce []byte // the nonce used to encrypt the value
}

type Key struct {
	EncryptedKey []byte // The encrypted key with session key
	Nonce []byte // the nonce used to encrypt the key
}
// Get the key as plaintext by decrypting the body
func (k *Key) Get(sessKey []byte, seAlgo uint64) ([]byte, func(), error) {
	key,deallocFn,err := unencryptData(k.EncryptedKey, k.Nonce, sessKey, seAlgo)
	if err != nil {return nil,func(){}, err}
	return key, deallocFn, nil
}

type Session struct {
	Version uint64
	Filepath string // The file of the session.
	Header UnmarshaledHeader

	SessionKey []byte // The random session key used to encrypt OutEncKey, InnEncKey, MacKey and environment variables.
	SessKeyDealloc func() // The deallocator for the SessionKey

	Signature []byte

	OutEncKey *Key // The key used for encryption and decryption of the whole  body
	InnEncKey *Key // The key used for the encryption of the individual fields
	MacKey *Key // The key used for the HMAC signature

	Pwd string // The current working directory in entries. For navigation in the pseudo filesystem.

	EntryMap map[string]*Entry // FrontDecoded(Entry.Path) -> Entry map
	EnvMap map[string]Env // Environment variable map
}

/////////////////////////////////////////////

// Delete the session and remove the lock key
func (s *Session) Destroy() {
	s.SessKeyDealloc() // Securely deallocate the session key

	// Zero encrypted keys in memory
	securemem.ZeroBytes(s.OutEncKey.EncryptedKey)
	securemem.ZeroBytes(s.InnEncKey.EncryptedKey)
	securemem.ZeroBytes(s.MacKey.EncryptedKey)

	// Zero encrypted entry and environment values in memory
	for _, v := range s.EntryMap { securemem.ZeroBytes(v.Value) }
	for _, v := range s.EnvMap { securemem.ZeroBytes(v.EncryptedValue) }

	// Remove the lock file
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
		EnvMap: make(map[string]Env),

		Pwd: "/",
	}

	derivedKey,deallocDerivedKey, err := deriveKey(password, salt, sess.Header.KDAlgo, sess.Header.SEAlgo, sess.Header.KDParams)
	if err != nil { return nil, err }

	sessionKey, sessionKeyDealloc, outenckey, innenckey, mackey, err := getVaultKeys(
		derivedKey, polysha.SHAType(sess.Header.HashAlgo), sess.Header.SEAlgo,
	)
	deallocDerivedKey() // We do not need the derived key anymore
	if err != nil { return nil, err }

	sess.SessionKey = sessionKey
	sess.SessKeyDealloc = sessionKeyDealloc

	sess.OutEncKey = outenckey
	sess.InnEncKey = innenckey
	sess.MacKey = mackey

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
		EnvMap: make(map[string]Env),
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
	derivedKey, deallocDerivedKey, err := deriveKey(
		password, sess.Header.KDSalt,
		sess.Header.KDAlgo, sess.Header.SEAlgo,
		sess.Header.KDParams,
	)
	if err != nil {return nil, err} 

	// Get vault keys from the derived key
	sessionKey, deallocSessionKey, outenckey, innenckey, mackey, err := getVaultKeys(
		derivedKey, polysha.SHAType(sess.Header.HashAlgo), sess.Header.SEAlgo,
	)
	deallocDerivedKey() // Wipe derivedKey from memory. We do not need it anymore.
	if err != nil { return nil, err } // After getting keys is successful, we should destroy the session in any error to remove them from memory.

	sess.SessionKey = sessionKey // Save the session key
	sess.SessKeyDealloc = deallocSessionKey

	sess.OutEncKey = outenckey
	sess.InnEncKey = innenckey
	sess.MacKey = mackey

	plaintextMacKey, macDealloc, err := mackey.Get(sess.SessionKey, sess.Header.SEAlgo)
	if err != nil { sess.Destroy(); return nil, err }

	// Do integrity check (Encrypt-then-MAC)
	expectedSignature, err := computeSignature(
		polysha.SHAType(sess.Header.HashAlgo),
		plaintextMacKey,
		fileStruct.Version,
		fileStruct.Header,
		fileStruct.Body,
	)
	macDealloc() // Remove plaintext mackey from memory after using it.
	if err != nil { sess.Destroy(); return nil, err } // Destroy the session to remove the encrypted key from memory.
	
	// Compare the expected signature and received  one in constant time
	if subtle.ConstantTimeCompare(expectedSignature, fileStruct.Signature) != 1 {
		sess.Destroy()
		return nil, errors.New("integrity check failed: invalid password or tampered vault")
	}

	plaintextOutEncKey, outencDealloc, err := outenckey.Get(sess.SessionKey, sess.Header.SEAlgo)
	if err != nil { sess.Destroy(); return nil, err }

	// Decrypt the body. Compack reuses bytes in here when parsing to structs. Deleting them will remove them from the struct fields too. So we need to clone it when using
	unencryptedBodyBytes, deallocBody, err := unencryptData(fileStruct.Body, sess.Header.SENonce, plaintextOutEncKey, sess.Header.SEAlgo)
	outencDealloc()
	if err!=nil { sess.Destroy(); return nil, err }

	var unencryptedBody UnencryptedBody 
	err = cmpck.Unmarshal(bytes.Clone(unencryptedBodyBytes), &unencryptedBody)
	deallocBody()
	if err!=nil { sess.Destroy(); return nil, err }

	// Load file entries to the session.
	var prev string
	for _,entry := range unencryptedBody.Entries {
		decoded, err := frontDecode(prev, entry.Path)
		if err != nil {return nil, err}
		prev = decoded
		entry.Path = []byte(decoded)
		sess.EntryMap[decoded] = &entry
		
	}

	return sess, nil
}

// Update the vault settings using the old password and overwrite the file.
func (s *Session) VaultChange(
	oldpass []byte, newpass []byte,
	kdAlgoStr, seAlgoStr, hashAlgoStr string,
) error {
	// Check if the old password is correct
	oldDerivedKey, oldDerivedDealloc, err := deriveKey(
		oldpass, s.Header.KDSalt, s.Header.KDAlgo, s.Header.SEAlgo, s.Header.KDParams,
	)
	if err != nil {return err}

	// It's enough to check if inner encryption key is equal.
	// We gonna use it anyway.
	tmpSKey,deallocTmpSkey,_,oldInnerEncKey,_,err := getVaultKeys(
		oldDerivedKey, polysha.SHAType(s.Header.HashAlgo), s.Header.SEAlgo,
	)
	oldDerivedDealloc() // deallocate the old derived key here
	if err != nil { return err }

	// get the old plaintext inner encryption key
	oldPlaintextInnerEncKey, deallocOldInnEncKey, err := oldInnerEncKey.Get(tmpSKey, s.Header.SEAlgo)
	deallocTmpSkey() // we do not need generated tmp session key anymore. It was used only to encrypt oldInnerEncKey
	if err != nil {return err}

	oldEncAlgo := s.Header.SEAlgo
	oldHashAlgo := s.Header.HashAlgo // Required for generating nonces in decryption

	// Decrypt the current inner encryption key
	expectedInnEncKey, deallocExpectedInn, err := s.InnEncKey.Get(s.SessionKey, s.Header.SEAlgo)
	if err != nil {return err}

	// Compare them and give error if they do not match
	if !bytes.Equal(oldPlaintextInnerEncKey, expectedInnEncKey) {
		deallocExpectedInn()
		return errors.New("provided password is incorrect")
	}
	deallocExpectedInn()

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

	derivedKey,deallocNewDerived,err := deriveKey(newpass, s.Header.KDSalt, s.Header.KDAlgo, s.Header.SEAlgo, s.Header.KDParams)
	if err != nil {return err}

	newSessK,deallocNewSessK, newOutEncK, newInnEncK, newMacK, err := getVaultKeys(
		derivedKey, polysha.SHAType(s.Header.HashAlgo), s.Header.SEAlgo,
	)
	deallocNewDerived()
	if err != nil {return err}

	// Update the session key
	s.SessionKey = newSessK
	s.SessKeyDealloc = deallocNewSessK

	s.OutEncKey = newOutEncK
	s.InnEncKey = newInnEncK
	s.MacKey = newMacK

	// Decrpyt the new inner encryption key
	plaintextNewInnEncK, deallocNewInnEncK, err := newInnEncK.Get(newSessK, s.Header.SEAlgo)
	if err != nil {
		deallocOldInnEncKey()
		return err
	}

	// Update the inner encryptions from old to new
	for _,entry := range s.EntryMap {
		// the old nonce withold ""hashing algorithm
		oldNonce,err := polysha.HashRaw(
			polysha.SHAType(oldHashAlgo),
			append(entry.MTime, entry.Path...),
		)
		if err != nil { return err }

		// Decrypt the value using old parameters
		plaintextVal,deallocPlaintextVal, err := unencryptData(entry.Value, oldNonce, oldPlaintextInnerEncKey, oldEncAlgo)
		if err != nil { deallocPlaintextVal(); return err }

		// new nonce with new hash algorithm
		newNonce,err := polysha.HashRaw(
			polysha.SHAType(s.Header.HashAlgo),
			append(entry.MTime, entry.Path...),
		)
		if err != nil { return err }
		
		// Encrypt it with the new ones
		_, newVal, err := encryptData(plaintextVal, plaintextNewInnEncK, newNonce, s.Header.SEAlgo)
		if err != nil { deallocPlaintextVal(); return err }

		entry.Value = newVal
		deallocPlaintextVal()
	}

	// Deallocate the old and new plaintext inner encryption key
	deallocOldInnEncKey()
	deallocNewInnEncK()

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
func (s *Session) SaveAs(filePath string) error {

	var fileStruct = &File{}

	var sortedPathList = make([]string, 0, len(s.EntryMap))
	for epath := range s.EntryMap {
		sortedPathList = append(sortedPathList, epath)
	}
	sort.Slice(sortedPathList, func(i, j int) bool {
		return sortedPathList[i] < sortedPathList[j]
	})

	// Create an unencryptedBody with len(s.EntryMap) capacity
	var unencryptedBody = &UnencryptedBody{ Entries: make([]Entry, 0, len(s.EntryMap)) }
	var prev string
	for _,epath := range sortedPathList {
		// Front code the path
		entry := *s.EntryMap[epath]
		entry.Path = frontCode(prev, epath)
		prev = epath
		unencryptedBody.Entries = append(unencryptedBody.Entries, entry)
	}

	unencryptedBodyBytes, err := cmpck.Marshal(unencryptedBody, cmpck.EncOpts{Canonical:true})
	if err!=nil {return err}
	defer securemem.ZeroBytes(unencryptedBodyBytes)

	// Decrypt the outer encryption key using SessionKey
	plainOutEncKey, deallocOutEncKey, err := s.OutEncKey.Get(s.SessionKey, s.Header.SEAlgo)
	if err != nil {return err}

	// Encrypt the body using plainOutEncKey
	nonce,encryptedData, err := encryptData(unencryptedBodyBytes, plainOutEncKey, nil, s.Header.SEAlgo)
	deallocOutEncKey() // Remove outenckey from memory.
	if err!=nil{return err}

	s.Header.SENonce = nonce // Set the nonce to the session.

	// Marshal the header for fileStruct
	headerBytes, err := cmpck.Marshal(s.Header, cmpck.EncOpts{Canonical:true})
	if err != nil {return err}

	// Decrypt the mac key using SessionKey
	plainMacKey, deallocMacKey, err := s.MacKey.Get(s.SessionKey, s.Header.SEAlgo)
	if err != nil {return err}

	// Compute the signature
	signature, err := computeSignature(
		polysha.SHAType(s.Header.HashAlgo),
		plainMacKey,
		s.Version,
		headerBytes,
		encryptedData,
	)
	deallocMacKey() // Remove mackey from memory
	if err != nil { return err }

	s.Signature = signature // Update the signature of the session

	fileStruct.Version = s.Version
	fileStruct.Header = headerBytes // save the header to the fileStruct
	fileStruct.Body = encryptedData
	fileStruct.Signature = signature

	fileBytes, err := cmpck.Marshal(fileStruct, cmpck.EncOpts{Canonical:true})
	if err!=nil {return err}

	// Write filebytes to the disk

	// Open the temporary file. Only owner can read/write. First write to a temporary file.
	f, err := os.OpenFile(filePath+".tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil { return err }
	// write the data to the temporary file
	_, err = f.Write(fileBytes)
	if err != nil { f.Close(); os.Remove(filePath+".tmp"); return err }
	// Sync the file content and metadata to storage hardware
	if err := f.Sync(); err != nil { f.Close(); os.Remove(filePath+".tmp"); return err }
	// close the opened file
	if err := f.Close(); err != nil { os.Remove(filePath+".tmp"); return err }

	// If everything is successful, overwrite the original file with the temporary one by performing an atomic rename.
	err = os.Rename(filePath+".tmp", filePath)
	if err!=nil { os.Remove(filePath+".tmp"); return err}

	// sync the parent directory to persist the file system directory entry update
	// because os.Rename updates the directory entry in cache
	dir, err := os.Open(filepath.Dir(filePath))
	if err != nil { return nil } // File is written, directory sync failure is usually non-fatal
	defer dir.Close()

	_ = dir.Sync()

	return nil
}

// Get the value using key with a manual deallocator
func (s *Session) Get(key string) ([]byte, func(), error) {
	// key must be a file path string.
	if !PathRegexp.MatchString(key) || strings.HasSuffix(key, "/") {
		return nil, func(){}, errors.New("key must be a filepath string")
	}
	// If it does not have slash at the start, join it to the current working directory.
	if !strings.HasPrefix(key, "/") { key = path.Join(s.Pwd, key) }

	entry, found := s.EntryMap[key]

	if !found { return nil, func(){}, errors.New("not found") }

	// Decrypt the inner encryption key
	plainInnEncKey, deallocInnEncKey, err := s.InnEncKey.Get(s.SessionKey, s.Header.SEAlgo)
	if err != nil {return nil,func(){}, err}

	nonce,err := polysha.HashRaw(
		polysha.SHAType(s.Header.HashAlgo),
		append(entry.MTime, entry.Path...),
	)
	if err != nil {
		deallocInnEncKey()
		return nil,func(){}, err
	}

	// Decrypt and return the value with the inner encryption key
	value,deallocVal, err := unencryptData(entry.Value, nonce, plainInnEncKey, s.Header.SEAlgo)
	deallocInnEncKey()
	if err != nil {return nil,func(){},err}

	return value,deallocVal,nil
}

// If an entry does not exist, add it directly with given mtime. If mtime is empty, use the current time
// If an entry exists, add it only if provided mtime is bigger than the existing one. If no mtime is provided, give already exists error.
func (s *Session) Put(epath string, mtime []byte, value []byte) error {
	// key must be an absolute filepath like string. (no slash at the end)
	if !PathRegexp.MatchString(epath) || strings.HasSuffix(epath, "/") { return errors.New("path must be a file path string") }

	// If it does not have slash at the start, join it to the current working directory.
	if !strings.HasPrefix(epath, "/") { epath = path.Join(s.Pwd, epath) }

	existingEntry,exists := s.EntryMap[epath]

	var mTimeBytes = make([]byte, 8)

	// If an entry already exists and mtime is not provided
	if exists && len(mtime) == 0 {
		return errors.New("key already exists")

	// If an entry exists and mtime is provided
	} else if exists {
		// Set mTimeBytes only if given mtime is higher than entry's mtime
		givenmtime := binary.LittleEndian.Uint64(mtime)
		existingmtime := binary.LittleEndian.Uint64(existingEntry.MTime)
		if givenmtime > existingmtime {
			mTimeBytes = mtime
		// If provided entry has a lower mtime, do not insert it
		} else { return nil }

	// If an entry does not exists
	} else {
		mTime := time.Now().UTC().UnixMilli()
		binary.LittleEndian.PutUint64(mTimeBytes, uint64(mTime))
	}

	// mTimeBytes is set when we reach here

	// Decrypt the inner encryption key
	plainInnEncKey, deallocInnEncKey, err := s.InnEncKey.Get(s.SessionKey, s.Header.SEAlgo)
	if err != nil {return err}

	nonce,err := polysha.HashRaw(
		polysha.SHAType(s.Header.HashAlgo),
		append(mTimeBytes, []byte(epath)...),
	)
	if err != nil { deallocInnEncKey(); return err}

	// Encrypt the value with the key
	_, chiphertext, err := encryptData(value, plainInnEncKey, nonce, s.Header.SEAlgo)
	deallocInnEncKey()
	securemem.ZeroBytes(value) // Zero the passed value
	if err != nil {return err}

	var newEntry = &Entry{
		Path: []byte(epath),
		Value: chiphertext,
		MTime: mTimeBytes,
	}

	s.EntryMap[epath] = newEntry

	return nil
}

// Update a key/value pair. Give error if it does not exist or modification times are the same
func (s *Session) Update(epath string, value []byte) error {
	// path must be an absolute filepath like string. (no slash at the end)
	if !PathRegexp.MatchString(epath) || strings.HasSuffix(epath, "/") { return errors.New("path must be an file path string") }
	// If it does not have slash at the start, join it to the current working directory.
	if !strings.HasPrefix(epath, "/") { epath = path.Join(s.Pwd, epath) }

	existingEntry,exists := s.EntryMap[epath]

	if !exists { return errors.New("key does not exist") }

	mTimeNow := uint64(time.Now().UTC().UnixMilli())

	entryMtime := binary.LittleEndian.Uint64(existingEntry.MTime)

	mTime := max(mTimeNow, entryMtime+1) // The current time or old entry mtime+1. Ensures it's always different

	var mTimeBytes = make([]byte, 8)
	binary.LittleEndian.PutUint64(mTimeBytes, uint64(mTime))

	// Decrypt the inner encryption key
	plainInnEncKey, deallocInnEncKey, err := s.InnEncKey.Get(s.SessionKey, s.Header.SEAlgo)
	if err != nil {return err}

	nonce,err := polysha.HashRaw(
		polysha.SHAType(s.Header.HashAlgo),
		append(mTimeBytes, []byte(epath)...),
	)
	if err != nil {deallocInnEncKey(); return err}

	// Encrypt the new value with the key
	_, chiphertext, err := encryptData(value, plainInnEncKey, nonce, s.Header.SEAlgo)
	deallocInnEncKey()
	securemem.ZeroBytes(value)
	if err != nil {return err}

	// Zero the old value
	securemem.ZeroBytes(s.EntryMap[epath].Value)

	s.EntryMap[epath].Value = chiphertext
	s.EntryMap[epath].MTime = mTimeBytes

	return nil
}

// Delete a field with key. Give error if it does not exists.
func (s *Session) Rm(key string) error {
	// path must be an absolute filepath like string.
	if !PathRegexp.MatchString(key) || strings.HasSuffix(key, "/") { return errors.New("path must be a file path string") }
	// If it does not have slash at the start, join it to the current working directory.
	if !strings.HasPrefix(key, "/") { key = path.Join(s.Pwd, key) }

	_,exists := s.EntryMap[key]

	if !exists { return errors.New("key does not exist") }

	// Wait for 1 millisecond to prevent Put > Delete > Put from happening in the same millisecond, making nonce the same
	time.Sleep(1*time.Millisecond)

	// Zero the value
	securemem.ZeroBytes(s.EntryMap[key].Value)

	delete(s.EntryMap, key)

	return nil
}

// Delete a dir and everything in it.
func (s *Session) Rmd(dirPath string) error {
	if dirPath == "" { return errors.New("dirpath cannot be empty.") }

	// dirPath must start and end with "/"
	if !PathRegexp.MatchString(dirPath) { return errors.New("malformed folder path. It should be POSIX portable path.") }
	// If it does not have slash at the start, join it to the current working directory.
	if !strings.HasPrefix(dirPath, "/") { dirPath = path.Join(s.Pwd, dirPath) }
	// if it does not have slash at the end, add it.
	if !strings.HasSuffix(dirPath, "/") { dirPath = dirPath+"/" }

	folderExists := false

	for key := range s.EntryMap {
		if strings.HasPrefix(key, dirPath) {
			folderExists = true

			time.Sleep(1*time.Millisecond)
			
			securemem.ZeroBytes(s.EntryMap[key].Value)
			delete(s.EntryMap, key)
		}
	}

	if !folderExists { return errors.New("no such dir exists") }

	return nil
}

func (s *Session) Mv(oldKey, newKey string) error {
	// paths must be an absolute filepath like string.
	if (!PathRegexp.MatchString(oldKey) || strings.HasSuffix(oldKey, "/")) || (!PathRegexp.MatchString(newKey) || strings.HasSuffix(newKey, "/")) {
		return errors.New("path must be a file path string")
	}
	// If it does not have slash at the start, join it to the current working directory.
	if !strings.HasPrefix(oldKey, "/") { oldKey = path.Join(s.Pwd, oldKey) }
	if !strings.HasPrefix(newKey, "/") { newKey = path.Join(s.Pwd, newKey) }

	entry,exists := s.EntryMap[oldKey]

	if !exists { return errors.New("key does not exist") }

	// Decrypt the inner encryption key
	plainInnEncKey, deallocInnEncKey, err := s.InnEncKey.Get(s.SessionKey, s.Header.SEAlgo)
	if err != nil {return err}

	nonce,err := polysha.HashRaw(
		polysha.SHAType(s.Header.HashAlgo),
		append(entry.MTime, entry.Path...),
	)
	if err != nil { deallocInnEncKey(); return err}

	// Decrypt the value with the inner encryption key.
	// Put needs it in plaintext.
	value, deallocVal, err := unencryptData(entry.Value, nonce, plainInnEncKey, s.Header.SEAlgo)
	deallocInnEncKey()
	if err != nil {return err}
	defer deallocVal() // Clean even if s.Put() returns without clearing value.

	err = s.Put(newKey, entry.MTime, value)
	if err != nil {return err}

	err = s.Rm(oldKey)
	if err != nil {return err}

	return nil
}

// Change the current working directory. If dirPath is empty, navigate to root.
func (s *Session) Cd(dirPath string) error {
	if dirPath == "" { dirPath = "/" }

	// dirPath must start and end with "/"
	if !PathRegexp.MatchString(dirPath) { return errors.New("malformed folder path. It should be POSIX portable path.") }
	// If it does not have slash at the start, join it to the current working directory.
	if !strings.HasPrefix(dirPath, "/") { dirPath = path.Join(s.Pwd, dirPath) }
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
	if !PathRegexp.MatchString(dirPath) { return nil, nil, errors.New("malformed folder path. It should be POSIX portable path.") }
	// If it does not have slash at the start, join it to the current working directory.
	if !strings.HasPrefix(dirPath, "/") { dirPath = path.Join(s.Pwd, dirPath) }
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
	if !PathRegexp.MatchString(dirPath) { return nil, errors.New("malformed folder path. It should be POSIX portable path.") }
	// If it does not have slash at the start, join it to the current working directory.
	if !strings.HasPrefix(dirPath, "/") { dirPath = path.Join(s.Pwd, dirPath) }
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

// Set an environment variable
func (s *Session) Senv(name string, value []byte) error {

	nonce, encryptedVal, err := encryptData(value, s.SessionKey, nil, s.Header.SEAlgo)
	securemem.ZeroBytes(value)
	if err != nil { return err }

	s.EnvMap[name] = Env{EncryptedValue: encryptedVal, Nonce: nonce}
	return nil
}
// Get an environment variable
func (s *Session) Genv(name string) ([]byte, func(), error) {
	if _,exists := s.EnvMap[name]; exists {

		plainVal, dealloc, err := unencryptData(
			s.EnvMap[name].EncryptedValue, s.EnvMap[name].Nonce, s.SessionKey, s.Header.SEAlgo,
		)
		if err != nil { return nil, func(){}, err }

		return plainVal, dealloc, err
	}
	return nil, func(){}, nil
}
// Delete an environment variable
func (s *Session) Renv(name string) {
	_,exists := s.EnvMap[name]
	if exists {
		securemem.ZeroBytes(s.EnvMap[name].EncryptedValue)
		delete(s.EnvMap, name)
	}
}

/////////////////////////////////////////////////////////////////

// deriveKey generates a key from password and salt, used for symmetric encryption and signature
// Returns keys in order: OutEncKey, InnEncKey, MacKey
func deriveKey(
	password []byte, salt []byte,
	kdAlgorithm uint64, seAlgorithm uint64,
	params []byte,
) ([]byte, func(), error) {

	// Determine the key length based on the seAlgorithm
	keylen, exists := encAlgoToKeylen[seAlgorithm]
	if !exists { return nil, func(){}, errors.New("unsupported encryption algorithm for key length") }

	switch kdAlgorithm {
	case Derive_ARGON2ID:
		var argon2idParams Argon2IDParams
		err := cmpck.Unmarshal(params, &argon2idParams)
		if err != nil {return nil,func(){}, err}

		// generate the key on go heap which is handled by go runtime (we do not want that)
		heapKey := argon2.IDKey(
			password, salt,
			argon2idParams.Iterations, argon2idParams.Memory*1024, uint8(argon2idParams.Threads), uint32(keylen),
		)

		// allocate a secure memory
		secKey, deallocFn, err := securemem.Alloc(keylen)
		if err != nil {
			securemem.ZeroBytes(heapKey) // Wipe heap key before returning on error
			return nil, nil, err
		}

		// Copy to secure memory and immediately wipe the heap allocation
		copy(secKey, heapKey)
		securemem.ZeroBytes(heapKey)

		return secKey, deallocFn, nil
	default:
		return nil,func(){}, errors.New("unsupported algorithm for key derivation")
	}
}

// getVaultKeys generates A random session key, and derives OuterEncryptionKey, InnerEncryptionKey and MacKey from the derived key using the given hash function.
func getVaultKeys(
	derivedKey []byte, hashAlgo polysha.SHAType, seAlgorithm uint64,
) ([]byte, func(), *Key, *Key, *Key, error) {

	// Determine the key length based on the seAlgorithm
	keylen, exists := encAlgoToKeylen[seAlgorithm]
	if !exists { return nil,func(){},nil,nil,nil, errors.New("unsupported encryption algorithm for key length") }

	if keylen != 32 {
		return nil,func(){}, nil, nil, nil, errors.New("currently only logic for 32 byte symmetric encryption keys is implemented")
	}

	// Create a new random session key
	sessionKey,sessKeyDealloc,err := securemem.Alloc(keylen, securemem.WithLocking(true))
	if err != nil { return nil,func(){},nil,nil,nil,err }

	if _, err := io.ReadFull(rand.Reader, sessionKey); err != nil {
		sessKeyDealloc()
		return nil,func(){},nil,nil,nil,err
	}

	deriveSecureKey := func(prefix string) (*Key, error) {
		heapHash, err := polysha.HashRaw(hashAlgo, append([]byte(prefix), derivedKey...))
		if err != nil { return nil, err }

		var key = &Key{}
		nonce, encryptedKey, err := encryptData(heapHash, sessionKey, nil, seAlgorithm)
		securemem.ZeroBytes(heapHash) // Wipe the heap-allocated slice

		if err != nil { securemem.ZeroBytes(heapHash); return nil, err }
		key.EncryptedKey = encryptedKey
		key.Nonce = nonce
		
		return key, nil
	}

	out,err := deriveSecureKey("out_key")
	if err!=nil {return nil,func(){}, nil, nil, nil, err}

	inn, err := deriveSecureKey("inn_key")
	if err!=nil {return nil,func(){}, nil, nil, nil, err}

	mac, err := deriveSecureKey("mac_key")
	if err!=nil {return nil,func(){}, nil, nil, nil, err}

	return sessionKey,sessKeyDealloc, out, inn, mac, nil
}

func encryptData(plaintext []byte, enckey []byte, nonce []byte, algorithm uint64) ([]byte, []byte, error) {
	switch algorithm {
	case Encrypt_AES_CBC_256:
		// Create AES block cipher
		block, err := aes.NewCipher(enckey)
		if err != nil { return nil, nil, err }

		// pad the plaintext data
		pkcs7Pad := func(data []byte, blockSize int) []byte {
			padding := blockSize - (len(data) % blockSize)
			padtext := bytes.Repeat([]byte{byte(padding)}, padding)
			return append(data, padtext...)
		}

		var iv_nonce = make([]byte, aes.BlockSize)
		// Derive the nonce from provided variable or generate a random nonce if it's nil
		if nonce != nil {
			if len(nonce) < aes.BlockSize {
				return nil, nil, errors.New("provided nonce does not satisfy the required size")
			}
			iv_nonce = nonce[:aes.BlockSize]
		} else {
			if _, err := io.ReadFull(rand.Reader, iv_nonce); err != nil { return nil, nil, err }
		}

		paddedPlaintext := pkcs7Pad(plaintext, block.BlockSize())

		ciphertext := make([]byte, len(paddedPlaintext))

		// Encrypt the paddedPlaintext using iv_nonce and enckey and save to chiphertext slice.
		mode := cipher.NewCBCEncrypter(block, iv_nonce)
		mode.CryptBlocks(ciphertext, paddedPlaintext)

		return iv_nonce, ciphertext, nil

	case Encrypt_CHACHA20:
		iv_nonce := make([]byte, chacha20.NonceSizeX) // 24 byte
		if nonce != nil {
			if len(nonce) < chacha20.NonceSizeX {
				return nil, nil, errors.New("provided nonce does not satisfy the required size")
			}
			iv_nonce = nonce[:chacha20.NonceSizeX]
		} else {
			if _, err := io.ReadFull(rand.Reader, iv_nonce); err != nil { return nil, nil, err }
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
// It returns the plaintext data and a deallocator to wipe it from memory
func unencryptData(ciphertext []byte, iv_nonce []byte, enckey []byte, algorithm uint64) ([]byte, func(), error){
	switch algorithm {
	case Encrypt_AES_CBC_256:

		if len(ciphertext)%aes.BlockSize != 0 {
			return nil,func(){}, errors.New("decryption failed: ciphertext length is not a multiple of block size")
		}

		// Initialize AES-CBC
		block, err := aes.NewCipher(enckey)
		if err != nil { return nil, func(){}, err }

		// Securely allocate memory for the plaintext
		paddedPlaintext, deallocFn, err := securemem.Alloc(len(ciphertext))
		if err != nil {return nil, func() {}, fmt.Errorf("secure allocation failed: %w", err)}

		// Decrypt to paddedPlaintext using the key and iv_nonce

		// iv_nonce can be anything aslong as its bigger than the aes blocksize. We get the first blocksize bytes
		mode := cipher.NewCBCDecrypter(block, iv_nonce[:aes.BlockSize])
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
		if err != nil {
			deallocFn() // wipe the allocated memory if an error happens
			return nil, func(){}, errors.New("decryption failed: invalid padding")
		}

		// Note: Because deallocFn captures the original 'paddedPlaintext' slice from Alloc(), it will safely zero and unmap the entire buffer, even though we return a sub-slice here.
		return plaintext,deallocFn,nil

	case Encrypt_CHACHA20:
		// Ensure the nonce matches xchacha20's expectations
		if len(iv_nonce) > chacha20.NonceSizeX { iv_nonce = iv_nonce[:chacha20.NonceSizeX] }
		if len(iv_nonce) != chacha20.NonceSizeX {
			return nil,func(){}, errors.New("decryption failed: invalid nonce length for XChaCha20")
		}

		cipher, err := chacha20.NewUnauthenticatedCipher(enckey, iv_nonce)
		if err != nil { return nil,func(){}, err }

		// Securely allocate memory for the plaintext
		plaintext, deallocFn, err := securemem.Alloc(len(ciphertext))
		if err != nil {return nil, func() {}, fmt.Errorf("secure allocation failed: %w", err)}

		// Direct XOR stream back into plaintext
		cipher.XORKeyStream(plaintext, ciphertext)

		return plaintext, deallocFn, nil

	default:
		return nil,func(){}, errors.New("UnencryptData: unsupported encryption algorithm")
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

////////////////////////////////////

// Compress a given string with front coding relative to the previous uncompressed string based on the common prefix length
func frontCode(prev string, str string) ([]byte) {
	// We will iterate through one of them. We choose the one with less characters.
	n := len(prev)
	if len(str) < n {n = len(str)}

	// get the common byte prefix length
	i := 0
	for i < n && prev[i] == str[i] { i++ }

	// format: [varint prefix-length][remaining str suffix]
	compressed := make([]byte, 0, binary.MaxVarintLen64+len(str)-1) // create a byte buffer capable of holding everything
	compressed = binary.AppendUvarint(compressed, uint64(i)) // Write the prefix length matched
	compressed = append(compressed, str[i:]...) // Append the rest of the string to the compressed form.

	return compressed
}
// Decompress a given front coded string using the previous uncompressed string
func frontDecode(prev string, compressed []byte) (string, error) {
	prefixLen, n := binary.Uvarint(compressed)
	if n <= 0 { return "", errors.New("invalid or corrupted varint encoding") }
	if len(prev) < int(prefixLen) { return "", errors.New("prefix length exceeds previous string length")}

	return prev[:prefixLen]+string(compressed[n:]), nil
}
