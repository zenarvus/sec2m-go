# Sec2M Secure Secrets Manager
A CLI based key/value secret manager that stores everything inside a simple file formatted with compack.

## Features
- Simple, Compack formatted file structure.
- Smaller, auditable codebase (~1800 LoC) with small amount of dependencies compared to alternatives using KDBX (kpcli is ~8000 LoC)
- Strong cryptographic algorithms (xchacha20, aes-cbc-256, polysha, argon2id etc.)
- MAC integrity check for the entire file (version, header, payload) using the provided hash algorithm.
- Along with entire payload encryption, every secret value is encrypted individually and stay in memory encrypted.
- The encryption and signature keys are encrypted in memory using the session key and only decrypted on demand.
- Session key is stored securely on memory using memory locking and by preventing core dumping in supported platforms (android & linux)
- Flat, `POSIX portable filepath -> binary value` array structure, supporting all kinds of values.
- Shell like directory navigation using and `cd`, `ls`
- Shell session, executing system binaries and command piping.
- Command aliases using `/.shortcut/` values.

## Cryptography

```
Password: The input user writes in
Salt: A random set of bytes created on vault initialization. It's permanent per vault.

Nonce(): A random set of bytes. Generated uniquely from scratch for every sinlge encryption operation.

DerivedKey = KeyDerivationAlgorithm(password, salt)

OuterEncryptionKey = HashAlgorithm("out_key" || DerivedKey) # Used for encrypting the whole body
InnerEncryptionKey = HashAlgorithm("inn_key" || DerivedKey) # Used for encrypting individual field values
MessageAuthenticationCodeKey = HashAlgorithm("mac_key" || DerivedKey)

SessionKey = `[randomly generated according to required key length of provided encryption algorithm in each session]`

# DerivedKey removed from memory and SessionKey locked to the memory here

EncryptedOutKey = Encryption(OuterEncryptionKey, SessionKey, Nonce())
EncryptedInnKey = Encryption(InnerEncryptionKey, SessionKey, Nonce())
EncryptedMacKey = Encryption(MessageAuthenticationCodeKey, SessionKey, Nonce())

# OuterEncryptionKey, InnerEncryptionKey and MessageAuthenticationCodeKey are removed from memory here. We store the encrypted ones and decrypt them on demand.

EncryptedFieldValue = Encryption(value, InnerEncryptionKey, Nonce())
EncryptedBody = Encryption(body, OuterEncryptionKey, Nonce())
Signature = HashMAC(MessageAuthenticationCodeKey, Version, Header, EncryptedBody) # Uses the provided hash algorithm for the MAC signature
```

- Salt guarantees that the derived key is completely unique per vault, even if two vaults use the identical password.
- Nonce ensures that saving the vault generates unique ciphertext every time, even if the data inside hasn't changed.
- Signature authenticates the file version, headers and the encrypted data before decryption. If anything is modified, it fails.

## Commands

```
Usage: VAULT=/path/to/file gosecrets <command> [args]

=== MAIN COMMANDS ===
init <dalg> <ealg> <halg>   - Init the vault file in VAULT location
change <dalg> <ealg> <halg> - Change the given vault's algorithms and password
help                        - Write this output
shell                       - Long lived gosecrets shell session you can execute commands
info                        - Print non-critical info about the vault: headers, shortcuts and entry-count.

=== ALGORITHMS ===
Key Derivation (<dalg>):
  - argon2id-<slen>-<iter>-<mem>-<thread>: Argon2ID with given parameters. <slen> is the length of the salt, <iter> is the amount of iterations, <mem> is the required memory in bytes and <thread> is the amount of threads it will run. Recommended: <slen:16>, <iter:4>, <mem:256>, <thread:2>

Symmetric Encryption (<ealg>):
  - aes-cbc-256: AES-256 with CBC mode
  - xchacha20: CHACHA20 with 24 byte nonce size (recommended)

Hashing (<halg>):
  - sha2-256: 32 byte sha2-256
  - sha3-256: 32 byte sha3-256 (recommended)
  - sha3-384: 48 byte sha3-384
  - sha3-512: 64 byte sha3-512
  - blake3-256: 32 byte blake3

=== COMMANDS ===
put <key>      - Insert a key to the vault
update <key>   - Update a key in the vault
get <key>      - Get the value of a key in path
rm <key>       - Delete a key from the vault
rmd <dir>      - Delete a directory from the vault
mv <old> <new> - Rename a key in the vault
exec <args>    - Execute a command from the system

ls <?dir>      - Print the items in the path in vault
cd <?dir>      - Change the current directory to the given path in vault
lsall <?dir>   - List all the keys in the given dir and in all of it's subdirs
```

## Quick Pipeline & Shortcut Guide
You can execute commands and pipe them from left to right using the `|` character. The following code copies the result of get command to the clipboard.
- `get /github/name | exec wl-copy`

Shortcuts are key/value entries in `/.shortcut/` root where key is the command alias name and the value is the actual command you want to run.

For example, this shell command adds a `cget` shortcut which executes `get {1} | exec wl-copy` command.
- `exec echo "get {1} | exec wl-copy" | put /.shortcut/cget`

`{1}` is the first argument provided to `cget`. You can also use `{2}`, `{3}` etc. if the shortcut command requires more arguments. Here is the example usage of `cget` which copies `/github/name` to the clipboard:
- `cget /github/name`

There are some example scripts in `helpers.sh` you can use with shortcuts to implement features like OTP tokens, clipboard deletion after waiting, and disabling clipboard history for clipman when copying secrets.
