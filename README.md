# Sec2M Secure Secrets Manager
A CLI based key/value secret manager that stores everything inside a simple file formatted with compack.

## Features
- Simple, Compack serialized `.sdb` file format
- Intentionally small, auditable codebase
- Strong cryptographic primitives (xchacha20, sha3-256, argon2id etc.)
- HMAC integrity check for the entire file (version, header, payload) using the provided hash algorithm and Encrypt-Then-MAC scheme
- Along with entire payload encryption, every secret value is encrypted individually to avoid storing them as plain-text in memory
- The encryption and signature keys are encrypted in memory using a random session key and only decrypted on demand.
- Session key is stored securely on memory using memory locking and by preventing core dumping in supported platforms (android & linux)
- Flat, `POSIX portable filepath -> binary value` array structure, supporting all kinds of values
- Shell like directory navigation using `cd`, `ls` and `lsall`
- Internal shell session with auto completions, system binary execution and command pipeline
- Command aliases using `/.shortcut/` values

## Motivation
For a long time, I used keepassxc as my password manager, but as I started to be more minimalist and use keyboard more often, using it started to feel like a burden. I tried keepassxc-cli right after, but it's usage also not really satisfied me. I could not make auto-completion work and navigation and entry management was hard. I then tried kpcli, but it would gave me errors I didn't know how to fix.

When all of these got out of option, I realized that no any robust CLI app exists to make me be able to use my existing `.kdbx` vault. I will have to migrate to an another format. I didn't wanna use unaudited password managers, so I looked for popular CLI alternatives to `.kdbx` password managers. `pass` looked good initially, but it mainly used asymmetric encryption and different file and folder for each entry, which I didn't really prefer. It was the time I decided to create my own one. While I knew one or two things about signatures, encryption and key derivation, I never used them together to create an app offering "enterprise grade" security. So, I decided to look how `.kdbx` format is structured.

While it helped me to understand how to implement a proper password manager; boy, it was bad. Not in terms of security, it's already well-known for being pretty solid about that, but in terms of structure and how thing glued to each other. Let me summarize what I didn't like about it:
- Using XML encoding in body: It's bloated and decoders are hard to write properly.
- Using compression in an attempt to reduce the size of the body: An additional complexity that increases the attack surface further on top of already complex XML. You wouldn't need that if you just used protobuf.
- Weird body structure: Just look at this and tell me it's well-structured and easy to implement, can you? <https://keepass.info/help/download/KDBX_XML.xsd>
- How the keys are derived: I think it looks ugly, uneven and not really clean. Master seed is also redundant. We already have nonces! Read: <https://www.panicvault.org/keepass/kdbx-format-guide/#the-key-derivation-pipeline>

Chunking idea was neat, but not really needed for my or %95 percent of the use cases, so I didn't bother to implement it. If you want chunking so bad, just create different vaults with the same password.

When these are combined, it makes the overall format really difficult to reason about and implement from scratch. You will also have a hard time while auditing and trusting to the password managers using it. Bla bla bla. In short: it's bad imho. Thank you for listening my TED talk.

I guess I need to rewrite this section.

## Installation
It's a single binary app with no external dependencies nor config files. You need go and git to install it.

```
git clone https://github.com/zenarvus/sec2m-go
cd sec2m-go
go build main.go
```

It outputs an executable file named `main` which is our application. Feel free to move it anywhere you want or simply delete. Sec2m-go does not create any file other than your vault and it's lock and temporary save file, which are in the same directory.

## Roadmap
- Allocate critical memory directly with system calls and manage them manually, bypassing GC runtime.
- Make rm, rmd, ls, lsall and cd accept arguments from stdin
- Make being able to unlock the vault by passing password as stdin possible. This should not prevent passing things to internal commands. So, the first line should be the vault password and the second should be the internal arguments (if an environment variable is set
- Unify the terminology across the codebase

## Help
```
Usage: VAULT=/path/to/file sec2m <command> [args...]

=== MAIN COMMANDS ===
init <dalg> <ealg> <halg>   - Init the vault file in VAULT location
change <dalg> <ealg> <halg> - Change the given vault's algorithms and password
help                        - Write this output
shell                       - Long lived sec2m shell session you can execute commands
shot <cmds>                 - Execute a sec2m shell pipeline command and exit
info                        - Print info about the version, header and signature of the file

=== ALGORITHMS ===
Key Derivation (<dalg>):
  - argon2id-<slen>-<iter>-<mem>-<thread>: Argon2ID with given parameters. <slen> is the length of the salt, <iter> is the amount of iterations, <mem> is the required memory in megabytes and <thread> is the amount of threads it will run. Recommended: <slen:16>, <iter:4>, <mem:256>, <thread:2>

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
put <?epath> <?value>    - Insert an entry to the vault
update <?epath> <?value> - Update an entry in the vault
get <?epath>             - Get the value using entry path
rm <?epath>              - Delete an entry from the vault
rmd <?dpath>             - Delete a directory from the vault
mv <?old> <?ew>          - Rename an entry in the vault

exec [args]              - Execute a system binary with given arguments
iter <cmds>              - Split the provided stdin by newlines, iterate through them and execute the provided command in every iteration while passing the item as stdin

ls <?dpath>              - Print the items in the path in vault
cd <?dpath>              - Change the current directory to the given path in vault
lsall <?dpath>           - List all the keys in the given dir and in all of it's subdirs
```

## Quick Pipeline & Shortcut Guide
You can execute commands and pipe them from left to right using the `|` character. The following code copies the result of get command to the clipboard if `wl-clipboard` is installed.
- `get /github/name | exec wl-copy`

Shortcuts are epath/value entries in `/.shortcut/` root where entry name is the command alias and the value is the actual command you want to run.

For example, this shell command adds a `cget` shortcut which executes `get {1} | exec wl-copy` command.
- `put /.shortcut/cget "get {1} | exec wl-copy"`

`{1}` is the first argument provided to `cget`. You can also use `{2}`, `{3}` etc. if the shortcut command requires more arguments. Here is the example usage of `cget` which copies `/github/name` to the clipboard:
- `cget /github/name`

There are some example scripts in `helpers.sh` you can use with shortcuts to implement features like password generation TOTP, clipboard deletion with interval, and disabling clipboard history when copying secrets.

## Migrating From `.kdbx`
WIP

## `.sdb` Format
The `.sdb` format uses compack, a protobuf like binary encoding protocol with 1-bit wire-type, for the file according to the following scheme:

```go
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
```

## Cryptography
```
Password: The input user writes in
Salt: A random set of bytes created on vault initialization. It's permanent per vault. Guarantees that the derived key is completely unique per vault, even if two vaults use the identical password.

Nonce(): A random set of bytes. Generated uniquely from scratch for every sinlge encryption operation. Ensures that saving the vault generates unique ciphertext every time, even if the data inside hasn't changed.

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
Signature = HMAC(MessageAuthenticationCodeKey, Version, Header, EncryptedBody) # Uses the provided hash algorithm for the HMAC signature. Authenticates the file version, headers and the encrypted data before decryption, and verifies if the password is correct.
```
