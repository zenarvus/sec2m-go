# Sec2M Secure Secrets Manager
<p align="left">
<img src="https://github.com/zenarvus/sec2m-go/raw/refs/heads/main/logo.png" width="150" alt="Sec2M Logo" align="left"/>
<h3>Got secrets to keep?</h3>
<p>Sec2M is a CLI based, one-file secrets manager for cool kids who love security and minimalism.</p>
  
![GitHub Repo stars](https://img.shields.io/github/stars/zenarvus/sec2m-go?style=for-the-badge&color=darkred)
![GitHub forks](https://img.shields.io/github/forks/zenarvus/sec2m-go?style=for-the-badge&color=darkred)
![GitHub Issues](https://img.shields.io/github/issues/zenarvus/sec2m-go?style=for-the-badge&color=darkred)
![GitHub License](https://img.shields.io/github/license/zenarvus/sec2m-go?style=for-the-badge&color=darkred)
</p>
<br clear="left"/>

## Features
\> Everything stays local with a small and simple, Compack serialized `.sdb` file format

\> Strong and flexible cryptographic primitive list containing xchacha20, sha3-256 and argon2id

\> Whole file HMAC integrity check using the Encrypt-Then-MAC scheme

\> Additional per-value encryption for in-memory security

\> Per-Session-Key to store encryption and signature keys securely on memory

\> Core-dumping prevention and memory locking for the session key on supported platforms (android & linux)

\> Explicit variable zeroing after usage (not when passed as literal command arguments)

\> Extensible `[POSIX Portable Filepath] -> [Binary Value]` array structure. Like UNIX, everything is an entry

\> Shell like directory navigation using `cd`, `ls` and `lsall`

\> Internal shell session with auto completions, system binary execution, command substitutions and pipelines

\> Command aliasing using the entries in `/.shortcut/`

\> TOTP, Clipboard copy/clearing, password generation and more with helper scripts

## Installation
Sec2M is a single binary application with no external runtime dependencies nor config files. You just need go and git to install it.

```bash
git clone https://github.com/zenarvus/sec2m-go && cd sec2m-go && go build main.go
```

Now you are ready to go!

## Roadmap
Allocate critical memory directly with system calls and manage them manually, bypassing GC runtime

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
put <epath> <value>          - Insert an entry to the vault
mput <epath> <mtime> <value> - Put an entry by overwriting an existing one if passed mtime is larger
update <epath> <value>       - Update an entry in the vault
get <epath>                  - Get the value using entry path
mtime <epath>                - Get the modification time of an entry
rm <epath>                   - Delete an entry from the vault
rmd <dpath>                  - Delete a directory from the vault
mv <oldpath> <newpath>       - Rename an entry in the vault

exec [args]              - Execute a system binary with given arguments
eval <cmds>              - Run given command pipeline from stdin or as an argument
iter <cmds>              - Split the provided stdin by newlines, iterate through them and execute the provided command in every iteration while passing the item as stdin

ls <dpath>               - Print the items in the path in vault
cd <dpath>               - Change the current directory to the given path in vault
lsall <dpath>            - List all the keys in the given dir and in all of it's subdirs

senv <name> <value>      - Set an environment variable in the shell session and write to stdout
genv <name>              - Get an environment variable from the session
renv <name>              - Wipe an environment variable from the memory securely
```

## Quick Pipeline & Shortcut Guide
You can execute commands and pipe them from left to right using the `|` character. The following code copies the result of get command to the clipboard if `wl-clipboard` is installed.
- `get /github/name | exec wl-copy`

Shortcuts are epath/value entries in `/.shortcut/` root where entry name is the command alias and the value is the actual command you want to run.

For example, this shell command adds a `cget` shortcut which executes `get {1} | exec wl-copy` command.
- `put /.shortcut/cget "get {1} | exec wl-copy"`

`{1}` is the first argument provided to `cget`. You can also use `{2}`, `{3}` etc. if the shortcut command requires more arguments. Here is the example usage of `cget` which copies `/github/name` to the clipboard:
- `cget /github/name`

## Import & Export
It's convenient to use a flat list of `[entry path] [base64 encoded value] [modification time]` separated with `\n` on imports and exports. So `migration.sh` folder contains helper scripts using this format. (requires base64 binary)

To export everything in this flat list format, use the following command in shell:

`lsall / | iter "senv EXPORT | get | exec /path/to/exporter.sh $(genv EXPORT) $(genv EXPORT | mtime)"`

- `lsall /`: Prints every entry in the vault
- `iter [cmd]`: Iterates on them line by line and executes the command
- `senv EXPORT`: Sets the entry path as an environment variable, also writes it to output
- `get`: Gets the entry value from that output
- `exec /path/to/exporter.sh $(genv EXPORT) $(genv EXPORT | mtime)"`: Executes exporter.sh with stdin from get and path and modification time as arguments

To import everything from it, use the following command in shell:

`exec cat /path/to/sec2m.export | iter "exec /path/to/importer.sh | mput"`

- `exec cat /path/to/sec2m.export`: Prints all the lines in sec2m.export
- `iter [cmd]`: Iterates on them line by line and executes the command
- `exec /path/to/importer.sh`: Reads the line, decodes the base64 value and writes the path, mtime and value as arguments to mput
- `mput` Puts the value to the vault according to given arguments

## Migrating From KeePass*
`migration.sh` folder contains a `flatten-kdbx.sh <xmlfilepath>` script that converts a kdbx xml export to the flat list. Then, you can use the command above to import it.
- Note: It's actually a go code wrapped in a shell script. Make sure you installed go.

## SDB Format
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
	Entries []Entry `cmpck:"1"` // alphabetically sorted list of entries by path
}
type Entry struct {
	Path []byte `cmpck:"1"` // The front coded path of the entry (decoded in session)
	Value []byte `cmpck:"2"`  // The value encrypted with inner key
	MTime []byte `cmpck:"4"` // The modification time of the entry (uint64 unix epoch milliseconds [little endian]). It MUST be always larger than the previous MTime value of the entry
}
type Argon2IDParams struct {
	Iterations uint32 `cmpck:"1"` // Iterations
	Memory uint32 `cmpc:"2"` // Required memory in megabytes
	Threads uint32 `cmpck:"3"` // Parallel threads used while deriving keys
}
```

## Comparison With KDBX
SDB stays small by using an optimized format: binary encoding for the file and front coding for the paths, making using extra compression algorithms redundant. Whereas, KDBX(4.1) uses XML for the body and needs daddy gzip to reduce it's needy file size.

SDB's file structure is simpler and easier to implement from scratch. See: <https://keepass.info/help/download/KDBX_XML.xsd> and [SDB Format Section](#sdb-format).

SDB does not care or know about what kind of values entries have. You can even represent KDBX format structure entirely within SDB (which would be bad IMHO). KDBX on the other hand, kind of enforces a set of values for a set of fields, and as it's not really flexible, also adds optional key/value fields, making things unnecessarily complex.

SDB's cryptography is simpler and cleaner than KDBX while providing roughly the same amount of security when implemented as intended. See: <https://www.panicvault.org/keepass/kdbx-format-guide/> and [Cryptography Section](#cryptography)

KDBX uses chunked blocks, making it be able to handle with large vault files seamlessly, while SDB loads the whole file in memory. However, no proper vault reaches to megabytes of size unless you add PDF files or something in them, which is stupid anyway.

## Cryptography
```
Password: The input user writes in
Salt: A random set of bytes created on vault initialization. It's permanent per vault. Guarantees that the derived key is completely unique per vault, even if two vaults use the identical password.

Nonce(): A random set of bytes. Generated uniquely from scratch for every single encryption operation. Ensures that saving the vault generates unique ciphertext every time, even if the data inside hasn't changed.
FieldNonce(): HashAlgorithm(MTime || EntryPath).NonceSize() Guarantineed uniqueness as mtime is strictly different on each update

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

EncryptedFieldValue = Encryption(value, InnerEncryptionKey, FieldNonce())
EncryptedBody = Encryption(body, OuterEncryptionKey, Nonce())
Signature = HMAC(MessageAuthenticationCodeKey, Version, Header, EncryptedBody) # Uses the provided hash algorithm for the HMAC signature. Authenticates the file version, headers and the encrypted data before decryption, and verifies if the password is correct.
```
