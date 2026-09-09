# Sec2M Secure Secrets Manager
<p align="left">
<img src="https://github.com/zenarvus/sec2m-go/raw/refs/heads/main/logo.png" width="155" alt="Sec2M Logo" align="left"/>
<h3>Got secrets to keep?</h3>
<p>Sec2m is a local, serverless and daemonless, CLI based secrets manager that uses SDB file format with no runtime dependencies. Written in golang, for cool kids.</p>
  
![GitHub Repo stars](https://img.shields.io/github/stars/zenarvus/sec2m-go?style=for-the-badge&color=darkred)
![GitHub forks](https://img.shields.io/github/forks/zenarvus/sec2m-go?style=for-the-badge&color=darkred)
![GitHub Issues](https://img.shields.io/github/issues/zenarvus/sec2m-go?style=for-the-badge&color=darkred)
![GitHub License](https://img.shields.io/github/license/zenarvus/sec2m-go?style=for-the-badge&color=darkred)
</p>
<br clear="left"/>

## Features
**>** Everything stays local with a small and simple, Compack serialized `.sdb` file format

**>** Strong and flexible cryptographic primitive list containing xchacha20, sha3-256 and argon2id

**>** Whole file HMAC integrity check using the Encrypt-Then-MAC scheme

**>** Additional per-value encryption for in-memory security

**>** Per-Session-Key to store encryption and signature keys encrypted on memory

**>** Core-dumping prevention and memory locking for the session key on supported platforms (android & linux)

**>** Secret zeroing and deallocation after usage (not when passed as literal positional arguments)

**>** Extensible `[POSIX Portable Filepath] => [Binary Value]` array structure. Like UNIX, everything is an entry

**>** Shell like directory navigation using `cd`, `ls` and `lsall`

**>** Internal shell session with auto completions, system binary execution, command substitutions and pipelines

**>** Command aliasing using the entries in `/.shortcut/`

**>** TOTP, Clipboard copy/clearing, password generation and more with helper scripts

## Installation
Sec2M is a single binary application with no external runtime dependencies nor config files. You just need go and git to install it.

```bash
git clone https://github.com/zenarvus/sec2m-go && cd sec2m-go && go build .
```

Now you are ready to go!

## Roadmap
Improve CLI side and command substitution handling, move parser logic to an another file and write a test file for the parser.

Consider migrating to <https://github.com/reeflective/readline> or <https://github.com/c-bata/go-prompt>?

## Help
```
Usage: VAULT=/path/to/file.sdb sec2m <command> [args]

The binary requires VAULT environment variable pointing to a .sdb file. The file can be maximum 1GiB

=== VAULT  ===
init <dalg> <ealg> <halg>: Inits the vault file in VAULT location. Gives error if it already exists.

change <dalg> <ealg> <halg>: Updates the vault algorithms and password in VAULT location. Will ask for the old password one time and the new one for two times.

== ALGORITHMS ==
Key Derivation (<dalg>):
	- argon2id-<slen>-<iter>-<mem>-<thread>: Argon2ID with given parameters.
		- <slen>: Length of the salt (Recommended: 16)
		- <iter>: The amount of iterations (Recommended: 4, Max: 16)
		- <mem>: Required memory in megabytes (Recommended: 256, Max: 2048)
		- <thread>: Amount of threads used (Recommended: 2, Max: 32)

Symmetric Encryption (<ealg>):
	- aes-cbc-256: AES-256 with CBC mode
	- xchacha20: CHACHA20 with 24 byte nonce size (Recommended)

Hashing (<halg>):
	- sha2-256: 32 byte sha2-256
	- sha3-256: 32 byte sha3-256 (Recommended)
	- sha3-384: 48 byte sha3-384
	- sha3-512: 64 byte sha3-512
	- blake3-256: 32 byte blake3

=== MAIN COMMANDS ===
help: Write this output

shell: Long lived sec2m shell session you can execute commands

shot <pipeline>: Execute a sec2m shell pipeline and exit

<cmd> [args]: Execute a single command with provided argument

info: Print info about the version, header and signature of the file

=== COMMAND REFERENCE ===
put <epath> <value>: Inserts a new entry to the vault. Gives error if it already exists.
- Ingests "<epath>" and/or "<value>" separated by "\n" or asks for user input.

mput <epath> <mtime> <value>: Inserts an entry and overwrites the existing one if passed unix epoch (<mtime>) is larger.
- Ingests missing arguments via "\n" split "stdin" or asks for user input.

update <epath> <value>: Updates an existing vault entry.
- Ingests missing arguments via "stdin" or asks for user input. Prompts for "(y/n)" confirmation.

get <epath>: Gets the value using entry path.
- Ingests "<epath>" from "stdin" if missing.

mtime <epath>: Gets the modification time of an entry
- Ingests "<epath>" from "stdin" if missing.

rm <epath>: Deletes an entry from the vault.
- Ingests "<epath>" from "stdin" if missing. Prompts for "(y/n)" confirmation.

rmd <dpath>: Deletes a directory from the vault.
- Ingests "<dpath>" from "stdin" if missing. Prompts for "(y/n)" confirmation.

mv <oldpath> <newpath>: Renames a vault entry.
- Ingests missing arguments via "stdin".

==========

exec [args]: Executes a system binary.
- Forwards incoming stdin to external command stdin.

eval <pipeline>: Runs given command pipeline.
- Ingests command string from "stdin" if missing.

iter <pipeline>: Splits the provided stdin by newlines and iterates through them.
- Runs "<pipeline>" repeatedly, passing each line as "stdin".

==========

ls <dpath>: Prints the items in the given path in vault
- Prints items in the current directory if <dpath> is missing.

cd <dpath>: Changes the current directory to the given path in vault
- Changes the directory to root if <dpath> is missing.

lsall <dpath>: Lists all the keys in the given dir and in all of it's subdirs
- Prints items in the current directory and it's sub-directories if <dpath> is missing.

==========

senv <name> <value>: Sets an environment variable in the shell session.
- Ingests "<name>" and "<value>" from "stdin" if missing.

genv <name>: Get an environment variable from the session
- Ingests "<name>" from "stdin" if missing.

renv <name>: Wipe an environment variable from the memory securely
- Ingests "<name>" from "stdin" if missing.

=== PIPING COMMANDS ===
Commands can be chained using the pipe operator ("|"). Output from the left command is passed directly as standard input to the right command.

The following code copies the result of get command to the clipboard if "wl-clipboard" is installed.
- 'get /github/name | exec wl-copy'

=== COMMAND SUBSTITUTION ===
Arguments wrapped in "$(...)" are evaluated dynamically as internal commands before the outer command executes. The output of the inner command replaces the substitution token.

Copy a secret value from one path to another dynamically:
- put /backup/token $(get /tokens/github)

=== SHORTCUTS ===
Shortcuts act as customizable CLI aliases stored directly inside the encrypted vault under the "/.shortcut/" directory. They support positional argument placeholders ("{1}", "{2}", "{3}", etc.) Unsupplied placeholders are automatically removed prior to command execution.

To define a shortcut named "cget" that copies the secret to the clipboard, create an entry in "/.shortcut/cget":
- 'put /.shortcut/cget "get {1} | exec wl-copy"'
- Usage: cget /github/name
```

## Import & Export
It's convenient to use a list of `[entry path] [base64 encoded value] [modification time]` separated with `\n` on imports and exports. We call this format "flat list." `migration.sh` folder contains helper scripts to process flat lists. (requires base64 binary)

To export everything in a flat list, use the following command in shell:

`lsall / | iter "senv EXP | genv EXP | get | exec /path/to/exporter.sh $(genv EXP) $(genv EXP | mtime)"`

- `lsall /`: Prints every entry in the vault
- `iter [cmd]`: Iterates on them line by line and executes the command
- `senv EXP`: Sets the entry path as an environment variable
- `genv EXP`: Get the value of EXP
- `get`: Gets the entry value from the path provided from pipe
- `exec /path/to/exporter.sh $(genv EXP) $(genv EXP | mtime)"`: Executes exporter.sh with stdin from get and path and modification time as arguments

To import everything from flat list, use the following command in shell:

`exec cat /path/to/sec2m.export | iter "exec /path/to/importer.sh | mput"`

- `exec cat /path/to/sec2m.export`: Prints all the lines in sec2m.export
- `iter [cmd]`: Iterates on them line by line and executes the command
- `exec /path/to/importer.sh`: Reads the line, decodes the base64 value and writes the path, mtime and value as arguments to mput
- `mput` Puts the value to the vault according to given arguments

## Migrating From KeePass*
`migration.sh` folder contains a `flatten-kdbx.sh <xmlfilepath>` script that converts a kdbx xml export to a flat list. Then, you can use the command above to import it.

> [!NOTE]
> It's actually a go code wrapped in a shell script. Make sure you installed go.

## Dos and Nos
> [!CAUTION]
> **NEVER** pass an entry value to an external script as positional arguments! Always pass it via stdin instead. Positional arguments will be visible to other processes and will leak your secrets.

> [!NOTE]
> Positional arguments passed to internal commands in shell session will be hidden to other processes. Meaning, you can pass entry values to them relatively securely, but they will be visible in session history. Try to prefer providing them as stdin or via provided input request.

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
	MTime []byte `cmpck:"4"` // The modification time of the entry (uint64 unix epoch milliseconds [little endian])
}
type Argon2IDParams struct {
	Iterations uint32 `cmpck:"1"` // Iterations. Max:16
	Memory uint32 `cmpck:"2"` // Required memory in megabytes. Max:2048
	Threads uint32 `cmpck:"3"` // Parallel threads used while deriving keys. Max:32
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
