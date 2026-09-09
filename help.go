/*
sec2m-go: CLI based secure secrets manager
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

package main

import (
	"fmt"

	cmpck "github.com/zenarvus/compack/go"
	"github.com/zenarvus/sec2m-go/core"
)

func printMainHelp() {
fmt.Printf(`Usage: VAULT=/path/to/file.sdb sec2m <command> [args]

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
`)
}

func printShellHelp() {
fmt.Printf(`Usage: <command> [args]

=== SHELL ===
help: Write this output

exit: Exit from the sec2m shell
`)
}

func printCommonHelp() {
fmt.Printf(`=== COMMAND REFERENCE ===
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
`)
}

func printVaultInfo(file *core.File, header *core.UnmarshaledHeader) {
	fmt.Println("=== FILE INFO ===")
	fmt.Println("Vault-Version:", file.Version)
	fmt.Println("Key-Derivation-Algorithm:", core.DerAlgoToStrMap[header.KDAlgo])
	fmt.Printf("Key-Derivation-Salt: %x\n", header.KDSalt)

	switch header.KDAlgo {
	case core.Derive_ARGON2ID:
		var argon2idParams core.Argon2IDParams
		_ = cmpck.Unmarshal(header.KDParams, &argon2idParams)
		fmt.Println("Argon2ID-Params")
		fmt.Println("- Iterations:", argon2idParams.Iterations)
		fmt.Println("- Memory:", argon2idParams.Memory)
		fmt.Println("- Parallelism:", argon2idParams.Threads)
	}

	fmt.Println("Encryption-Algorithm:", core.EncAlgoToStrMap[header.SEAlgo])
	fmt.Printf("Encryption-Nonce: %x\n", header.SENonce)
	fmt.Println("Hash-Algorithm:", core.HashAlgoToStrMap[header.HashAlgo])
	fmt.Printf("Signature: %x\n", file.Signature)
}

func printShortcuts(sess *core.Session) {
	fmt.Println("=== SHORTCUTS ===")
	shortcuts := getShortcuts(sess)
	if len(shortcuts) == 0 {fmt.Println("No shortcuts exist")}
	for key, val := range shortcuts {
		fmt.Printf("'%s' => %s\n", key, val)
	}
}

