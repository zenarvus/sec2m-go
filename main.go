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
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/chzyer/readline"
	"github.com/zenarvus/sec2m-go/core"
	"github.com/zenarvus/sec2m-go/platforms"
	"golang.org/x/term"
)

func printMainHelp() {
	fmt.Println("Usage: VAULT=/path/to/file gosecrets <command> [args]")
	fmt.Println()
	fmt.Println("=== MAIN COMMANDS ===")
	fmt.Println("init <dalg> <ealg> <halg>   - Init the vault file in VAULT location")
	fmt.Println("change <dalg> <ealg> <halg> - Change the given vault's algorithms and password")
	fmt.Println("help                        - Write this output")
	fmt.Println("shell                       - Long lived gosecrets shell session you can execute commands")
	fmt.Println("info                        - Print non-critical info about the vault: headers, shortcuts and entry-count.")
	fmt.Println()
	fmt.Println("=== ALGORITHMS ===")
	fmt.Println("Key Derivation (<dalg>):")
	fmt.Println("  - argon2id-<slen>-<iter>-<mem>-<thread>: Argon2ID with given parameters. <slen> is the length of the salt, <iter> is the amount of iterations, <mem> is the required memory in bytes and <thread> is the amount of threads it will run. Recommended: <slen:16>, <iter:4>, <mem:256>, <thread:2>")
	fmt.Println()
	fmt.Println("Symmetric Encryption (<ealg>):")
	fmt.Println("  - aes-cbc-256: AES-256 with CBC mode")
	fmt.Println("  - xchacha20: CHACHA20 with 24 byte nonce size (recommended)")
	fmt.Println()
	fmt.Println("Hashing (<halg>):")
	fmt.Println("  - sha2-256: 32 byte sha2-256")
	fmt.Println("  - sha3-256: 32 byte sha3-256 (recommended)")
	fmt.Println("  - sha3-384: 48 byte sha3-384")
	fmt.Println("  - sha3-512: 64 byte sha3-512")
	fmt.Println("  - blake3-256: 32 byte blake3")
}
func printShellHelp() {
	fmt.Println("Usage: <command> [args]")
	fmt.Println()
	fmt.Println("=== SHELL ===")
	fmt.Println("help - Write this output")
	fmt.Println("exit - Exit from the gosecrets shell")
}
func printCommonHelp() {
	fmt.Println("=== COMMANDS ===")
	fmt.Println("put <key>      - Insert a key to the vault")
	fmt.Println("update <key>   - Update a key in the vault")
	fmt.Println("get <key>      - Get the value of a key in path")
	fmt.Println("rm <key>       - Delete a key from the vault")
	fmt.Println("rmd <dir>      - Delete a directory from the vault")
	fmt.Println("mv <old> <new> - Rename a key in the vault")
	fmt.Println("exec <args>    - Execute a command from the system")
	fmt.Println()
	fmt.Println("ls <?dir>      - Print the items in the path in vault")
	fmt.Println("cd <?dir>      - Change the current directory to the given path in vault")
	fmt.Println("lsall <?dir>   - List all the keys in the given dir and in all of it's subdirs")
}
func printVaultInfo(sess *core.Session) {
	fmt.Println("=== FILE INFO ===")
	fmt.Println("Key-Derivation-Algorithm:", sess.Header.KDAlgo)
	fmt.Printf("Key-Derivation-Salt: %x\n", sess.Header.KDSalt)
	fmt.Println("Encryption-Algorithm:", sess.Header.SEAlgo)
	fmt.Printf("Encryption-Nonce: %x\n", sess.Header.SENonce)
	fmt.Println("Hash-Algorithm:", sess.Header.HashAlgo)
	fmt.Printf("Signature: %x\n", sess.Signature)
	fmt.Println("Entry-Count:", len(sess.EntryMap))
}
func printShortcuts(sess *core.Session) {
	fmt.Println("=== SHORTCUTS ===")
	shortcuts := getShortcuts(sess)
	if len(shortcuts) == 0 {fmt.Println("No shortcuts exist")}
	for key, val := range shortcuts {
		fmt.Printf("'%s' => %s\n", key, val)
	}
}

func main() {
	// Disable core dumps and ptrace attachment
	if err := platforms.DisableCoreDump(); err != nil {
		fmt.Printf("Failed to disable core dumps: %v\n", err)
		os.Exit(1)
	}

	if len(os.Args) < 2 {
		printMainHelp()
		fmt.Println()
		printCommonHelp()
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "help":
		printMainHelp()
		fmt.Println()
		printCommonHelp()
		os.Exit(0)

	case "init":
		if len(os.Args) != 5 {
			fmt.Println("init: invalid arguments")
			fmt.Println()
			printMainHelp()
			os.Exit(1)
		}

		vaultPath := getVaultPath()

		pw := getPassword("Set vault password: ")
		defer core.ZeroBytes(pw)

		pwAgain := getPassword("Repeat password: ")
		defer core.ZeroBytes(pwAgain)

		if !bytes.Equal(pw, pwAgain) {
			fmt.Println("Passwords do not match")
			os.Exit(1)
		}

		sess, err := core.InitSession(vaultPath, pw, os.Args[2], os.Args[3], os.Args[4])
		if err != nil {
			fmt.Println("Error: "+err.Error())
			os.Exit(1)
		}
		sess.Destroy()

		fmt.Println("File created successfully:",vaultPath)

	case "change":
		if len(os.Args) != 5 {
			fmt.Println("change: invalid arguments")
			fmt.Println()
			printMainHelp()
			os.Exit(1)
		}

		oldpw := getPassword("Old password: ")
		defer core.ZeroBytes(oldpw)

		newpw := getPassword("New password: ")
		defer core.ZeroBytes(newpw)

		newpwagain := getPassword("Retype password: ")
		defer core.ZeroBytes(newpwagain)

		if !bytes.Equal(newpw, newpwagain) {
			fmt.Println("Passwords do not match")
			os.Exit(1)
		}

		vaultPath := getVaultPath()

		sess, err := core.LoadSession(vaultPath, oldpw)
		if err != nil {
			fmt.Println("Error: "+err.Error())
			os.Exit(1)
		}
		defer sess.Destroy()

		err = sess.VaultChange(oldpw, newpw, os.Args[2], os.Args[3], os.Args[4])
		if err != nil {
			fmt.Println("Error: "+err.Error())
			os.Exit(1)
		}
		
		fmt.Println("Vault password and algorithms changed successfully.")

	case "shell":
		vaultPath := getVaultPath()

		pw := getPassword("Vault password: ")
		defer core.ZeroBytes(pw)

		sess, err := core.LoadSession(vaultPath, pw)
		if err != nil {
			fmt.Println("Error: "+err.Error())
			os.Exit(1)
		}
		defer sess.Destroy()

		err = startShell(sess)
		if err != nil {
			fmt.Println("Error: "+err.Error())
			os.Exit(1)
		}

	case "info":
		vaultPath := getVaultPath()

		pw := getPassword("Vault password: ")
		defer core.ZeroBytes(pw)

		sess, err := core.LoadSession(vaultPath, pw)
		if err != nil {
			fmt.Println("Error: "+err.Error())
			os.Exit(1)
		}
		defer sess.Destroy()

		printVaultInfo(sess)
		fmt.Println()
		printShortcuts(sess)

	default:
		result, err := processCommand(nil, []byte{}, os.Args[1:], true)
		if err != nil {
			fmt.Println("Error: "+err.Error())
			os.Exit(1)
		}
		defer core.ZeroBytes(result)

		fmt.Printf("%s", result)
	}
}

func startShell(sess *core.Session) error {

	// Initialize readline
	rl, err := readline.NewEx(&readline.Config{
		Prompt:          sess.Pwd + ": ",
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil { return err }
	defer rl.Close() // Exit from the readline when loop ends.

	for {
		// Set the prompt
		rl.SetPrompt(sess.Pwd+": ")

		// If an error happens with the readline, destroy the session.
		input, err := rl.Readline()
		if err != nil {
			sess.Destroy()
			rl.Close()
			return err
		}

		args, err := parseArgs(input)
		if err != nil {
			fmt.Println(err)
			continue
		}

		if len(args) > 0 {
			switch args[0] {
			case "exit":
				rl.Close()
				return nil
			case "help":
				printShellHelp()
				fmt.Println()
				printCommonHelp()
				fmt.Println()
				printShortcuts(sess)
				continue
			}
		}

		result, err := processCommandlist(sess, args)
		if err != nil { fmt.Println(err); continue }

		fmt.Printf("%s\n", result)
		
	}
}

func processCommandlist(sess *core.Session, args []string) ([]byte, error) {
	// split arguments using "|"
	var commandlist [][]string

	var command []string
	for i,arg := range args {
		// If we arrive to the pipe character, add the command slice generated so far to commandList
		if arg == "|" {
			commandlist = append(commandlist, command)
			command = []string{}
			continue
		}

		command = append(command, arg)

		// If this is the end of the arguments, add the command slice generated so far to commandList
		if i == len(args)-1 {
			commandlist = append(commandlist, command)
		}

	}

	var currentStdin []byte
	var result []byte

	for i, commandArgs := range commandlist {
		if len(commandArgs) == 0 { continue }

		isLastCommand := i == len(commandlist)-1

		res, err := processCommand(sess, currentStdin, commandArgs, isLastCommand)
		if err != nil { return nil, err }
		
		currentStdin = res

		// If we are at the end of the commandList, pass the res to the final result.
		if isLastCommand { result = res }

	}

	return result, nil
}


// Process command processes the given command and return the stdout
func processCommand(sess *core.Session, pipeStdin []byte, args []string, lastCommand bool) ([]byte, error) {
	isOneshot := false

	// If no session exists, create one.
	if sess == nil {
		isOneshot = true

		passwd := getPassword("Vault password: ")
		defer core.ZeroBytes(passwd)

		vaultPath := getVaultPath()

		var err error
		sess, err = core.LoadSession(vaultPath, passwd)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	shortcuts := getShortcuts(sess)

	if(isOneshot) { defer sess.Destroy() }

	switch args[0] {
	case "put": // Add an entry with the value
		if len(args) != 2 { return []byte{}, errors.New("Invalid arguments. Usage: put <key>") }

		key := args[1]

		var value []byte
		if len(pipeStdin) == 0 {
			value = getPassword("Value: ")
		} else {
			value = pipeStdin
		}

		err := sess.Put(key, value)
		if err != nil { return []byte{}, err }

		err = sess.Save()
		if err != nil {
			return []byte{}, errors.New("Error while saving changes: "+err.Error())
		}

		return []byte("Insertion successful\n"), nil

	case "update":
		if len(args) != 2 { return []byte{}, errors.New("Invalid arguments. Usage: update <key>") }

		key := args[1]


		var value []byte
		if len(pipeStdin) == 0 {
			value = getPassword("New value: ")
		} else {
			value = pipeStdin
		}

		err := sess.Update(key, value)
		if err != nil { return []byte{}, err }

		err = sess.Save()
		if err != nil {
			return []byte{}, errors.New("Error while saving changes: "+err.Error())
		}

		return []byte("Insertion successful\n"), nil
		
	case "get": // Get an entry's value
		if len(args) != 2 { return []byte{}, errors.New("Invalid arguments. Usage: get <key>") }

		key := args[1]

		val, err := sess.Get(key)
		if err != nil { return []byte{}, err }

		return val, nil

	case "mv":
		if len(args) != 3 { return []byte{}, errors.New("Invalid arguments. Usage: mv <oldkey> <newkey>") }

		oldkey, newkey := args[1], args[2]

		err := sess.Mv(oldkey, newkey)
		if err != nil { return []byte{}, err }

		err = sess.Save()
		if err != nil {
			return []byte{}, errors.New("Error while saving changes: "+err.Error())
		}

		return []byte("Key moved to the new destination\n"), nil

	case "rm": // Remove a single entry
		if len(args) != 2 { return []byte{}, errors.New("Invalid arguments. Usage: rm <key>") }

		fmt.Println("confirm the deletion attempt:",args[1])
		input := getPassword("(y/n): ")

		if string(input) == "y" {
			err := sess.Rm(args[1])
			if err != nil { return []byte{}, err }

			err = sess.Save()
			if err != nil {
				return []byte{}, errors.New("Error while saving changes: "+err.Error())
			}

			return []byte(args[1]+" deleted\n"), nil
		
		} else {
			return []byte("deletion attempt cancelled"), nil
		}

		
	case "rmd": // Remove a directory
		if len(args) != 2 { return []byte{}, errors.New("Invalid arguments. Usage: rmd <dir>") }

		fmt.Println("confirm the deletion attempt:",args[1])
		input := getPassword("(y/n): ")

		if string(input) == "y" {
			err := sess.Rmd(args[1])
			if err != nil { return []byte{}, err }

			err = sess.Save()
			if err != nil {
				return []byte{}, errors.New("Error while saving changes: "+err.Error())
			}

			return []byte(args[1]+" deleted\n"), nil
		} else {
			return []byte("deletion attempt cancelled"), nil
		}

	case "ls":
		var dirs []string
		var entries []string
		var err error

		if len(args) == 1 {
			dirs, entries, err = sess.Ls("")
			if err != nil { return []byte{}, err }

		} else if len(args) == 2 {
			dirs, entries, err = sess.Ls(args[1])
			if err != nil { return []byte{}, err }

		} else { return []byte{}, errors.New("Invalid arguments. Usage: ls <?dir>") }

		var s bytes.Buffer
		for _,dir := range dirs {
			s.WriteString(dir)
			s.WriteString("/\n")
		}
		for _,entry := range entries {
			s.WriteString(entry)
			s.WriteString("\n")
		}
		
		return s.Bytes(), nil

	case "lsall":
		var entries []string
		var err error

		if len(args) == 1 {
			entries, err = sess.Lsall("")
			if err != nil { return []byte{}, err }

		} else if len(args) == 2 {
			entries, err = sess.Lsall(args[1])
			if err != nil { return []byte{}, err }

		} else { return []byte{}, errors.New("Invalid arguments. Usage: lsall <?dir>") }

		var s bytes.Buffer
		for _,entry := range entries {
			s.WriteString(entry)
			s.WriteString("\n")
		}
		
		return s.Bytes(), nil

	case "cd":
		if len(args) == 1 {
			err := sess.Cd("")
			if err != nil { return []byte{}, err }

		} else if len(args) == 2 {
			err := sess.Cd(args[1])
			if err != nil { return []byte{}, err }

		} else { return []byte{}, errors.New("Invalid arguments. Usage: cd <?dir>") }

		return []byte{}, nil

	case "exec":
		if len(args) < 2 { return []byte{}, errors.New("Invalid arguments. Usage: exec <shell-command> <args>") }

		// Create the command
		var shellCmd *exec.Cmd
		if len(args) > 2 {
			shellCmd = exec.Command(args[1], args[2:]...)
		} else {
			shellCmd = exec.Command(args[1])
		}

		// If there is pipe stdin, pass it to the shellCmd's stdin
		if len(pipeStdin) > 0 {
			shellCmd.Stdin = bytes.NewReader(pipeStdin)
		}

		var outBuf bytes.Buffer
		// If it's the last command, forward the outputs to the process output.
		if lastCommand {
			shellCmd.Stdout = os.Stdout
			shellCmd.Stderr = os.Stderr
		// Capture both stdout and stderr in a buffer
		} else {
			shellCmd.Stdout = &outBuf
			shellCmd.Stderr = &outBuf
		}

		// Run the command
		err := shellCmd.Run()
    	if err != nil { return outBuf.Bytes(), err } // Return both the captured output and the error

		return outBuf.Bytes(), nil

	default:
		shortcutVal := shortcuts[args[0]]

		expanded := string(shortcutVal)

		// If the shortcut has a value
		if len(shortcutVal) > 0 {
			// Replace placeholders {1}, {2}, etc. with provided arguments
			for i := 1; i < len(args); i++ {
				placeholder := fmt.Sprintf("{%d}", i)
				expanded = strings.ReplaceAll(expanded, placeholder, args[i])
			}

			// Parse the expanded shortcut string into arguments
			expandedArgs, err := parseArgs(expanded)
			if err != nil {
				return []byte{}, fmt.Errorf("Shortcut expansion error: %w", err)
			}

			return processCommandlist(sess, expandedArgs)
		}
	}

	return []byte{}, errors.New("Unknown command: '"+args[0]+"'")
}

func getShortcuts(sess *core.Session) (map[string][]byte) {
	var shortcuts = make(map[string][]byte)

	for key := range sess.EntryMap {
		// If the key is the top level key in the shortcut dir, add it to the shortcuts.
		if strings.HasPrefix(key, "/.shortcut/") {
			shortcut,_ := strings.CutPrefix(key, "/.shortcut/")
			if !strings.Contains(shortcut, "/") {
				shortcutVal, _ := sess.Get(shortcut)
				shortcuts[shortcut] = shortcutVal
			}
		}

	}

	return shortcuts
}

func getVaultPath() string {
	vaultPath := os.Getenv("VAULT")
	if vaultPath == "" {
		fmt.Println("VAULT environment variable is not set.")
		os.Exit(1)
	}
	return vaultPath
}

// getPassword prompts user to give an input. The written text will not shown.
func getPassword(prompt string) []byte {

	fmt.Fprintf(os.Stderr, "%s", prompt)

	input, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("\nError reading input:", err)
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr)
	return input
}

// parseArgs splits the input into arguments where things in quotes considered one argument.
func parseArgs(input string) ([]string, error) {
	// Trim whitespace
	input = strings.TrimSpace(input)

	var args []string
	var arg strings.Builder

	inQuote := rune(0)
	escaped := false

	for _, r := range input {
		// If the element is escaped, write it directly to arg, disable escaping and continue.
		if escaped { arg.WriteRune(r); escaped=false; continue }

		// If there is a slash, escape the next element.
		if r == '\\' { escaped=true; continue }

		// If it's in quote
		if inQuote != 0 {
			// If the character is equal to the quote start character, make inQuote = 0
			if r == inQuote {
				inQuote = 0
			// Else write whatever this char is to the current argument.
			} else { arg.WriteRune(r) }
			// Skip to the next char
			continue
		}

		if r == '"' || r == '\'' { inQuote=r; continue }

		if r == ' ' || r == '\t' || r == '\n' {
			if arg.Len() > 0 {
				args = append(args, arg.String())
				arg.Reset()
			}
			continue
		}

		arg.WriteRune(r)
	}

	if inQuote != 0 { return nil, fmt.Errorf("unclosed quote in command string") }

	if arg.Len() > 0 { args = append(args, arg.String()) }

	return args, nil
}
