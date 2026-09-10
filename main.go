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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/chzyer/readline"
	cmpck "github.com/zenarvus/compack/go"
	"github.com/zenarvus/sec2m-go/core"
	"github.com/zenarvus/sec2m-go/securemem"
	"golang.org/x/term"
)

func main() {
	// Disable core dumps and ptrace attachment
	if err := securemem.Setup(); err != nil {
		fmt.Println(err)
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

		pw,dealloc1,err := getInput(nil, "set password: ", true)
		defer dealloc1()
		if err!=nil{fmt.Println(err); os.Exit(1)}

		pwAgain,dealloc2,err := getInput(nil, "repeat: ", true)
		defer dealloc2()
		if err!=nil{fmt.Println(err); os.Exit(1)}

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

		oldpw,dealloc1,err := getInput(nil, "old password: ", true)
		defer dealloc1()
		if err!=nil{fmt.Println(err); os.Exit(1)}

		newpw,dealloc2,err := getInput(nil, "new password: ", true)
		defer dealloc2()
		if err!=nil{fmt.Println(err); os.Exit(1)}

		newpwagain,dealloc3,err := getInput(nil, "repeat: ", true)
		defer dealloc3()
		if err!=nil{fmt.Println(err); os.Exit(1)}

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

		pw,dealloc,err := getInput(nil, "password: ", true)
		defer dealloc()
		if err!=nil{fmt.Println(err); os.Exit(1)}

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
	case "shot":
		vaultPath := getVaultPath()

		pw,dealloc,err := getInput(nil, "password: ", true)
		defer dealloc()
		if err != nil{fmt.Println(err); os.Exit(1)}

		sess, err := core.LoadSession(vaultPath, pw)
		if err != nil {
			fmt.Println("Error: "+err.Error())
			os.Exit(1)
		}
		defer sess.Destroy()

		if len(os.Args) != 3 { 
			fmt.Println("Invalid arguments. Usage: shot 'piped | command-list'")
			os.Exit(1)
		}

		cmdArgs,err := tokenize([]byte(os.Args[2]))
		if err != nil {
			fmt.Println("Error while parsing arguments:", err)
			os.Exit(1)
		}

		err = processPipeline(sess, cmdArgs, bytes.NewReader(nil), os.Stdout)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

	case "info":
		vaultPath := getVaultPath()

		fileBytes, err := os.ReadFile(vaultPath)
		if err!=nil {
			fmt.Println("Error: "+err.Error())
			os.Exit(1)
		}

		var fileStruct core.File
		err = cmpck.Unmarshal(fileBytes, &fileStruct)
		if err != nil {
			fmt.Println("Error: "+err.Error())
			os.Exit(1)
		}

		var header core.UnmarshaledHeader
		err = cmpck.Unmarshal(fileStruct.Header, &header) // Copy the metadata of the file to the session.
		if err != nil {
			fmt.Println("Error: "+err.Error())
			os.Exit(1)
		}

		printVaultInfo(&fileStruct, &header)

	default:
		var byteArgs = make([][]byte, 0, len(os.Args[1:]))
		for i:=1; i < len(os.Args); i++ {
			byteArgs = append(byteArgs, []byte(os.Args[i]))
		}

		err := processCommand(nil, bytes.NewReader(nil), os.Stdout, byteArgs)
		if err != nil {
			fmt.Println("Error: "+err.Error())
			os.Exit(1)
		}
	}
}

func startShell(sess *core.Session) error {

	// Initialize readline
	rl, err := readline.NewEx(&readline.Config{
		Prompt:          sess.Pwd + ": ",
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		AutoComplete: &AutoCompleter{sess:sess},
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

		args, err := tokenize([]byte(input))
		if err != nil {
			fmt.Println(err)
			continue
		}

		if len(args) > 0 {
			switch string(args[0].Value.String()) {
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

		err = processPipeline(sess, args, bytes.NewReader(nil), os.Stdout)
		if err != nil { fmt.Println(err); continue }
	}
}

func processPipeline(
	sess *core.Session, tokens []Token, stdin io.Reader, finalStdout io.Writer,
) (error) {
	// commants split using "|"
	var commandlist [][]Token

	var command []Token

	for i,token := range tokens {
		// If we arrive to the pipe character, add the command slice generated so far to commandList
		if  token.Type == PIPE {
			commandlist = append(commandlist, command)
			command = []Token{}
			continue
		}

		command = append(command, token)

		// If this is the end of the arguments, add the command slice generated so far to commandList
		if i == len(tokens)-1 {
			commandlist = append(commandlist, command)
		}

	}

	var currentStdin = stdin

	var currentStdout io.Writer
	var nextStdin io.Reader

	for i, commandArgs := range commandlist {
		if len(commandArgs) == 0 { continue }

		// If we are at the last command, make the stdout the final stdout
		if i == len(commandlist)-1 {
			currentStdout = finalStdout
		// Else, make it a buffer
		} else {
			var buf = &bytes.Buffer{}
			currentStdout = buf
			nextStdin = buf // We also write to next stdin and pass it as stdin to the next command
		}

		// Process the substitutions and return an array of []byte as args
		args,err := processAllSubstitutions(sess, commandArgs)
		if err != nil {return err}

		err = processCommand(sess, currentStdin, currentStdout, args)
		if err != nil { return err }

		currentStdin = nextStdin // update stdin to next stdin
	}

	return nil
}

var placeholderRegex = regexp.MustCompile(`\{\d+\}`) // Used to replace the placeholders in shortcuts

// Process command processes the given command and return the stdout
func processCommand(sess *core.Session, stdin io.Reader, stdout io.Writer, args [][]byte) (error) {
	isOneshot := false

	// If no session exists, create one.
	if sess == nil {
		isOneshot = true

		passwd,dealloc,err := getInput(sess, "password: ", true)
		defer dealloc()
		if err != nil {return err}
		defer securemem.ZeroBytes(passwd)

		vaultPath := getVaultPath()

		sess, err = core.LoadSession(vaultPath, passwd)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	shortcuts := getShortcuts(sess)

	if(isOneshot) { defer sess.Destroy() }

	switch string(args[0]) {
	case "put": // Add an entry with the value

		putArgs,deallocArgs, err := getArgs(sess, 2, args[1:], stdin, true)
		defer deallocArgs()
		if err != nil {
			return errors.New("Usage: put <epath> <value>\n"+err.Error())
		}

		err = sess.Put(string(putArgs[0]), []byte{}, putArgs[1])
		if err != nil { return err }
		err = sess.Save()
		if err != nil { return errors.New("Error while saving changes: "+err.Error()) }

		stdout.Write([]byte("inserted: "+string(putArgs[0])+"\n"))
		return nil
	
	case "mput":

		mputArgs,deallocArgs, err := getArgs(sess, 3, args[1:], stdin, true)
		defer deallocArgs()
		if err != nil {
			return errors.New("Usage: put <epath> <mtime> <value>\n"+err.Error())
		}

		var epath = mputArgs[0]
		var newMtime = mputArgs[1] // Unix epoch in milliseconds
		var value = mputArgs[2]

		newMtimeInt, err := strconv.ParseUint(string(newMtime), 10, 64)
		if err != nil { return errors.New("invalid mtime format") }

		var newMtimeBytes = make([]byte, 8)
		binary.LittleEndian.PutUint64(newMtimeBytes, newMtimeInt)

		err = sess.Put(string(epath), newMtimeBytes, value)
		if err != nil { return err }
		err = sess.Save()
		if err != nil { return errors.New("Error while saving changes: "+err.Error()) }

		stdout.Write([]byte("inserted: "+string(epath)+"\n"))
		return nil

	case "update":
		updateArgs,deallocArgs, err := getArgs(sess, 2, args[1:], stdin, true)
		defer deallocArgs()
		if err != nil {
			return errors.New("Usage: update <epath> <value>\n"+err.Error())
		}

		var epath = updateArgs[0]
		var value = updateArgs[1]

		fmt.Println("confirm the update attempt:",string(epath))
		input,dealloc,err := getInput(sess, "(y/n): ", false)
		defer dealloc()

		if string(input) == "y" {
			err := sess.Update(string(epath), value)
			if err != nil { return err }
			err = sess.Save()
			if err != nil { return errors.New("Error while saving changes: "+err.Error()) }

			stdout.Write([]byte("updated: "+string(epath)+"\n"))
			return nil

		} else { stdout.Write([]byte("update attempt cancelled")); return nil }
	
	case "mtime":

		mtimeArgs,deallocArgs, err := getArgs(sess, 1, args[1:], stdin, false)
		defer deallocArgs()
		if err != nil {
			return errors.New("Usage: mtime <epath>\n"+err.Error())
		}

		var epath = string(mtimeArgs[0])

		// epath must be a file path string.
		if !core.PathRegexp.MatchString(epath) || strings.HasSuffix(epath, "/") {
			return errors.New("key must be a filepath string")
		}
		// If it does not have slash at the start, join it to the current working directory.
		if !strings.HasPrefix(epath, "/") { epath = path.Join(sess.Pwd, epath) }

		entry, exists := sess.EntryMap[string(epath)]
		if !exists { return errors.New(string(epath)+": Entry does not exist")}

		mtimeInt := binary.LittleEndian.Uint64(entry.MTime)

		stdout.Write(fmt.Appendf(nil, "%v\n", mtimeInt))
		return nil
		
	case "get": // Get an entry's value
		getArgs,deallocArgs, err := getArgs(sess, 1, args[1:], stdin, false)
		defer deallocArgs()
		if err != nil {
			return errors.New("Usage: get <epath>\n"+err.Error())
		}

		var epath = getArgs[0]
		val,deallocVal, err := sess.Get(string(epath))
		if err != nil { return err }

		stdout.Write(val)
		deallocVal()
		stdout.Write([]byte("\n"))

		return nil

	case "mv":
		mvArgs,deallocArgs, err := getArgs(sess, 2, args[1:], stdin, false)
		defer deallocArgs()
		if err != nil {
			return errors.New("Usage: mv <old> <new>\n"+err.Error())
		}

		var oldpath = string(mvArgs[0])
		var newpath = string(mvArgs[1])

		err = sess.Mv(oldpath, newpath)
		if err != nil { return err }

		err = sess.Save()
		if err != nil {
			return errors.New("Error while saving changes: "+err.Error())
		}

		stdout.Write([]byte("key moved to the new destination\n"))
		return  nil

	case "rm": // Remove a single entry
		rmArgs,deallocArgs, err := getArgs(sess, 1, args[1:], stdin, false)
		defer deallocArgs()
		if err != nil {
			return errors.New("Usage: rm <epath>\n"+err.Error())
		}

		var epath = string(rmArgs[0])

		fmt.Println("confirm the deletion attempt:",epath)
		input,dealloc,err := getInput(sess, "(y/n): ", false)
		defer dealloc()

		if string(input) == "y" {
			err := sess.Rm(string(epath))
			if err != nil { return err }

			err = sess.Save()
			if err != nil {
				return errors.New("Error while saving changes: "+err.Error())
			}

			stdout.Write([]byte(epath+" deleted"))
			return nil
		
		} else { stdout.Write([]byte("deletion attempt cancelled\n")); return nil }

		
	case "rmd": // Remove a directory
		rmdArgs,deallocArgs, err := getArgs(sess, 1, args[1:], stdin, false)
		defer deallocArgs()
		if err != nil { return errors.New("Usage: rmd <dpath>\n"+err.Error()) }

		var dpath = string(rmdArgs[0])

		fmt.Println("confirm the deletion attempt:",dpath)
		input,dealloc,err := getInput(sess, "(y/n): ", false)
		defer dealloc()

		if string(input) == "y" {
			err := sess.Rmd(dpath)
			if err != nil { return err }

			err = sess.Save()
			if err != nil {
				return errors.New("Error while saving changes: "+err.Error())
			}

			stdout.Write([]byte(dpath+" deleted\n"))
			return nil

		} else { stdout.Write([]byte("deletion attempt cancelled")); return nil }

	// ls does not accept stdin as argument
	case "ls":
		var dirs []string
		var entries []string
		var err error

		if len(args) == 1 {
			dirs, entries, err = sess.Ls("")
			if err != nil { return err }

		} else if len(args) == 2 {
			dirs, entries, err = sess.Ls(string(args[1]))
			if err != nil { return err }

		} else { return errors.New("Usage: ls <dpath>") }

		// Sort the dirs slice
		sort.Slice(dirs, func(i, j int) bool {
			return dirs[i] < dirs[j]
		})
		// Sort the entries slice
		sort.Slice(entries, func(i, j int) bool {
			return entries[i] < entries[j]
		})

		var s bytes.Buffer
		for _,dir := range dirs {
			s.WriteString(dir)
			s.WriteString("/\n")
		}
		for _,entry := range entries {
			s.WriteString(entry)
			s.WriteString("\n")
		}
		
		stdout.Write(s.Bytes())
		return nil

	// ls does not accept stdin as argument
	case "lsall":
		var entries []string
		var err error

		if len(args) == 1 {
			entries, err = sess.Lsall("")
			if err != nil { return err }

		} else if len(args) == 2 {
			entries, err = sess.Lsall(string(args[1]))
			if err != nil { return err }

		} else { return errors.New("Usage: lsall <dpath>") }

		// Sort the entries slice
		sort.Slice(entries, func(i, j int) bool {
			return entries[i] < entries[j]
		})

		var s bytes.Buffer
		for _,entry := range entries {
			s.WriteString(entry)
			s.WriteString("\n")
		}
		
		stdout.Write(s.Bytes())
		return nil

	// cd does not support stdin as argument
	case "cd":
		if len(args) == 1 {
			err := sess.Cd("")
			if err != nil { return err }

		} else if len(args) == 2 {
			err := sess.Cd(string(args[1]))
			if err != nil { return err }

		} else { return errors.New("Usage: cd <dpath>") }

		return nil

	case "exec":
		if len(args) < 2 { return errors.New("Usage: exec <shell-command> <args>") }

		// Create the command
		cmdArgs := make([]string, 0, len(args[1:]))
		for i:=1; i < len(args); i++ {
			cmdArgs = append(cmdArgs, string(args[i]))
		}

		shellCmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)

		// pass stdin to the shellCmd's stdin
		shellCmd.Stdin = stdin
		shellCmd.Stdout = stdout
		shellCmd.Stderr = os.Stderr

		// Run the command
		err := shellCmd.Run()
    	if err != nil { return err } // Return both the captured output and the error

		return nil

	case "eval":
		evalArgs,deallocArgs, err := getArgs(sess, 1, args[1:], stdin, false)
		defer deallocArgs()
		if err != nil { return errors.New("Usage: eval <pipeline>\n"+err.Error()) }

		var cmd = evalArgs[0]
		cmdArgs, err := tokenize(cmd)
		if err != nil { return err }

		return processPipeline(sess, cmdArgs, bytes.NewReader(nil), stdout)

	// Read the stdin, split it with the given delimiter, iterate through them and execute the provided command in every iteration
	case "iter":
		if len(args) != 2 { return errors.New("Usage: iter <pipeline>")}

		stdinBytes,err := io.ReadAll(stdin)
		if err != nil {return err}
		
		lines := bytes.Split(stdinBytes, []byte{'\n'})

		for _, line := range lines {
			// Skip empty slices resulting from trailing newline characters
			if len(bytes.TrimSpace(line)) == 0 { continue }

			cmd, err := tokenize(args[1])
			if err != nil {return err}

			err = processPipeline(sess, cmd, bytes.NewReader(line), stdout)
			if err != nil {return err}
		}

		return nil
	
	case "senv":
		senvArgs,deallocArgs, err := getArgs(sess, 2, args[1:], stdin, false)
		defer deallocArgs()
		if err != nil {
			return errors.New("Usage: senv <name> <value>\n"+err.Error())
		}

		err = sess.Senv(string(senvArgs[0]), senvArgs[1]) // Senv zeroes the value
		if err != nil { return err }

		return nil

	case "genv":
		genvArgs,deallocArgs, err := getArgs(sess, 1, args[1:], stdin, false)
		defer deallocArgs()
		if err != nil { return errors.New("Usage: genv <name>\n"+err.Error()) }

		val,dealloc,err := sess.Genv(string(genvArgs[0]))
		if err!=nil{return err}

		stdout.Write(val)
		stdout.Write([]byte("\n"))
		dealloc()

		return nil

	case "renv":
		renvArgs,deallocArgs, err := getArgs(sess, 1, args[1:], stdin, false)
		defer deallocArgs()
		if err != nil { return errors.New("Usage: renv <name>\n"+err.Error()) }

		sess.Renv(string(renvArgs[0]))

		return nil

	default:
		shortcutVal := shortcuts[string(args[0])]

		expanded := string(shortcutVal)

		// If the shortcut has a value
		if len(shortcutVal) > 0 {
			// Replace placeholders {1}, {2}, etc. with provided arguments.
			for i := 1; i < len(args); i++ {
				placeholder := fmt.Sprintf("{%d}", i)
				expanded = strings.ReplaceAll(expanded, placeholder, string(args[i]))
			}

			// Remove the remaining placeholders. This removes unused ones when no argument is passed etc.
			expanded = placeholderRegex.ReplaceAllString(expanded, "")

			// Parse the expanded shortcut string into arguments
			expandedArgs, err := tokenize([]byte(expanded))
			if err != nil {
				return fmt.Errorf("shortcut expansion error: %w", err)
			}

			return processPipeline(sess, expandedArgs, stdin, stdout)
		}
	}

	return errors.New("unknown command: '"+string(args[0])+"'")
}

func getShortcuts(sess *core.Session) (map[string][]byte) {
	var shortcuts = make(map[string][]byte)

	for epath := range sess.EntryMap {
		// If the key is the top level key in the shortcut dir, add it to the shortcuts.
		if strings.HasPrefix(epath, "/.shortcut/") {
			shortcut,_ := strings.CutPrefix(epath, "/.shortcut/")
			if !strings.Contains(shortcut, "/") {
				shortcutVal,deallocVal, _ := sess.Get(epath) // they are non-secret info. We can clone them to go heap
				shortcuts[shortcut] = bytes.Clone(shortcutVal)
				deallocVal()
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
	if !strings.HasSuffix(vaultPath, ".sdb") {
		fmt.Println("Vault must contain '.sdb' at the end.")
		os.Exit(1)
	}
	return vaultPath
}

// getInput prompts user to give an input. The written text will not shown if hidden is true.
func getInput(sess *core.Session, prompt string, hidden bool) ([]byte,func(), error) {
	fmt.Fprintf(os.Stderr, "%s", prompt)

	fd := int(os.Stdin.Fd())

	// Put the terminal into raw mode to catch key presses
	oldState, err := term.MakeRaw(fd)
	if err != nil { return nil, func(){}, err }
	defer term.Restore(fd, oldState)

	// restore the state on SIGINT or SIGTERM
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigChan)
	go func() {
		<-sigChan
		term.Restore(fd, oldState)
		if sess != nil { sess.Destroy() }
		os.Exit(1)
	}()

	// Allocate a 8 KB buffer for whole password input
	inputBuf,dealloc,err := securemem.Alloc(1024*8)
	if err != nil {return nil, func(){},err}

	pos := 0 // the position in the input buffer. The length of the byte array

	// allocate a 1 byte buffer for per char input
	charBuf, deallocCharBuf, err := securemem.Alloc(1)
	if err != nil {return nil,dealloc,err}
	defer deallocCharBuf()

	for {
		_, err := os.Stdin.Read(charBuf)
		if err != nil { return nil,dealloc,err }

		b := charBuf[0]

		// Handle ctrl+c (ascii 3)
        if b == 3 {
            term.Restore(fd, oldState)
            fmt.Fprintf(os.Stderr, "\r\n")
            return nil, func(){}, errors.New("interrupted")
        }

		// suppress ansi escape sequences (arrow keys, home, end, etc.)
		if b == 27 { // 0x1B (esc)
			// read the next character to check for '['
			subCharBuf, deallocSubCharBuf, err := securemem.Alloc(2)
			if err != nil { deallocSubCharBuf(); return nil,dealloc, err }

			n, _ := os.Stdin.Read(subCharBuf[:1])
			// If it's '[', read and consume one more byte too.
			if n > 0 && subCharBuf[0] == '[' {
				// Read the final specifier byte (e.g., A, B, C, D)
				os.Stdin.Read(subCharBuf[1:2])
			}
			deallocSubCharBuf()
			continue
		}

		// Handle enter (\r or \n)
		if b == '\r' || b == '\n' { break }

		// Handle backspace (ascii 8) and del (ascii 127)
		if b == 8 || b == 127 {
			if pos > 0 {
				pos-- // delete the char from input buf

				// erase the last asterisk: step back, overwrite with space, step back
				fmt.Fprintf(os.Stderr, "\b \b")
			}
			continue
		}

		// Skip non-printable control characters
		if b < 32 { continue }

		// check the length limit
		if pos+1 > 1024*8 { return nil,dealloc,errors.New("character limit exceeded (max 8kb)") }

		// store the key
		inputBuf[pos] = b
		pos++ // as we first add and increase later, post represents the length of the array. Aka: the next element's index

		// if it's hidden, show asterix instead of raw chars
		if hidden {
			fmt.Fprintf(os.Stderr, "*")

		} else { fmt.Fprintf(os.Stderr, "%s", string(b)) }
	}

	// Move to a new line after raw mode finishes
	fmt.Fprintf(os.Stderr, "\r\n")
	return inputBuf[:pos], dealloc, nil
}

// get the arguments from passed positional arguments and stdin. Give error if it's not enough to create args in requiredCount.
// Ask for user input if given arguments does not match the required count while ask is true
func getArgs(
	sess *core.Session, requiredCount int, givenargs [][]byte, stdin io.Reader, ask bool,
) (totalargs [][]byte, dealloc func(), err error) {

	var deallocChain []func()
	dealloc = func(){
		for _,d := range deallocChain { d() }
	}

	for _,arg := range givenargs {
		totalargs = append(totalargs, arg)
		// zero the given arguments
		deallocChain = append(deallocChain, func() { securemem.ZeroBytes(arg) })
	}

	// If argument count exceeds the requiredCount, give error
	if len(totalargs) > requiredCount {
		return nil,dealloc, errors.New("passed argument count exceeds the required count")
	
	// If it matches the count exactly, return it.
	} else if len(totalargs) == requiredCount {
		return totalargs,dealloc, nil

	// Else, split stdin by newlines and add them as args until requiredCount is satisfied. If there is still more '\n' separated arguments left in stdinArgs, combine them in the last totalargs argument.
	} else {
		requiredArgsLeft := requiredCount - len(totalargs)
		var stdinArgs [][]byte
		// Only split stdinArgs if stdinBytes is not empty. If we don't do that, bytes.Split returns stdinArgs with one empty slice item.
		stdinBytes,err := io.ReadAll(stdin) // zero the stdin bytes
		if err != nil {return nil,dealloc, err}

		deallocChain = append(deallocChain, func() { securemem.ZeroBytes(stdinBytes) })

		if len(stdinBytes) > 0 {
			stdinArgs = bytes.Split(stdinBytes, []byte{'\n'})
		}

		// Give error if stdinArgs has not enough arguments to satisfy requiredArgsLeft
		if !ask && len(stdinArgs) < requiredArgsLeft {return nil,dealloc, errors.New("not enough arguments provided")}

		// Take what's available from stdinArgs
		argsToTake := requiredArgsLeft
		if len(stdinArgs) < argsToTake {
			argsToTake = len(stdinArgs)
		}

		// Append those arguments to the totalargs list
		for i := range argsToTake { totalargs = append(totalargs, stdinArgs[i]) }

		// Append the leftover stdinArgs to the last totalargs argument
		if len(stdinArgs) > requiredArgsLeft {
			totalargs[len(totalargs)-1] = append(
				totalargs[len(totalargs)-1],
				// combine the rest with the last argument using '\n'
				append([]byte{'\n'}, bytes.Join(stdinArgs[requiredArgsLeft:], []byte{'\n'})...)...,
			)
		}
	}

	// Ask until required argument count is satisfied
	if ask && requiredCount-len(totalargs) > 0 {
		// Get argument until requiredCount gets equal to len(totalargs)
		for requiredCount-len(totalargs) > 0 {
			arg,deallocArg,err := getInput(sess, fmt.Sprintf("arg-%v: ", len(totalargs)+1), true)
			deallocChain = append(deallocChain, deallocArg) // zero the inputs
			if err != nil {return nil,dealloc,err}
			totalargs = append(totalargs, arg)
		}
	}

	return totalargs,dealloc, nil
}

////////////////////////////////////////////////////////

func processAllSubstitutions(sess *core.Session, tokens []Token) ([][]byte, error) {
	var expanded [][]byte

	for _,token := range tokens {
		exp, err := processSubstitution(sess, token)
		if err != nil { return nil, err }
		expanded = append(expanded, exp)
	}
	return expanded, nil
}

// Get the substitution token, tokenize it's value, process the pipeline and return the value
func processSubstitution(sess *core.Session, input Token) ([]byte, error) {
	if input.Type == SUBSTITUTION {

		cmdArgs,err := tokenize(input.Value.Bytes())
		if err != nil {return nil, err}

		var buf = &bytes.Buffer{}
		err = processPipeline(sess, cmdArgs, bytes.NewReader(nil), buf)
		if err != nil { return nil, err }

		return buf.Bytes(),nil

	} else { return input.Value.Bytes(), nil }
}

///////////////////////////////////////////////////////

type AutoCompleter struct { sess *core.Session }

// Do implements the readline.AutoCompleter interface directly
func (v *AutoCompleter) Do(line []rune, pos int) (completionOpts [][]rune, length int) {
	lineStr := string(line[:pos]) // Get the everything until the cursor
	
	// Handle empty or whitespace-only input
	if strings.TrimSpace(lineStr) == "" { return nil, 0 }

	// Split by space to figure out if we are completing a command or a path
	args := strings.Split(lineStr, " ")

	// If we are typing the first word, complete the command itself
	if len(args) == 1 {
		cmds := []string{"help", "exit", "info", "put", "get", "rm", "update", "mv", "cd", "rmd", "ls", "lsall"}
		for _, cmd := range cmds {
			if strings.HasPrefix(cmd, lineStr) {
				// Append the remaining string for completion of the current types string
				completionOpts = append(completionOpts, []rune(strings.TrimPrefix(cmd, lineStr)))
			}
		}
		// Return the completion options
		return completionOpts, 0
	}

	// If there are more than one argument, we are typing arguments of the command (file/folder paths)

	cmd := args[0]
	lastArg := args[len(args)-1]

	dirsOnly := false
	switch cmd {
	case "cd", "rmd", "ls", "lsall":
		dirsOnly = true
	case "get", "rm", "update", "mv":
		dirsOnly = false
	// For other things like shortcuts, complete everything
	default: dirsOnly = false
	}

	// Fetch dynamic completions
	results := v.getCompletions(lastArg, dirsOnly)
	
	// Filter results to only those that match what the user typed and return the remaining possibilities
	for _, res := range results {
		if strings.HasPrefix(res, lastArg) {
			completionOpts = append(completionOpts, []rune(strings.TrimPrefix(res, lastArg)))
		}
	}

	// Return the completion possibilities
	return completionOpts, 0
}

// Updated helper logic attached to the struct
func (v *AutoCompleter) getCompletions(line string, dirsOnly bool) []string {
	dirPath := ""
	
	// Extract the directory portion of the string
	if idx := strings.LastIndex(line, "/"); idx != -1 {
		dirPath = line[:idx]
		if dirPath == "" { dirPath = "/"  } // For absolute paths (like typing "/folder")
	}

	dirs, entries, err := v.sess.Ls(dirPath)
	if err != nil { return nil }

	var results []string
	prefix := dirPath
	if prefix != "" && prefix != "/" {
		prefix += "/"
	} else if prefix == "/" { prefix = "/" }

	// Add subdirectories (always append trailing slash so we can keep pressing TAB)
	for _, d := range dirs { results = append(results, prefix+d+"/") }

	// Add files if not restricted to directories
	if !dirsOnly {
		for _, e := range entries { results = append(results, prefix+e) }
	}
	
	return results
}
