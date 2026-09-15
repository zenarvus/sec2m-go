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
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	cmpck "github.com/zenarvus/compack/go"
	"github.com/zenarvus/sec2m-go/core"
	"github.com/zenarvus/sec2m-go/readline"
	"github.com/zenarvus/sec2m-go/securemem"
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

		pw,err := readline.NewReadline("set password: ", true, nil).Read()
		if err!=nil{fmt.Println(err); os.Exit(1)}
		defer pw.Dealloc()

		pwAgain,err := readline.NewReadline("repeat: ", true, nil).Read()
		if err!=nil{fmt.Println(err); os.Exit(1)}
		defer pwAgain.Dealloc()

		if !bytes.Equal(pw.Bytes, pwAgain.Bytes) {
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

		oldpw,err := readline.NewReadline("old password: ", true, nil).Read()
		if err!=nil{fmt.Println(err); os.Exit(1)}
		defer oldpw.Dealloc()

		newpw,err := readline.NewReadline("new password: ", true, nil).Read()
		if err!=nil{fmt.Println(err); os.Exit(1)}
		defer newpw.Dealloc()

		newpwagain,err := readline.NewReadline("repeat: ", true, nil).Read()
		if err!=nil{fmt.Println(err); os.Exit(1)}
		defer newpwagain.Dealloc()

		if !bytes.Equal(newpw.Bytes, newpwagain.Bytes) {
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

		pw,err := readline.NewReadline("password: ", true, nil).Read()
		if err!=nil{fmt.Println(err); os.Exit(1)}
		defer pw.Dealloc()

		sess, err := core.LoadSession(vaultPath, pw)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		defer sess.Destroy()

		err = startShell(sess)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
	case "shot":
		vaultPath := getVaultPath()

		pw,err := readline.NewReadline("password: ", true, nil).Read()
		if err!=nil{fmt.Println(err); os.Exit(1)}
		defer pw.Dealloc()

		sess, err := core.LoadSession(vaultPath, pw)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		defer sess.Destroy()

		if len(os.Args) != 3 { 
			fmt.Println("Invalid arguments. Usage: shot 'piped | command-list'")
			os.Exit(1)
		}

		// go strings are immutable and os.Args are go strings. We cannot zero them out or deallocate.
		cmdArgs,err := tokenize(securemem.ToByteSlice([]byte(os.Args[2])))
		if err != nil {
			fmt.Println("Error while parsing arguments:", err)
			os.Exit(1)
		}

		err = processPipeline(sess, cmdArgs, bytes.NewReader(nil), os.Stdout, true)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

	case "info":
		vaultPath := getVaultPath()

		fileBytes, err := os.ReadFile(vaultPath)
		if err!=nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		var fileStruct core.File
		err = cmpck.Unmarshal(fileBytes, &fileStruct)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		var header core.UnmarshaledHeader
		err = cmpck.Unmarshal(fileStruct.Header, &header) // Copy the metadata of the file to the session.
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		printVaultInfo(&fileStruct, &header)

	default:
		// go strings are immutable and os.Args are go strings. We cannot zero them out or deallocate.
		var byteArgs = make([]*securemem.ByteSlice, 0, len(os.Args[1:]))
		for i:=1; i < len(os.Args); i++ {
			byteArgs = append(byteArgs, securemem.ToByteSlice([]byte(os.Args[i])))
		}

		err := processCommand(nil, bytes.NewReader(nil), os.Stdout, byteArgs)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
	}
}

func startShell(sess *core.Session) error {

	// Initialize readline
	rl := readline.Readline{
		Prompt:sess.Pwd+": ",
		Completer: &Completer{sess:sess},
	}
	defer rl.Dealloc() // Deallocate the history and other stuff readline accumulated

	for {
		// Set the prompt
		rl.SetPrompt(sess.Pwd+": ")

		// If an error happens with the readline, destroy the session.
		input, err := rl.Read()
		if err != nil {
			sess.Destroy()
			rl.Dealloc()
			return err
		}

		args, err := tokenize(input)
		if err != nil {
			input.Dealloc()
			fmt.Println(err)
			continue
		}
		
		input.Dealloc()

		if len(args) > 0 {
			switch string(string(args[0].Value.Bytes)) {
			case "exit":
				rl.Dealloc()
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

		err = processPipeline(sess, args, bytes.NewReader(nil), os.Stdout, true)
		if err != nil { fmt.Println(err); continue }
	}
}

func processPipeline(
	sess *core.Session, tokens []Token, stdin io.Reader, finalStdout io.Writer, toTerminal bool,
) (error) {

	if len(tokens) == 0 {return nil} // do nothing if no token is provided

	defer func(){
		// explicit deallocation after usage
		for _,token := range tokens { token.Value.Dealloc() }
	}()

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

	var prevStdoutBuf = &securemem.Buffer{} // the previous stdout buffer. It's used as stdin in the next command
	defer prevStdoutBuf.Dealloc()

	for i, commandArgs := range commandlist {
		if len(commandArgs) == 0 { continue }

		var buf = &securemem.Buffer{}

		// If we are at the last command, make the stdout the final stdout
		if i == len(commandlist)-1 {
			currentStdout = finalStdout
		// Else, make it a buffer
		} else {
			currentStdout = buf
		}

		// Process the substitutions and return an array of []byte as args
		args,err := processAllSubstitutions(sess, commandArgs)
		if err != nil {return err}
		defer func(){
			// deallocate args after usage
			for _,arg := range args { arg.Dealloc() }
		}()

		err = processCommand(sess, currentStdin, currentStdout, args)
		if err != nil { return err }

		// clear the previous stdout
		prevStdoutBuf.Dealloc()
		prevStdoutBuf = buf // make the prevStdout the stdout buffer

		currentStdin = buf // update stdin to the buffer. Things we write to currentStdout buf will be used as the stdin on the next command.
	}

	// If we are expected to write to the terminal, add a newline to the currentStdout.
	// readline will replace this newline with the prompt. Otherwise, it will replace the last line in stdout
	if toTerminal { currentStdout.Write([]byte("\n")) }

	return nil
}

var placeholderRegex = regexp.MustCompile(`\{\d+\}`) // Used to replace the placeholders in shortcuts

// Process command processes the given command and return the stdout
// Outputs will contain an extra newline character at the end
func processCommand(sess *core.Session, stdin io.Reader, stdout io.Writer, args []*securemem.ByteSlice) (error) {
	isOneshot := false

	// If no session exists, create one.
	if sess == nil {
		isOneshot = true

		passwd,err := readline.NewReadline("password: ", true, nil).Read()
		if err != nil {return err}
		defer passwd.Dealloc()

		vaultPath := getVaultPath()

		sess, err = core.LoadSession(vaultPath, passwd)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	shortcuts := getShortcuts(sess)

	if(isOneshot) { defer sess.Destroy() }

	// its safe to convert first argument to string as it's a non-secret
	switch string(args[0].Bytes) {
	case "put": // Add an entry with the value

		putArgs, err := getArgs(2, args[1:], stdin, true)
		if err != nil {return errors.New("Usage: put <epath> <value>\n"+err.Error())}
		defer func(){ for _,arg := range putArgs { arg.Dealloc() } }()

		err = sess.Put(string(putArgs[0].Bytes), []byte{}, putArgs[1])
		if err != nil { return err }
		err = sess.Save()
		if err != nil { return errors.New("Error while saving changes: "+err.Error()) }

		stdout.Write([]byte("inserted: "+string(putArgs[0].Bytes)))
		return nil
	
	case "mput":

		mputArgs, err := getArgs(3, args[1:], stdin, true)
		if err != nil { return errors.New("Usage: put <epath> <mtime> <value>\n"+err.Error()) }
		defer func(){ for _,arg := range mputArgs { arg.Dealloc() } }()

		var epath = string(mputArgs[0].Bytes)
		var newMtime = mputArgs[1] // Unix epoch in milliseconds
		var value = mputArgs[2]

		newMtimeInt, err := strconv.ParseUint(string(newMtime.Bytes), 10, 64)
		if err != nil { return errors.New("invalid mtime format") }

		var newMtimeBytes = make([]byte, 8)
		binary.LittleEndian.PutUint64(newMtimeBytes, newMtimeInt)

		err = sess.Put(epath, newMtimeBytes, value)
		if err != nil { return err }
		err = sess.Save()
		if err != nil { return errors.New("Error while saving changes: "+err.Error()) }

		stdout.Write([]byte("inserted: "+epath))
		return nil

	case "update":
		updateArgs, err := getArgs(2, args[1:], stdin, true)
		if err != nil { return errors.New("Usage: update <epath> <value>\n"+err.Error()) }
		defer func(){ for _,arg := range updateArgs { arg.Dealloc() } }()

		var epath = string(updateArgs[0].Bytes)
		var value = updateArgs[1]

		fmt.Println("confirm the update attempt:",epath)
		input,err := readline.NewReadline("(y/n): ", false, nil).Read()
		if err != nil {return err}
		defer input.Dealloc()

		if string(input.Bytes) == "y" {
			err := sess.Update(epath, value)
			if err != nil { return err }
			err = sess.Save()
			if err != nil { return errors.New("Error while saving changes: "+err.Error()) }

			stdout.Write([]byte("updated: "+epath))
			return nil

		} else { stdout.Write([]byte("update attempt cancelled\n")); return nil }
	
	case "mtime":

		mtimeArgs, err := getArgs(1, args[1:], stdin, false)
		if err != nil { return errors.New("Usage: mtime <epath>\n"+err.Error()) }
		defer func(){ for _,arg := range mtimeArgs { arg.Dealloc() } }()

		var epath = string(mtimeArgs[0].Bytes)

		// epath must be a file path string.
		if !core.PathRegexp.MatchString(epath) || strings.HasSuffix(epath, "/") {
			return errors.New("key must be a filepath string")
		}
		// If it does not have slash at the start, join it to the current working directory.
		if !strings.HasPrefix(epath, "/") { epath = path.Join(sess.Pwd, epath) }

		entry, exists := sess.EntryMap[string(epath)]
		if !exists { return errors.New(string(epath)+": Entry does not exist")}

		mtimeInt := binary.LittleEndian.Uint64(entry.MTime)

		stdout.Write(fmt.Appendf(nil, "%v", mtimeInt))
		return nil
		
	case "get": // Get an entry's value
		getArgs, err := getArgs(1, args[1:], stdin, false)
		if err != nil { return errors.New("Usage: get <epath>\n"+err.Error()) }
		defer func(){ for _,arg := range getArgs { arg.Dealloc() } }()

		var epath = getArgs[0]
		val, err := sess.Get(string(epath.Bytes))
		defer val.Dealloc()
		if err != nil { return err }

		stdout.Write(val.Bytes)

		return nil

	case "mv":
		mvArgs, err := getArgs(2, args[1:], stdin, false)
		if err != nil { return errors.New("Usage: mv <old> <new>\n"+err.Error()) }
		defer func(){ for _,arg := range mvArgs { arg.Dealloc() } }()

		var oldpath = string(mvArgs[0].Bytes)
		var newpath = string(mvArgs[1].Bytes)

		err = sess.Mv(oldpath, newpath)
		if err != nil { return err }

		err = sess.Save()
		if err != nil {
			return errors.New("Error while saving changes: "+err.Error())
		}

		stdout.Write([]byte("key moved to the new destination"))
		return  nil

	case "rm": // Remove a single entry
		rmArgs, err := getArgs(1, args[1:], stdin, false)
		if err != nil { return errors.New("Usage: rm <epath>\n"+err.Error()) }
		defer func(){ for _,arg := range rmArgs { arg.Dealloc() } }()

		var epath = string(rmArgs[0].Bytes)

		fmt.Println("confirm the deletion attempt:",epath)
		input,err := readline.NewReadline("(y/n): ", false, nil).Read()
		if err != nil {return err}
		defer input.Dealloc()

		if string(input.Bytes) == "y" {
			err := sess.Rm(string(epath))
			if err != nil { return err }

			err = sess.Save()
			if err != nil {
				return errors.New("Error while saving changes: "+err.Error())
			}

			stdout.Write([]byte(epath+" deleted"))
			return nil
		
		} else { stdout.Write([]byte("deletion attempt cancelled")); return nil }

		
	case "rmd": // Remove a directory
		rmdArgs, err := getArgs(1, args[1:], stdin, false)
		if err != nil { return errors.New("Usage: rmd <dpath>\n"+err.Error()) }
		defer func(){ for _,arg := range rmdArgs { arg.Dealloc() } }()

		var dpath = string(rmdArgs[0].Bytes)

		fmt.Println("confirm the deletion attempt:",dpath)
		input,err := readline.NewReadline("(y/n): ", false, nil).Read()
		if err != nil {return err}
		defer input.Dealloc()

		if string(input.Bytes) == "y" {
			err := sess.Rmd(dpath)
			if err != nil { return err }

			err = sess.Save()
			if err != nil {
				return errors.New("Error while saving changes: "+err.Error())
			}

			stdout.Write([]byte(dpath+" deleted"))
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
			dirs, entries, err = sess.Ls(string(args[1].Bytes))
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
		
		stdout.Write(s.Bytes()[:s.Len()-1]) // ignore the last char (newline)
		return nil

	// ls does not accept stdin as argument
	case "lsall":
		var entries []string
		var err error

		if len(args) == 1 {
			entries, err = sess.Lsall("")
			if err != nil { return err }

		} else if len(args) == 2 {
			entries, err = sess.Lsall(string(args[1].Bytes))
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
		
		stdout.Write(s.Bytes()[:s.Len()-1]) // ignore the last char (newline)
		return nil

	// cd does not support stdin as argument
	case "cd":
		if len(args) == 1 {
			err := sess.Cd("")
			if err != nil { return err }

		} else if len(args) == 2 {
			err := sess.Cd(string(args[1].Bytes)) // its okay to convert it to string as it's non-secret
			if err != nil { return err }

		} else { return errors.New("Usage: cd <dpath>") }

		return nil

	case "exec":
		if len(args) < 2 { return errors.New("Usage: exec <shell-command> <args>") }

		// Create the command. This creates immutable strings from arguments. We must not pass secrets as arguments in here.
		cmdArgs := make([]string, 0, len(args[1:]))
		for i:=1; i < len(args); i++ {
			cmdArgs = append(cmdArgs, string(args[i].Bytes))
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
		evalArgs, err := getArgs(1, args[1:], stdin, false)
		if err != nil { return errors.New("Usage: eval <pipeline>\n"+err.Error()) }
		defer func(){ for _,arg := range evalArgs { arg.Dealloc() } }()

		var cmd = evalArgs[0]
		cmdArgs, err := tokenize(cmd)
		if err != nil { return err }

		return processPipeline(sess, cmdArgs, bytes.NewReader(nil), stdout, false)

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

			err = processPipeline(sess, cmd, bytes.NewReader(line), stdout, false)
			if err != nil {return err}
		}

		return nil
	
	case "senv":
		senvArgs, err := getArgs(2, args[1:], stdin, false)
		if err != nil {
			return errors.New("Usage: senv <name> <value>\n"+err.Error())
		}
		defer func(){ for _,arg := range senvArgs { arg.Dealloc() } }()

		err = sess.Senv(string(senvArgs[0].Bytes), senvArgs[1]) // Senv zeroes the value
		if err != nil { return err }

		return nil

	case "genv":
		genvArgs, err := getArgs(1, args[1:], stdin, false)
		if err != nil { return errors.New("Usage: genv <name>\n"+err.Error()) }
		defer func(){ for _,arg := range genvArgs { arg.Dealloc() } }()

		val,err := sess.Genv(string(genvArgs[0].Bytes))
		defer val.Dealloc()
		if err!=nil{return err}

		stdout.Write(val.Bytes)

		return nil

	case "renv":
		renvArgs, err := getArgs(1, args[1:], stdin, false)
		if err != nil { return errors.New("Usage: renv <name>\n"+err.Error()) }
		defer func(){ for _,arg := range renvArgs { arg.Dealloc() } }()

		sess.Renv(string(renvArgs[0].Bytes))

		return nil

	default:
		shortcutVal := shortcuts[string(args[0].Bytes)] // we can convert it to string as it's a non-secret

		expanded := bytes.Clone(shortcutVal) // we clone it to not modify the actual shortcutVal

		// If the shortcut has a value
		if len(shortcutVal) > 0 {
			// Replace placeholders {1}, {2}, etc. with provided arguments.
			for i := 1; i < len(args); i++ {
				placeholder := fmt.Appendf(nil, "{%d}", i)
				expanded = bytes.ReplaceAll(expanded, placeholder, args[i].Bytes)
			}

			// Remove the remaining placeholders. This removes unused ones when no argument is passed etc.
			expanded = placeholderRegex.ReplaceAll(expanded, []byte{})

			// Parse the expanded shortcut string into arguments
			expandedArgs, err := tokenize(securemem.ToByteSlice(expanded)) // expanded may contain sensitive arguments here. We zero it out in ToByteSlice
			if err != nil { return fmt.Errorf("shortcut expansion error: %w", err) }

			return processPipeline(sess, expandedArgs, stdin, stdout, false)
		}
	}

	return errors.New("unknown command: '"+string(args[0].Bytes)+"'")
}

func getShortcuts(sess *core.Session) (map[string][]byte) {
	var shortcuts = make(map[string][]byte)

	for epath := range sess.EntryMap {
		// If the key is the top level key in the shortcut dir, add it to the shortcuts.
		if strings.HasPrefix(epath, "/.shortcut/") {
			shortcut,_ := strings.CutPrefix(epath, "/.shortcut/")
			if !strings.Contains(shortcut, "/") {
				shortcutVal, _ := sess.Get(epath) // they are non-secret info. We can clone them to go heap
				shortcuts[shortcut] = bytes.Clone(shortcutVal.Bytes)
				shortcutVal.Dealloc()
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

// get the arguments from passed positional arguments and stdin. Give error if it's not enough to create args in requiredCount.
// Ask for user input if given arguments does not match the required count while ask is true
func getArgs(requiredCount int, givenargs []*securemem.ByteSlice, stdin io.Reader, ask bool,
) (totalargs []*securemem.ByteSlice, err error) {

	for _,arg := range givenargs {
		totalargs = append(totalargs, arg)
	}

	// If argument count exceeds the requiredCount, give error
	if len(totalargs) > requiredCount {
		return totalargs, errors.New("passed argument count exceeds the required count")
	
	// If it matches the count exactly, return it.
	} else if len(totalargs) == requiredCount {
		return totalargs, nil

	// Else, split stdin by newlines and add them as args until requiredCount is satisfied. If there is still more '\n' separated arguments left in stdinArgs, combine them in the last totalargs argument.
	} else {
		requiredArgsLeft := requiredCount - len(totalargs)
		var stdinArgs [][]byte
		// Only split stdinArgs if stdinBytes is not empty. If we don't do that, bytes.Split returns stdinArgs with one empty slice item.
		stdinBytes,err := io.ReadAll(stdin) // zero the stdin bytes
		defer securemem.ZeroBytes(stdinBytes)
		if err != nil {return totalargs, err}

		if len(stdinBytes) > 0 {
			stdinArgs = bytes.Split(stdinBytes, []byte{'\n'}) // bytes.Split does not copy the bytes
		}

		// Give error if stdinArgs has not enough arguments to satisfy requiredArgsLeft
		if !ask && len(stdinArgs) < requiredArgsLeft {return totalargs, errors.New("not enough arguments provided")}

		// Take what's available from stdinArgs
		argsToTake := requiredArgsLeft
		if len(stdinArgs) < argsToTake { argsToTake = len(stdinArgs) }

		// Append those arguments to the totalargs list
		for i := range argsToTake { totalargs = append(totalargs, securemem.ToByteSlice(stdinArgs[i])) }

		// Append the leftover stdinArgs to the last totalargs argument
		if len(stdinArgs) > requiredArgsLeft {
			lastArg := totalargs[len(totalargs)-1]
			lastArgBuf := &securemem.Buffer{} // Create a buffer
			lastArgBuf.Write(lastArg.Bytes) // write the last arg to it
			lastArg.Dealloc() // deallocate the last argument

			for i,argLeft := range stdinArgs[requiredArgsLeft:] {
				// append argLeft to lastArgBuf
				lastArgBuf.Write(argLeft)
				// if it's not the last argument in stdinArgs[requiredArgsLeft:], add a '\n'. Because we split by it above
				if i < len(stdinArgs[requiredArgsLeft:])-1 {
					lastArgBuf.WriteByte('\n')
				}
			}

			// Replace the last argument with lastArgBuf
			totalargs[len(totalargs)-1] = lastArgBuf.Bytes()
		}
	}

	// Ask until required argument count is satisfied
	if ask && requiredCount-len(totalargs) > 0 {
		// Get argument until requiredCount gets equal to len(totalargs)
		for requiredCount-len(totalargs) > 0 {

			arg,err := readline.NewReadline(fmt.Sprintf("arg-%v: ",len(totalargs)+1), true, nil).Read()
			if err!=nil{return totalargs, err}

			totalargs = append(totalargs, arg)
		}
	}

	return totalargs, nil
}

////////////////////////////////////////////////////////

func processAllSubstitutions(sess *core.Session, tokens []Token) ([]*securemem.ByteSlice, error) {
	var expanded []*securemem.ByteSlice

	for _,token := range tokens {
		exp, err := processSubstitution(sess, token)
		if err != nil { return expanded, err }
		expanded = append(expanded, exp)
	}
	return expanded, nil
}

// Get the substitution token, tokenize it's value, process the pipeline and return the value
func processSubstitution(sess *core.Session, input Token) (*securemem.ByteSlice, error) {
	if input.Type == SUBSTITUTION {

		cmdArgs,err := tokenize(input.Value)
		// deallocate the tokens after usage
		defer func(){ for _,arg := range cmdArgs { arg.Value.Dealloc() } }()
		if err != nil {return &securemem.ByteSlice{Dealloc:func()error{return nil}}, err}

		var buf = &securemem.Buffer{}
		err = processPipeline(sess, cmdArgs, bytes.NewReader(nil), buf, false)
		if err != nil { return &securemem.ByteSlice{Dealloc:func()error{return nil}}, err }

		return buf.Bytes(),nil

	} else { return input.Value, nil }
}

///////////////////////////////////////////////////////

type Completer struct { sess *core.Session }

// Do implements the readline.AutoCompleter interface
func (v *Completer) Get(line *securemem.ByteSlice, pos int) (completionOpts [][]byte, deleteChars int) {
	lineStr := string(line.Bytes[:pos]) // Get the everything until the cursor
	
	// Split by space to figure out if we are completing a command or a path
	args := strings.Split(lineStr, " ")

	// If we are typing the first word, complete the command itself (lineStr is the entire argument)
	if len(args) <= 1 {
		cmds := []string{
			"help", "exit",
			"put", "mput", "get", "rm", "update", "mtime",
			"mv", "cd", "rmd", "ls", "lsall",
			"iter", "exec", "eval",
		}
		for _, cmd := range cmds {
			if strings.HasPrefix(cmd, lineStr) {
				// Append the command to the completionOpts
				completionOpts = append(completionOpts, []byte(cmd))
			}
		}
		// Return the completion options
		return completionOpts, len(lineStr) // delete lineStr and replace them with completionOpts
	}

	// If there are more than one argument, we are typing arguments of the command (file/folder paths)

	cmd := args[0]
	lastArg := args[len(args)-1] // the argument we gonna replace. It's not the last argument in the whole line but the last argument of the line until the cursor

	dirsOnly := false
	switch cmd {
	case "cd", "rmd", "ls", "lsall":
		dirsOnly = true
	case "get", "rm", "update", "mv", "mtime", "mput", "put":
		dirsOnly = false
	// For other things like shortcuts, complete everything
	default: dirsOnly = false
	}

	// Fetch dynamic completions. This will get results in path
	// we should delete only the entry part after the last slash
	completionOpts = v.getCompletions(lastArg, dirsOnly)

	partToDelete := 0
	lastSlashIdx := strings.LastIndex(lastArg, "/")
	// if slash exists and there are chars after the last slash 
	if lastSlashIdx != -1 && lastSlashIdx+1 < len(lastArg) {
		partToDelete = len(lastArg[lastSlashIdx+1:])
	// if slash does not exists, delete everything
	} else if lastSlashIdx == -1 {
		partToDelete = len(lastArg)
	}

	// Return the completion possibilities
	return completionOpts, partToDelete
}

func (v *Completer) getCompletions(arg string, dirsOnly bool) [][]byte {
	dirPath := ""
	prefixInDir := "" // the entry or dir's prefix in the dirsPath. Like foo in /dir/foo
	
	// Extract the directory portion of the string
	idx := strings.LastIndex(arg, "/");
	if idx != -1 {
		dirPath = arg[:idx]
		if idx+1 < len(arg) { prefixInDir = arg[idx+1:] }
		if dirPath == "" { dirPath = "/"  } // For absolute paths (like typing "/folder")

	// if there is no slash, make the argument prefixInDir
	} else { prefixInDir = arg }

	// get everything in the dir
	dirs, entries, err := v.sess.Ls(dirPath)
	if err != nil { return nil }

	var results [][]byte

	// Add subdirectories (always append trailing slash so we can keep pressing TAB)
	for _, d := range dirs {
		// only append if dir has prefixInDir as prefix
		if strings.HasPrefix(d, prefixInDir) {
			results = append(results,[]byte(d+"/"))
		}
	}

	// Add files if not restricted to directories
	if !dirsOnly {
		for _, e := range entries {
			// only append if entry has prefixInDir as prefix
			if strings.HasPrefix(e, prefixInDir) {
				results = append(results, []byte(e))
			}
		}
	}
	
	return results
}
