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

		pw := getPassword(nil, "Set vault password: ")
		defer securemem.ZeroBytes(pw)

		pwAgain := getPassword(nil, "Repeat password: ")
		defer securemem.ZeroBytes(pwAgain)

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

		oldpw := getPassword(nil, "Old password: ")
		defer securemem.ZeroBytes(oldpw)

		newpw := getPassword(nil, "New password: ")
		defer securemem.ZeroBytes(newpw)

		newpwagain := getPassword(nil, "Retype password: ")
		defer securemem.ZeroBytes(newpwagain)

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

		pw := getPassword(nil, "Vault password: ")
		defer securemem.ZeroBytes(pw)

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

		pw := getPassword(nil, "Vault password: ")
		defer securemem.ZeroBytes(pw)

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

		cmdArgs,err := parseArgs([]byte(os.Args[2]))
		if err != nil {
			fmt.Println("Error while parsing arguments:", err)
			os.Exit(1)
		}

		result,resDealloc, err := processCommandlist(sess, cmdArgs, []byte{}, true)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		defer resDealloc()

		fmt.Printf("%s", result)

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

		result, resultDealloc, err := processCommand(nil, []byte{}, byteArgs, true)
		if err != nil {
			fmt.Println("Error: "+err.Error())
			os.Exit(1)
		}
		defer resultDealloc()

		fmt.Printf("%s", result)
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

		args, err := parseArgs([]byte(input))
		if err != nil {
			fmt.Println(err)
			continue
		}

		if len(args) > 0 {
			switch string(args[0]) {
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

		result, resultDealloc, err := processCommandlist(sess, args, []byte{}, true)
		if err != nil { fmt.Println(err); continue }

		fmt.Printf("%s\n", result)
		resultDealloc() // Clean the result from memory after printing
		
	}
}

func processCommandlist(
	sess *core.Session, args [][]byte, currentStdin []byte, isPipelineLastCommand bool,
) ([]byte, func(), error) {
	// split arguments using "|"
	var commandlist [][][]byte

	var command [][]byte
	for i,arg := range args {
		// If we arrive to the pipe character, add the command slice generated so far to commandList
		if string(arg) == "|" {
			commandlist = append(commandlist, command)
			command = [][]byte{}
			continue
		}

		command = append(command, arg)

		// If this is the end of the arguments, add the command slice generated so far to commandList
		if i == len(args)-1 {
			commandlist = append(commandlist, command)
		}

	}

	var result []byte
	var chainDealloc []func()

	cleanupAll := func() {
		for _,deallocator := range chainDealloc { if deallocator!= nil {deallocator()} }
    }

	for i, commandArgs := range commandlist {
		if len(commandArgs) == 0 { continue }

		// If it's the last command in the commandlist and the caller says it's the last command in outer pipeline (required for exec in shortcuts etc)
		isLastCommand := i == len(commandlist)-1 && isPipelineLastCommand

		res,resDealloc, err := processCommand(sess, currentStdin, commandArgs, isLastCommand)
		if err != nil { return nil,cleanupAll, err }

		chainDealloc = append(chainDealloc, resDealloc)
		
		currentStdin = res

		// If we are at the end of the commandList, pass the res to the final result.
		if i == len(commandlist)-1 { result = res }

	}

	return result, cleanupAll, nil
}

var placeholderRegex = regexp.MustCompile(`\{\d+\}`) // Used to replace the placeholders in shortcuts

// Process command processes the given command and return the stdout
func processCommand(sess *core.Session, pipeStdin []byte, args [][]byte, lastCommand bool) ([]byte, func(), error) {
	isOneshot := false

	// If no session exists, create one.
	if sess == nil {
		isOneshot = true

		passwd := getPassword(sess, "Vault password: ")
		defer securemem.ZeroBytes(passwd)

		vaultPath := getVaultPath()

		var err error
		sess, err = core.LoadSession(vaultPath, passwd)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	args,deallocSubs,err := processCmdSubstitutions(sess, args)
	defer deallocSubs() // deallocate the substitution results at the end via the deallocation chain func
	if err != nil {return []byte{}, func(){}, err}

	shortcuts := getShortcuts(sess)

	if(isOneshot) { defer sess.Destroy() }

	switch string(args[0]) {
	case "put": // Add an entry with the value

		putArgs, err := getArgsFromArgsNStdin(sess, 2, args[1:], pipeStdin, true)
		if err != nil {
			return nil, func(){}, errors.New("Usage: put <epath> <value>\n"+err.Error())
		}

		err = sess.Put(string(putArgs[0]), []byte{}, putArgs[1])
		if err != nil { return nil, func(){}, err }
		err = sess.Save()
		if err != nil { return nil, func(){}, errors.New("Error while saving changes: "+err.Error()) }
		return []byte("inserted: "+string(putArgs[0])+"\n"), func(){}, nil
	
	case "mput":

		mputArgs, err := getArgsFromArgsNStdin(sess, 3, args[1:], pipeStdin, true)
		if err != nil {
			return []byte{},func(){}, errors.New("Usage: put <epath> <mtime> <value>\n"+err.Error())
		}

		var epath = mputArgs[0]
		var newMtime = mputArgs[1] // Unix epoch in milliseconds
		var value = mputArgs[2]

		newMtimeInt, err := strconv.ParseUint(string(newMtime), 10, 64)
		if err != nil { return nil,func(){}, errors.New("invalid mtime format") }

		var newMtimeBytes = make([]byte, 8)
		binary.LittleEndian.PutUint64(newMtimeBytes, newMtimeInt)

		err = sess.Put(string(epath), newMtimeBytes, value)
		if err != nil { return nil,func(){}, err }
		err = sess.Save()
		if err != nil { return []byte{},func(){}, errors.New("Error while saving changes: "+err.Error()) }
		return []byte("inserted: "+string(epath)+"\n"),func(){}, nil

	case "update":
		updateArgs, err := getArgsFromArgsNStdin(sess, 2, args[1:], pipeStdin, true)
		if err != nil {
			return nil,func(){}, errors.New("Usage: update <epath> <value>\n"+err.Error())
		}

		var epath = updateArgs[0]
		var value = updateArgs[1]

		fmt.Println("confirm the update attempt:",string(epath))
		input := getPassword(sess, "(y/n): ")

		if string(input) == "y" {
			err := sess.Update(string(epath), value)
			if err != nil { return nil,func(){}, err }
			err = sess.Save()
			if err != nil { return nil, func(){}, errors.New("Error while saving changes: "+err.Error()) }
			return []byte("updated: "+string(epath)+"\n"),func(){}, nil

		} else { return []byte("Update attempt cancelled\n"),func(){}, nil }
	
	case "mtime":

		mtimeArgs, err := getArgsFromArgsNStdin(sess, 1, args[1:], pipeStdin, false)
		if err != nil {
			return nil,func(){}, errors.New("Usage: mtime <epath>\n"+err.Error())
		}

		var epath = string(mtimeArgs[0])

		// epath must be a file path string.
		if !core.PathRegexp.MatchString(epath) || strings.HasSuffix(epath, "/") {
			return nil,func(){}, errors.New("key must be a filepath string")
		}
		// If it does not have slash at the start, join it to the current working directory.
		if !strings.HasPrefix(epath, "/") { epath = path.Join(sess.Pwd, epath) }

		entry, exists := sess.EntryMap[string(epath)]
		if !exists { return nil,func(){}, errors.New(string(epath)+": Entry does not exist")}

		mtimeInt := binary.LittleEndian.Uint64(entry.MTime)

		return fmt.Appendf(nil, "%v", mtimeInt),func(){}, nil
		
	case "get": // Get an entry's value
		getArgs, err := getArgsFromArgsNStdin(sess, 1, args[1:], pipeStdin, false)
		if err != nil {
			return nil,func(){}, errors.New("Usage: get <epath>\n"+err.Error())
		}

		var epath = getArgs[0]
		val,deallocVal, err := sess.Get(string(epath))
		if err != nil { return nil,func(){},err }

		return val,deallocVal, nil

	case "mv":
		mvArgs, err := getArgsFromArgsNStdin(sess, 2, args[1:], pipeStdin, false)
		if err != nil {
			return nil,func(){},errors.New("Usage: mv <old> <new>\n"+err.Error())
		}

		var oldpath = string(mvArgs[0])
		var newpath = string(mvArgs[1])

		err = sess.Mv(oldpath, newpath)
		if err != nil { return nil,func(){},err }

		err = sess.Save()
		if err != nil {
			return nil,func(){}, errors.New("Error while saving changes: "+err.Error())
		}

		return []byte("Key moved to the new destination\n"),func(){}, nil

	case "rm": // Remove a single entry
		rmArgs, err := getArgsFromArgsNStdin(sess, 1, args[1:], pipeStdin, false)
		if err != nil {
			return nil,func(){}, errors.New("Usage: rm <epath>\n"+err.Error())
		}

		var epath = string(rmArgs[0])

		fmt.Println("confirm the deletion attempt:",epath)
		input := getPassword(sess, "(y/n): ")

		if string(input) == "y" {
			err := sess.Rm(string(epath))
			if err != nil { return nil,func(){}, err }

			err = sess.Save()
			if err != nil {
				return nil,func(){}, errors.New("Error while saving changes: "+err.Error())
			}

			return []byte(epath+" deleted\n"),func(){}, nil
		
		} else { return []byte("deletion attempt cancelled"),func(){}, nil }

		
	case "rmd": // Remove a directory
		rmdArgs, err := getArgsFromArgsNStdin(sess, 1, args[1:], pipeStdin, false)
		if err != nil { return nil,func(){}, errors.New("Usage: rmd <dpath>\n"+err.Error()) }

		var dpath = string(rmdArgs[0])

		fmt.Println("confirm the deletion attempt:",dpath)
		input := getPassword(sess, "(y/n): ")

		if string(input) == "y" {
			err := sess.Rmd(dpath)
			if err != nil { return nil,func(){}, err }

			err = sess.Save()
			if err != nil {
				return nil,func(){}, errors.New("Error while saving changes: "+err.Error())
			}

			return []byte(dpath+" deleted\n"),func(){}, nil

		} else { return []byte("deletion attempt cancelled"),func(){}, nil }

	// ls does not accept stdin as argument
	case "ls":
		var dirs []string
		var entries []string
		var err error

		if len(args) == 1 {
			dirs, entries, err = sess.Ls("")
			if err != nil { return nil, func(){}, err }

		} else if len(args) == 2 {
			dirs, entries, err = sess.Ls(string(args[1]))
			if err != nil { return nil,func(){}, err }

		} else { return nil,func(){}, errors.New("Usage: ls <dpath>") }

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
		
		return s.Bytes(),func(){}, nil

	// ls does not accept stdin as argument
	case "lsall":
		var entries []string
		var err error

		if len(args) == 1 {
			entries, err = sess.Lsall("")
			if err != nil { return nil,func(){}, err }

		} else if len(args) == 2 {
			entries, err = sess.Lsall(string(args[1]))
			if err != nil { return nil,func(){}, err }

		} else { return nil,func(){}, errors.New("Usage: lsall <dpath>") }

		// Sort the entries slice
		sort.Slice(entries, func(i, j int) bool {
			return entries[i] < entries[j]
		})

		var s bytes.Buffer
		for _,entry := range entries {
			s.WriteString(entry)
			s.WriteString("\n")
		}
		
		return s.Bytes(),func(){}, nil

	// cd does not support stdin as argument
	case "cd":
		if len(args) == 1 {
			err := sess.Cd("")
			if err != nil { return nil,func(){}, err }

		} else if len(args) == 2 {
			err := sess.Cd(string(args[1]))
			if err != nil { return nil,func(){}, err }

		} else { return nil, func(){}, errors.New("Usage: cd <dpath>") }

		return nil, func(){}, nil

	case "exec":
		if len(args) < 2 { return nil, func(){}, errors.New("Usage: exec <shell-command> <args>") }

		// Create the command
		cmdArgs := make([]string, 0, len(args[1:]))
		for i:=1; i < len(args); i++ {
			cmdArgs = append(cmdArgs, string(args[i]))
		}

		shellCmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)

		// If there is pipe stdin, pass it to the shellCmd's stdin
		if len(pipeStdin) > 0 { shellCmd.Stdin = bytes.NewReader(pipeStdin) }

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
    	if err != nil { return outBuf.Bytes(),func(){}, err } // Return both the captured output and the error

		return outBuf.Bytes(),func(){}, nil

	case "eval":
		evalArgs, err := getArgsFromArgsNStdin(sess, 1, args[1:], pipeStdin, false)
		if err != nil { return nil,func(){}, errors.New("Usage: eval <pipeline>\n"+err.Error()) }

		var cmd = evalArgs[0]
		cmdArgs, err := parseArgs(cmd)
		if err != nil { return nil,func(){}, err }

		return processCommandlist(sess, cmdArgs, []byte{}, lastCommand)

	// Read the stdin, split it with the given delimiter, iterate through them and execute the provided command in every iteration
	case "iter":
		if len(args) != 2 { return nil,func(){}, errors.New("Usage: iter <pipeline>")}
		
		lines := bytes.Split(pipeStdin, []byte{'\n'})

		var finalResult []byte
		var deallocateFn func()
		for _, line := range lines {
			// Skip empty slices resulting from trailing newline characters
			if len(bytes.TrimSpace(line)) == 0 { continue }

			cmd, err := parseArgs(args[1])
			if err != nil {return nil,func(){}, err}

			result,deallocFn, err := processCommandlist(sess, cmd, line, lastCommand)
			deallocateFn = deallocFn
			if err != nil {return nil,func(){}, err}
			finalResult = append(finalResult, result...)
		}

		return finalResult,deallocateFn, nil
	
	case "senv":
		senvArgs, err := getArgsFromArgsNStdin(sess, 2, args[1:], pipeStdin, false)
		if err != nil {
			return nil,func(){}, errors.New("Usage: senv <name> <value>\n"+err.Error())
		}

		err = sess.Senv(string(senvArgs[0]), senvArgs[1]) // Senv zeroes the value
		if err != nil { return nil,func(){}, err }

		return nil,func(){}, nil

	case "genv":
		genvArgs, err := getArgsFromArgsNStdin(sess, 1, args[1:], pipeStdin, false)
		if err != nil { return nil,func(){}, errors.New("Usage: genv <name>\n"+err.Error()) }

		val,dealloc,err := sess.Genv(string(genvArgs[0]))
		if err!=nil{return nil,func(){}, err}

		return val, dealloc, nil

	case "renv":
		renvArgs, err := getArgsFromArgsNStdin(sess, 1, args[1:], pipeStdin, false)
		if err != nil { return nil,func(){}, errors.New("Usage: renv <name>\n"+err.Error()) }

		sess.Renv(string(renvArgs[0]))

		return nil,func(){}, nil

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
			expandedArgs, err := parseArgs([]byte(expanded))
			if err != nil {
				return nil,func(){}, fmt.Errorf("Shortcut expansion error: %w", err)
			}

			return processCommandlist(sess, expandedArgs, pipeStdin, lastCommand)
		}
	}

	return nil,func(){}, errors.New("Unknown command: '"+string(args[0])+"'")
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

// getPassword prompts user to give an input. The written text will not shown.
func getPassword(sess *core.Session, prompt string) []byte {

	fmt.Fprintf(os.Stderr, "%s", prompt)

	// Get the old terminal state
	fd := int(os.Stdin.Fd())
	oldState, err := term.GetState(fd)
	if err != nil {
		fmt.Println("\nError reading state:", err)
		if sess != nil { sess.Destroy() }
		os.Exit(1)
	}
	// Catch the interrupt signal and safely restore echo
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		term.Restore(fd, oldState)
		if sess != nil { sess.Destroy() }
		os.Exit(1)
	}()

	input, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("\nError reading input:", err)
		if sess != nil { sess.Destroy() }
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr)
	return input
}

// get the arguments from passed arguments and stdin. Give error if it's not enough to create args in requiredCount.
// Ask for user input if given arguments does not match the required count and ask is true
func getArgsFromArgsNStdin(
	sess *core.Session, requiredCount int, givenargs [][]byte, stdin []byte, ask bool,
) (totalargs [][]byte, err error) {

	for _,arg := range givenargs {
		totalargs = append(totalargs, arg)
	}

	// If argument count exceeds the requiredCount, give error
	if len(totalargs) > requiredCount {
		return nil, errors.New("passed argument count exceeds the required count")
	
	// If it matches the count exactly, return it.
	} else if len(totalargs) == requiredCount {
		return totalargs, nil

	// Else, split stdin by newlines and add them as args until requiredCount is satisfied. If there is still more '\n' separated arguments left in stdinArgs, combine them in the last totalargs argument.
	} else {
		requiredArgsLeft := requiredCount - len(totalargs)
		var stdinArgs [][]byte
		// Only split stdinArgs if stdin is not empty. If we don't do that, bytes.Split returns stdinArgs with one empty slice item.
		if len(stdin) > 0 {
			stdinArgs = bytes.Split(stdin, []byte{'\n'})
		}

		// Give error if stdinArgs has not enough arguments to satisfy requiredArgsLeft
		if !ask && len(stdinArgs) < requiredArgsLeft {return nil, errors.New("not enough arguments provided")}

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
			arg := getPassword(sess, fmt.Sprintf("Arg-%v:", len(totalargs)))
			totalargs = append(totalargs, arg)
		}
	}

	return totalargs, nil
}

func processCmdSubstitutions(sess *core.Session, args [][]byte) ([][]byte,func(), error) {
	var expanded [][]byte
	var deallocators []func()

	cleanupAll := func() {
		for _,deallocator := range deallocators { if deallocator!= nil {deallocator()} }
    }

	for _, arg := range args {
		exp,dealloc, err := processSubstitution(sess, arg)
		deallocators = append(deallocators, dealloc) // chain deallocators
		if err != nil { return nil,cleanupAll, err }
		expanded = append(expanded, exp)
	}
	return expanded, cleanupAll, nil
}

func processSubstitution(sess *core.Session, input []byte) ([]byte,func(), error) {
	if bytes.HasPrefix(input, []byte("$(")) && bytes.HasSuffix(input, []byte(")")) {
		cmdArgsStr := input[2:len(input)-1]

		cmdArgs,err := parseArgs(cmdArgsStr)
		if err != nil {return nil,func(){}, err}

		res,dealloc, err := processCommandlist(sess, cmdArgs, []byte{}, false)
		if err != nil { return nil,func(){}, err }

		return res,dealloc,nil

	} else { return input,func(){securemem.ZeroBytes(input)}, nil }
}

// parseArgs splits the input into arguments where things in quotes and command substitutions considered one argument.
func parseArgs(input []byte) ([][]byte, error) {
	// Trim whitespace
	input = bytes.TrimSpace(input)

	var args [][]byte
	var arg bytes.Buffer

	inQuote := rune(0)
	escaped := false

	for i := 0; i < len(input); i++ {
		r := rune(input[i])

		// If the element is escaped, write it directly to arg, disable escaping and continue.
		if escaped {
			switch r {
			case 'n':
				arg.WriteRune('\n')
			case 't':
				arg.WriteRune('\t')
			case 'r':
				arg.WriteRune('\r')
			default:
				arg.WriteRune(r)
			}
			escaped = false
			continue
		}

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

		// Get $(...) as a whole argument
		// TODO: Improve this. It lacks proper quote handling and escapes
		if r == '$' && i+1 < len(input) && input[i+1] == '(' {
			parenCount := 1

			j := i+2 // the position of the first char in $()

            // Find the matching closing parenthesis
            for ; j < len(input); j++ {
				// Skip the escape characters
                if input[j] == '\\' && j+1 < len(input) { j++; continue }

				// Handle with nested parenthesis
                if input[j] == '(' {
                    parenCount++
                } else if input[j] == ')' {
                    parenCount--
					// break the loop when we reach to the parenthesis closing ours
                    if parenCount == 0 { break }
                }
            }

            if parenCount != 0 { return nil, fmt.Errorf("unclosed $() command substitution") }

			arg.Write(input[i:j+1]) // Include everything from $( to ) including the last parenthesis

            i = j // Advance the index past the closing ')'
			// finish and append the arg
			args = append(args, bytes.Clone(arg.Bytes()))
			arg.Reset()
            continue
		}

		if r == '"' || r == '\'' { inQuote=r; continue }

		if r == ' ' || r == '\t' || r == '\n' {
			if arg.Len() > 0 {
				args = append(args, bytes.Clone(arg.Bytes())) // create a copy of arg.Bytes(), or arg.Reset will zero the value out
				arg.Reset()
			}
			continue
		}

		arg.WriteRune(r)
	}

	if inQuote != 0 { return nil, fmt.Errorf("unclosed quote in command string") }

	if arg.Len() > 0 { args = append(args, bytes.Clone(arg.Bytes())) }

	return args, nil
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
