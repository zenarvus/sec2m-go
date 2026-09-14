package readline

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"unicode/utf8"

	"github.com/zenarvus/sec2m-go/securemem"
	"golang.org/x/term"
)

// TODO: implement proper wrapping for completion  suggestions!

type Completer interface {
	Get(line securemem.ByteSlice, cursorPos int) (opts [][]byte)
}

// Readline provides a minimal raw-mode terminal prompt interface.
type Readline struct {
	Prompt    string
	Completer Completer
	Hidden bool // disables history and shows asterisk instead of actual chars
	
	history   []securemem.ByteSlice
}
func NewReadline(prompt string, hidden bool, completer Completer) *Readline {
	return &Readline{Prompt: prompt, Hidden: hidden, Completer: completer}
}

// deallocate the history items
func (rl *Readline) Dealloc() {
	for _,item := range rl.history { item.Dealloc() }
}

func (rl *Readline) SetPrompt(p string) { rl.Prompt = p }

// Read blocks until the user presses Enter, handling line editing and history.
func (rl *Readline) Read() (securemem.ByteSlice, error) {
	// Make the terminal raw and get the old state
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil { return securemem.ByteSlice{}, err }
	// Restore to the old terminal stte after return
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	// we need to set Dealloc otherwise it will be nil and callers will panic
	var input = securemem.ByteSlice{Dealloc:func()error{return nil}}

	cursorPos := 0 // byte based cursor position (not rune)

	histIdx := len(rl.history)

	promptLen := len([]rune(rl.Prompt))
	// Track the exact row index (relative to the prompt) the cursor is left on
	prevCursorRow := 0

	render := func() {
		width, _, err := term.GetSize(int(os.Stdin.Fd()))
		if err != nil || width <= 0 { width = 80 } // Fallback to 80 width terminal on error

		// Move cursor UP to the origin of the current input block
		if prevCursorRow > 0 { fmt.Fprintf(os.Stderr, "\033[%dA", prevCursorRow) }
		// Carriage return and Clear to end of screen
		fmt.Fprint(os.Stderr, "\r\033[J")

		// Render the prompt and input
		os.Stderr.Write([]byte(rl.Prompt))
		if !rl.Hidden {
			os.Stderr.Write(input.Bytes)
		} else {
			os.Stderr.Write(bytes.Repeat([]byte("*"), len(input.Bytes)))
		}

		// Calculate how many physical rows the text actually occupies
		fullLen := promptLen + utf8.RuneCount(input.Bytes)
		totalRows := 0
		if fullLen > 0 { totalRows = (fullLen-1) / width }

		// Calculate where the cursor SHOULD physically be placed
		// As the cursor pos is by bytes, we need to get the position by runes.
		targetOffset := promptLen + utf8.RuneCount(input.Bytes[:cursorPos])
		targetRow := targetOffset / width
		targetCol := (targetOffset % width) + 1

		// Move cursor vertically to the target row
		if targetRow < totalRows {
			// Move UP if cursor is behind the end of the text
			fmt.Fprintf(os.Stderr, "\033[%dA", totalRows-targetRow)
		} else if targetRow > totalRows {
			// Move DOWN using newline to safely allow terminal scrolling
			// when the cursor is waiting at the edge of the wrap.
			for i := 0; i < (targetRow - totalRows); i++ {
				fmt.Fprint(os.Stderr, "\n")
			}
		}

		// Move cursor horizontally to the exact column
		fmt.Fprintf(os.Stderr, "\r\033[%dG", targetCol)

		// Save the row offset so we can clear properly on the next keystroke
		prevCursorRow = targetRow
	}

	char,err := securemem.Alloc(1)
	if err != nil {return securemem.ByteSlice{}, err}
	defer char.Dealloc()

	for {
		render()

		_, err := os.Stdin.Read(char.Bytes)
		if err != nil { return securemem.ByteSlice{}, err }

		switch char.Bytes[0] {
		// Return when pressed to enter
		case '\r', '\n': // Enter
			width, _, _ := term.GetSize(int(os.Stdin.Fd()))
			if width <= 0 {
				width = 80
			}

			fullLen := promptLen + utf8.RuneCount(input.Bytes)
			totalRows := 0
			if fullLen > 0 { totalRows = (fullLen-1) / width }

			// Jump to the physical bottom of the wrapped text
			if moveDown := totalRows - prevCursorRow; moveDown > 0 {
				fmt.Fprintf(os.Stderr, "\033[%dB", moveDown)
			}

			// Avoid double-spacing if the cursor was already pushed to a fresh wrap line
			if prevCursorRow > totalRows {
				fmt.Fprint(os.Stderr, "\r")
			} else {
				fmt.Fprint(os.Stderr, "\r\n")
			}

			// If it's length is bigger than zero even we trim the spaces, and it's not equal to the last item in the history
			// Add it to the history
			if !rl.Hidden && len(bytes.TrimSpace(input.Bytes)) > 0 &&
			( len(rl.history)==0 || (len(rl.history) > 0 &&
			input.Bytes != nil && !bytes.Equal(input.Bytes, rl.history[len(rl.history)-1].Bytes)) ) {
				rl.history = append(rl.history, securemem.Clone(input)) // clone it so history does not get affected by input deallocations
			}
			return input, nil

		case 3: // Ctrl+C
			return securemem.ByteSlice{}, fmt.Errorf("interrupted")
		case 4: // Ctrl+D
			if len(input.Bytes) == 0 {
				return securemem.ByteSlice{}, fmt.Errorf("EOF")
			}
		case 127, 8: // Backspace
			if cursorPos > 0 {
				start := prevRuneStart(input.Bytes, cursorPos) // deleted char start

				newBuf := &securemem.Buffer{} // create a new buffer
				newBuf.Write(input.Bytes[:start]) // Write until the char we deleted
				newBuf.Write(input.Bytes[cursorPos:]) // ignore the deleted char and write the rest
				input.Dealloc()

				input = newBuf.Bytes() // Update the input

				cursorPos = cursorPos - (cursorPos-start) // decrease the cursorPos by the byte count of the rune bytes
			}
		case '\t': // tab completion (only if a completer is set)
			if rl.Completer != nil {
				opts := rl.Completer.Get(input, cursorPos)
				if len(opts) > 0 { // if there are options returned
					prefix := commonPrefix(opts) // find the common longest prefix between completion options
					defer prefix.Dealloc()

					// if there are more than 1 option, list suggestions
					if len(opts) > 1 {
						width, _, _ := term.GetSize(int(os.Stdin.Fd()))
						if width <= 0 { width = 80 }

						fullLen := promptLen + utf8.RuneCount(input.Bytes[:cursorPos])
						totalRows := 0
						if fullLen > 0 {
							totalRows = (fullLen - 1) / width
						}

						if moveDown := totalRows - prevCursorRow; moveDown > 0 {
							fmt.Fprintf(os.Stderr, "\033[%dB", moveDown)
						}

						if prevCursorRow > totalRows {
							os.Stderr.WriteString("\r")
						} else {
							os.Stderr.WriteString("\r\n")
						}

						prettyPrintOpts(opts, width)

						// Reset tracking state since we printed a fresh prompt origin
						prevCursorRow = 0
					}

					// place returned prefix to the cursor position
					newBuf := &securemem.Buffer{}
					newBuf.Write(input.Bytes[:cursorPos])
					newBuf.Write(prefix.Bytes)
					newBuf.Write(input.Bytes[cursorPos:])
					cursorPos = len(input.Bytes[:cursorPos])+len(prefix.Bytes) // move the cursor to it's new position
					input.Dealloc()
					input = newBuf.Bytes() // make the input the new buf
				}
			}
		case 27: // Escape sequence (Arrows)
			if os.Stdin.Read(char.Bytes); char.Bytes[0] == '[' {
				os.Stdin.Read(char.Bytes)
				switch char.Bytes[0] {
				case 'A': // Up
					if histIdx > 0 {
						histIdx--
						input.Dealloc()
						input = securemem.Clone(rl.history[histIdx])
						cursorPos = len(input.Bytes)
					}
				case 'B': // Down
					if histIdx < len(rl.history)-1 {
						histIdx++
						input.Dealloc()
						input = securemem.Clone(rl.history[histIdx])
						cursorPos = len(input.Bytes)
					} else if histIdx == len(rl.history)-1 {
						histIdx++
						input.Dealloc()
						input = securemem.ByteSlice{ Dealloc:func()error{return nil} }
						cursorPos = 0
					}
				case 'C': // Right
					cursorPos = nextRuneEnd(input.Bytes, cursorPos)
				case 'D': // Left
					cursorPos = prevRuneStart(input.Bytes, cursorPos)
				}
			}
		default: // Insert printable characters
			if char.Bytes[0] >= 32 {
				newBuf := &securemem.Buffer{}
				newBuf.Write(input.Bytes[:cursorPos])
				newBuf.Write(char.Bytes)
				newBuf.Write(input.Bytes[cursorPos:])
				input.Dealloc()
				input = newBuf.Bytes()

				cursorPos++
			}
		}
	}
}

// commonPrefix finds the longest common starting string among completion options
func commonPrefix(opts [][]byte) securemem.ByteSlice {
	if len(opts) == 0 { return securemem.ByteSlice{Dealloc:func()error{return nil}} }

	prefix := opts[0]
	for _, opt := range opts[1:] {
		for !bytes.HasPrefix(opt, prefix) {
			prefix = prefix[:len(prefix)-1]
		}
	}
	return securemem.ToByteSlice(prefix)
}

/////////////////////////////////////////

func prevRuneStart(b []byte, pos int) int {
	if pos <= 0 { return 0 }
	pos--
	// Move backwards over utf8 continuation bytes.
	for pos > 0 && !utf8.RuneStart(b[pos]) { pos-- }

	return pos
}

func nextRuneEnd(b []byte, pos int) int {
	if pos >= len(b) { return len(b) }

	_, size := utf8.DecodeRune(b[pos:])
	if size <= 0 { size = 1 }

	end := pos + size
	if end > len(b) { return len(b) }

	return end
}

func prettyPrintOpts(opts [][]byte, width int) {
	lineWidth := 0

	// sort options alphabetically
	slices.SortFunc(opts, bytes.Compare)

	for _, opt := range opts {
		// if line is gonna exceed the width when we insert the text, move to a new line
		if lineWidth + utf8.RuneCount(opt) + 2 > width-1 {
			os.Stderr.WriteString("\r\n")
			lineWidth = 0
		}
		os.Stderr.Write(opt)
		os.Stderr.WriteString("  ")
		lineWidth += 2+utf8.RuneCount(opt)
	}

	os.Stderr.WriteString("\r\n") // place a newline
	os.Stderr.WriteString("\r\n")
}
