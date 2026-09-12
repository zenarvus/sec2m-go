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

	"github.com/zenarvus/sec2m-go/securemem"
)

// Process things like:
// cmd1 arg1 escaped\ arg2 spaces "quote with $(stuff)" $(substition "quote" $(innter substition)) | comd2 "with other stuff"

// All of them are considered as one argument
type TokenType uint8
const(
	ARG = 0 // Regular whole literal argument.
	SUBSTITUTION = 1 // An argument that needs to be tokenized and processed. The returned things is considered as one whole argument. SUBSTITUTION token value includes "(" prefix and ")" suffix that should be trimmed
	PIPE = 2 // A literal pipe token that is not in a quote.
)

type Token struct {
	Type TokenType
	Value []byte
}

func tokenize(input []byte) ([]Token, error) {
	var (
		tokens []Token // The token list that will be returned
		token Token // the current token. Defaults to ARG and an empty Value buffer
		inQuote byte = '0' // Are we in a quote? It's the quote char used if we are in one.
		escaped bool // Is the current character escaped? (via "\")
		parenCount int // The parenthesis count used in command substitutions
		scratch securemem.Buffer
	)
	defer scratch.Dealloc()

	// Add the generated token to tokens list and empty token variable for the next token
	emit := func() {
		// If token length is greater than zero, or token type is substitution, add it to the arguments list
		if scratch.Len() > 0 || token.Type == SUBSTITUTION {
			token.Value = bytes.Clone(scratch.Bytes()) // We need to clone it as scratch.Reset() reuses the same slice
			tokens = append(tokens, token) // append the token

			token.Type = ARG // reset the token type
			token.Value = []byte{} // reset the value field
			scratch.Reset() // reset the scratch
		}
	}

	// Iterate through the input bytes
	for i := 0; i < len(input); i++ {
		b := input[i] // the current byte in the input

		// ESCAPE HANDLING

		// If the element is escaped, write it directly to token, disable escaping and continue.
		if escaped {
			switch b {
			case 'n':
				scratch.WriteByte('\n')
			case 't':
				scratch.WriteByte('\t')
			case 'r':
				scratch.WriteByte('\r')
			default:
				scratch.WriteByte(b)
			}
			escaped = false
			continue	
		}
		// If byte is an escape character, escape the next char
		if b == '\\' {
			escaped = true
			continue // Do not add this character to the token
		}

		// COMMAND SUBSTITUTION HANDLING
		if token.Type == SUBSTITUTION {
			// If the char is in a quote and the current byte is equal to the char used to open the quote, close the quote
			if inQuote != '0' {
				if b == inQuote { inQuote = '0' }

			// If the character is not in a quote
			} else {
				switch b {
				// If it's a quote start char, set inQuote to that char
				case '\'', '"':
					inQuote = b
				// If it's a nested substitution parenthesis outside a quote
				case '(':
					parenCount++
				// If it's a substitution closing parenthesis
				case ')':
					parenCount-- // decrease the parenthesis count
					// when it reaches to zero, it means the substitution is ended
					if parenCount == 0 {
						emit() // Add the token to the tokens list
						continue // bypass writing the final closing character
					}

				}
			}
			// Write the byte to the token and skip it
			scratch.WriteByte(b)
			continue

		}

		// QUOTE ARGUMENT HANDLING

		// If we are in a quote
		if inQuote != '0' {
			// If the current byte is equal to the quote start char, close the quote and do not write it to the token
			if b == inQuote {
				inQuote = '0'
			// Else, write the char to the quote token
			} else {
				scratch.WriteByte(b)

			}
			continue // Skip the char
		}

		// REGULAR ARGUMENT HANDLING
		switch b {
		// If it's a command substitution starter char
		case '$':
			// If the next character is parenthesis, make the token SUBSTITUTION
			if i+1 < len(input) && input[i+1] == '(' {
				token.Type = SUBSTITUTION
				parenCount = 1 // Make the parenthesis count 1
				i++ // Skip the starting parenthesis

			// If not, consider it as a literal char
			} else { scratch.WriteByte(b) }
		// If it's a quote char, start a quote with that char
		case '\'', '"':
			inQuote = b
		// If it's a literal pipe character, add the token generated so far and add the pipe token
		case '|':
			emit()
			token.Type = PIPE
			scratch.WriteByte('|')
			emit()
		// If it's a regular space, it's the ending of the token generated so far
		case ' ', '\n', '\t':
			emit() // emit the token
		// If the char is nothing above, append it to the current token
		default:
			scratch.WriteByte(b)
		}
	}

	if inQuote != '0' { return nil, errors.New("unclosed quote in command string") }
	if parenCount != 0 { return nil, errors.New("unclosed $() command substitution") }

	emit() // Add the last token if the buffer isn't empty

	return tokens, nil
}
