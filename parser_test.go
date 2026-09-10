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
	"testing"
)

type expectedToken struct {
	Type  TokenType
	Value string
}

func TestTokenize(t *testing.T) {
	tests := []struct {
		input       string
		expected    []expectedToken
		expectError bool
	}{
		{
			input: "cmd arg1 arg2",
			expected: []expectedToken{
				{Type: ARG, Value: "cmd"},
				{Type: ARG, Value: "arg1"},
				{Type: ARG, Value: "arg2"},
			},
		},
		{
			input: "escaped\\ space new\\nline",
			expected: []expectedToken{
				{Type: ARG, Value: "escaped space"},
				{Type: ARG, Value: "new\nline"},
			},
		},
		{
			input: "cmd \"double quote\" 'single quote'",
			expected: []expectedToken{
				{Type: ARG, Value: "cmd"},
				{Type: ARG, Value: "double quote"},
				{Type: ARG, Value: "single quote"},
			},
		},
		{
			input: "cmd1 | cmd2 '|'",
			expected: []expectedToken{
				{Type: ARG, Value: "cmd1"},
				{Type: PIPE, Value: "|"},
				{Type: ARG, Value: "cmd2"},
				{Type: ARG, Value: "|"},
			},
		},
		{
			input: "cmd $(subcmd arg)",
			expected: []expectedToken{
				{Type: ARG, Value: "cmd"},
				{Type: SUBSTITUTION, Value: "subcmd arg"},
			},
		},
		{
			input: "cmd $(outer $(inner))",
			expected: []expectedToken{
				{Type: ARG, Value: "cmd"},
				{Type: SUBSTITUTION, Value: "outer $(inner)"},
			},
		},
		{
			input: "cmd $(outer '(')",
			expected: []expectedToken{
				{Type: ARG, Value: "cmd"},
				{Type: SUBSTITUTION, Value: "outer '('"},
			},
		},
		{
			input: "cmd1 arg1 escaped\\ arg2 \"quote spaces\" | cmd2 $(sub $(inner))",
			expected: []expectedToken{
				{Type: ARG, Value: "cmd1"},
				{Type: ARG, Value: "arg1"},
				{Type: ARG, Value: "escaped arg2"},
				{Type: ARG, Value: "quote spaces"},
				{Type: PIPE, Value: "|"},
				{Type: ARG, Value: "cmd2"},
				{Type: SUBSTITUTION, Value: "sub $(inner)"},
			},
		},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			tokens, err := tokenize([]byte(tt.input))

			// Check error expectations
			if (err != nil) != tt.expectError {
				t.Fatalf("expected error: %v, got: %v", tt.expectError, err)
			}

			// If we expected an error and got one, the test for this case is complete
			if tt.expectError { return }

			// Check token count
			if len(tokens) != len(tt.expected) {
				t.Fatalf("expected %d tokens, got %d", len(tt.expected), len(tokens))
			}

			// Check individual tokens
			for i, tok := range tokens {
				expectedTok := tt.expected[i]
				
				if tok.Type != expectedTok.Type {
					t.Errorf("token %d: expected type %d, got %d", i, expectedTok.Type, tok.Type)
				}
				
				actualVal := string(tok.Value)
				if actualVal != expectedTok.Value {
					t.Errorf("token %d: expected value %q, got %q", i, expectedTok.Value, actualVal)
				}
			}
		})
	}
}
