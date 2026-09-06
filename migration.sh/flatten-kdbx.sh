#!/bin/sh

trap 'rm -f "flatten-kdbx.go"' EXIT

# Create a temporary go file
# Write the go code to that temporary file
cat << 'EOF' > "flatten-kdbx.go"
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Flatten them into /group/sub-group/entry-title/key -> [][]byte{value, mtime} structure

type KeePassFile struct {
	XMLName xml.Name `xml:"KeePassFile"`
	Root    struct {
		Group Group `xml:"Group"` // Top-level group
	} `xml:"Root"`
}
type Group struct {
	Name    string  `xml:"Name"`
	Groups  []Group `xml:"Group"` // Recursive nested groups
	Entries []Entry `xml:"Entry"` // Entries in this group
}
type Field struct {
	Key string `xml:"Key"`
	Value string `xml:"Value"`
}
type Entry struct {
	Fields []Field `xml:"String"`
	Times struct{
		LastModificationTime string `xml:"LastModificationTime"` // base64 encoded seconds elapsed since 0001-01-01 00:00 UTC in int64 little endian. We need to make it uint64 milliseconds in unix epoch
	} `xml:"Times"`
}

func (e *Entry) GetTitleNFields() (title string, fields []Field) {
	for _,field := range e.Fields {
		if field.Key == "Title" {
			title = field.Value
		} else {
			fields = append(fields, field)
		}
	}
	return title, fields
}

func main() {
	var flatList = make(map[string][][]byte)

	if len(os.Args) < 2 {fmt.Println("Usage:",os.Args[0],"<xml-filepath>"); os.Exit(1)}

	xmlExportPath := os.Args[1] // Get the first argument
	xmlExportBytes, err := os.ReadFile(xmlExportPath)
	if err != nil { fmt.Println(err); os.Exit(1) }

	var kpFile KeePassFile
	err = xml.Unmarshal(xmlExportBytes, &kpFile)
	if err != nil { fmt.Println(err); os.Exit(1) }

	// This is the root path (/)
	rootGroup := kpFile.Root.Group

	recursiveFlattening(rootGroup, "/", flatList)

	// Create a file with path base64Val mtime lines
	var output bytes.Buffer
	for ePath,valueNTime := range flatList {
		output.WriteString(ePath)
		output.WriteString(" ")
		output.WriteString(base64.StdEncoding.EncodeToString(valueNTime[0]))
		output.WriteString(" ")
		output.Write(valueNTime[1])
		output.WriteString("\n")
	}

	err = os.WriteFile(xmlExportPath+".flat", output.Bytes(), 0600)
	if err != nil { fmt.Println(err); os.Exit(1) }

	fmt.Println("xml export has been flattened into:",xmlExportPath+".flat")

}

func recursiveFlattening(grp Group, workingDir string, flatList map[string][][]byte) {

	for _,entry := range grp.Entries  {
		title, fields := entry.GetTitleNFields()

		mtimeBytes := parseKeePassTime(entry.Times.LastModificationTime)

		for _,field := range fields {
			ePath := path.Join(workingDir, Slugify(title), Slugify(field.Key))

			// Only append if Value is not empty.
			if strings.Trim(field.Value, " \n\t") != "" {
				flatList[ePath] = [][]byte{[]byte(field.Value), mtimeBytes}
			}
		}
	}

	for _, childgroup := range grp.Groups {
		groupName := Slugify(childgroup.Name)

		recursiveFlattening(
			childgroup,
			path.Join(workingDir, string(groupName)),
			flatList,
		)
	}
}

// Converts KeePass base64 time to a Unix timestamp in milliseconds
func parseKeePassTime(b64Time string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(b64Time)
	if err != nil || len(decoded) < 8 {
		return []byte("0") // Fallback for invalid/empty times
	}

	// Read as int64 little endian
	kpSeconds := int64(binary.LittleEndian.Uint64(decoded))

	// Seconds between 0001-01-01 and 1970-01-01 is 62,135,596,800
	unixSeconds := kpSeconds - 62135596800
	if unixSeconds < 0 { unixSeconds = 0 } // Prevent underflow if time is corrupted or pre-1970

	unixMillis := uint64(unixSeconds) * 1000
	return []byte(strconv.FormatUint(unixMillis, 10))
}

// Map of common unicode runes to ASCII replacements.
var repl = map[rune]string{
	'á': "a", 'à': "a", 'â': "a", 'ä': "a", 'ã': "a", 'å': "a",
	'é': "e", 'è': "e", 'ê': "e", 'ë': "e",
	'í': "i", 'ì': "i", 'î': "i", 'ï': "i", 'ı': "i",
	'ó': "o", 'ò': "o", 'ô': "o", 'ö': "o", 'õ': "o",
	'ú': "u", 'ù': "u", 'û': "u", 'ü': "u",
	'ğ': "g", 'ñ': "n", 'ç': "c",
	'ý': "y", 'ÿ': "y",
	'þ': "th", 'ð': "d",
	'æ': "ae", 'œ': "oe",
}

// Slugify converts input bytes to a slug bytes slice using sep (e.g., '-').
// Result is lowercased ASCII; non-transliterable runes are removed or become sep.
func Slugify(in string) string {
	sep := '-'
	if len(in) == 0 {return ""}
	var out bytes.Buffer
	out.Grow(len(in))
	prevSep := false

	for len(in) > 0 {
		r, size := utf8.DecodeRune([]byte(in))
		in = in[size:]

		// ASCII fast-path
		if r < utf8.RuneSelf {
			switch {
			case r >= 'A' && r <= 'Z':
				out.WriteByte(byte(r + ('a' - 'A'))) // to lowercase
				prevSep = false
			case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
				out.WriteByte(byte(r))
				prevSep = false
			default:
				if !prevSep && out.Len() > 0 {
					out.WriteRune(sep)
					prevSep = true
				}
			}
			continue
		} else {
			// Transliterate common runes
			if s, ok := repl[unicode.ToLower(r)]; ok {
				// write transliteration as lowercase
				out.WriteString(s)
				prevSep = false
				continue
			}
		}

		// For letters in other scripts try to use unicode.IsLetter -> drop if not ASCII
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			// Attempt a naive decomposition: remove diacritics isn't cheap; drop unknown non-ASCII.
			// To keep short and fast, we omit expensive normalization and treat as separator.
			if !prevSep && out.Len() > 0 {
				out.WriteRune(sep)
				prevSep = true
			}
			continue
		}

		// Other runes -> separator
		if !prevSep && out.Len() > 0 {
			out.WriteRune(sep)
			prevSep = true
		}
	}
	// Trim trailing separator
	b := out.Bytes()
	if len(b) > 0 && b[len(b)-1] == byte(sep) { b = b[:len(b)-1] }
	// Trim leading separator
	if len(b) > 0 && b[0] == byte(sep) { b = b[1:] }
	// Return a copy to ensure external mutation won't affect internal buffer
	res := make([]byte, len(b))
	copy(res, b)
	return string(res)
}
EOF

# Run the go app
go run flatten-kdbx.go "$@"
