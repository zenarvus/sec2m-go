#!/bin/sh

trap 'rm -f "flatten-kdbx.go"' EXIT

# Create a temporary go file
# Write the go code to that temporary file
cat << 'EOF' > "flatten-kdbx.go"
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// Flatten them into /group/sub-group/entry-title/key -> value structure

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
	var flatList = make(map[string][]byte)

	xmlExportPath := os.Args[1] // Get the first argument
	xmlExportBytes, err := os.ReadFile(xmlExportPath)
	if err != nil { fmt.Println(err); os.Exit(1) }

	var kpFile KeePassFile
	err = xml.Unmarshal(xmlExportBytes, &kpFile)
	if err != nil { fmt.Println(err); os.Exit(1) }

	// This is the root path (/)
	rootGroup := kpFile.Root.Group

	recursiveFlattening(rootGroup, "/", flatList)

	// Create a file with key -> base64 value pairs
	var output bytes.Buffer
	for ePath,value := range flatList {
		output.WriteString(ePath)
		output.WriteString(" ")
		output.WriteString(base64.RawStdEncoding.EncodeToString(value))
		output.WriteString("\n")
	}

	err = os.WriteFile(xmlExportPath+".flat", output.Bytes(), 0600)
	if err != nil { fmt.Println(err); os.Exit(1) }

	fmt.Println("xml export has been flattened into:",xmlExportPath+".flat")

}

func recursiveFlattening(grp Group, workingDir string, flatList map[string][]byte) {

	for _,entry := range grp.Entries  {
		title, fields := entry.GetTitleNFields()

		for _,field := range fields {
			ePath := path.Join(workingDir, Slugify(title), Slugify(field.Key))

			// Only append if Value is not empty.
			if strings.Trim(field.Value, " \n\t") != "" {
				flatList[ePath] = []byte(field.Value)
			}
		}
	}

	for _, childgroup := range grp.Groups {
		groupName := Slugify(childgroup.Name)

		recursiveFlattening(
			childgroup,
			path.Join(workingDir, groupName),
			flatList,
		)
	}
}

// Slugify path names so they become compatible with POSIX portable filepaths
var nonAlphaNumRegex = regexp.MustCompile(`[^a-zA-Z0-9]+`)
func Slugify(s string) string {
	// normalize and strip accents/diacritical marks
	t := transform.Chain(norm.NFD, runes.Remove(runes.In(unicode.Mn)), norm.NFC)
	s, _, _ = transform.String(t, s)

	// replace non-alphanumeric characters with dashes
	s = nonAlphaNumRegex.ReplaceAllString(s, "-")

	// trim leading/trailing dashes
	return strings.Trim(s, "-")
}
EOF

# Run the go app
go run flatten-kdbx.go "$@"
