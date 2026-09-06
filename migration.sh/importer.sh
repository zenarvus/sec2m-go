#!/bin/sh

# read ENTRY_PATH, BASE64_VAL and MTIME from stdin
read -r ENTRY_PATH BASE64_VAL MTIME

DECODED_VAL="$(echo $BASE64_VAL | base64 -d)"

printf "%s\n%s\n%s" "$ENTRY_PATH" "$MTIME" "$DECODED_VAL"
