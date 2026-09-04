#!/bin/sh

# read ENTRY_PATH and BASE64_VAL from stdin
read -r ENTRY_PATH BASE64_VAL

# base64 expects a padded input. We use awk for that

DECODED_VAL="$(echo $BASE64_VAL | awk '{ l=length($0)+2; print substr($0"==", 1, l-l%4) }' | base64 -d)"

printf "%s\n%s" "$ENTRY_PATH" "$DECODED_VAL"
