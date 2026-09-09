#!/bin/sh

OUTPUT_FILE="sec2m.export"

ENCODED_VAL=$(base64 | tr -d '\n') # get the value from stdin. $1 is path and $2 is mtime

printf "/$1 %s $2\n" "$ENCODED_VAL" >> "$OUTPUT_FILE"
