#!/bin/sh

OUTPUT_FILE="sec2m.export"

RAW_VAL=$(cat) # get the value from stdin. $1 is path and $2 is mtime

printf "/$1 %s $2\n" "$(echo $RAW_VAL | base64 | tr -d '\n')" >> "$OUTPUT_FILE"
