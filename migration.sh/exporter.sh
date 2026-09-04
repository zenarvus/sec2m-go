#!/bin/sh

STDIN_VAL=$(cat)

OUTPUT_FILE="sec2m.export"

if [ "$1" = "1" ]; then
	printf "$STDIN_VAL " >> "$OUTPUT_FILE"
	printf "$STDIN_VAL"

elif [ "$1" = "2" ]; then
	BASE64_ENCODED_VAL=$(printf "%s" "$STDIN_VAL" | base64 | tr -d "=") # trim the leading equal signs.
	printf "$BASE64_ENCODED_VAL\n" >> "$OUTPUT_FILE"
fi
