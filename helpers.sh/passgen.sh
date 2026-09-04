#!/bin/sh

# Generate a cryptographically secure random password with given length and character set. If character set is empty, 'A-Za-z0-9._-' is used.a If length is empty or not a number, 16 is used.

PASS_LEN="$1"
CHAR_SET="$2"

if [ -z "$PASS_LEN" ]; then
	PASS_LEN=16
fi

# Ensure length is only digits using case pattern matching
case "$PASS_LEN" in
        ''|*[!0-9]*) PASS_LEN=16 ;;
esac

if [ -z "$CHAR_SET" ]; then
	CHAR_SET='A-Za-z0-9._-'
fi

generate_password() {
    tr -dc "$CHAR_SET" < /dev/urandom | head -c "$PASS_LEN"
    echo
}

generate_password "$@"
