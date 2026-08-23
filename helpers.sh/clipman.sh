#!/bin/sh

# Store the entry only if ~/.cache/clipman-nostore.tmp file does not exist, which is created by clipboard.sh on copies.
if [[ ! -f "~/.cache/clipman-nostore.tmp" ]]; then
	clipman store --histpath="~/.cache/clipman-primary.json"
fi
