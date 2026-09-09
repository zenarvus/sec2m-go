#!/bin/sh

set +x # disable command tracing/debugging
ulimit -c 0 # disable core dumping

# Read all incoming data from stdin into a variable
data=$(cat)

# Check if data was actually received
if [ -z "$data" ]; then
    echo "Error: No data received from pipe." >&2
    exit 1
fi

# Create ~/.cache/clipman-nostore.tmp to prevent clipman from putting it in history.
touch /tmp/clipman-nostore.tmp

# Copy the data to the Wayland clipboard
printf '%s' "$data" | wl-copy

echo "Copied to clipboard and will be cleared after 10 seconds."

# Spawn a background process to clear the clipboard after 10 seconds
#
(
    sleep 0.5 # wl-copy starts a sub process asyncly. We need to wait it to complete some time before removing the lock file

	# Remove the temporary file
	rm -f /tmp/clipman-nostore.tmp

	sleep 9.5

    # Only clear if the current clipboard content is still what we put in, preventing from accidentally wiping newer clipboard entries.
    if [ "$(wl-paste)" = "$data" ]; then
        wl-copy --clear
    fi
) </dev/null >/dev/null 2>&1 &

# Detach the background process so it doesn't hang the terminal
