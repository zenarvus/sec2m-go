#!/bin/sh

# HOW TO SIGN GIT COMMITS USING SEC2M
#
# Generate a SSH key:
# - `ssh-keygen -t ed25519 -f ./git-signing -C "email@example.com" -N ""`
#
# It creates two files in the current dir: `git-signing` and `git-signing.pub`. To save them, run sec2m in the current dir.
# - `exec cat git-signing | put /work/git/sign.priv`
# - `exec cat git-signing.pub | put /work/git/sign.pub`
#
# Make git  use ssh for signing:
# - `git config --global gpg.format ssh`
# Enable commit signing:
# - `git config --global commit.gpgsign true`
# Point git to this script file:
# - git config --global gpg.ssh.program "/path/to/git-signer.sh"
# Pass a dummy user.signingkey
# - `git config --global user.signingkey "github"`

OPERATION=""
NAMESPACE=""
TARGET_FILE=""

# git passes: -Y OPERATION -f KEY_FILE -n NAMESPACE TARGET_FILE
# we need to process those arguments
while [ $# -gt 0 ]; do
	case $1 in
		-Y)
			OPERATION="$2"
			shift 2 # skip those args
			;;
		-f)
			# we ignore this
			shift 2
			;;
		-n)
			NAMESPACE="$2"
			shift 2
			;;
		*)
			TARGET_FILE="$1"
			shift
			;;
	esac
done

# OPERATION must be sign
if [ ! "$OPERATION" = "sign" ]; then
	echo "operation must be signing"
	exit 1
fi

# create a temporary file for the private key. ssh-keygen expects a file
PRIV_KEY_FILE=$(mktemp)
chmod 600 "$PRIV_KEY_FILE"
trap 'rm -f "$PRIV_KEY_FILE"' EXIT

# fetch the private key from sec2m
# `< /dev/tty` redirects inputs to sec2m and `2> /dev/tty` outputs sec2m's stderr to the terminal
sec2m get /work/git/sign.priv > "$PRIV_KEY_FILE" < /dev/tty 2> /dev/tty

# sign the target file using the parameters. ssh-keygen outputs to "$TARGET_FILE.sig", which is the file git already expects
ssh-keygen -Y sign -n "$NAMESPACE" -f "$PRIV_KEY_FILE" "$TARGET_FILE"

STATUS=$? # get the status code of the command

exit $STATUS # exit with that status code. 0 means signing is successful while 1 cancels the op
