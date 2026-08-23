#!/bin/sh

# Get the OTP code from the base32 secret provided.
sed -n 's/.*[?&]secret=\([^&]*\).*/\1/p' | oathtool --totp --base32 -

# The OTP strings you will store should look like this: otpauth://totp/github:user@email.com?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=GitHub
# The sed will only extract the secret= part and pass it to oathtool. It will work because the default behavior already is period=30&digits=6.
