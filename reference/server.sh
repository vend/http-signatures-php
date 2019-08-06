#!/bin/sh

echo \
"==================================================
Signing HTTP Messages v10 Reference Implementation
=================================================="
echo \
"Using Public Key:---------------------------------"
echo \
"Listening for incoming HTTP Requests:-------------"

cat reference/keys/Test-public.pem;
php -S localhost:6789 -t reference/server/
