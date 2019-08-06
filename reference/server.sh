#!/bin/sh

echo \
"==================================================
Signing HTTP Messages v10 Reference Implementation
=================================================="
echo \
"Using Public Key:---------------------------------"

cat reference/keys/Test-public.pem;

echo \
"Listening for incoming HTTP Requests:-------------"
php -S localhost:6789 -t reference/server/
