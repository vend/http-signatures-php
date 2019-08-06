#!/bin/sh

echo \
"==================================================
Signing HTTP Messages v10 Reference Implementation
=================================================="
echo \
"Using Public Key:---------------------------------"
echo \

cat reference/keys/Test-public.pem;

"Listening for incoming HTTP Requests:-------------"
php -S localhost:6789 -t reference/server/
