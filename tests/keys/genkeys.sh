#!/bin/bash

rm *named*
for c in secp112r1 secp256k1 prime192v1 prime256v1 secp224r1 secp384r1 secp521r1; do
  echo $c
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$c -pkeyopt ec_param_enc:named_curve | tee $c.named.key | openssl pkey -text
  openssl pkey -in $c.named.key -pubout | tee $c.named.pub | openssl pkey -pubin -text
  done

for a in RSA RSA-PSS X25519 X448 ED25519 ED448; do openssl genpkey -algorithm $a -out ./$a.key; openssl pkey -in ./$a.key -out ./$a.pub -pubout; done

