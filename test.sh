#!/bin/sh

./rsa g > keys
e=`sed -n 's/^public key: \(.*\)/\1/p' keys`
d=`sed -n 's/^private key: \(.*\)/\1/p' keys`
n=`sed -n 's/^modulo: \(.*\)/\1/p' keys`
rm keys
for f in `ls test/`; do
	encrypted="test/$f.encrypted"
	decrypted="test/$f.decrypted"
	./rsa e "$e" "$n" "test/$f" "$encrypted"
	./rsa d "$d" "$n" "$encrypted" "$decrypted"
	cmp "test/$f" "$decrypted"
	rm "$encrypted" "$decrypted"
done
