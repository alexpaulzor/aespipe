#!/bin/bash

testsize='10485766'       #10 MB + 6B
#testsize='104857600'       #100 MB
threads='8'
pass='asdfasdfasdfasdfasdfasdf'
pseed=';lkj;lkj;lkj;lkj;lkj'

passfile=$(mktemp)
echo "$pass" > $passfile
plaintext="/tmp/testaespipe.$testsize"
if [ ! -e "$plaintext" ]; then
    echo "Generating $testsize B file '$plaintext'"
    dd if=/dev/urandom of=$plaintext bs=1 count=$testsize
    echo "Done."
fi
ciphertext=$(mktemp)
echo "Encrypting '$plaintext' using $threads threads to '$ciphertext'"
cat $plaintext | ./aespipe -e aes256 -H sha512 -m ctr -t $threads -P $passfile -S "$pseed" -v > $ciphertext
echo "Done"
plaintext2=$(mktemp)
echo "Decrypting '$ciphertext' using $threads to '$plaintext2'"
cat $ciphertext | ./aespipe -e aes256 -H sha512 -m ctr -t $threads -P $passfile -S "$pseed" -d -v > $plaintext2
echo "Done"
echo "Comparing plaintexts"
diffval=$(diff $plaintext $plaintext2)
if [ -z "$diffval" ]; then
    echo "PASS -- plaintexts are equivalent"
else
    echo "FAIL -- plaintexts differ"
fi

