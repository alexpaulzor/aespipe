#!/bin/bash

testsize='10485760'       #10 MB
#testsize='104857600'       #100 MB
threads='8'
pass='asdfasdfasdfasdfasdfasdf'
pseed=';lkj;lkj;lkj;lkj;lkj'

passfile=$(mktemp)
echo "$pass" > $passfile
plaintext=$(mktemp)
echo "Generating $testsize B file '$plaintext'"
dd if=/dev/urandom of=$plaintext bs=1 count=$testsize
echo "Done."
ciphertext=$(mktemp)
echo "Encrypting '$plaintext' using $threads threads to '$ciphertext'"
cat $plaintext | ./aespipe -e aes256 -H sha512 -m ctr -t $threads -P $passfile -S "$pseed" -v > $ciphertext
echo "Done"
plaintext2=$(mktemp)
echo "Decrypting '$ciphertext' using $threads to '$plaintext2'"
cat $ciphertext | ./aespipe -e aes256 -H sha512 -m ctr -t $threads -P $passfile -S "$pseed" -d -v > $plaintext2
echo "Done"
echo "Comparing plaintexts"
md5sum $plaintext $plaintext2
xxd $plaintext | head
xxd $plaintext2 | head
echo "Done"

