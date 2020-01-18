#!/bin/sh
set -e

make

for i in 1 2
do
    for k in 128 192 256
    do
        echo [$i][$k] Encrypting...
        ./aes -e -i tests/test$i.in -o tests/test$i.$k.eout -k$k tests/key$k
        echo [$i][$k] Decrypting...
        ./aes -d -i tests/test$i.$k.eout -o tests/test$i.$k.dout -k$k tests/key$k
        if cmp -s tests/test$i.$k.dout tests/test$i.in
        then
            rm tests/test$i.$k.eout tests/test$i.$k.dout
        else
            echo "  [$i][$k] Failed"
        fi
    done
done