#!/bin/sh
set -e

make

for mode in cbc ecb
do
    for i in 1 2
    do
        for k in 128 192 256
        do
            echo [$mode][$i][$k] Encrypting...
            ./aes -e -$mode -i tests/test$i.in -o tests/test$i.$mode.$k.eout -k$k tests/key$k
            echo [$mode][$i][$k] Decrypting...
            ./aes -d -$mode -i tests/test$i.$mode.$k.eout -o tests/test$i.$mode.$k.dout -k$k tests/key$k
            if cmp -s tests/test$i.$mode.$k.dout tests/test$i.in
            then
                rm tests/test$i.$mode.$k.eout tests/test$i.$mode.$k.dout
            else
                echo "  [$mode][$i][$k] Failed"
            fi
        done
    done
done