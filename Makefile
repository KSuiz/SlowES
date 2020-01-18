CC = gcc
CFLAGS = -std=gnu11 -Wall -Werror

aes: aes.o block.o cbc.o ecb.o
	$(CC) -o $@ $^ $(CFLAGS)

debug: aes.o block.o cbc.o ecb.o
	$(CC) -o aes $^ $(CFLAGS) -g -DDBUG

clean:
	rm -f *.o aes
