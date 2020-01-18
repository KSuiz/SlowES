CC = gcc
CFLAGS = -std=gnu11

aes: aes.o block.o cbc.o
	$(CC) -o $@ $^ $(CFLAGS)

debug: aes.o block.o cbc.o
	$(CC) -o aes $^ $(CFLAGS) -g -DDBUG

clean:
	rm -f *.o aes
