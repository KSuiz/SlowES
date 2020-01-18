CC = gcc
CFLAGS = -std=gnu11

aes: aes.o
	$(CC) -o $@ $^ $(CFLAGS)

debug: aes.o
	$(CC) -o aes $^ $(CFLAGS) -g -DDBUG

clean:
	rm -f *.o aes
