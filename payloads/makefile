CC	= clang
CFLAGS	= -std=gnu99 -ggdb

sample-library.so: sample-library.c
	$(CC) $(CFLAGS) -D_GNU_SOURCE -shared -o sample-library.so -fPIC sample-library.c

clean:
	rm -f sample-library.so
