
all: libaudit.so

libaudit.so: audit.c common.c common.h
	$(CC) -shared -o libaudit.so audit.c common.c -ldw -std=c99 -fPIC -O -Wl,-znow

clean:
	rm -f audit.o common.o libaudit.so
