
.PHONY = rebuild clean

all:safefile.o list.o aesdsocket.o 
	$(CC) $(CFLAGS) aesdsocket.o safefile.o list.o -o aesdsocket

rebuild:clean all

aesdsocket.o:aesdsocket.c safefile.o list.o
	$(CC) $(CFLAGS) -c aesdsocket.c -o aesdsocket.o

safe_file.o:safefile.c safefile.h
	$(CC) $(CFLAGS) -c safefile.c -o safefile.o

list.o:list.h list.c 
	$(CC) $(CFLAGS) -c list.c -o list.o

clean:
	$(RM) *.o
	$(RM) aesdsocket
