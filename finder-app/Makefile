
#ifeq ($(CROSS_COMPILE), aarch64-none-linux-gnu-)
#CC=aarch64-none-linux-gnu-gcc
#endif

CROSS_CC=$(CROSS_COMPILE)$(CC)

all: writer.c
	$(CROSS_CC) $(CFLAGS) writer.c -o writer

clean:
	$(RM) writer
