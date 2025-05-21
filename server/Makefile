ifeq ($(CROSS_COMPILE),aarch64-none-linux-gnu-)
	CC=aarch64-none-linux-gnu-gcc
else
	CC=gcc
endif
# $(compiler)
all: aesdsocket

aesdsocket: aesdsocket.o
	$(CC) $(LDFLAGS) aesdsocket.o  -o aesdsocket

aesdsocket.o: aesdsocket.c
	$(CC) $(CCFLAGS) -c aesdsocket.c 


clean:
	rm -f aesdsocket *.o