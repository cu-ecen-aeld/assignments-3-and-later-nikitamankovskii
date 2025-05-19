ifeq ($(CROSS_COMPILE),aarch64-none-linux-gnu-)
	compiler=aarch64-none-linux-gnu-gcc
else
	compiler=gcc
endif

all: aesdsocket

aesdsocket: aesdsocket.o
	$(compiler) aesdsocket.o  -o aesdsocket

aesdsocket.o: aesdsocket.c
	$(compiler) -c aesdsocket.c 


clean:
	rm -f aesdsocket *.o