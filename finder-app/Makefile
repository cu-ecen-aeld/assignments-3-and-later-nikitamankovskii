ifeq ($(CROSS_COMPILE),aarch64-none-linux-gnu-)
	compiler=aarch64-none-linux-gnu-gcc
else
	compiler=gcc
endif


writer: writer.o
	$(compiler) writer.o  -o writer

writer.o: writer.c
	$(compiler) -c writer.c 


clean:
	rm -f writer *.o