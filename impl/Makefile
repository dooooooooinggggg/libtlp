CC = gcc
INCLUDE := -I../include -I../../include
LDFLAGS := -L../lib -L../../lib
LDLIBS  := -ltlp -lpthread
CFLAGS  := -g -Wall $(INCLUDE)

PROGNAME = dma_read dma_write dump_mem mem_read

all: $(PROGNAME)

.c.o: util.h
	$(CC) $< -o $@

clean:
	rm -rf *.o
	rm -rf $(PROGNAME)
	rm -rf *.dSYM
