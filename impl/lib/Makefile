CC = gcc
INCLUDE	:= -I./ -I../../include -I../include
LDFLAGS	:=
LDLIBS	:=
CFLAGS	:= -g -Wall $(INCLUDE)

OBJECTS := adaptor.o devmem.o
PROGNAME = adaptor.a devmem.a

all: $(PROGNAME)

.c.o:
	$(CC) $(INCLUDE) -c $<

adaptor.a: adaptor.o
	ar rcs adaptor.a adaptor.o

devmem.a: devmem.o
	ar rcs devmem.a devmem.o

clean:
	rm -rf *.o
	rm -rf $(PROGNAME)
