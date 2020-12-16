CC = gcc
INCLUDE	:= -I./ -I../include
LDFLAGS	:=
LDLIBS	:=
CFLAGS	:= -g -Wall $(INCLUDE)

OBJECTS := libtlp.o adaptor.o devmem.o
PROGNAME = libtlp.a adaptor.a devmem.a

all: $(PROGNAME)

.c.o:
	$(CC) $(INCLUDE) -c $<

libtlp.a: libtlp.o
	ar rcs libtlp.a libtlp.o

adaptor.a: adaptor.o
	ar rcs adaptor.a adaptor.o

devmem.a: devmem.o
	ar rcs devmem.a devmem.o



clean:
	rm -rf *.o
	rm -rf $(PROGNAME)
