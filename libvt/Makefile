SYSNAME:=${shell uname}
SYSNAME!=uname
HFILES=vt.h
CFLAGS=-Wall -g -I ../include -D$(SYSNAME)
LFLAGS=-g -L. -lvt -lcrypto -lpthread

OFILES=\
	clnt.o\
	conn.o\
	conv.o\
	error.o\
	file.o\
	fmt.o\
	socksrv.o\
	srv.o\
	vacfile.o\

all: libvt.a

libvt.a: $(OFILES)
	ar rc libvt.a $(OFILES)
	ranlib libvt.a

$(CMDS): libvt.a

vtram: $(OFILES) $(HFILES) vtram.o Makefile
	$(CC) -o vtram $(CFLAGS) vtram.o $(LFLAGS)

vtproxy: $(OFILES) $(HFILES) vtproxy.o Makefile
	$(CC) -o vtproxy $(CFLAGS) vtproxy.o $(LFLAGS)

unvac: $(OFILES) $(HFILES) unvac.o Makefile
	$(CC) -o unvac $(CFLAGS) unvac.o $(LFLAGS)

vac: $(OFILES) $(HFILES) vac.o Makefile
	$(CC) -o vac $(CFLAGS) vac.o $(LFLAGS)

clean:
	rm -f *.o *.a *~ core.* $(CMDS)

$(OFILES): Makefile $(HFILES)

%.o: %.c
	$(CC) $(CFLAGS) -c $*.c
