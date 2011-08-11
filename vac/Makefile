SYSNAME:=${shell uname}
SYSNAME!=uname
HFILES=../libvt/vt.h
CFLAGS=-Wall -g -I ../libvt -D$(SYSNAME)
LFLAGS=-g -L../libvt -lvt -lcrypto -lpthread

CMDS=vac unvac

all: $(CMDS)

$(CMDS): ../libvt/libvt.a Makefile $(HFILES)

unvac: $(OFILES) $(HFILES) unvac.o Makefile
	$(CC) -o unvac $(CFLAGS) unvac.o $(LFLAGS)

vac: $(OFILES) $(HFILES) vac.o Makefile
	$(CC) -o vac $(CFLAGS) vac.o $(LFLAGS)

clean:
	rm -f *.o *.a *~ core.* $(CMDS)

%.o: %.c
	$(CC) $(CFLAGS) -c $*.c
