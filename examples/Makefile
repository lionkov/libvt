SYSNAME:=${shell uname}
SYSNAME!=uname
HFILES=../libvt/vt.h
CFLAGS=-Wall -g -I ../libvt -D$(SYSNAME)
LFLAGS=-g -L../libvt -lvt -lcrypto -lpthread
CMDS=vtram vtproxy vtmm

all: $(CMDS)

$(CMDS): ../libvt/libvt.a Makefile $(HFILES)

vtram: $(OFILES) $(HFILES) vtram.o Makefile
	$(CC) -o vtram $(CFLAGS) vtram.o $(LFLAGS)

vtproxy: $(OFILES) $(HFILES) vtproxy.o Makefile
	$(CC) -o vtproxy $(CFLAGS) vtproxy.o $(LFLAGS)

vtmm: $(OFILES) $(HFILES) vtmm.o Makefile
	$(CC) -o vtmm $(CFLAGS) vtmm.o $(LFLAGS)

clean:
	rm -f *.o *.a *~ core.* $(CMDS)

%.o: %.c
	$(CC) $(CFLAGS) -c $*.c
