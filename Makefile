SYSNAME:=${shell uname}
SYSNAME!=uname

all:
	make -C libvt
	make -C examples

clean:
	make -C libvt clean
	make -C examples clean
	rm -f *~

