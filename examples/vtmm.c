#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <openssl/sha.h>
#include <search.h>
#include "vt.h"

typedef struct Arena Arena;

struct Arena {
	int	fd;		// file containing the arena
	u64	size;		// file size
	uchar*	arena;		// content of the file mmaped to the memory
	uchar*	top;		// where to write the next block
	uchar*	synctop;	// end of last msync
};
	
static pthread_mutex_t hashlock = PTHREAD_MUTEX_INITIALIZER;
static Arena *arena;
static int pagesize = 4096;	// align blocks to page size. 0 == no alignment

static void
scorestr(uchar *bscore, char *score)
{
	int i;

	for(i = 0; i < Vscoresize; i++)
		sprintf(&score[i*2], "%02x", bscore[i]);
}

static void
calcscore(uchar *buf, int buflen, char *score)
{
	uchar bscore[Vscoresize];

	SHA1(buf, buflen, bscore);
	scorestr(bscore, score);
}

static Arena *
openarena(char *name)
{
	Arena *a;
	struct stat st;

	a = malloc(sizeof(*a));
	a->fd = open(name, O_RDWR);
	if (a->fd < 0) {
error:
		free(a);
		return NULL;
	}

	if (fstat(a->fd, &st) < 0) {
		goto error;
	}

	a->size = st.st_size;
	a->arena = mmap(NULL, a->size, PROT_WRITE, MAP_SHARED, a->fd, 0);
	if (a->arena == MAP_FAILED) {
		goto error;
	}

	a->top = a->arena;
	a->synctop = a->arena;
	return a;
}

static int buildhash(Arena *a)
{
	uchar *b;
	u32 sz;
	int nblocks;
	u64 nsz;
	char *score;
	ENTRY item;
	struct timeval stime, etime;
	u64 s, e;

	printf("create hash table with %lld entries\n", a->size / 1024);
	if (hcreate(a->size / 8192) == 0) {
		return -1;
	}

	nblocks = 0;
	nsz = 0;
	gettimeofday(&stime, NULL);
	for(b = a->arena; b < a->arena+a->size;) {
		sz = ntohl(*((u32 *) b));
		if (sz==0)
			break;

		nsz += sz;
		score = malloc(Vscoresize*2+1);
		calcscore(b+4, sz, score);
		item.key = score;
		item.data = b;
		if (!hsearch(item, ENTER)) {
			fprintf(stderr, "Hash table full\n");
			return -1;
		}

		sz += 4;
		if (pagesize)
			sz = sz + (pagesize - sz%pagesize);

		b += sz;
		nblocks++;
	}

	a->top = b;
	a->synctop = a->top;
	gettimeofday(&etime, NULL);

	s = stime.tv_sec*1000000ULL + stime.tv_usec;
	e = etime.tv_sec*1000000ULL + etime.tv_usec;
	printf("read %d blocks total %lld bytes in %lld ms\n", nblocks, nsz, (e - s) / 1000);
	printf("total space used: %lld bytes\n", a->top - a->arena);
	
	return 0;
}

static void
usage()
{
	fprintf(stderr, "vtmm: -h -d -p port arena\n");
	exit(-1);
}

static void
vtping(Vreq *req)
{
	respondreq(req, packrping());
}

static void
vthello(Vreq *req)
{
	respondreq(req, packrhello("anonymous", 0, 0));
}

static void
vtread(Vreq *req)
{
	u32 sz;
	uchar *b;
	char score[Vscoresize*2 + 1];
	ENTRY item, *fitem;

	scorestr(req->tc->score, score);
	item.key = score;
	pthread_mutex_lock(&hashlock);
	fitem = hsearch(item, FIND);
	pthread_mutex_unlock(&hashlock);
	if (fitem != NULL) {
		b = fitem->data;
		sz = ntohl(*((u32 *)b));
		respondreq(req, packrread(sz, b + 4));
	} else {
		respondreqerr(req, "not found");
	}
}

static void
vtwrite(Vreq *req)
{
	Vcall *tc;
	u32 sz;
	uchar bscore[Vscoresize];
	char score[Vscoresize*2+1];
	ENTRY item;

	tc = req->tc;
	SHA1(tc->data, tc->count, bscore);
	scorestr(bscore, score);
	
	pthread_mutex_lock(&hashlock);
	item.key = score;
	if (hsearch(item, FIND) == NULL) {
		if (arena->top+tc->count > arena->arena+arena->size)
			goto error;

		item.key = strdup(score);
		item.data = arena->top;
		*((u32 *) arena->top) = htonl(tc->count);
		memmove(arena->top + 4, tc->data, tc->count);

		sz = tc->count + 4;
		if (pagesize)
			sz = sz + (pagesize - sz%pagesize);

		arena->top += sz;
		if (!hsearch(item, ENTER)) {
error:
			pthread_mutex_unlock(&hashlock);
			respondreqerr(req, "arena full");
			return;
		}
	}

	pthread_mutex_unlock(&hashlock);
	respondreq(req, packrwrite(bscore));
}

static void
vtsync(Vreq *req)
{
	u64 s, e;

	pthread_mutex_lock(&hashlock);
	s = (u64) arena->synctop;
	e = (u64) arena->top;
	arena->synctop = arena->top;
	pthread_mutex_unlock(&hashlock);

	// align to page size
	s -= s%4096;
	e += 4096 - e%4096;
	msync((void *) s, e - s, MS_SYNC);
	respondreq(req, packrsync());
}

int
main(int argc, char *argv[])
{
	int c, debuglevel;
	int port, hbits;
	char *s;
	Vsrv *srv;

	debuglevel = 0;
	port = 17034;
	hbits = 9;
	while ((c = getopt(argc, argv, "dp:hb:")) != -1) {
		switch (c) {
		case 'd':
			debuglevel = 1;
			break;

		case 'p':
			port = strtol(optarg, &s, 10);
			if (*s != '\0')
				usage();
			break;

		case 'b':
			hbits = strtol(optarg, &s, 10);
			if (*s != '\0')
				usage();
			break;

		case 'h':
		default:
			usage();
		}
	}

	if (argc - optind < 1)
		usage();

	arena = openarena(argv[optind]);
	if (arena==NULL) {
		perror("openarena");
		return -1;
	}

	if (buildhash(arena) < 0) {
		perror("buildhash");
		return -1;
	}

	srv = socksrvcreate(16, &port);
	if (!srv) 
		goto error;

	srv->debuglevel = debuglevel;
	srv->ping = vtping;
	srv->hello = vthello;
	srv->read = vtread;
	srv->write = vtwrite;
	srv->sync = vtsync;
	srvstart(srv);
	while (1) {
		sleep(100);
	}

	return 0;

error:
	fprintf(stderr, "Error\n");
	return -1;
}
