/*
 * Copyright (C) 2008 by Latchesar Ionkov <lucho@ionkov.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * LATCHESAR IONKOV AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <openssl/sha.h>
#include "vt.h"

typedef struct Block Block;

struct Block {
	uchar	type;
	uchar	score[Vscoresize];
	uchar*	block;
	int	blocksize;

	Block*	next;
};

static pthread_mutex_t hashlock = PTHREAD_MUTEX_INITIALIZER;
static int hashbits;
static int hashmask;
static Block **hashtbl;

static void
calcscore(uchar *buf, int buflen, uchar *score)
{
	SHA1(buf, buflen, score);
}

static void
inithtable(int hbits)
{
	hashbits = hbits;
	hashtbl = calloc(1<<hbits, sizeof(Block *));
	hashmask = (1<<hbits) - 1;
}

static int
hash(uchar *score)
{
	int n;

	n = *((int *)score);

	return n & hashmask;
}

static Block *
getblock(uchar *score)
{
	int h;
	Block *b, *ret;

	h = hash(score);
	ret = NULL;
	pthread_mutex_lock(&hashlock);
	for(b = hashtbl[h]; b != NULL; b = b->next)
		if (memcmp(b->score, score, Vscoresize) == 0) {
			ret = b;
			break;
		}

	pthread_mutex_unlock(&hashlock);
	return ret;
}

static Block *
putblock(uchar type, uchar *block, int blocksize)
{
	int h;
	uchar score[Vscoresize];
	Block *b;

	calcscore(block, blocksize, score);
	h = hash(score);
	b = getblock(score);
	if (!b) {
		b = malloc(sizeof(*b) + blocksize);
		b->type = type;
		memmove(b->score, score, Vscoresize);
		b->block = (uchar *)b + sizeof(*b);
		b->blocksize = blocksize;
		memmove(b->block, block, blocksize);
		pthread_mutex_lock(&hashlock);
		b->next = hashtbl[h];
		hashtbl[h] = b;
		pthread_mutex_unlock(&hashlock);
	}

	assert(b->type == type);
	return b;
}

static void
usage()
{
	fprintf(stderr, "vtram: -h -d -p port\n");
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
	Block *b;

	b = getblock(req->tc->score);
	if (!b) {
		respondreqerr(req, "not found");
		return;
	}

	respondreq(req, packrread(b->blocksize, b->block));
}

static void
vtwrite(Vreq *req)
{
	Block *b;
	Vcall *tc;

	tc = req->tc;
	b = putblock(tc->btype, tc->data, tc->count);
	respondreq(req, packrwrite(b->score));
}

static void
vtsync(Vreq *req)
{
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

	inithtable(hbits);
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
