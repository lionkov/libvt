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

static int opt;
static Vclnt *clnt;

static void
calcscore(uchar *buf, int buflen, uchar *score)
{
	SHA1(buf, buflen, score);
}

static void
usage()
{
	fprintf(stderr, "vtproxy: -h -d -p port\n");
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
	int n, ecode;
	uchar *buf;
	char *ename;


	buf = malloc(req->tc->count);
	n = blockget(clnt, req->tc->score, req->tc->btype, buf, req->tc->count);
	if (n < 0) {
		rerror(&ename, &ecode);
		respondreqerr(req, ename);
		werror(NULL, 0);
	} else
		respondreq(req, packrread(n, buf));

	free(buf);
}

static void
vtwrite(Vreq *req)
{
	int ecode, n, btype;
	char *ename, *buf;
	Vcall *tc;
	uchar score[Vscoresize];

	buf = NULL;
	tc = req->tc;
	n = tc->count;
	btype = tc->btype;
	if (opt) {
		buf = malloc(tc->count);
		memmove(buf, tc->data, tc->count);
		calcscore(tc->data, tc->count, score);
		respondreq(req, packrwrite(score));
	} else
		buf = tc->data;

	if (blockput(clnt, btype, buf, n, score) < 0) {
		rerror(&ename, &ecode);
		if (!opt)
			respondreqerr(req, ename);
		werror(NULL, 0);
	} else if (!opt)
		respondreq(req, packrwrite(score));

	free(buf);
}

static void
vtsync(Vreq *req)
{
	respondreq(req, packrsync());
}

int
main(int argc, char *argv[])
{
	int c, debuglevel, cdebuglevel;
	int port, wthreads;
	char *s, *addr;
	Vsrv *srv;

	debuglevel = 0;
	cdebuglevel = 0;
	port = 17034;
	wthreads = 16;
	while ((c = getopt(argc, argv, "Ddop:h:w:")) != -1) {
		switch (c) {
		case 'D':
			cdebuglevel = 1;
			break;

		case 'd':
			debuglevel = 1;
			break;

		case 'p':
			port = strtol(optarg, &s, 10);
			if (*s != '\0')
				usage();
			break;

		case 'w':
			wthreads = strtol(optarg, &s, 10);
			if (*s != '\0')
				usage();
			break;

		case 'h':
			addr = strdup(optarg);
			break;

		case 'o':
			opt = 1;
			break;

		default:
			usage();
		}
	}

	if (!addr)
		addr = strdup("127.0.0.1");


	clnt = vclntcreate(addr, port, cdebuglevel);
	if (!clnt) {
		fprintf(stderr, "can't connect\n");
		return -1;
	}

	srv = socksrvcreate(wthreads, &port);
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
