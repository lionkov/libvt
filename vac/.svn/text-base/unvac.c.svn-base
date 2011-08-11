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
#include "vac.h"

static void
usage()
{
	fprintf(stderr, "vac: -h addr -p port score\n");
	exit(-1);
}

int
str2score(char *s, uchar *score)
{
	int i;
	char *p, buf[3];

	buf[2] = '\0';
	for(i = 0; i < Vscoresize; i++) {
		buf[0] = s[i*2];
		buf[1] = s[i*2 + 1];
		score[i] = strtol(buf, &p, 16);
		if (*p != '\0')
			return -1;
	}

	return 0;
}

int
printnames(char *prefix, Vacfile *f)
{
	char buf[64];
	Vacentry *ve;
	Vacfile *ff;

	while ((ve = vacdirnext(f)) != NULL) {
		printf("%s name %s mode %x entry %d\n", prefix, ve->name, ve->mode, ve->entry);
		if (ve->mode & Vacdir) {
			snprintf(buf, sizeof(buf), "%s\t", prefix);
			ff = vacopen(f, ve);
			printnames(buf, ff);
			vacclunk(ff);
		}
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	int c, debuglevel;
	int port, n;
	char *s, *addr;
	uchar score[Vscoresize];
	char buf[65536];
	Vclnt *clnt;
	Vacfile *f;

	debuglevel = 0;
	port = 17034;
	addr = NULL;
	while ((c = getopt(argc, argv, "dp:h:")) != -1) {
		switch (c) {
		case 'd':
			debuglevel = 1;
			break;

		case 'p':
			port = strtol(optarg, &s, 10);
			if (*s != '\0')
				usage();
			break;

		case 'h':
			addr = strdup(optarg);
			break;

		default:
			usage();
		}
	}

	if (!addr)
		addr = strdup("127.0.0.1");

	if (optind >= argc)
		usage();

	if (str2score(argv[optind], score) < 0) {
		fprintf(stderr, "invalid score\n");
		return -1;
	}

	clnt = vclntcreate(addr, port, debuglevel);
	if (!clnt) {
		fprintf(stderr, "can't connect\n");
		return -1;
	}

	f = vacroot(clnt, score);
	printnames("", f);
	vacclunk(f);

	return 0;

error:
	fprintf(stderr, "Error\n");
	return -1;
}
