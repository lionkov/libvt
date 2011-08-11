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
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <dirent.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include "vt.h"
#include "vac.h"

Vclnt *clnt;
int blocksize = 8192;

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

static char *
uid2uname(int uid)
{
	int n, bufsize;
	struct passwd pw, *pwp;
	char *buf, *ret;

	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize < 256)
		bufsize = 256;

	buf = malloc(bufsize);
	n = getpwuid_r(uid, &pw, buf, bufsize, &pwp);
	if (n) {
		uwerror(n);
		free(buf);
		return NULL;
	}

	ret = strdup(pw.pw_name);
	free(buf);
	return ret;
}

static char *
gid2gname(int gid)
{
	int n, bufsize;
	struct group grp, *pgrp;
	char *buf, *ret;

	bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (bufsize < 256)
		bufsize = 256;

	buf = malloc(bufsize);
	n = getgrgid_r(gid, &grp, buf, bufsize, &pgrp);
	if (n) {
		uwerror(n);
		free(buf);
		return NULL;
	}

	ret = strdup(grp.gr_name);
	free(buf);
	return ret;
}

Vacfile *
vacfile(char *path)
{
	int n, blen, fd;
	char *p, *buf, *uid, *gid;
	struct stat st;
	DIR *d;
	struct dirent *de;
	Vacfile *f, *f1;

	if (stat(path, &st) < 0) {
		uwerror(errno);
		return NULL;
	}

	p = strrchr(path, '/');
	if (p)
		p++;
	else
		p = path;

	uid = uid2uname(st.st_uid);
	gid = gid2gname(st.st_gid);
	f = vaccreate(clnt, blocksize, p, (st.st_mode&0777) | (S_ISDIR(st.st_mode)?Vacdir:0),
		0 /* TODO: qid */, uid, gid, uid, st.st_mtime, st.st_ctime, st.st_atime);
	if (!f)
		return NULL;

	if (S_ISDIR(st.st_mode)) {
		blen = strlen(path) + NAME_MAX + 2;
		buf = malloc(blen);
		d = opendir(path);
		if (!d) {
			uwerror(errno);
			return NULL;
		}

		while ((de = readdir(d)) != NULL) {
			if (de->d_name[0] == '.' && (de->d_name[1]=='.' || de->d_name[1]==0))
				continue;

			snprintf(buf, blen, "%s/%s", path, de->d_name);
			f1 = vacfile(buf);
			if (f1) {
				vacdirwrite(f, f1);
				vacclunk(f1);
			} else if (haserror()) {
				free(buf);
				goto error;
			}
		}
		closedir(d);
		free(buf);
	} else if (S_ISREG(st.st_mode)) {
		blen = 65536;
		buf = malloc(blen);
		fd = open(path, O_RDONLY);
		if (fd < 0) {
			uwerror(errno);
			goto error;
		}

		while ((n = read(fd, buf, blen)) > 0)
			if (vacwrite(f, buf, n) < 0) {
				free(buf);
				close(fd);
				goto error;
			}

		if (n < 0) {
			uwerror(errno);
			free(buf);
			close(fd);
			goto error;
		}
		close(fd);
		free(buf);
	} else
		return NULL;

	free(uid);
	free(gid);
	return f;

error:
	if (f)
		vacclunk(f);

	free(uid);
	free(gid);
	return NULL;
}

int
main(int argc, char *argv[])
{
	int c, debuglevel, fd;
	int port, i;
	char *s, *addr;
	uchar rootscore[Vscoresize];
	Vacfile *f, *d;
	struct stat st;

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

	if (stat(argv[optind], &st) < 0) {
		perror("stat");
		return -1;
	}

	fd = open(argv[optind], O_RDONLY);
	if (fd < 0) {
		perror("open");
		return -1;
	}

	clnt = vclntcreate(addr, port, debuglevel);
	if (!clnt) {
		fprintf(stderr, "can't connect\n");
		return -1;
	}

	d = vaccreate(clnt, 8192, "/", Vacdir | 0777, 0,
		"lucho", "lucho", "lucho", time(NULL), time(NULL), time(NULL));

	for(i = optind; i < argc; i++) {
		f = vacfile(argv[i]);
		if (!f)
			goto error;

		vacdirwrite(d, f);
		vacclunk(f);
	}

	if (vacrootcreate(d, NULL, rootscore) < 0) {
		fprintf(stderr, "vacrootcreate\n");
		return -1;
	}

	for(i = 0; i < Vscoresize; i++)
		printf("%02x", rootscore[i]);
	printf("\n");

	return 0;

error:
	fprintf(stderr, "Error\n");
	return -1;
}
