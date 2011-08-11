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
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <errno.h>
#include "vt.h"

typedef struct Socksrv Socksrv;

struct Socksrv {
	int			domain;
	int			type;
	int			proto;
	struct sockaddr*	saddr;
	int			saddrlen;
	
	int			sock;
	int			shutdown;
	pthread_t		listenproc;
};

static void socksrvstart(Vsrv *srv);
static void *socksrvlistenproc(void *a);

static int
socksrvconnect(Socksrv *ss)
{
	int flag;

	flag = 1;
	ss->sock = socket(ss->domain, ss->type, ss->proto);
	if (ss->sock < 0) {
		uwerror(errno);
		return -1;
	}

	setsockopt(ss->sock, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(int));

	if (bind(ss->sock, ss->saddr, ss->saddrlen) < 0) {
		uwerror(errno);
		return -1;
	}

	return 0;
}

Vsrv*
socksrvcreate(int nwthreads, int *port)
{
	int flag;
	socklen_t n;
	Vsrv *srv;
	Socksrv *ss;
	struct sockaddr_in* saddr;

	flag = 1;
	ss = malloc(sizeof(*ss));
	ss->domain = PF_INET;
	ss->type = SOCK_STREAM;
	ss->proto = 0;
	ss->shutdown = 0;
	ss->sock = socket(PF_INET, SOCK_STREAM, 0);
	if (ss->sock < 0) {
		uwerror(errno);
		free(ss);
		return NULL;
	}
	setsockopt(ss->sock, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(int));
	saddr = malloc(sizeof(*saddr));
	ss->saddr = (struct sockaddr *) saddr;
	ss->saddrlen = sizeof(*saddr);

	saddr->sin_family = AF_INET;
	saddr->sin_port = htons(*port);
	saddr->sin_addr.s_addr = htonl(INADDR_ANY);
	if (socksrvconnect(ss) < 0) {
		uwerror(errno);
		free(saddr);
		free(ss);
		return NULL;
	}

	saddr->sin_port = 4242;
	n = sizeof(*saddr);
	if (getsockname(ss->sock, ss->saddr, &n) < 0) {
		uwerror(errno);
		free(saddr);
		free(ss);
		return NULL;
	}

	*port = ntohs(saddr->sin_port);

	srv = srvcreate(nwthreads);
	srv->srvaux = ss;
	srv->start = socksrvstart;

	return srv;
}

static void
socksrvstart(Vsrv *srv)
{
	Socksrv *ss;

	ss = srv->srvaux;
	pthread_create(&ss->listenproc, NULL, socksrvlistenproc, srv);
}

static void *
socksrvlistenproc(void *a)
{
	int csock;
	char b;
	Vsrv *srv;
	Socksrv *ss;
	struct sockaddr_in caddr;
	socklen_t caddrlen;
	char *hello = "venti-02-moo\n";

	srv = a;
	ss = srv->srvaux;

	if (listen(ss->sock, 1) < 0)
		return NULL;

	while (1) {
		caddrlen = sizeof(caddr);
		csock = accept(ss->sock, (struct sockaddr *) &caddr, &caddrlen);
		if (csock<0) {
			close(ss->sock);
			if (socksrvconnect(ss) < 0) {
				fprintf(stderr, "error while reconnecting: %d\n", errno);
				sleep(5);
			}
			continue;
		}

		write(csock, hello, strlen(hello));
		while (read(csock, &b, 1) > 0) {
			if (b == '\n')
				break;
		}

		conncreate(srv, csock);
	}

	return NULL;
}
