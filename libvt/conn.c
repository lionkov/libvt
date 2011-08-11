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
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include "vt.h"

static void *connrproc(void *a);
static void *connwproc(void *a);
static Vcall *vcalloc(void);
static void vcfree(Vcall *vc);
static Vreq *reqalloc(Vconn *conn, Vcall *tc);
static void reqfree(Vreq *req);

Vconn *
conncreate(Vsrv *srv, int fd)
{
	Vconn *conn;

	conn = malloc(sizeof(*conn));
	conn->shutdown = 0;
	pthread_mutex_init(&conn->lock, NULL);
	pthread_cond_init(&conn->cond, NULL);
	conn->srv = srv;
	conn->shutdown = 0;
	conn->fd = fd;
	conn->outreqs = NULL;
	conn->prev = NULL;
	conn->next = NULL;
	srvaddconn(srv, conn);
	pthread_create(&conn->rthread, NULL, connrproc, conn);
	pthread_create(&conn->wthread, NULL, connwproc, conn);

	return conn;
}

void
conndestroy(Vconn *conn)
{
	if (!srvdelconn(conn->srv, conn))
		return;

	pthread_mutex_lock(&conn->lock);
	conn->shutdown = 1;
	if (conn->fd >= 0) {
		close(conn->fd);
		conn->fd = -1;
	}
	pthread_cond_signal(&conn->cond);
	pthread_mutex_unlock(&conn->lock);
}

void
connoutreq(Vconn *conn, Vreq *req)
{
	pthread_mutex_lock(&conn->lock);
	req->next = conn->outreqs;
	conn->outreqs = req;
	pthread_cond_broadcast(&conn->cond);
	pthread_mutex_unlock(&conn->lock);
}

static void *
connrproc(void *a)
{
	int i, n, size, fd;
	Vconn *conn;
	Vsrv *srv;
	Vcall *vc, *vc1;
	Vreq *req;

	pthread_detach(pthread_self());
	conn = a;
	srv = conn->srv;
	fd = conn->fd;
	vc = vcalloc();
	n = 0;
	while ((i = read(fd, vc->pkt + n, Vmaxblock - n)) > 0) {
		n += i;
again:
		if (n < 2)
			continue;

		size = (vc->pkt[1] | (vc->pkt[0]<<8)) + 2;
		if (n < size)
			continue;

		n = unpack(vc, vc->pkt);
		if (srv->debuglevel) {
			fprintf(stderr, "<<< ");
			printvcall(stderr, vc);
			fprintf(stderr, "\n");
		}

		vc1 = vcalloc();
		if (n > size)
			memmove(vc1->pkt, vc->pkt + size, n - size);
		n -= size;

		req = reqalloc(conn, vc);
		srvinreq(srv, req);
		vc = vc1;
		if (n > 0)
			goto again;
	}

	vcfree(vc);
	if (srvdelconn(srv, conn)) {
		conn->shutdown = 1;
		pthread_cond_signal(&conn->cond);
	}

	return NULL;
}

static void *
connwproc(void *a)
{
	int err, n, fd;
	Vconn *conn;
	Vsrv *srv;
	Vcall *vc;
	Vreq *req, *req1;

	pthread_detach(pthread_self());
	conn = a;
	srv = conn->srv;
	fd = conn->fd;
	pthread_mutex_lock(&conn->lock);
	while (!conn->shutdown) {
		req = conn->outreqs;
		if (!req) {
			pthread_cond_wait(&conn->cond, &conn->lock);
			continue;
		}

		conn->outreqs = req->next;
		pthread_mutex_unlock(&conn->lock);
		if (srv->debuglevel) {
			fprintf(stderr, ">>> ");
			printvcall(stderr, req->rc);
			fprintf(stderr, "\n");
		}

		n = 0;
		vc = req->rc;
		while (n < vc->size) {
			err = write(fd, vc->pkt + n, vc->size - n);
			if (err < 0)
				break;

			n += err;
		}

		vcfree(req->tc);
		free(req->rc);
		reqfree(req);
		pthread_mutex_lock(&conn->lock);
		if (err < 0)
			break;
	}

	/* free all requests waiting to go out */
	req = conn->outreqs;
	conn->outreqs = NULL;
	while (req) {
		req1 = req->next;
		vcfree(req->tc);
		free(req->rc);
		reqfree(req);
		req = req1;
	}

	pthread_mutex_unlock(&conn->lock);
	srvdelconn(srv, conn);
	free(conn);

	return NULL;
}

static Vcall *
vcalloc(void)
{
	Vcall *vc;

	vc = malloc(sizeof(*vc) + Vmaxblock);
	vc->size = Vmaxblock;
	vc->pkt = (uchar *)vc + sizeof(*vc);

	return vc;
}

static void
vcfree(Vcall *vc)
{
	free(vc);
}

static Vreq *
reqalloc(Vconn *conn, Vcall *tc)
{
	Vreq *req;

	req = calloc(1, sizeof(*req));
	req->conn = conn;
	req->tc = tc;

	return req;
}

static void
reqfree(Vreq *req)
{
	free(req);
}
