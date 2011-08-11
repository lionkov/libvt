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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <time.h>
#include "vt.h"
#include "vimpl.h"

typedef struct Vcreq Vcreq;
typedef struct Vcpool Vcpool;
typedef struct Vcrpc Vcrpc;

struct Vcreq {
	Vclnt*		clnt;
	u8		tag;
	Vcall*		tc;
	Vcall*		rc;

	void		(*cb)(Vcreq *, void *);
	void*		cba;
	Vcreq*		next;
};

struct Vcpool {
	pthread_mutex_t	lock;
	pthread_cond_t	cond;
	u32		maxid;
	int		msize;
	uchar*		map;
};

struct Vclnt {
	pthread_mutex_t	lock;
	pthread_cond_t	cond;
	int		fd;
	int		debuglevel;

	Vcpool*		tagpool;

	Vcreq*		unsentfirst;
	Vcreq*		unsentlast;
	Vcreq*		pendfirst;

	pthread_t	readproc;
	pthread_t	writeproc;
};

struct Vcrpc {
	pthread_mutex_t	lock;
	pthread_cond_t	cond;
	Vcall*		tc;
	Vcall*		rc;
	int		ecode;
	char*		ename;
};

static Vcreq *reqalloc(Vclnt *);
static void reqfree(Vcreq *req);
static Vcall *vcalloc(void);
static void vcfree(Vcall *vc);
static void vrpccb(Vcreq *req, void *cba);
static void *clntwproc(void *a);
static void *clntrproc(void *a);

static Vcpool *vpoolcreate(u32 maxid);
static void vpooldestroy(Vcpool *p);
static u32 vpoolgetid(Vcpool *p);
static void vpoolputid(Vcpool *p, u32 id);

static char banner[] = "venti-02-libventi\n";

Vclnt *
vclntcreate(char *addr, int port, int debuglevel)
{
	int i, n, fd;
	char p[256];
	Vclnt *clnt;
	Vcall *tc, *rc;
	struct sockaddr_in saddr;
	struct hostent *hostinfo;

/*
	struct addrinfo *addrs;

	snprintf(p, sizeof(p), "%d", port);
	if (getaddrinfo(addr, p, NULL, &addrs) < 0)
		return NULL;

	fd = socket(addrs->ai_family, addrs->ai_socktype, 0);
	if (fd < 0)
		return NULL;

	if (connect(fd, addrs->ai_addr, sizeof(*addrs->ai_addr)) < 0) {
		perror("connect");
		close(fd);
		return NULL;
	}
	freeaddrinfo(addrs);
*/

	fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		uwerror(errno);
		return NULL;
	}

	hostinfo = gethostbyname(addr);
	if (!hostinfo) {
		werror("can't resolve", EIO);
		return NULL;
	}

	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);
	saddr.sin_addr = *(struct in_addr *) hostinfo->h_addr;

	if (connect(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
		uwerror(errno);
		return NULL;
	}

	write(fd, banner, strlen(banner));
	for(i = 0; i < sizeof(p); i++) {
		n = read(fd, &p[i], 1);
		if (n < 0) {
			uwerror(errno);
			return NULL;
		}

		if (p[i] == '\n') {
			p[i] = '\0';
			break;
		}
	}

	if (memcmp(p, banner, 9) != 0)
		return NULL;

	clnt = malloc(sizeof(*clnt));
	pthread_mutex_init(&clnt->lock, NULL);
	pthread_cond_init(&clnt->cond, NULL);
	clnt->fd = fd;
	clnt->unsentfirst = NULL;
	clnt->unsentlast = NULL;
	clnt->pendfirst = NULL;
	clnt->writeproc = 0;
	clnt->readproc = 0;
	clnt->tagpool = vpoolcreate(255);
	pthread_create(&clnt->readproc, NULL, clntrproc, clnt);
	pthread_create(&clnt->writeproc, NULL, clntwproc, clnt);
	clnt->debuglevel = debuglevel;

	tc = packthello("02", "anonymous", 0, 0, NULL, 0, NULL);
	if (vrpc(clnt, tc, &rc) < 0)
		return NULL;

	if (rc->id != Vrhello)
		return NULL;

	free(tc);
	free(rc);
	return clnt;
}

void
vclntdisconnect(Vclnt *clnt)
{
	void *v;
	pthread_t rproc, wproc;

	pthread_mutex_lock(&clnt->lock);
	if (clnt->fd >= 0) {
		shutdown(clnt->fd, 2);
		close(clnt->fd);
		clnt->fd = -1;
	}
	rproc = clnt->readproc;
	clnt->readproc = 0;
	wproc = clnt->writeproc;
	clnt->writeproc = 0;
	pthread_cond_broadcast(&clnt->cond);
	pthread_mutex_unlock(&clnt->lock);

	if (rproc)
		pthread_join(rproc, &v);

	if (wproc)
		pthread_join(wproc, &v);
}

void
vclntdestroy(Vclnt *clnt)
{
	pthread_mutex_lock(&clnt->lock);
	if (clnt->tagpool) {
		vpooldestroy(clnt->tagpool);
		clnt->tagpool = NULL;
	}
	pthread_mutex_unlock(&clnt->lock);
	free(clnt);
}

static void *
clntrproc(void *a)
{
	int i, n, size, fd;
	Vclnt *clnt;
	Vcall *vc, *vc1;
	Vcreq *req, *req1, *unsent, *pend, *preq;

	clnt = a;
	vc = vcalloc();
	n = 0;
	fd = clnt->fd;
	while ((i = read(fd, vc->pkt + n, vc->size - n)) > 0) {
//		if (i == 0)
//			continue;

		n += i;

again:
		if (n < 2)
			continue;

		size = (vc->pkt[1] | (vc->pkt[0]<<8)) + 2;
		if (n < size)
			continue;

		n = unpack(vc, vc->pkt);
		if (clnt->debuglevel) {
			fprintf(stderr, "<<< ");
			printvcall(stderr, vc);
			fprintf(stderr, "\n");
		}

		vc1 = vcalloc();
		if (n > size)
			memmove(vc1->pkt, vc->pkt + size, n - size);
		n -= size;

		pthread_mutex_lock(&clnt->lock);
//		printf("- tag %d %d\n", vc->tag, vc->size);
		for(preq = NULL, req = clnt->pendfirst; req != NULL; preq = req, req = req->next) {
			if (req->tag == vc->tag) {
				if (preq)
					preq->next = req->next;
				else
					clnt->pendfirst = req->next;

				pthread_mutex_unlock(&clnt->lock);
				req->rc = vc;
				(*req->cb)(req, req->cba);
				reqfree(req);
				break;
			}
		}

		pthread_mutex_unlock(&clnt->lock);
		if (!req) {
			fprintf(stderr, "unmatched response: ");
			printvcall(stderr, vc);
			fprintf(stderr, "\n");
			free(vc);
		}

		vc = vc1;
		if (n > 0)
			goto again;
	}

	vcfree(vc);
	pthread_mutex_lock(&clnt->lock);
	unsent = clnt->unsentfirst;
	clnt->unsentfirst = NULL;
	clnt->unsentlast = NULL;
	pend = clnt->pendfirst;
	clnt->pendfirst = NULL;
	pthread_mutex_unlock(&clnt->lock);

	uwerror(EPIPE);
	req = unsent;
	while (req) {
		req1 = req->next;
		(*req->cb)(req, req->cba);
		reqfree(req);
		req = req1;
	}

	req = pend;
	while (req) {
		req1 = req->next;
		(*req->cb)(req, req->cba);
		reqfree(req);
		req = req1;
	}
	return NULL;
}

static void *
clntwproc(void *a)
{
	int i, n, sz;
	uchar *p;
	Vcreq *req;
	Vclnt *clnt;

	clnt = a;
	pthread_mutex_lock(&clnt->lock);
	while (clnt->fd >= 0) {
		req = clnt->unsentfirst;
		if (!req) {
			pthread_cond_wait(&clnt->cond, &clnt->lock);
			continue;
		}

		clnt->unsentfirst = req->next;
		if (!clnt->unsentfirst)
			clnt->unsentlast = NULL;

		req->next = clnt->pendfirst;
		clnt->pendfirst = req;
		if (clnt->fd < 0)
			break;

		pthread_mutex_unlock(&clnt->lock);

		if (clnt->debuglevel) {
			fprintf(stderr, "<<< ");
			printvcall(stderr, req->tc);
			fprintf(stderr, "\n");
		}

		n = 0;
		sz = req->tc->size;
		p = req->tc->pkt;
		while (n < sz) {
			i = write(clnt->fd, p + n, sz - n);
//			printf("+ %p tag %d %d %d\n", req, req->tc->tag, n, req->tc->size);
			if (i <= 0)
				break;
			n += i;
		}
		pthread_mutex_lock(&clnt->lock);
		if (i < 0) {
			if (clnt->fd>=0) {
				shutdown(clnt->fd, 2);
				close(clnt->fd);
			}
			break;
		}
	}

	pthread_mutex_unlock(&clnt->lock);
	return NULL;
}

int
vrpcnb(Vclnt *clnt, Vcall *tc, void (*cb)(Vcreq *, void *), void *cba)
{
	Vcreq *req;

	req = reqalloc(clnt);
	req->tc = tc;
	req->cb = cb;
	req->cba = cba;
	settag(tc, req->tag);

	pthread_mutex_lock(&clnt->lock);
	if (clnt->fd < 0) {
		pthread_mutex_unlock(&clnt->lock);
		reqfree(req);
		werror("no connection", EPIPE);
		return -1;
	}

	if (clnt->unsentlast)
		clnt->unsentlast->next = req;
	else
		clnt->unsentfirst = req;

	clnt->unsentlast = req;
	pthread_mutex_unlock(&clnt->lock);
	pthread_cond_signal(&clnt->cond);

	return 0;
}

static void
vrpccb(Vcreq *req, void *cba)
{
	char *ename;
	Vcrpc *r;

	r = cba;
	pthread_mutex_lock(&r->lock);
	r->rc = req->rc;
	if (haserror()) {
		rerror(&ename, &r->ecode);
		r->ename = strdup(ename);
		werror(NULL, 0);
	}
	pthread_mutex_unlock(&r->lock);
	pthread_cond_signal(&r->cond);
}

int
vrpc(Vclnt *clnt, Vcall *tc, Vcall **rc)
{
	int n;
	Vcrpc r;
	struct timeval tv;
	struct timespec ts;

	if (rc)
		*rc = NULL;

	r.tc = tc;
	r.rc = NULL;
	r.ecode = 0;
	r.ename = NULL;
	pthread_mutex_init(&r.lock, NULL);
	pthread_cond_init(&r.cond, NULL);
	gettimeofday(&tv, NULL);
	ts.tv_sec = tv.tv_sec + 15;
	ts.tv_nsec = 0;
	if (!vrpcnb(clnt, tc, vrpccb, &r)) {
		pthread_mutex_lock(&r.lock);
		while (!r.rc && r.ecode == 0) {
			n = pthread_cond_timedwait(&r.cond, &r.lock, &ts);
			if (n == ETIMEDOUT) {
				ts.tv_sec += 15;
				shutdown(clnt->fd, SHUT_RDWR);
			}
		}

		pthread_mutex_unlock(&r.lock);
	}

	if (rc)
		*rc = r.rc;
	else
		free(r.rc);

	if (r.ecode)
		werror(r.ename, r.ecode);

	free(r.ename);

	return haserror()?-1:0;
}

int
blockget(Vclnt *clnt, uchar *score, int type, void *buf, int buflen)
{
	int n;
	Vcall *tc, *rc;

	tc = packtread(score, type, buflen);
	n = vrpc(clnt, tc, &rc);
	free(tc);
	if (n < 0)
		return n;

	if (rc->id == Vrread) {
		n = rc->count;
		if (n > buflen)
			n = buflen;

		memmove(buf, rc->data, n);
	} else
		n = -1;

	free(rc);
	return n;
}

int
blockput(Vclnt *clnt, int type, void *buf, int buflen, uchar *score)
{
	int n;
	Vcall *tc, *rc;

	tc = packtwrite(type, buflen, buf);
	n = vrpc(clnt, tc, &rc);
	free(tc);
	if (n < 0)
		return n;

	if (rc->id == Vrwrite) {
		memmove(score, rc->score, Vscoresize);
		n = 0;
	} else
		n = -1;

	free(rc);
	return n;
}

static Vcreq *
reqalloc(Vclnt *clnt)
{
	Vcreq *req;

	req = calloc(1, sizeof(*req));
	req->clnt = clnt;
	req->tag = vpoolgetid(clnt->tagpool);

	return req;
}

static void
reqfree(Vcreq *req)
{
	vpoolputid(req->clnt->tagpool, req->tag);
	free(req);
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

static u8 m2id[] = {
	0, 1, 0, 2, 0, 1, 0, 3, 
	0, 1, 0, 2, 0, 1, 0, 4, 
	0, 1, 0, 2, 0, 1, 0, 3, 
	0, 1, 0, 2, 0, 1, 0, 5, 
	0, 1, 0, 2, 0, 1, 0, 3, 
	0, 1, 0, 2, 0, 1, 0, 4, 
	0, 1, 0, 2, 0, 1, 0, 3, 
	0, 1, 0, 2, 0, 1, 0, 6, 
	0, 1, 0, 2, 0, 1, 0, 3, 
	0, 1, 0, 2, 0, 1, 0, 4, 
	0, 1, 0, 2, 0, 1, 0, 3, 
	0, 1, 0, 2, 0, 1, 0, 5, 
	0, 1, 0, 2, 0, 1, 0, 3, 
	0, 1, 0, 2, 0, 1, 0, 4, 
	0, 1, 0, 2, 0, 1, 0, 3, 
	0, 1, 0, 2, 0, 1, 0, 7, 
	0, 1, 0, 2, 0, 1, 0, 3, 
	0, 1, 0, 2, 0, 1, 0, 4, 
	0, 1, 0, 2, 0, 1, 0, 3, 
	0, 1, 0, 2, 0, 1, 0, 5, 
	0, 1, 0, 2, 0, 1, 0, 3, 
	0, 1, 0, 2, 0, 1, 0, 4, 
	0, 1, 0, 2, 0, 1, 0, 3, 
	0, 1, 0, 2, 0, 1, 0, 6, 
	0, 1, 0, 2, 0, 1, 0, 3, 
	0, 1, 0, 2, 0, 1, 0, 4, 
	0, 1, 0, 2, 0, 1, 0, 3, 
	0, 1, 0, 2, 0, 1, 0, 5, 
	0, 1, 0, 2, 0, 1, 0, 3, 
	0, 1, 0, 2, 0, 1, 0, 4, 
	0, 1, 0, 2, 0, 1, 0, 3, 
	0, 1, 0, 2, 0, 1, 0, 0,
};

static Vcpool *
vpoolcreate(u32 maxid)
{
	Vcpool *p;

	p = malloc(sizeof(*p));
	p->maxid = maxid;
	pthread_mutex_init(&p->lock, NULL);
	pthread_cond_init(&p->cond, NULL);
	p->msize = 32;
	p->map = calloc(p->msize, 1);

	return p;
}

static void
vpooldestroy(Vcpool *p)
{
	free(p->map);
	free(p);
}

static u32
vpoolgetid(Vcpool *p)
{
	int i, n;
	u32 ret;
	uchar *pt;

	pthread_mutex_lock(&p->lock);
again:
	for(i = 0; i < p->msize; i++)
		if (p->map[i] != 0xFF)
			break;

	if (i>=p->msize && p->msize*8<p->maxid) {
		n = p->msize + 32;
		if (n*8 > p->maxid)
			n = p->maxid/8 + 1;

		pt = realloc(p->map, n);
		if (pt) {
			memset(pt + p->msize, 0, n - p->msize);
			p->map = pt;
			i = p->msize;
			p->msize = n;
		}
	}

	if (i >= p->msize) {
		pthread_cond_wait(&p->cond, &p->lock);
		goto again;
	}

	ret = m2id[p->map[i]];
	p->map[i] |= 1 << ret;
	ret += i * 8;
	pthread_mutex_unlock(&p->lock);

	return ret;
}

static void
vpoolputid(Vcpool *p, u32 id)
{
	pthread_mutex_lock(&p->lock);
	if (id < p->msize*8)
		p->map[id / 8] &= ~(1 << (id % 8));
	pthread_mutex_unlock(&p->lock);
	pthread_cond_broadcast(&p->cond);
}

Vcall *
packtping(void)
{
	return vcempty(Vtping);
}

Vcall *
packthello(char *version, char *uid, uchar strength, uchar ncrypto,
			uchar *crypto, uchar ncodec, uchar *codec)
{
	int size;
	Vcall *vc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	size = strlen(version) + 7 + ncrypto + ncodec;	/* version[s] strength[1] crypto[n] codec[n] */
	if (uid)
		size += strlen(uid);	/* uid[s] */

	vc = vcpack(bufp, size, Vthello);
	if (!vc)
		return NULL;

	buf_put_str(bufp, version, &vc->version);
	buf_put_str(bufp, uid, &vc->uid);
	buf_put_int8(bufp, strength, &vc->strength);
	buf_put_var(bufp, ncrypto, crypto, &vc->crypto);
	buf_put_var(bufp, ncodec, codec, &vc->codec);

	return vc;
}

Vcall *
packtgoodbye(void)
{
	return vcempty(Vtgoodbye);
}

Vcall *
packtread(uchar *score, uchar btype, u16 count)
{
	int size;
	Vcall *vc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	size = Vscoresize + 1 + 1 + 2; /* score[20] type[1] pad[1] count[2] */
	vc = vcpack(bufp, size, Vtread);
	if (!vc)
		return NULL;

	buf_put_score(bufp, score, &vc->score);
	buf_put_int8(bufp, vtodisktype(btype), &vc->btype);
	buf_put_int8(bufp, 0, NULL);
	buf_put_int16(bufp, count, &vc->count);

	return vc;
}

Vcall *
packtwrite(uchar type, u16 count, uchar *data)
{
	int size;
	Vcall *vc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	size = 1 + 3 + count;	/* type[1] pad[3] data[] */
	vc = vcpack(bufp, size, Vtwrite);
	if (!vc)
		return NULL;

	buf_put_int8(bufp, vtodisktype(type), &vc->btype);
	buf_put_int16(bufp, 0, NULL);
	buf_put_int8(bufp, 0, NULL);
	vc->data = buf_alloc(bufp, count);
	memmove(vc->data, data, count);
	vc->count = count;

	return vc;
}

Vcall *
packtsync(void)
{
	return vcempty(Vtsync);
}

