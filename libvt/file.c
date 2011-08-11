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
#include "vimpl.h"

struct Vblock {
	int	size;
	uchar	*buf;
};

static int vfiledepth(Vfile *f);

static Vfile *
vfilealloc(Vclnt *clnt, int flags, int psize, int dsize)
{
	int i;
	uchar *p;
	Vfile *f;

	psize = psize / Vscoresize;
	f = calloc(1, sizeof(*f) + psize*Vscoresize*7 + dsize + sizeof(Vblock)*8);
	pthread_mutex_init(&f->lock, NULL);
	f->clnt = clnt;
	f->flags = flags;
	f->psize = psize;
	f->dsize = dsize;
	f->dblock = (Vblock *) ((uchar *)f + sizeof(*f));
	f->dblock->buf = (uchar *)f->dblock + sizeof(*f->dblock);
	p = f->dblock->buf + dsize;
	for(i = 0; i < 7; i++) {
		f->pblocks[i] = (Vblock *) p;
		f->pblocks[i]->buf = (uchar *) p + sizeof(Vblock);
		p += f->psize * Vscoresize + sizeof(Vblock);
	}

	return f;
}

int
vfilesync(Vfile *f)
{
	int i, ret;
	u64 n, m;
	uchar *pscore, *p;

	if (!(f->omode&Vowrite)) {
		werror("can't sync read-only file", EIO);
		return -1;
	}

	pthread_mutex_lock(&f->lock);
	if (f->omode & Vosynced) {
		pthread_mutex_unlock(&f->lock);
		return 0;
	}

	ret = 0;
	n = f->size / f->dsize;
	m = f->size % f->dsize;
	if (!m)
		goto out;

	for(i = 0, p = f->dblock->buf; i < 7; i++) {
		pscore = f->pblocks[i]->buf + (n%f->psize) * Vscoresize;
		if (blockput(f->clnt, f->type + i, p, m, pscore) < 0) {
			ret = -1;
			goto out;
		}

		n++;
		if (n == 1)
			break;

		m = (n%f->psize) * Vscoresize;
		n = n / f->psize;
		p = f->pblocks[i]->buf;
	}

	f->depth = vfiledepth(f);
	f->omode |= Vosynced;

out:
	pthread_mutex_unlock(&f->lock);
	return 0;
}

Vfile *
vfilecreate(Vclnt *clnt, int flags, u16 psize, u16 dsize)
{
	Vfile *f;

	f = vfilealloc(clnt, 1 | (flags&Vdir?2:0), psize, dsize);
	f->type = flags;
	f->omode = Vowrite;
	return f;
}

Vfile *
vfileopen(Vclnt *clnt, Ventry *e)
{
	Vfile *f;

	f = vfilealloc(clnt, e->flags&1, e->psize, e->dsize);
	f->type = e->flags&2?Vdir:Vdata;
	f->omode = Voread;
	f->size = e->size;
	f->depth = vfiledepth(f);
	memmove(f->pblocks[f->depth]->buf, e->score, Vscoresize);
	f->offset = f->size;
	vfileseek(f, 0, 0);

	return f;
}

Vfile *
vrootopen(Vclnt *clnt, uchar *score)
{
	char buf[Vrootsize];
	Ventry e;
	Vroot *r;

	if (blockget(clnt, score, Vrblock, buf, sizeof(buf)) < 0)
		return NULL;

	r = vrootunpack(buf, sizeof(buf));
	if (!r)
		return NULL;

	e.psize = r->bsize - r->bsize%Vscoresize;
	e.dsize = r->bsize;
	e.flags = 2;
	e.size = 3 * Ventrysize;
	memmove(e.score, r->score, Vscoresize);
	free(r);

	return vfileopen(clnt, &e);
}

int
vrootcreate(Vclnt *clnt, char *name, char *type, uchar *score,
	u16 bsize, uchar *pscore, uchar *rootscore)
{
	char buf[Vrootsize];
	Vroot r;

	strncpy(r.name, name, sizeof(r.name));
	strncpy(r.type, type, sizeof(r.type));
	memmove(r.score, score, Vscoresize);
	r.bsize = bsize;
	if (pscore)
		memmove(r.pscore, pscore, Vscoresize);
	else
		memmove(r.pscore, zeroscore, Vscoresize);

	if (vrootpack(&r, buf, sizeof(buf)) < 0)
		return -1;

	if (blockput(clnt, Vrblock, buf, sizeof(buf), rootscore) < 0)
		return -1;

	return 0;
}

int
vfileclose(Vfile *f)
{
	if (f->omode & Vowrite)
		vfilesync(f);

	free(f);
	return 0;
}

u64
vfiletell(Vfile *f)
{
	return f->offset;
}

u64
vfileseek(Vfile *f, int64_t offset, int type)
{
	int i, useold;
	int of[7];
	u64 no, oo;
	uchar *pscore;

	if (f->omode & Vowrite) {
		werror("can't seek writable files", EIO);
		return -1;
	}

	pthread_mutex_lock(&f->lock);
	switch (type) {
	case 0:
		break;
	case 1:
		offset += f->offset;
		break;
	case 2:
		offset = f->size + offset;
		break;
	}

	if (offset >= f->size) {
		f->offset = f->size;
		pthread_mutex_unlock(&f->lock);
		return f->offset;
	}

	useold = f->offset < f->size;
	no = offset / f->dsize;
	oo = f->offset / f->dsize;
	for(i = 0; i < f->depth; i++) {
		of[i] = no % f->psize;
		if (useold && no==oo)
			break;

		no /= f->psize;
		oo /= f->psize;
	}

	/* now read the new blocks with scores */
	i--;
	while (i > 0) {
		pscore = f->pblocks[i]->buf + of[i]*Vscoresize;
		if (blockget(f->clnt, pscore, f->type+i, f->pblocks[i-1]->buf,
						f->psize*Vscoresize) < 0) {
			pthread_mutex_unlock(&f->lock);
			return -1;
		}

		i--;
	}

	if (i == 0 || !useold) {
		if (i < 0)
			pscore = f->pblocks[0]->buf;
		else
			pscore = f->pblocks[0]->buf + of[0]*Vscoresize;

		if (blockget(f->clnt, pscore, f->type, f->dblock->buf, f->dsize) < 0) {
			pthread_mutex_unlock(&f->lock);
			return -1;
		}
	}

	f->offset = offset;
	pthread_mutex_unlock(&f->lock);

	return offset;
}

int
vfileread(Vfile *f, void *buf, int buflen)
{
	int n, len;
	char *p, *ep;

	p = buf;
	if (f->offset+buflen > f->size)
		buflen = f->size - f->offset;

	ep = p + buflen;
	while (p < ep) {
		n = f->offset%f->dsize;
		len = f->dsize - n;
		if (len > buflen)
			len = buflen;

		memmove(p, f->dblock->buf + n, len);
		p += len;
		buflen -= len;
		vfileseek(f, len, 1);
	}

	return p - (char *) buf;
}

Ventry *
vdirnext(Vfile *f)
{
	int n;
	char buf[Ventrysize];

	n = vfileread(f, buf, sizeof(buf));
	if (n != sizeof(buf))
		return NULL;

	return ventryunpack(buf, sizeof(buf));
}

static int
vfilewritenolock(Vfile *f, void *buf, int buflen)
{
	int i, n, len, pbsz;
	u64 m;
	uchar *p, *pb, *pscore;

	p = buf;

	while (buflen > 0) {
		n = f->size % f->dsize;
		len = f->dsize - n;
		if (len > buflen)
			len = buflen;

		memmove(f->dblock->buf + n, p, len);
		f->size += len;
		p += len;
		buflen -= len;
	
		if (f->size%f->dsize != 0)
			continue;

		m = f->size/f->dsize - 1;
		pb = f->dblock->buf;
		pbsz = f->dsize;
		for(i = 0; i < 7; i++) {
			pscore = f->pblocks[i]->buf + (m%f->psize)*Vscoresize;
			if (blockput(f->clnt, f->type + i, pb, pbsz, pscore) < 0)
				return -1;

			if ((m+1)%f->psize != 0)
				break;

			m /= f->psize;
			pb = f->pblocks[i+1]->buf;
			pbsz = f->psize * Vscoresize;
		}
	}

	f->offset = f->size;
	return p - (uchar *) buf;
}

int
vfilewrite(Vfile *f, void *buf, int buflen)
{
	int ret;

	pthread_mutex_lock(&f->lock);
	ret = vfilewritenolock(f, buf, buflen);
	pthread_mutex_unlock(&f->lock);
	return ret;
}

int64_t
vdirwrite(Vfile *dir, Vfile *f)
{
	int n;
	int64_t ret;
	char buf[Ventrysize];
	Ventry e;

	vfile2entry(f, &e);
	n = ventrypack(&e, buf, sizeof(buf));
	if (n < 0)
		return -1;

	pthread_mutex_lock(&f->lock);
	ret = dir->offset;
	n = vfilewritenolock(dir, buf, n);
	if (n < 0)
		ret = n;
	pthread_mutex_unlock(&f->lock);

	return ret;
}

static int
vfiledepth(Vfile *f)
{
	int i;
	u64 n;

	n = f->size/f->dsize + (f->size%f->dsize?1:0);
	for(i = 0; n > 1; i++)
		n = n/f->psize + (n%f->psize?1:0);

	return i;
}

int
vfile2entry(Vfile *f, Ventry *e)
{
	if (vfilesync(f) < 0)
		return -1;

	e->psize = f->psize * Vscoresize;
	e->dsize = f->dsize;
	e->flags = f->flags | (f->type==Vdir?2:0) | (vfiledepth(f) << 2);
	e->size = f->size;
	memmove(e->score, f->pblocks[f->depth]->buf, Vscoresize);

	return 0;
}

int
ventrypack(Ventry *e, void *buf, int buflen)
{
	char *p;
	struct cbuf buffer, *bufp;

	bufp = &buffer;
	buf_init(bufp, (char *) buf, buflen);
	buf_put_int32(bufp, 0, NULL);
	buf_put_int16(bufp, e->psize, NULL);
	buf_put_int16(bufp, e->dsize, NULL);
	buf_put_int8(bufp, e->flags, NULL);
	p = buf_alloc(bufp, 5);
	memset(p, 0, 5);
	buf_put_int48(bufp, e->size, NULL);
	buf_put_score(bufp, e->score, NULL);

	if (buf_check_overflow(bufp))
		return -1;

	return bufp->p - bufp->sp;
}

Ventry *
ventryunpack(void *buf, int buflen)
{
	u8 *p;
	struct cbuf buffer, *bufp;
	Ventry *e;

	e = malloc(sizeof(*e));
	bufp = &buffer;
	buf_init(bufp, (char *) buf, buflen);
	buf_get_int32(bufp);	/* gen */
	e->psize = buf_get_int16(bufp);
	e->dsize = buf_get_int16(bufp);
	e->flags = buf_get_int8(bufp);
	buf_alloc(bufp, 5);
	e->size = buf_get_int48(bufp);
	p = buf_get_score(bufp);
	memmove(e->score, p, Vscoresize);

	if (buf_check_overflow(bufp)) {
		free(e);
		return NULL;
	}

	return e;
}

int
vrootpack(Vroot *r, void *buf, int buflen)
{
	char *p;
	struct cbuf buffer, *bufp;

	bufp = &buffer;
	buf_init(bufp, (char *) buf, buflen);
	buf_put_int16(bufp, 2, NULL);		/* version */
	p = buf_alloc(bufp, sizeof(r->name));
	memmove(p, r->name, sizeof(r->name));
	p = buf_alloc(bufp, sizeof(r->type));
	memmove(p, r->type, sizeof(r->type));
	buf_put_score(bufp, r->score, NULL);
	buf_put_int16(bufp, r->bsize, NULL);
	buf_put_score(bufp, r->pscore, NULL);

	if (buf_check_overflow(bufp))
		return -1;

	return bufp->ep - bufp->p;
}

Vroot *
vrootunpack(void *buf, int buflen)
{
	u8 *p;
	u16 n;
	struct cbuf buffer, *bufp;
	Vroot *r;

	r = malloc(sizeof(*r));
	bufp = &buffer;
	buf_init(bufp, (char *) buf, buflen);
	n = buf_get_int16(bufp);	/* version */
	if (n != 2)
		return NULL;

	p = buf_alloc(bufp, sizeof(r->name));
	memmove(r->name, p, sizeof(r->name));
	r->name[sizeof(r->name) - 1] = 0;

	p = buf_alloc(bufp, sizeof(r->type));
	memmove(r->type, p, sizeof(r->type));
	r->type[sizeof(r->type) - 1] = 0;

	p = buf_get_score(bufp);
	memmove(r->score, p, Vscoresize);

	r->bsize = buf_get_int16(bufp);

	p = buf_get_score(bufp);
	memmove(r->pscore, p, Vscoresize);
	
	if (buf_check_overflow(bufp)) {
		free(r);
		return NULL;
	}

	return r;
}
