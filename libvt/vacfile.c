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
#include "vimpl.h"
#include "vac.h"

static Mblock *mbcreate(int maxsize);
static void mbdestroy(Mblock *mb);
static int mbadd(Mblock *mb, Vacentry *ve);
static int mblockpack(Mblock *mb, char *buf, int buflen);
static Mblock *mblockunpack(char *buf, int buflen);
static int vacentrysize(Vacentry *ve);
static int vacentrypack(Vacentry *ve, char *buf, int buflen);
static Vacentry *vacentryunpack(char *mbstart, int offset, int size);

Vacfile *
vacfilealloc(Vacentry *ve, Vfile *df, Vfile *mf)
{
	Vacfile *f;

	f = calloc(1, sizeof(*f) + strlen(ve->name) + strlen(ve->uid) + 
		strlen(ve->gid) + strlen(ve->muid) + 4);

	pthread_mutex_init(&f->lock, NULL);
	f->name = (char *)f + sizeof(*f);
	strcpy(f->name, ve->name);
	f->mode = ve->mode;
	f->size = df->size;
	f->qid = ve->qid;
	f->uid = f->name + strlen(f->name) + 1;
	strcpy(f->uid, ve->uid);
	f->gid = f->uid + strlen(f->uid) + 1;
	strcpy(f->gid, ve->gid);
	f->muid = f->gid + strlen(f->gid) + 1;
	strcpy(f->muid, ve->muid);
	f->mtime = ve->mtime;
	f->ctime = ve->ctime;
	f->atime = ve->atime;

	f->df = df;
	f->mf = mf;

	return f;
}

Vacfile *
vacroot(Vclnt *clnt, uchar *score)
{
	int n, dsize;
	char *buf;
	Vfile *r, *f, *df, *mf;
	Ventry *e;
	Vacfile *root;
	Mblock *mb;

	buf = NULL;
	mb = NULL;
	r = vrootopen(clnt, score);
	if (!r)
		goto error;

	e = vdirnext(r);
	if (!e)
		goto error;

	df = vfileopen(clnt, e);
	free(e);
	if (!df)
		goto error;

	e = vdirnext(r);
	if (!e)
		goto error;

	mf = vfileopen(clnt, e);
	free(e);
	if (!mf)
		goto error;

	e = vdirnext(r);
	if (!e)
		goto error;

	f = vfileopen(clnt, e);
	free(e);
	if (!f)
		goto error;

	dsize = f->dsize;
	buf = malloc(dsize);
	n = vfileread(f, buf, dsize);
	if (n < 0)
		goto error;

	mb = mblockunpack(buf, dsize);
	if (!mb)
		return NULL;

	root = vacfilealloc(mb->entries[0], df, mf);
	if (!root)
		goto error;

	root->omode = Voread;
	mbdestroy(mb);
	vfileclose(f);
	vfileclose(r);
	return root;

error:
	free(buf);
	if (mb)
		mbdestroy(mb);
	if (r)
		vfileclose(r);
	if (f)
		vfileclose(f);
	if (mf)
		vfileclose(root->mf);
	if (df)
		vfileclose(root->df);

	return NULL;
}

Vacfile *
vacopen(Vacfile *dir, Vacentry *ve)
{
	Ventry *de, *me;
	Vfile *df, *mf;
	Vacfile *ret;

	if (!(dir->mode & Vacdir)) {
		werror("not a directory", EIO);
		return NULL;
	}

	vfileseek(dir->df, ve->entry * Ventrysize, 0);
	de = vdirnext(dir->df);
	if (!de)
		return NULL;

	df = vfileopen(dir->df->clnt, de);
	if (!df)
		return NULL;

	if (ve->mode & Vacdir) {
		vfileseek(dir->df, ve->mentry * Ventrysize, 0);
		me = vdirnext(dir->df);
		mf = vfileopen(dir->df->clnt, me);
	} else {
		me = NULL;
		mf = NULL;
	}

	free(me);
	free(de);

	ret = vacfilealloc(ve, df, mf);
	ret->omode = Voread;

	return ret;
}

Vacfile *
vacwalk(Vacfile *dir, char *path)
{
	return NULL;
}

static int
vacsync(Vacfile *f)
{
	int n;
	char *buf;

	if (!(f->omode&Vowrite)) {
		werror("can't sync read-only files", EIO);
		return -1;
	}

	pthread_mutex_lock(&f->lock);
	if (f->omode & Vosynced) {
		pthread_mutex_unlock(&f->lock);
		return 0;
	}

	if (f->mb) {
		buf = malloc(f->mf->dsize);
		if (mblockpack(f->mb, buf, f->mf->dsize) < 0)
			goto error;

		n = vfilewrite(f->mf, buf, f->mf->dsize);
		free(buf);
		if (n < 0)
			goto error;

		mbdestroy(f->mb);
		f->mb = NULL;
		vfilesync(f->mf);
	}

	vfilesync(f->df);
	f->omode |= Vosynced;
	pthread_mutex_unlock(&f->lock);
	return 0;

error:
	pthread_mutex_unlock(&f->lock);
	return -1;
}

int
vacclunk(Vacfile *f)
{
	if (f->omode==Vowrite && vacsync(f)<0)
		return -1;

	if (f->df)
		vfileclose(f->df);
	if (f->mf)
		vfileclose(f->mf);
	if (f->mb)
		mbdestroy(f->mb);

	free(f);

	return 0;
}

int64_t vacseek(Vacfile *f, int64_t offset, int type)
{
	if (f->omode != Voread) {
		werror("can't seek writable files", EIO);
		return -1;
	}

	if (f->mf) {
		if (type != 0 || offset != 0) {
			werror("invalid seek offset", EIO);
			return -1;
		}

		vfileseek(f->mf, 0, 0);
		if (f->mb)
			mbdestroy(f->mb);
		f->nent = 0;
	}

	offset = vfileseek(f->df, offset, type);
	if (offset < 0)
		return -1;

	return 0;
}

int vacread(Vacfile *f, void *buf, int buflen)
{
	if (f->mf) {
		werror("can't read directories", EIO);
		return -1;
	}

	return vfileread(f->df, buf, buflen);
}

Vacentry *vacdirnext(Vacfile *f)
{
	int n;
	char *buf;

	if (f->omode != Voread) {
		werror("permission denied", EPERM);
		return NULL;
	}

	if (!f->mf) {
		werror("not a directory", EIO);
		return NULL;
	}

	if (f->mb && f->mb->nentries > f->nent)
		return f->mb->entries[f->nent++];

	f->nent = 0;
	if (f->mb) {
		mbdestroy(f->mb);
		f->mb = NULL;
	}

	buf = malloc(f->mf->dsize);
	n = vfileread(f->mf, buf, f->mf->dsize);
	if (n < 0) {
		free(buf);
		return NULL;
	}

	f->mb = mblockunpack(buf, n);
	free(buf);
	if (!f->mb)
		return NULL;

	return f->mb->entries[f->nent++];
}

int
vacrootcreate(Vacfile *f, uchar *pscore, uchar *rootscore)
{
	int n;
	char *buf;
	Vacentry ve;
	Vfile *rf, *mf;
	Mblock *mb;
	Ventry e;

	rf = NULL;
	mf = NULL;
	mb = NULL;
	if (!(f->mode&Vacdir)) {
		werror("not a directory", EIO);
		return -1;
	}

	if (vacsync(f) < 0)
		return -1;

	ve.name = f->name;
	ve.entry = 0;
	ve.gen = 0;
	ve.mentry = 1;
	ve.mgen = 0;
	ve.qid = f->qid;
	ve.uid = f->uid;
	ve.gid = f->gid;
	ve.muid = f->muid;
	ve.mtime = f->mtime;
	ve.ctime = f->ctime;
	ve.atime = f->atime;
	ve.mode = f->mode;
	ve.qidoffset = 0; 	/* TODO */
	ve.qidmax = 0;		/* TODO */

	/* create file with Vacentry for the root */
	mf = vfilecreate(f->df->clnt, 0, f->df->dsize, f->df->dsize);
	if (!mf)
		goto error;

	mb = mbcreate(mf->dsize);
	mbadd(mb, &ve);
	buf = malloc(mf->dsize);
	if (mblockpack(mb, buf, mf->dsize) < 0)
		goto error;

	n = vfilewrite(mf, buf, mf->dsize);
	free(buf);
	if (n < 0)
		goto error;

	mbdestroy(mb);

	/* create the root file */
	rf = vfilecreate(f->df->clnt, Vdir, f->df->dsize, f->df->dsize);
	if (!rf)
		goto error;

	if (vdirwrite(rf, f->df) < 0)
		goto error;

	if (vdirwrite(rf, f->mf) < 0)
		goto error;

	if (vdirwrite(rf, mf) < 0)
		goto error;

	vfile2entry(rf, &e);
	vfileclose(mf);
	vfileclose(rf);

	return vrootcreate(f->df->clnt, f->name, "vac", e.score, f->df->dsize,
		pscore, rootscore);

error:
	if (rf)
		vfileclose(rf);

	if (mf)
		vfileclose(mf);

	if (mb)
		mbdestroy(mb);

	return -1;
}

Vacfile *
vaccreate(Vclnt *clnt, u16 bsize, char *name, u32 mode, u64 qid, char *uid,
	char *gid, char *muid, u32 mtime, u32 ctime, u32 atime)
{
	Vacentry ve;
	Vfile *df, *mf;
	Vacfile *ret;

	ve.name = name;
	ve.entry = 0;
	ve.gen = 0;
	ve.mentry = 0;
	ve.mgen = 0;
	ve.qid = qid;
	ve.uid = uid;
	ve.gid = gid;
	ve.muid = muid;
	ve.mtime = mtime;
	ve.ctime = ctime;
	ve.atime = atime;
	ve.mode = mode;
	ve.qidoffset = 0; 	/* TODO */
	ve.qidmax = 0;		/* TODO */

	mf = NULL;
	df = vfilecreate(clnt, mode&Vacdir?Vdir:0, bsize, bsize);
	if (!df)
		return NULL;

	if (mode&Vacdir) {
		mf = vfilecreate(clnt, 0, bsize, bsize);
		if (!mf) {
			vfileclose(df);
			return NULL;
		}
	}

	ret = vacfilealloc(&ve, df, mf);
	ret->omode = Vowrite;

	return ret;
}

int
vacwrite(Vacfile *f, void *buf, int buflen)
{
	if (f->mode & Vacdir) {
		werror("can't write in directory", EIO);
		return -1;
	}

	return vfilewrite(f->df, buf, buflen);
}

int
vacdirwrite(Vacfile *dir, Vacfile *f)
{
	int n;
	int64_t doff, moff;
	char *buf;
	Vacentry ve;

	if (vacsync(f) < 0)
		return -1;

	doff = vdirwrite(dir->df, f->df);
	if (doff < 0)
		return -1;

	if (f->mf) {
		moff = vdirwrite(dir->df, f->mf);
		if (moff < 0)
			return -1;
	} else
		moff = 0;

	ve.name = f->name;
	ve.entry = doff / Ventrysize;
	ve.gen = 0;
	ve.mentry = moff / Ventrysize;
	ve.mgen = 0;
	ve.qid = f->qid;
	ve.uid = f->uid;
	ve.gid = f->gid;
	ve.muid = f->muid;
	ve.mtime = f->mtime;
	ve.ctime = f->ctime;
	ve.atime = f->atime;
	ve.mode = f->mode;
	ve.qidoffset = 0; 	/* TODO */
	ve.qidmax = 0;		/* TODO */

again:
	if (!dir->mb)
		dir->mb = mbcreate(dir->mf->dsize);

	n = mbadd(dir->mb, &ve);
	if (n < 0)
		return -1;
	else if (n == 0) {
		buf = malloc(dir->mf->dsize);
		if (mblockpack(dir->mb, buf, dir->mf->dsize) < 0) {
			free(buf);
			return -1;
		}

		n = vfilewrite(dir->mf, buf, dir->mf->dsize);
		free(buf);
		if (n < 0)
			return -1;

		mbdestroy(dir->mb);
		dir->mb = NULL;
		goto again;
	}

	return 0;
}

static Mblock *
mbcreate(int maxsize)
{
	Mblock *mb;

	mb = malloc(sizeof(*mb));
	mb->nentries = 0;
	mb->entries = NULL;
	mb->maxentries = 0;
	mb->size = 12;
	mb->maxsize = maxsize;

	return mb;
}

static void
mbdestroy(Mblock *mb)
{
	int i;

	for(i = 0; i < mb->nentries; i++)
		free(mb->entries[i]);

	free(mb->entries);
	free(mb);
}

static int
mbadd(Mblock *mb, Vacentry *ve)
{
	int sz;
	Vacentry **p, *ve1;

	if (mb->nentries+1 > mb->maxentries) {
		mb->maxentries += 16;
		p = realloc(mb->entries, mb->maxentries * sizeof(Vacentry *));
		if (!p) {
			werror("no memory", ENOMEM);
			return -1;
		}

		mb->entries = p;
	}

	sz = vacentrysize(ve) + 4;
	if (mb->size+sz > mb->maxsize)
		return 0;

	ve1 = malloc(sizeof(*ve1) + strlen(ve->name) + strlen(ve->uid) +
		strlen(ve->gid) + strlen(ve->muid) + 4);
	ve1->name = (char *)ve1 + sizeof(*ve1);
	strcpy(ve1->name, ve->name);
	ve1->entry = ve->entry;
	ve1->gen = ve->gen;
	ve1->mentry = ve->mentry;
	ve1->mgen = ve->mgen;
	ve1->qid = ve->qid;
	ve1->uid = ve1->name + strlen(ve->name) + 1;
	strcpy(ve1->uid, ve->uid);
	ve1->gid = ve1->uid + strlen(ve->uid) + 1;
	strcpy(ve1->gid, ve->gid);
	ve1->muid = ve1->gid + strlen(ve->gid) + 1;
	strcpy(ve1->gid, ve->gid);
	ve1->mtime = ve->mtime;
	ve1->mcount = ve->mcount;
	ve1->ctime = ve->ctime;
	ve1->atime = ve->atime;
	ve1->mode = ve->mode;
	ve1->qidoffset = ve->qidoffset;
	ve1->qidmax = ve->qidmax;

	mb->entries[mb->nentries] = ve1;
	mb->nentries++;
	mb->size += sz;

	return 1;
}

static int
vecmp(const void *a1, const void *a2)
{
	Vacentry *e1, *e2;

	e1 = *(Vacentry **) a1;
	e2 = *(Vacentry **) a2;

	return strcmp(e1->name, e2->name);
}

static int
mblockpack(Mblock *mb, char *buf, int buflen)
{
	int i, n, np, sz;
	char *p;
	struct cbuf buffer, *bufp;

	n = mb->nentries*4 + 12; /* magic[4] size[2] freesz[2] maxidx[2] nidx[2] */
	p = buf + n; 
	np = buflen - n;

	qsort(mb->entries, mb->nentries, sizeof(Vacentry *), vecmp);
	memset(buf, 0, buflen);
	bufp = &buffer;
	buf_init(bufp, buf, n);
	buf_put_int32(bufp, 0x5656fc7a, NULL);
	buf_put_int16(bufp, buflen, NULL);
	buf_put_int16(bufp, buflen - mb->size, NULL);
	buf_put_int16(bufp, mb->nentries, NULL);
	buf_put_int16(bufp, mb->nentries, NULL);

	for(i = 0; i < mb->nentries; i++) {
		sz = vacentrysize(mb->entries[i]);
		if ((p - buf) + sz > buflen) {
			werror("mblock overflow", EIO);
			goto error;
		}

		buf_put_int16(bufp, p - buf, NULL);
		buf_put_int16(bufp, sz, NULL);
		if (vacentrypack(mb->entries[i], p, sz) < 0)
			goto error;

		p += sz;
	}

	if (buf_check_overflow(bufp)) {
		werror("mblock overflow", EIO);
		goto error;
	}

	return 0;

error:
	return -1;
}

static Mblock *
mblockunpack(char *buf, int buflen)
{
	int i;
	u32 m;
	u16 size, freesz, maxidx, nidx, offset;
	char *p, *vp, *vep;
	struct cbuf buffer, *bufp;
	Mblock *mb;

	bufp = &buffer;
	buf_init(bufp, buf, buflen);

	mb = calloc(1, sizeof(*mb));
	m = buf_get_int32(bufp);
	if (m != 0x5656fc79 && m != 0x5656fc7a) {
		werror("invalid mblock magic", EIO);
		goto error;
	}

	size = buf_get_int16(bufp);
	freesz = buf_get_int16(bufp);
	maxidx = buf_get_int16(bufp);
	nidx = buf_get_int16(bufp);

	if (buf_check_overflow(bufp)) {
		werror("invalid mblock", EIO);
		goto error;
	}

	p = buf;
	vp = p + maxidx * 4;
	vep = p + (size - freesz);
	mb->nentries = nidx;
	mb->entries = malloc(sizeof(Vacentry *) * nidx);
	for(i = 0; i < nidx; i++) {
		offset = buf_get_int16(bufp);
		size = buf_get_int16(bufp);
		mb->entries[i] = vacentryunpack(p, offset, size);
		if (!mb->entries[i])
			goto error;
	}

	return mb;

error:
	free(mb);
	return NULL;
}

static int
vacentrypack(Vacentry *ve, char *buf, int buflen)
{
	struct cbuf buffer, *bufp;

	bufp = &buffer;
	buf_init(bufp, buf, buflen);
	buf_put_int32(bufp, 0x1c4d9072, NULL);
	buf_put_int16(bufp, 9, NULL);
	buf_put_str(bufp, ve->name, NULL);
	buf_put_int32(bufp, ve->entry, NULL);
	buf_put_int32(bufp, ve->gen, NULL);
	buf_put_int32(bufp, ve->mentry, NULL);
	buf_put_int32(bufp, ve->mgen, NULL);
	buf_put_int64(bufp, ve->qid, NULL);
	buf_put_str(bufp, ve->uid, NULL);
	buf_put_str(bufp, ve->gid, NULL);
	buf_put_str(bufp, ve->muid, NULL);
	buf_put_int32(bufp, ve->mtime, NULL);
	buf_put_int32(bufp, ve->mcount, NULL);
	buf_put_int32(bufp, ve->ctime, NULL);
	buf_put_int32(bufp, ve->atime, NULL);
	buf_put_int32(bufp, ve->mode, NULL);
	buf_put_int8(bufp, 2, NULL);
	buf_put_int16(bufp, 16, NULL);
	buf_put_int64(bufp, ve->qidoffset, NULL);
	buf_put_int64(bufp, ve->qidmax, NULL);
	
	if (buf_check_overflow(bufp)) {
		werror("vacentry buffer overflow", EIO);
		return -1;
	}

	return 0;
}

static Vacentry *
vacentryunpack(char *mbstart, int offset, int size)
{
	u16 ver, sz;
	u32 m, entry, gen, mentry, mgen, mtime, mcount, ctime;
	u32 fatime, mode, p9ver;
	u64 qid, qidoffset, qidmax, p9path;
	char *p;
	Vstr name, uid, gid, muid;
	struct cbuf buffer, *bufp;
	struct cbuf buffer1, *bufp1;
	Vacentry *ve;

	bufp = &buffer;
	bufp1 = &buffer1;
	buf_init(bufp, mbstart+offset, size);

	m = buf_get_int32(bufp);
	if (m != 0x1c4d9072) {
		werror("invalid vacentry magic", EIO);
		return NULL;
	}

	ver = buf_get_int16(bufp);
	if (ver!=9 && ver!=8) {
		werror("invalid vacentry version", EIO);
		return NULL;
	}

	buf_get_str(bufp, &name);
	entry = buf_get_int32(bufp);
	if (ver==9) {
		gen = buf_get_int32(bufp);
		mentry = buf_get_int32(bufp);
		mgen = buf_get_int32(bufp);
	} else {
		gen = 0;
		mentry = entry + 1;
		mgen = 0;
	}

	qid = buf_get_int64(bufp);
	buf_get_str(bufp, &uid);
	buf_get_str(bufp, &gid);
	buf_get_str(bufp, &muid);
	mtime = buf_get_int32(bufp);
	mcount = buf_get_int32(bufp);
	ctime = buf_get_int32(bufp);
	fatime = buf_get_int32(bufp);
	mode = buf_get_int32(bufp);

	p9path = 0;
	p9ver = 0;
	qidmax = 0;
	qidoffset = 0;
	while (!buf_check_end(bufp)) {
		m = buf_get_int8(bufp);
		sz = buf_get_int16(bufp);
		p = buf_alloc(bufp, sz);
		buf_init(bufp1, p, sz);

		switch (m) {
		case 1:
			if (ver >= 9) {
				p9path = buf_get_int64(bufp1);
				p9ver = buf_get_int32(bufp1);
			}
			break;

		case 3:
			qidoffset = buf_get_int64(bufp1);
			qidmax = buf_get_int64(bufp1);
			break;

		case 4:
			gen = buf_get_int32(bufp1);
			break;
		}

		if (buf_check_overflow(bufp1)) {
			werror("invalid vacentry", EIO);
			return NULL;
		}
	}

	if (buf_check_overflow(bufp)) {
		werror("invalid vacentry", EIO);
		return NULL;
	}

	ve = malloc(sizeof(*ve) + name.len + uid.len + gid.len + muid.len + 4);
	ve->name = (char *)ve + sizeof(*ve);
	memmove(ve->name, name.str, name.len);
	ve->name[name.len] = '\0';
	ve->entry = entry;
	ve->gen = gen;
	ve->mentry = mentry;
	ve->mgen = mgen;
	ve->qid = qid;
	ve->uid = ve->name + name.len + 1;
	memmove(ve->uid, uid.str, uid.len);
	ve->uid[uid.len] = '\0';
	ve->gid = ve->uid + uid.len + 1;
	memmove(ve->gid, gid.str, gid.len);
	ve->gid[gid.len] = '\0';
	ve->muid = ve->gid + gid.len + 1;
	memmove(ve->gid, gid.str, gid.len);
	ve->gid[gid.len] = '\0';
	ve->mtime = mtime;
	ve->mcount = mcount;
	ve->ctime = ctime;
	ve->atime = fatime;
	ve->mode = mode;
	ve->qidoffset = qidoffset;
	ve->qidmax = qidmax;
	ve->offset = offset;

	return ve;
}

static int vacentrysize(Vacentry *ve)
{
	int sz;

	sz = 4 + 2 + 2;	/* magic[4] version[2] name[s] */
	if (ve->name)
		sz += strlen(ve->name);

	sz += 4 + 4 + 4 + 4 + 8; /* entry[4] gen[4] mentry[4] mgen[4] qid[8] */

	sz += 2 + 2 + 2;	/* uid[s] gid[s] muid[s] */
	if (ve->uid)
		sz += strlen(ve->uid);
	if (ve->gid)
		sz += strlen(ve->gid);
	if (ve->muid)
		sz += strlen(ve->muid);

	sz += 4 + 4 + 4 + 4 + 4; /* mtime[4] mcount[4] ctime[4] atime[4] mode[4] */
	sz += 1 + 2 + 8 + 8;	/* exttype[1] extsize[2] qidoffset[8] qidmax[8] */

	return sz;
}
