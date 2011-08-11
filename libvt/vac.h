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

typedef struct Vacfile Vacfile;
typedef struct Mblock Mblock;
typedef struct Mentry Mentry;
typedef struct Vacentry Vacentry;

enum {
	/* file modes */
	Vacsticky	= (1<<9),
	Vacsetuid	= (1<<10),
	Vacsetgid	= (1<<11),
	Vacappend	= (1<<12),
	Vacexcl		= (1<<13),
	Vaclink		= (1<<14),
	Vacdir		= (1<<15),
	Vacdevice	= (1<<21),
	Vacnpipe	= (1<<22),
};

struct Vacfile {
	pthread_mutex_t	lock;
	char*		name;
	u32		mode;
	u64		size;
	u64		qid;
	char*		uid;
	char*		gid;
	char*		muid;
	u32		mtime;
	u32		ctime;
	u32		atime;

	/* for internal use only */
	int		omode;
	Vfile*		df;

	/* directories only */
	Vfile*		mf;
	Mblock*		mb;
	int		nent;	/* current entry in mb */
};

struct Mblock {
	int		nentries;
	Vacentry**	entries;

	int		maxentries;
	int		maxsize;
	int		size;
};

struct Vacentry {
	char*		name;
	u32		entry;
	u32		gen;
	u32		mentry;
	u32		mgen;
	u64		qid;
	char*		uid;
	char*		gid;
	char*		muid;
	u32		mtime;
	u32		mcount;
	u32		ctime;
	u32		atime;
	u32		mode;
	u64		qidoffset;
	u64		qidmax;

	u64		offset;
};

/* reading vac trees */
Vacfile *vacroot(Vclnt *clnt, uchar *score);
Vacfile *vacwalk(Vacfile *dir, char *path);
Vacfile *vacopen(Vacfile *f, Vacentry *e);
int vacclunk(Vacfile *f);
int64_t vacseek(Vacfile *f, int64_t offset, int type);
int vacread(Vacfile *f, void *buf, int buflen);
Vacentry *vacdirnext(Vacfile *f);

/* writing new vac trees */
int vacrootcreate(Vacfile *f, uchar *pscore, uchar *rootscore);
Vacfile *vaccreate(Vclnt *clnt, u16 bsize, char *name, u32 mode, u64 qid,
	char *uid,char *gid, char *muid, u32 mtime, u32 ctime, u32 atime);
int vacwrite(Vacfile *f, void *buf, int buflen);
int vacdirwrite(Vacfile *dir, Vacfile *f);
