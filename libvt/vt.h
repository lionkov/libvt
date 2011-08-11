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

#include <sys/types.h>
#include <stdint.h>

typedef uint8_t   u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef u8 uchar;
typedef struct Vstr Vstr;
typedef struct Vcall Vcall;

/* server */
typedef struct Vreq Vreq;
typedef struct Vconn Vconn;
typedef struct Vwthread Vwthread;
typedef struct Vsrv Vsrv;

/* client */
typedef struct Vclnt Vclnt;
typedef struct Ventry Ventry;
typedef struct Vblock Vblock;
typedef struct Vfile Vfile;
typedef struct Vroot Vroot;

#define NELEM(x)   (sizeof(x)/sizeof((x)[0]))

enum {
	Vfirst,
	Vrerror		= 1,
	Vtping		= 2,
	Vrping,
	Vthello		= 4,
	Vrhello,
	Vtgoodbye	= 6,
	Vtread		= 12,
	Vrread,
	Vtwrite		= 14,
	Vrwrite,
	Vtsync		= 16,
	Vrsync,
	Vlast,

	Vscoresize	= 20,
	Ventrysize	= 40,
	Vrootsize	= 300,
	Vmaxblock	= 56*1024,
};

/* block type */
enum {
	Vdata		= 0<<3,
	Vdir		= 1<<3,
	Vrblock		= 2<<3,
};

/* open modes */
enum {
	Vowrite		= 1,
	Voread		= 2,
	Vosynced	= 4,
};

struct Vstr {
	u16	len;
	char*	str;
};

struct Vcall {
	uchar	id;
	uchar	tag;

	Vstr	ename;		/* Rerror */
	Vstr	version;	/* Thello */
	Vstr	uid;		/* Thello */
	uchar	strength;	/* Thello */
	Vstr	crypto;		/* Thello */
	Vstr	codec;		/* Thello */
	Vstr	sid;		/* Rhello */
	uchar	rcrypto;	/* Rhello */
	uchar	rcodec;		/* Rhello */
	uchar*	score;		/* Tread, Rwrite */
	uchar	btype;		/* Tread, Rwrite */
	u16	count;		/* Tread */
	uchar*	data;		/* Twrite, Rread */

	u16	size;
	uchar*	pkt;
};

struct Vreq {
	Vconn*	conn;
	Vcall*	tc;
	Vcall*	rc;

	Vreq*	next;
	Vreq*	prev;
};

struct Vconn {
	pthread_mutex_t	lock;
	pthread_cond_t	cond;
	Vsrv*		srv;
	int		shutdown;
	int		fd;

	pthread_t	rthread;
	pthread_t	wthread;
	Vreq*		outreqs;
	Vconn*		prev;
	Vconn*		next;
};

struct Vwthread {
	Vsrv*		srv;
	int		shutdown;
	pthread_t	thread;

	Vwthread*	next;
};

struct Vsrv {
	int		debuglevel;
	void*		aux;

	void		(*start)(Vsrv *);
	void		(*ping)(Vreq *req);
	void		(*hello)(Vreq *req);
	void		(*read)(Vreq *req);
	void		(*write)(Vreq *req);
	void		(*sync)(Vreq *req);

	/* implementation specific */
	void*		srvaux;
	pthread_mutex_t	lock;
	pthread_cond_t	reqcond;
	Vconn*		conns;
	Vwthread*	wthreads;
	Vreq*		reqfirst;
	Vreq*		reqlast;
	Vreq*		workreqs;
};

/* client */
struct Ventry {
	u16		psize;
	u16		dsize;
	uchar		flags;
	u64		size;
	uchar		score[Vscoresize];
};

struct Vroot {
	char		name[128];
	char		type[128];
	uchar		score[Vscoresize];
	ushort		bsize;
	uchar		pscore[Vscoresize];	/* previous root */
};

struct Vfile {
	pthread_mutex_t	lock;
	Vclnt*		clnt;
	int		psize;
	int		dsize;
	int		flags;
	int		size;
	int		omode;
	int		type;
	Vblock*		dblock;
	Vblock*		pblocks[7];
	u64		offset;
	int		depth;
};

struct cbuf {
	unsigned char *sp;
	unsigned char *p;
	unsigned char *ep;
};

extern uchar zeroscore[Vscoresize];

/* conv.c */
int unpack(Vcall *vc, uchar *data);
void settag(Vcall *vc, uchar tag);

/* conn.c */
Vconn *conncreate(Vsrv *srv, int fd);
void conndestroy(Vconn *conn);
void connoutreq(Vconn *conn, Vreq *req);

/* error.c */
void werror(char *ename, int ecode, ...);
void rerror(char **ename, int *ecode);
int haserror();
void uwerror(int ecode);
void suwerror(char *s, int ecode);

/* fmt.c */
int printvcall(FILE *f, Vcall *vc);

/* srv.c */
Vsrv *srvcreate(int nwthread);
void srvstart(Vsrv *srv);
void srvaddconn(Vsrv *srv, Vconn *conn);
int srvdelconn(Vsrv *srv, Vconn *conn);
void srvinreq(Vsrv *srv, Vreq *req);
void respondreq(Vreq *req, Vcall *rc);
void respondreqerr(Vreq *req, char *ename);
Vcall *packrerror(char *ename);
Vcall *packrping(void);
Vcall *packrhello(char *sid, uchar rcrypto, uchar rcodec);
Vcall *packrread(u16 count, uchar *data);
Vcall *packrwrite(uchar *score);
Vcall *packrsync(void);

/* socksrv.c */
Vsrv *socksrvcreate(int nwthreads, int *port);

/* clnt.c */
Vclnt *vclntcreate(char *addr, int port, int debuglevel);
void vclntdisconnect(Vclnt *clnt);
void vclntdestroy(Vclnt *clnt);
int vrpc(Vclnt *clnt, Vcall *tc, Vcall **rc);
int blockget(Vclnt *, uchar *score, int type, void *buf, int buflen);
int blockput(Vclnt *, int type, void *buf, int buflen, uchar *score);
Vcall *packtping(void);
Vcall *packthello(char *version, char *uid, uchar strength, uchar ncrypto,
	uchar *crypto, uchar ncodec, uchar *codec);
Vcall *packtgoodbye(void);
Vcall *packtread(uchar *score, uchar btype, u16 count);
Vcall *packtwrite(uchar type, u16 count, uchar *data);
Vcall *packtsync(void);

/* file.c */
Vfile *vfilecreate(Vclnt *, int flags, u16 psize, u16 dsize);
Vfile *vfileopen(Vclnt *, Ventry *);
int vfileclose(Vfile *);
Vfile *vrootopen(Vclnt *clnt, uchar *score);
int vrootcreate(Vclnt *clnt, char *name, char *type, uchar *score,
	u16 bsize, uchar *pscore, uchar *rootscore);
int ventrypack(Ventry *e, void *buf, int buflen);
Ventry *ventryunpack(void *buf, int buflen);
int vrootpack(Vroot *r, void *buf, int buflen);
Vroot *vrootunpack(void *buf, int buflen);

/* read-only files */
u64 vfileseek(Vfile *f, int64_t offset, int type);
u64 vfiletell(Vfile *f);
int vfileread(Vfile *f, void *buf, int buflen);
Ventry *vdirnext(Vfile *f);

/* write-only files */
int vfilewrite(Vfile *, void *buf, int buflen);
int vfilesync(Vfile *f);
int vfile2entry(Vfile *f, Ventry *e);
int64_t vdirwrite(Vfile *dir, Vfile *f);	/* returns offset */

/* conv.c */
void buf_init(struct cbuf *buf, void *data, int datalen);
int buf_check_overflow(struct cbuf *buf);
int buf_check_end(struct cbuf *buf);
void *buf_alloc(struct cbuf *buf, int len);
void buf_put_int8(struct cbuf *buf, u8 val, u8* pval);
void buf_put_int16(struct cbuf *buf, u16 val, u16 *pval);
void buf_put_int32(struct cbuf *buf, u32 val, u32 *pval);
void buf_put_int48(struct cbuf *buf, u64 val, u64 *pval);
void buf_put_int64(struct cbuf *buf, u64 val, u64 *pval);
void buf_put_str(struct cbuf *buf, char *s, Vstr *ps);
void buf_put_var(struct cbuf *buf, uchar len, uchar *val, Vstr *ps);
void buf_put_score(struct cbuf *buf, uchar *score, uchar **ps);

u8 buf_get_int8(struct cbuf *buf);
u16 buf_get_int16(struct cbuf *buf);
u32 buf_get_int32(struct cbuf *buf);
u64 buf_get_int48(struct cbuf *buf);
u64 buf_get_int64(struct cbuf *buf);
void buf_get_str(struct cbuf *buf, Vstr *str);
void buf_get_var(struct cbuf *buf, Vstr *var);
uchar *buf_get_score(struct cbuf *buf);
