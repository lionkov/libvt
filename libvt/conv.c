#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "vt.h"
#include "vimpl.h"

enum {
	Overrtype,
	Ovroottype,
	Ovdirtype,
	Ovptype0,
	Ovptype1,
	Ovptype2,
	Ovptype3,
	Ovptype4,
	Ovptype5,
	Ovptype6,
	Ovptype7,
	Ovptype8,
	Ovptype9,
	Ovdtype,
	Ovmaxtype,
};


u16 todisk[] = {
	Ovdtype,
	Ovptype0,
	Ovptype1,
	Ovptype2,
	Ovptype3,
	Ovptype4,
	Ovptype5,
	Ovptype6,
	Ovdirtype,
	Ovptype0,
	Ovptype1,
	Ovptype2,
	Ovptype3,
	Ovptype4,
	Ovptype5,
	Ovptype6,
	Ovroottype,
};

uint fromdisk[] = {
	-1,
	Vrblock,
	Vdir,
	Vdir+1,
	Vdir+2,
	Vdir+3,
	Vdir+4,
	Vdir+5,
	Vdir+6,
	Vdir+7,
	-1,
	-1,
	-1,
	Vdata,
};

uchar zeroscore[Vscoresize] = {
	0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
	0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
};

void
buf_init(struct cbuf *buf, void *data, int datalen)
{
	buf->sp = data;
	buf->p = data;
	buf->ep = data + datalen;
}

int
buf_check_end(struct cbuf *buf)
{
	return buf->p == buf->ep;
}

int
buf_check_overflow(struct cbuf *buf)
{
	return buf->p > buf->ep;
}

static inline int
buf_check_size(struct cbuf *buf, int len)
{
	if (buf->p+len > buf->ep) {
		if (buf->p < buf->ep)
			buf->p = buf->ep + 1;

		return 0;
	}

	return 1;
}

void *
buf_alloc(struct cbuf *buf, int len)
{
	void *ret = NULL;

	if (buf_check_size(buf, len)) {
		ret = buf->p;
		buf->p += len;
	}

	return ret;
}

void
buf_put_int8(struct cbuf *buf, u8 val, u8* pval)
{
	if (buf_check_size(buf, 1)) {
		buf->p[0] = val;
		buf->p++;

		if (pval)
			*pval = val;
	}
}

void
buf_put_int16(struct cbuf *buf, u16 val, u16 *pval)
{
	if (buf_check_size(buf, 2)) {
		buf->p[0] = val >> 8;
		buf->p[1] = val;
		buf->p += 2;

		if (pval)
			*pval = val;

	}
}

void
buf_put_int32(struct cbuf *buf, u32 val, u32 *pval)
{
	if (buf_check_size(buf, 4)) {
		buf->p[0] = val >> 24;
		buf->p[1] = val >> 16;
		buf->p[2] = val >> 8;
		buf->p[3] = val;
		buf->p += 4;

		if (pval)
			*pval = val;

	}
}

void
buf_put_int48(struct cbuf *buf, u64 val, u64 *pval)
{
	if (buf_check_size(buf, 6)) {
		buf->p[0] = val >> 40;
		buf->p[1] = val >> 32;
		buf->p[2] = val >> 24;
		buf->p[3] = val >> 16;
		buf->p[4] = val >> 8;
		buf->p[5] = val;
		buf->p += 6;

		if (pval)
			*pval = val;

	}
}

void
buf_put_int64(struct cbuf *buf, u64 val, u64 *pval)
{
	if (buf_check_size(buf, 8)) {
		buf->p[0] = val >> 56;
		buf->p[1] = val >> 48;
		buf->p[2] = val >> 40;
		buf->p[3] = val >> 32;
		buf->p[4] = val >> 24;
		buf->p[5] = val >> 16;
		buf->p[6] = val >> 8;
		buf->p[7] = val;
		buf->p += 8;

		if (pval)
			*pval = val;

	}
}

void
buf_put_str(struct cbuf *buf, char *s, Vstr *ps)
{
	int slen;
	void *sbuf;

	if (s)
		slen = strlen(s);
	else
		slen = 0;

	if (buf_check_size(buf, 2+slen)) {
		buf_put_int16(buf, slen, NULL);
		sbuf = buf_alloc(buf, slen);
		memmove(sbuf, s, slen);

		if (ps) {
			ps->len = slen;
			ps->str = sbuf;
		}
	}
}

void
buf_put_var(struct cbuf *buf, uchar len, uchar *val, Vstr *ps)
{
	void *sbuf;

	if (buf_check_size(buf, 1+len)) {
		buf_put_int8(buf, len, NULL);
		if (len) {
			sbuf = buf_alloc(buf, len);
			memmove(sbuf, val, len);

			if (ps)
				ps->str = sbuf;
		} else {
			if (ps)
				ps->str = NULL;
		}

		if (ps)
			ps->len = len;
	}
}

void
buf_put_score(struct cbuf *buf, uchar *score, uchar **ps)
{
	void *sbuf;

	if (buf_check_size(buf, Vscoresize)) {
		sbuf = buf_alloc(buf, Vscoresize);
		memmove(sbuf, score, Vscoresize);
		if (ps)
			*ps = sbuf;
	}
}

u8
buf_get_int8(struct cbuf *buf)
{
	u8 ret;

	if (buf_check_size(buf, 1)) {
		ret = buf->p[0];
		buf->p++;
	} else
		ret = 0;

	return ret;
}

u16
buf_get_int16(struct cbuf *buf)
{
	u16 ret;

	if (buf_check_size(buf, 2)) {
		ret = buf->p[1] | (buf->p[0] << 8);
		buf->p += 2;
	} else
		ret = 0;

	return ret;
}

u32
buf_get_int32(struct cbuf *buf)
{
	u32 ret;

	if (buf_check_size(buf, 4)) {
		ret = buf->p[3] | (buf->p[2] << 8) | (buf->p[1] << 16) |
			(buf->p[0] << 24);
		buf->p += 4;
	} else
		ret = 0;

	return ret;
}

u64
buf_get_int48(struct cbuf *buf)
{
	u64 ret;

	if (buf_check_size(buf, 6)) {
		ret = buf->p[5] | (buf->p[4] << 8) | (buf->p[3] << 16) |
			((u64) buf->p[2] << 24) | ((u64) buf->p[1] << 32) |
			((u64) buf->p[0] << 40);
		buf->p += 6;
	} else
		ret = 0;

	return ret;
}

u64
buf_get_int64(struct cbuf *buf)
{
	u64 ret;

	if (buf_check_size(buf, 8)) {
		ret = buf->p[7] | (buf->p[6] << 8) | (buf->p[5] << 16) |
			((u64) buf->p[4] << 24) | ((u64) buf->p[3] << 32) |
			((u64) buf->p[2] << 40) | ((u64) buf->p[1] << 48) |
			((u64) buf->p[0] << 56);
		buf->p += 8;
	} else
		ret = 0;

	return ret;
}

void
buf_get_str(struct cbuf *buf, Vstr *str)
{
	str->len = buf_get_int16(buf);
	str->str = buf_alloc(buf, str->len);
}

void
buf_get_var(struct cbuf *buf, Vstr *var)
{
	var->len = buf_get_int8(buf);
	var->str = buf_alloc(buf, var->len);
}

uchar *
buf_get_score(struct cbuf *buf)
{
	return buf_alloc(buf, Vscoresize);
}

u16
vtodisktype(u16 n)
{
	if(n >= NELEM(todisk))
		return -1;
	return todisk[n];
}

u16
vfromdisktype(u16 n)
{
	if(n >= NELEM(fromdisk))
		return -1;
	return fromdisk[n];
}

int
unpack(Vcall *vc, uchar *data)
{
	struct cbuf buffer;
	struct cbuf *bufp;

	vc->pkt = data;
	bufp = &buffer;
	buf_init(bufp, data, 2);
	vc->size = buf_get_int16(bufp) + 2;

	buf_init(bufp, data + 2, vc->size - 2);
	vc->id = buf_get_int8(bufp);
	vc->tag = buf_get_int8(bufp);

	switch (vc->id) {
	default:
		goto error;

	case Vrerror:
		buf_get_str(bufp, &vc->ename);
		break;

	case Vtping:
	case Vrping:
	case Vtgoodbye:
	case Vtsync:
	case Vrsync:
		break;

	case Vthello:
		buf_get_str(bufp, &vc->version);
		buf_get_str(bufp, &vc->uid);
		vc->strength = buf_get_int8(bufp);
		buf_get_var(bufp, &vc->crypto);
		buf_get_var(bufp, &vc->codec);
		break;

	case Vrhello:
		buf_get_str(bufp, &vc->sid);
		vc->rcrypto = buf_get_int8(bufp);
		vc->rcodec = buf_get_int8(bufp);
		break;

	case Vtread:
		vc->score = buf_get_score(bufp);
		vc->btype = vfromdisktype(buf_get_int8(bufp));
		buf_alloc(bufp, 1);	/* padding */
		vc->count = buf_get_int16(bufp);
		break;

	case Vrread:
		vc->count = vc->size - 4;
		vc->data = buf_alloc(bufp, vc->count);
		break;

	case Vtwrite:
		vc->btype = vfromdisktype(buf_get_int8(bufp));
		buf_alloc(bufp, 3);	/* padding */
		vc->count = vc->size - 8;
		vc->data = buf_alloc(bufp, vc->count);
		break;

	case Vrwrite:
		vc->score = buf_get_score(bufp);
		break;
	}

	if (buf_check_overflow(bufp))
		goto error;

	return vc->size;

error:
	return -1;
}

void
settag(Vcall *vc, uchar tag)
{
	vc->tag = tag;
	vc->pkt[3] = tag;
}

Vcall *
vcpack(struct cbuf *bufp, u16 size, u8 id)
{
	Vcall *vc;

	size += 2 + 1 + 1;	/* size[2] id[1] tag[1] */
	vc = calloc(1, sizeof(Vcall) + size);
	if (!vc)
		return NULL;

	vc->pkt = (uchar *)vc + sizeof(*vc);
	buf_init(bufp, (char *) vc->pkt, size);
	buf_put_int16(bufp, size - 2, &vc->size);
	buf_put_int8(bufp, id, &vc->id);
	buf_put_int8(bufp, ~0, &vc->tag);

	vc->size = size;
	return vc;
}

Vcall *
vcempty(uchar id)
{
	struct cbuf buffer;
	struct cbuf *bufp;
	Vcall *vc;
	
	bufp = &buffer;
	vc = vcpack(bufp, 0, id);
	if (!vc)
		return NULL;

	return vc;
}

