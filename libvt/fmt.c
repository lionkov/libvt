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
#include "vt.h"

extern u16 vtodisktype(u16 n);
extern u16 vfromdisktype(u16 n);

static int
dumpdata(FILE *f, u8 *data, int datalen)
{
	int i, n;

	i = 0;
	n = 0;
	while (i < datalen) {
		n += fprintf(f, "%02x", data[i]);
		if (i%4 == 3)
			n += fprintf(f, " ");
		if (i%64 == 63)
			n += fprintf(f, "\n");

		i++;
	}
//	n += fprintf(f, "\n");

	return n;
}

static int
printdata(FILE *f, u8 *buf, int buflen)
{
	return dumpdata(f, buf, buflen<32?buflen:32);
}

static int
printscore(FILE *f, u8 *buf)
{
	return dumpdata(f, buf, Vscoresize);
}

int
printvcall(FILE *f, Vcall *vc)
{
	int ret, id, tag;

	if (!vc)
		return fprintf(f, "NULL");

	id = vc->id;
	tag = vc->tag;
	ret = 0;
	switch (id) {
	case Vrerror:
		ret += fprintf(f, "Rerror tag %u ename '%.*s'", tag,
			vc->version.len, vc->version.str);
		break;

	case Vtping:
		ret += fprintf(f, "Tping tag %u", tag);
		break;

	case Vrping:
		ret += fprintf(f, "Rping tag %u", tag);
		break;

	case Vthello:
		ret += fprintf(f,
			"Thello tag %u version '%.*s' uid '%.*s' strength %u crypto '%.*s' codec '%.*s'",
			tag, vc->version.len, vc->version.str, vc->uid.len,
			vc->uid.str, vc->strength, vc->crypto.len, vc->crypto.str,
			vc->codec.len, vc->codec.str);
		break;

	case Vrhello:
		ret += fprintf(f, "Rhello tag %u sid '%.*s' rcrypto %u rcodec %u", tag,
			vc->sid.len, vc->sid.str, vc->rcrypto, vc->rcodec);
		break;

	case Vtgoodbye:
		ret += fprintf(f, "Tgoodbye tag %u", tag);
		break;

	case Vtread:
		ret += fprintf(f, "Tread tag %u score ", tag);
		ret += printscore(f, vc->score);
		ret += fprintf(f, " type %u count %d", vfromdisktype(vc->btype),
			vc->count);
		break;

	case Vrread:
		ret += fprintf(f, "Rread tag %u count %d data ", tag, vc->count);
		ret += printdata(f, vc->data, vc->count);
		break;

	case Vtwrite:
		ret += fprintf(f, "Twrite tag %u type %u count %d data ", tag,
			vfromdisktype(vc->btype), vc->count);
		ret += printdata(f, vc->data, vc->count);
		break;

	case Vrwrite:
		ret += fprintf(f, "Rwrite tag %u score ", tag);
		ret += printscore(f, vc->score);
		break;

	case Vtsync:
		ret += fprintf(f, "Tsync tag %u", tag);
		break;

	case Vrsync:
		ret += fprintf(f, "Rsync tag %u", tag);
		break;
	}

	return ret;
}
