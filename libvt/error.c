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
#include <stdarg.h>
#include "vt.h"

typedef struct Verror Verror;
struct Verror {
	char*	ename;
	int	ecode;
};

static pthread_key_t error_key;
static pthread_once_t error_once = PTHREAD_ONCE_INIT;

static void
errorfree(void *a)
{
	Verror *err;

	err = a;
	free(err->ename);
	free(err);
}

static void
errkeyinit()
{
	pthread_key_create(&error_key, errorfree);
}

static void
vwerror(Verror *err, char *ename, int ecode, va_list ap)
{
	err->ecode = ecode;
	free(err->ename);
	err->ename = NULL;
	if (ename) {
		/* RHEL5 has issues
		vasprintf(&err->ename, ename, ap);
		  */
		err->ename = malloc(1024);
		vsnprintf(err->ename, 1024, ename, ap);
	}
}

void
werror(char *ename, int ecode, ...)
{
	va_list ap;
	Verror *err;

	pthread_once(&error_once, errkeyinit);
	err = pthread_getspecific(error_key);
	if (!err) {
		err = malloc(sizeof(*err));
		err->ename = NULL;
		err->ecode = 0;
		pthread_setspecific(error_key, err);
	}

	va_start(ap, ecode);
	vwerror(err, ename, ecode, ap);
	va_end(ap);
}

void
rerror(char **ename, int *ecode)
{
	Verror *err;

	pthread_once(&error_once, errkeyinit);
	err = pthread_getspecific(error_key);
	if (err) {
		*ename = err->ename;
		*ecode = err->ecode;
	} else {
		*ename = NULL;
		*ecode = 0;
	}
}

int
haserror()
{
	Verror *err;

	pthread_once(&error_once, errkeyinit);
	err = pthread_getspecific(error_key);
	if (err)
		return err->ename != NULL;
	else
		return 0;
}

void
uwerror(int ecode)
{
	char buf[256];

	strerror_r(ecode, buf, sizeof(buf));
	werror(buf, ecode);
}

void
suwerror(char *s, int ecode)
{
	char err[256];
	char buf[512];

	strerror_r(ecode, err, sizeof(err));
	snprintf(buf, sizeof(buf), "%s: %s", s, buf);
	werror(buf, ecode);
}
