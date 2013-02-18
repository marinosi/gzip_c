/*-
 * Copyright (c) 2009-2010 Robert N. M. Watson
 * All rights reserved.
 *
 * WARNING: THIS IS EXPERIMENTAL SECURITY SOFTWARE THAT MUST NOT BE RELIED
 * ON IN PRODUCTION SYSTEMS.  IT WILL BREAK YOUR SOFTWARE IN NEW AND
 * UNEXPECTED WAYS.
 * 
 * This software was developed at the University of Cambridge Computer
 * Laboratory with support from a grant from Google, Inc. 
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _GZIP_H_
#define	_GZIP_H_
	
#include <sys/types.h>

//#define BUFLEN		(64 * 1024)
#define BUFLEN		(4 * 1024)
#define MSG_SIZE	BUFLEN

#ifndef NO_BZIP2_SUPPORT
#include <bzlib.h>

#define BZ2_SUFFIX	".bz2"
#define BZIP2_MAGIC	"\102\132\150"
#endif

#ifndef NO_COMPRESS_SUPPORT
#define Z_SUFFIX	".Z"
#define Z_MAGIC		"\037\235"
#endif

#ifndef NO_PACK_SUPPORT
#define PACK_MAGIC	"\037\036"
#endif

#define GZ_SUFFIX	".gz"

#define GZIP_MAGIC0	0x1F
#define GZIP_MAGIC1	0x8B
#define GZIP_OMAGIC1	0x9E

#define GZIP_TIMESTAMP	(off_t)4
#define GZIP_ORIGNAME	(off_t)10

#define HEAD_CRC	0x02
#define EXTRA_FIELD	0x04
#define ORIG_NAME	0x08
#define COMMENT		0x10

#define OS_CODE		3	/* Unix */

/*
 * We need to forward the global variable 'numflag' to the sandbox as well as
 * function arguments.
 */
extern int	numflag;
extern int nflag;
extern int	gzsandbox_enabled;

void	maybe_warn(const char *fmt, ...)
    __attribute__((__format__(__printf__, 1, 2)));
void	maybe_warnx(const char *fmt, ...)
    __attribute__((__format__(__printf__, 1, 2)));
void	maybe_err(const char *fmt, ...) __dead2
    __attribute__((__format__(__printf__, 1, 2)));

off_t	gz_compress(int in, int out, off_t *gsizep, const char *origname,
	    uint32_t mtime);
off_t	gz_compress_wrapper(int in, int out, off_t *gsizep,
	    const char *origname, uint32_t mtime);
off_t	gz_uncompress(int in, int out, char *pre, size_t prelen,
	    off_t *gsizep, const char *filename);
off_t	gz_uncompress_wrapper(int in, int out, char *pre, size_t prelen,
	    off_t *gsizep, const char *filename);
off_t	unbzip2(int in, int out, char *pre, size_t prelen, off_t *bytes_in);
off_t	unbzip2_wrapper(int in, int out, char *pre, size_t prelen,
	    off_t *bytes_in);
void gzsandbox(void);

#endif /* !_GZIP_H_ */
