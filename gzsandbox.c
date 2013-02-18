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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
/*#include <sys/capability.h>*/
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/param.h>

#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
/*#include <libcapsicum.h>*/
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>
#include <fts.h>
#include <libgen.h>
#include <sandbox.h>
#include <sandbox_rpc.h>

#include "gzip.h"

/* DPRINTF */
#ifdef DEBUG
#define DPRINTF(format, ...)				\
	fprintf(stderr, "%s [%d] " format "\n", 	\
	__FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define DPRINTF(...)
#endif


#ifndef NO_SANDBOX_SUPPORT


#define	PROXIED_GZ_COMPRESS	1
#define	PROXIED_GZ_UNCOMPRESS	2
#define	PROXIED_UNBZIP2		3


struct sandbox_cb *gscb;
int			 gzsandbox_enabled;

struct host_gz_compress_req {
	char		hgc_req_origname[PATH_MAX];
	char	hgc_req_inbuf[MSG_SIZE];
	size_t	hgc_req_inbuf_sz;
	int		hgc_req_numflag;
	uint32_t	hgc_req_mtime;
	int		hgc_req_nflag;
} __packed;

struct host_gz_compress_rep {
	off_t	hgc_rep_gsize;
	off_t	hgc_rep_retval;
	char	hgc_rep_outbuf[MSG_SIZE];
	size_t	hgc_rep_outbuf_sz;
} __packed;


off_t gz_compress_host(struct sandbox_cb *scb, int in, int out, off_t *gsizep);
off_t gz_compress_sandbox(struct sandbox_cb *scb, const char *origname, uint32_t
	mtime);
static off_t
gz_compress_insandbox(int in, int out, off_t *gsizep, const char *origname,
    uint32_t mtime)
{
	struct host_gz_compress_req req;
	size_t len;

	bzero(&req, sizeof(req));
	strlcpy(req.hgc_req_origname, origname,
	    sizeof(req.hgc_req_origname));
	req.hgc_req_numflag = numflag;
	req.hgc_req_nflag = nflag;
	req.hgc_req_mtime = mtime;
	if (host_send(gscb, &req, sizeof(req), 0) < 0 )
		err(-1, "host_send");
	return (gz_compress_host(gscb, in, out, gsizep));
}

static void
sandbox_gz_compress_buffer(struct sandbox_cb *scb, uint32_t opno,
    uint32_t seqno, char *buffer, size_t len, int fd_in, int fd_out)
{
	struct host_gz_compress_req req;
	struct host_gz_compress_rep rep;
	struct iovec iov;

	if (len != sizeof(req))
		err(-1, "sandbox_gz_compress_buffer: len %zu", len);

	bcopy(buffer, &req, sizeof(req));
	bzero(&rep, sizeof(rep));
	numflag = req.hgc_req_numflag;
	nflag = req.hgc_req_nflag;
	rep.hgc_rep_retval = gz_compress(fd_in, fd_out, &rep.hgc_rep_gsize,
	    req.hgc_req_origname, req.hgc_req_mtime);
	iov.iov_base = &rep;
	iov.iov_len = sizeof(rep);
	if (sandbox_sendrpc(scb, opno, seqno, &iov, 1) < 0)
		err(-1, "sandbox_sendrpc");
}

off_t
gz_compress_wrapper(int in, int out, off_t *gsizep, const char *origname,
    uint32_t mtime)
{

	DPRINTF("gzsandbox_enabled: %d", gzsandbox_enabled);
	if (gzsandbox_enabled)
		return (gz_compress_insandbox(in, out, gsizep, origname,
		    mtime));
	else
		return (gz_compress(in, out, gsizep, origname, mtime));
}

struct host_gz_uncompress_req {
	size_t	hgu_req_prelen;
	char	hgu_req_filename[PATH_MAX];
	/* ... followed by data ... */
};

struct host_gz_uncompress_rep {
	off_t	hgu_rep_gsize;
	off_t	hgu_rep_retval;
};

static off_t
gz_uncompress_insandbox(int in, int out, char *pre, size_t prelen,
    off_t *gsizep, const char *filename)
{
	struct host_gz_uncompress_req req;
	struct host_gz_uncompress_rep rep;
	struct iovec iov_req[2], iov_rep;
	int fdarray[2];
	size_t len;

	bzero(&req, sizeof(req));
	req.hgu_req_prelen = prelen;
	strlcpy(req.hgu_req_filename, filename,
	    sizeof(req.hgu_req_filename));
	iov_req[0].iov_base = &req;
	iov_req[0].iov_len = sizeof(req);
	iov_req[1].iov_base = pre;
	iov_req[1].iov_len = prelen;
	iov_rep.iov_base = &rep;
	iov_rep.iov_len = sizeof(rep);
	fdarray[0] = dup(in);
	fdarray[1] = dup(out);
	if (host_rpc_rights(gscb, PROXIED_GZ_UNCOMPRESS, iov_req, 1,
	    fdarray, 2, &iov_rep, 1, &len, NULL, NULL) < 0)
		err(-1, "host_rpc_rights");
	if (len != sizeof(rep))
		errx(-1, "host_rpc_rights len %zu", len);
	if (gsizep != NULL)
		*gsizep = rep.hgu_rep_gsize;
	close(fdarray[0]);
	close(fdarray[1]);
	return (rep.hgu_rep_retval);
}

static void
sandbox_gz_uncompress_buffer(struct sandbox_cb *scb, uint32_t opno,
    uint32_t seqno, char *buffer, size_t len, int fd_in, int fd_out)
{
	struct host_gz_uncompress_req req;
	struct host_gz_uncompress_rep rep;
	struct iovec iov;
	char *pre;

	if (len != sizeof(req))
		err(-1, "sandbox_gz_uncompress_buffer: len %zu", len);

	bcopy(buffer, &req, sizeof(req));
	pre = buffer + sizeof(req);
	bzero(&rep, sizeof(rep));
	rep.hgu_rep_retval = gz_uncompress(fd_in, fd_out, pre,
	    req.hgu_req_prelen, &rep.hgu_rep_gsize, req.hgu_req_filename);
	iov.iov_base = &rep;
	iov.iov_len = sizeof(rep);
	if (sandbox_sendrpc(scb, opno, seqno, &iov, 1) < 0)
		err(-1, "sandbox_sendrpc");
}

off_t
gz_uncompress_wrapper(int in, int out, char *pre, size_t prelen,
    off_t *gsizep, const char *filename)
{

		return (gz_uncompress_insandbox(in, out,  pre, prelen,
		    gsizep, filename));
}

struct host_unbzip2_req {
	size_t	hub_req_prelen;
	/* ... followed by data ... */
};

struct host_unbzip2_rep {
	off_t	hub_rep_bytes_in;
	off_t	hub_rep_retval;
};

static off_t
unbzip2_insandbox(int in, int out, char *pre, size_t prelen, off_t *bytes_in)
{
	struct host_unbzip2_req req;
	struct host_unbzip2_rep rep;
	struct iovec iov_req[2], iov_rep;
	int fdarray[2];
	size_t len;

	bzero(&req, sizeof(req));
	req.hub_req_prelen = prelen;
	iov_req[0].iov_base = &req;
	iov_req[0].iov_len = sizeof(req);
	iov_req[1].iov_base = pre;
	iov_req[1].iov_len = prelen;
	iov_rep.iov_base = &rep;
	iov_rep.iov_len = sizeof(rep);
	fdarray[0] = dup(in);
	fdarray[1] = dup(out);
	if (host_rpc_rights(gscb, PROXIED_UNBZIP2, iov_req, 1,
	    fdarray, 2, &iov_rep, 1, &len, NULL, NULL) < 0)
		err(-1, "host_rpc_rights");
	if (len != sizeof(rep))
		errx(-1, "host_rpc_rights len %zu", len);
	if (bytes_in != NULL)
		*bytes_in = rep.hub_rep_bytes_in;
	close(fdarray[0]);
	close(fdarray[1]);
	return (rep.hub_rep_retval);
}

static void
sandbox_unbzip2_buffer(struct sandbox_cb *scb, uint32_t opno,
    uint32_t seqno, char *buffer, size_t len, int fd_in, int fd_out)
{
	struct host_unbzip2_req req;
	struct host_unbzip2_rep rep;
	struct iovec iov;
	char *pre;

	if (len != sizeof(req))
		err(-1, "sandbox_gz_uncompress_buffer: len %zu", len);

	bcopy(buffer, &req, sizeof(req));
	pre = buffer + sizeof(req);
	bzero(&rep, sizeof(rep));
	rep.hub_rep_retval = unbzip2(fd_in, fd_out, pre, req.hub_req_prelen,
	    &rep.hub_rep_bytes_in);
	iov.iov_base = &rep;
	iov.iov_len = sizeof(rep);
	if (sandbox_sendrpc(scb, opno, seqno, &iov, 1) < 0)
		err(-1, "sandbox_sendrpc");
}

off_t
unbzip2_wrapper(int in, int out, char *pre, size_t prelen, off_t *bytes_in)
{

	if (gzsandbox_enabled)
		return (unbzip2_insandbox(in, out, pre, prelen, bytes_in));
	else
		return (unbzip2(in, out, pre, prelen, bytes_in));
}

/*
 * Main entry point for capability-mode 
 */
void
gzsandbox(void)
{
	u_char *buffer;
	size_t len;
	char origname[PATH_MAX];
	uint32_t mtime;
	size_t nbytes;
	struct host_gz_compress_req req;

	/* Initialize req */
	bzero(&req, sizeof(req));

	DPRINTF("===> In gzsandbox()");
	nbytes = sandbox_recv(gscb, &req, sizeof(req), 0);
	DPRINTF("Nbytes: %ld", nbytes);
	DPRINTF("Sizeof(req): %ld", sizeof(req));
	if (nbytes != sizeof(req)) {
		if (errno == EPIPE) {
			DPRINTF("[XXX] EPIPE");
			exit(-1);
		}
		else {
			DPRINTF("[XXX] sandbox_recv");
			err(-1, "sandbox_recv");
		}
	}
	strlcpy(origname, req.hgc_req_origname,
	    sizeof(req.hgc_req_origname));
	numflag = req.hgc_req_numflag;
	nflag = req.hgc_req_nflag;
	mtime = req.hgc_req_mtime;

	gz_compress_sandbox(gscb, origname, mtime);

}

off_t
gz_compress_host(struct sandbox_cb *scb, int in, int out, off_t *gsizep)
{
	char *outbufp, *inbufp;
	off_t in_tot = 0, out_tot = 0;
	ssize_t in_size = -1;
	size_t nbytes, outbuflen;
	struct host_gz_compress_req req;
	struct host_gz_compress_rep rep;

	bzero(&req, sizeof(req));
	bzero(&rep, sizeof(rep));

	outbufp = malloc(BUFLEN);
	inbufp = malloc(BUFLEN);
	if (outbufp == NULL || inbufp == NULL) {
		maybe_err("malloc failed");
		goto out;
	}

	for( ;; ) {
		/* Receive compressed data and write them in out file descriptor */
		nbytes = host_recv_nonblock(scb, &rep, sizeof(rep), 0);
		if ( nbytes != 0 ) {
			if (nbytes != sizeof(rep)) {
				maybe_warn("host_recv");
				in_tot = -1;
				goto out;
			}

			outbuflen = rep.hgc_rep_outbuf_sz;

			/* Loop exit point */
			if ( outbuflen <= 0 ) {
				if (gsizep)
					*gsizep = out_tot;
				break;
			}

			memcpy(outbufp, rep.hgc_rep_outbuf, outbuflen);
			if (write(out, outbufp, outbuflen) != outbuflen) {
				maybe_warn("write");
				out_tot = -1;
				goto out;
			} else
				out_tot += outbuflen;
		}


		/* EOF: continue and break when (outbuflen == 0) */
		if (in_size == 0)
			continue;

		/* Read data from in fd and send uncompressed data to sandbox*/
		in_size = read(in, inbufp, BUFLEN);
		if (in_size < 0) {
			maybe_warn("read");
			in_tot = -1;
			goto out;
		} else
			in_tot += in_size;

		req.hgc_req_inbuf_sz = in_size;
		memcpy(&req.hgc_req_inbuf, inbufp, in_size);
		nbytes = host_send(scb, &req, sizeof(req), MSG_WAITALL);
		if ( nbytes != sizeof(req)) {
			maybe_warn("host_send");
			out_tot = -1;
			goto out;
		}
	}

	DPRINTF("Read %ld bytes of raw data and written %ld bytes of compressed "
		"data!", in_tot,  out_tot);


out:
	if (inbufp != NULL)
		free(inbufp);
	if (outbufp != NULL)
		free(outbufp);
	return in_tot;
}

/* compress input to output. Return bytes read, -1 on error */
off_t
gz_compress_sandbox(struct sandbox_cb *scb, const char *origname, uint32_t
	mtime)
{
	z_stream z;
	char *outbufp, *inbufp;
	off_t in_tot = 0, out_tot = 0;
	ssize_t in_size;
	int i, error;
	uLong crc;
	size_t nbytes;
	struct host_gz_compress_req req;
	struct host_gz_compress_rep rep;

	/* Initialize req and rep */
	bzero(&req, sizeof(req));
	bzero(&rep, sizeof(rep));

#ifdef SMALL
	static char header[] = { GZIP_MAGIC0, GZIP_MAGIC1, Z_DEFLATED, 0,
				 0, 0, 0, 0,
				 0, OS_CODE };
#endif

	outbufp = malloc(BUFLEN);
	inbufp = malloc(BUFLEN);
	if (outbufp == NULL || inbufp == NULL) {
		maybe_err("malloc failed");
		goto out;
	}

	memset(&z, 0, sizeof z);
	z.zalloc = Z_NULL;
	z.zfree = Z_NULL;
	z.opaque = 0;

#ifdef SMALL
	memcpy(outbufp, header, sizeof header);
	i = sizeof header;
#else
	if (nflag != 0) {
		mtime = 0;
		origname = "";
	}

	i = snprintf(outbufp, BUFLEN, "%c%c%c%c%c%c%c%c%c%c%s",
		     GZIP_MAGIC0, GZIP_MAGIC1, Z_DEFLATED,
		     *origname ? ORIG_NAME : 0,
		     mtime & 0xff,
		     (mtime >> 8) & 0xff,
		     (mtime >> 16) & 0xff,
		     (mtime >> 24) & 0xff,
		     numflag == 1 ? 4 : numflag == 9 ? 2 : 0,
		     OS_CODE, origname);
	if (i >= BUFLEN)
		/* this need PATH_MAX > BUFLEN ... */
		maybe_err("snprintf");
	if (*origname)
		i++;
#endif

	z.next_out = (unsigned char *)outbufp + i;
	z.avail_out = BUFLEN - i;

	error = deflateInit2(&z, numflag, Z_DEFLATED,
			     (-MAX_WBITS), 8, Z_DEFAULT_STRATEGY);
	if (error != Z_OK) {
		maybe_warnx("deflateInit2 failed");
		in_tot = -1;
		goto out;
	}

	crc = crc32(0L, Z_NULL, 0);
	for (;;) {
		if (z.avail_out == 0) {
			/* XXX IM: return to host */
			rep.hgc_rep_outbuf_sz = BUFLEN;
			memcpy(rep.hgc_rep_outbuf, outbufp, BUFLEN);
			nbytes = sandbox_send(scb, &rep, sizeof(rep), 0);
			DPRINTF("SANDBOX: Sent %ld", nbytes);
			if (nbytes != sizeof(rep)) {
				maybe_warn("sandbox_send");
				out_tot = -1;
				goto out;
			}

			out_tot += BUFLEN;
			z.next_out = (unsigned char *)outbufp;
			z.avail_out = BUFLEN;
		}

		if (z.avail_in == 0) {
			nbytes = sandbox_recv(scb, &req, sizeof(req), 0);
			DPRINTF("SANDBOX: Received %ld", nbytes);
			if ( nbytes != sizeof(req)) {
				maybe_warn("sandbox_recv");
				in_tot = -1;
				goto out;
			}
			in_size = req.hgc_req_inbuf_sz;
			DPRINTF("in_size: %ld", in_size);
			if (in_size == 0)
				break;

			memcpy(inbufp, req.hgc_req_inbuf, in_size);

			crc = crc32(crc, (const Bytef *)inbufp, (unsigned)in_size);
			in_tot += in_size;
			z.next_in = (unsigned char *)inbufp;
			z.avail_in = in_size;
		}

		error = deflate(&z, Z_NO_FLUSH);
		if (error != Z_OK && error != Z_STREAM_END) {
			maybe_warnx("deflate failed");
			in_tot = -1;
			goto out;
		}
	}

	/* clean up */
	for (;;) {
		size_t len;
		ssize_t w;

		error = deflate(&z, Z_FINISH);
		if (error != Z_OK && error != Z_STREAM_END) {
			maybe_warnx("deflate failed");
			in_tot = -1;
			goto out;
		}

		len = (char *)z.next_out - outbufp;

		/* XXX IM: return to host */
		rep.hgc_rep_outbuf_sz = len;
		memcpy(&rep.hgc_rep_outbuf, outbufp, len);
		DPRINTF("SANDBOX: Sent %ld bytes", sizeof(rep));
		if (sandbox_send(scb, &rep, sizeof(rep), 0) != sizeof(rep)) {
			maybe_warn("sandbox_send");
			out_tot = -1;
			goto out;
		}

		out_tot += len;
		z.next_out = (unsigned char *)outbufp;
		z.avail_out = BUFLEN;

		if (error == Z_STREAM_END)
			break;
	}

	if (deflateEnd(&z) != Z_OK) {
		maybe_warnx("deflateEnd failed");
		in_tot = -1;
		goto out;
	}

	i = snprintf(outbufp, BUFLEN, "%c%c%c%c%c%c%c%c",
		 (int)crc & 0xff,
		 (int)(crc >> 8) & 0xff,
		 (int)(crc >> 16) & 0xff,
		 (int)(crc >> 24) & 0xff,
		 (int)in_tot & 0xff,
		 (int)(in_tot >> 8) & 0xff,
		 (int)(in_tot >> 16) & 0xff,
		 (int)(in_tot >> 24) & 0xff);
	if (i != 8)
		maybe_err("snprintf");


	/* XXX IM: return to host */
	rep.hgc_rep_outbuf_sz = i;
	memcpy(&rep.hgc_rep_outbuf, outbufp, i);
	if (sandbox_send(scb, &rep, sizeof(rep), 0) != sizeof(rep)) {
		maybe_warn("sandbox_send");
		in_tot = -1;
	} else
		out_tot += i;

out:
	/* Let the parent know that we are finished */
	rep.hgc_rep_outbuf_sz = 0;
	rep.hgc_rep_gsize = out_tot;
	if (sandbox_send(scb, &rep, sizeof(rep), 0) != sizeof(rep)) {
		maybe_warn("sandbox_send");
	}
	if (inbufp != NULL)
		free(inbufp);
	if (outbufp != NULL)
		free(outbufp);
	return in_tot;
}
#else /* NO_SANDBOX_SUPPORT */

off_t
gz_compress_wrapper(int in, int out, off_t *gsizep, const char *origname,
    uint32_t mtime)
{

	return (gz_compress(in, out, gsizep, origname, mtime));
}

off_t
gz_uncompress_wrapper(int in, int out, u_char *pre, size_t prelen,
    off_t *gsizep, const char *filename)
{

	return (gz_uncompress(in, out, (char *) pre, prelen, gsizep, filename));
}

off_t
unbzip2_wrapper(int in, int out, char *pre, size_t prelen, off_t *bytes_in)
{

	return (unbzip2(in, out, pre, prelen, bytes_in));
}

#endif /* !NO_SANDBOX_SUPPORT */
