#	$NetBSD: Makefile,v 1.13 2009/04/14 22:15:20 lukem Exp $
# $FreeBSD: releng/9.1/usr.bin/gzip/Makefile 222210 2011-05-23 09:02:44Z delphij $

.include <bsd.own.mk>

CC=			clang
PROG=		gzip
SRCS=		gzip.c gzsandbox.c
MAN=		gzip.1 gzexe.1 zdiff.1 zforce.1 zmore.1 znew.1

DPADD=		${LIBZ}
LDADD=		-lz

.ifdef DEBUG
CFLAGS+=	-DDEBUG -g
.endif

.if ${MK_BZIP2_SUPPORT} != "no"
DPADD+=		${LIBBZ2}
LDADD+=		-lbz2 -L ../sep -lsep
.else
CFLAGS+=	-DNO_BZIP2_SUPPORT
.endif

.ifndef NO_SANDBOX
CFLAGS+=	-I ../libsep
LDADD+=		-L ../libsep -lsep
.endif

SCRIPTS=	gzexe zdiff zforce zmore znew

MLINKS+=	gzip.1 gunzip.1 \
		gzip.1 gzcat.1 \
		gzip.1 zcat.1 \
		zdiff.1 zcmp.1

LINKS+=		${BINDIR}/gzip ${BINDIR}/gzip_sandbox ${BINDIR}/gunzip \
		${BINDIR}/gzip ${BINDIR}/gzcat \
		${BINDIR}/gzip ${BINDIR}/zcat \
		${BINDIR}/zdiff ${BINDIR}/zcmp

.include <bsd.prog.mk>