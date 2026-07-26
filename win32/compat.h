/*
   Copyright (C) 2026 lrzip-win contributors

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

/* POSIX compatibility shims for native Windows (MinGW-w64) builds.
 *
 * The intent is that lrzip's shared sources stay unmodified: this header
 * supplies POSIX-shaped declarations so that existing call sites compile and
 * behave sensibly, and win32/compat.c implements them on top of Win32.
 *
 * This header deliberately does NOT include <windows.h>. windows.h defines
 * min/max macros and a large number of generic identifiers that collide with
 * lrzip's own names. Only win32/compat.c includes it.
 */

#ifndef LRZIP_WIN32_COMPAT_H
#define LRZIP_WIN32_COMPAT_H

#ifdef _WIN32

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <fcntl.h>
#include <io.h>
#include <malloc.h>	/* alloca() lives here on MinGW */
#include <signal.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ *
 * mmap
 *
 * lrzip needs exactly three operations:
 *   1. file-backed, read-only, shared      (the sliding rzip window)
 *   2. anonymous, read-write, private      (the STDIN scratch buffer)
 *   3. release, plus shrinking of (2)
 * That narrow contract is why this is hand-written rather than vendoring a
 * general-purpose mman emulation.
 * ------------------------------------------------------------------ */

#define PROT_NONE	0x0
#define PROT_READ	0x1
#define PROT_WRITE	0x2
#define PROT_EXEC	0x4

#define MAP_FILE	0x00
#define MAP_SHARED	0x01
#define MAP_PRIVATE	0x02
#define MAP_ANONYMOUS	0x20
#define MAP_ANON	MAP_ANONYMOUS
#define MAP_FAILED	((void *) -1)

void *mmap(void *addr, size_t len, int prot, int flags, int fd, int64_t offset);

/* Unlike UnmapViewOfFile(), this refuses a partial unmap of a file-backed
 * view rather than silently destroying the entire mapping, and it supports
 * shrinking an anonymous mapping by decommitting the tail. */
int munmap(void *addr, size_t len);

int msync(void *addr, size_t len, int flags);
#define MS_ASYNC	1
#define MS_SYNC		2
#define MS_INVALIDATE	4

/* ------------------------------------------------------------------ *
 * Positional I/O - MinGW has neither pread() nor pwrite().
 * Implemented with OVERLAPPED so the file pointer is untouched, matching
 * POSIX semantics (lrzip relies on this: fd_out and fd_hist refer to the
 * same file and are used concurrently).
 * ------------------------------------------------------------------ */
ssize_t pread(int fd, void *buf, size_t count, int64_t offset);
ssize_t pwrite(int fd, const void *buf, size_t count, int64_t offset);

/* ------------------------------------------------------------------ *
 * Filesystem
 * ------------------------------------------------------------------ */
int fsync(int fd);

struct statvfs {
	unsigned long	f_bsize;	/* filesystem block size */
	unsigned long	f_frsize;	/* fragment size */
	uint64_t	f_blocks;	/* size of fs in f_frsize units */
	uint64_t	f_bfree;	/* free blocks */
	uint64_t	f_bavail;	/* free blocks for unprivileged users */
};

int fstatvfs(int fd, struct statvfs *buf);
int statvfs(const char *path, struct statvfs *buf);

/* Windows has no POSIX mode/ownership model. These succeed as no-ops so that
 * callers treating failure as fatal keep working; see preserve_perms(). */
int fchmod(int fd, mode_t mode);
int fchown(int fd, int owner, int group);

int mkstemp(char *tmpl);

/* ------------------------------------------------------------------ *
 * Process scheduling priority. Mapped onto Win32 priority classes.
 * ------------------------------------------------------------------ */
#define PRIO_PROCESS	0
#define PRIO_PGRP	1
#define PRIO_USER	2
#define PRIO_MIN	(-20)
#define PRIO_MAX	20

int getpriority(int which, int who);
int setpriority(int which, int who, int prio);

/* ------------------------------------------------------------------ *
 * Resource limits - no meaningful Windows equivalent for RLIMIT_DATA.
 * ------------------------------------------------------------------ */
#define RLIMIT_DATA	2
#define RLIM_INFINITY	((uint64_t) -1)

typedef uint64_t rlim_t;

struct rlimit {
	rlim_t rlim_cur;
	rlim_t rlim_max;
};

int getrlimit(int resource, struct rlimit *rlim);
int setrlimit(int resource, const struct rlimit *rlim);

/* ------------------------------------------------------------------ *
 * sysconf
 * ------------------------------------------------------------------ */
#define _SC_PAGESIZE		1
#define _SC_PAGE_SIZE		_SC_PAGESIZE
#define _SC_PHYS_PAGES		2
#define _SC_NPROCESSORS_ONLN	3
#define _SC_NPROCESSORS_CONF	4

long sysconf(int name);

/* ------------------------------------------------------------------ *
 * random() - MinGW only offers rand(), whose RAND_MAX is 32767. rzip builds
 * its hash index from random() and needs a decent 32-bit spread.
 * ------------------------------------------------------------------ */
long random(void);
void srandom(unsigned int seed);

/* ------------------------------------------------------------------ *
 * Bounded read()/write().
 *
 * MSVCRT's _read()/_write() take a 32-bit count and return int, so any
 * request above INT_MAX fails outright with EINVAL. lrzip legitimately asks
 * for more than that - the STDIN path issues a single read() covering the
 * whole compression window, which on a large-memory machine is tens of
 * gigabytes. Linux caps such a request at 0x7ffff000 and returns a short
 * read; these wrappers reproduce that behaviour so the existing loops work
 * unchanged.
 * ------------------------------------------------------------------ */
ssize_t lrzip_win32_read(int fd, void *buf, size_t count);
ssize_t lrzip_win32_write(int fd, const void *buf, size_t count);

/* ------------------------------------------------------------------ *
 * open() with POSIX unlink semantics.
 *
 * Windows only refuses to delete an open file because MSVCRT's _open() omits
 * FILE_SHARE_DELETE from the share mode. Opening via CreateFile() with
 * delete sharing - and DELETE access - makes unlink() on an open file behave
 * exactly as it does on POSIX: the name goes away immediately and the data
 * is released when the last handle closes.
 *
 * lrzip relies on that idiom for its temporary files.
 * ------------------------------------------------------------------ */
int lrzip_win32_open(const char *path, int flags, ...);

#ifndef __cplusplus
# define read(fd, buf, count)	lrzip_win32_read((fd), (buf), (count))
# define write(fd, buf, count)	lrzip_win32_write((fd), (buf), (count))
# define open			lrzip_win32_open
#endif

/* ------------------------------------------------------------------ *
 * Force binary I/O.
 *
 * The MSVCRT default is text mode, which translates CRLF and - fatally for a
 * compressor - treats an embedded 0x1A byte as end-of-file, so read() returns
 * 0 partway through compressed data. Setting the process-wide default once is
 * cleaner and safer than sprinkling O_BINARY over every open() call.
 * ------------------------------------------------------------------ */
void win32_init_binary_mode(void);

/* ------------------------------------------------------------------ *
 * Cryptographically secure entropy, the equivalent of reading /dev/urandom.
 * Backed by BCryptGenRandom(). Returns 0 on success, -1 on failure; callers
 * must fail closed rather than substituting a weak PRNG, since this feeds
 * encryption salts and nonces.
 * ------------------------------------------------------------------ */
int win32_secure_random(void *buf, size_t len);

/* ------------------------------------------------------------------ *
 * Locking key material out of the pagefile.
 * ------------------------------------------------------------------ */
int mlock(const void *addr, size_t len);
int munlock(const void *addr, size_t len);

/* ------------------------------------------------------------------ *
 * Byte order. lrzip only needs ntohl(), and pulling in <winsock2.h> just for
 * that would drag in a ws2_32 link dependency for no reason. Every Windows
 * target is little-endian.
 * ------------------------------------------------------------------ */
static __inline uint32_t lrzip_bswap32(uint32_t x)
{
	return (x >> 24) | ((x >> 8) & 0xff00u) |
	       ((x << 8) & 0xff0000u) | (x << 24);
}

static __inline uint16_t lrzip_bswap16(uint16_t x)
{
	return (uint16_t)((x >> 8) | (x << 8));
}

#define ntohl(x) lrzip_bswap32(x)
#define htonl(x) lrzip_bswap32(x)
#define ntohs(x) lrzip_bswap16(x)
#define htons(x) lrzip_bswap16(x)

/* ------------------------------------------------------------------ *
 * Terminal echo control. Only used to restore echo after a password prompt,
 * so just enough of <termios.h> is emulated for that.
 * ------------------------------------------------------------------ */
#define ECHO	0x0008
#define TCSANOW	0

typedef unsigned int tcflag_t;

struct termios {
	tcflag_t c_iflag;
	tcflag_t c_oflag;
	tcflag_t c_cflag;
	tcflag_t c_lflag;
};

int tcgetattr(int fd, struct termios *t);
int tcsetattr(int fd, int actions, const struct termios *t);

/* ------------------------------------------------------------------ *
 * Signals. MinGW provides signal(), SIGINT and SIGTERM but not sigaction()
 * nor the job-control signals.
 * ------------------------------------------------------------------ */
#ifndef SIGTTIN
# define SIGTTIN 21
#endif
#ifndef SIGTTOU
# define SIGTTOU 22
#endif

typedef unsigned long sigset_t;

struct sigaction {
	void	(*sa_handler)(int);
	sigset_t  sa_mask;
	int	  sa_flags;
};

int sigemptyset(sigset_t *set);
int sigfillset(sigset_t *set);
int sigaddset(sigset_t *set, int signum);
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);

#ifdef __cplusplus
}
#endif

#endif /* _WIN32 */
#endif /* LRZIP_WIN32_COMPAT_H */
