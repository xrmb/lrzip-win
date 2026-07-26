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

#ifdef _WIN32

/* Keep <winsock.h> out: compat.h defines ntohl() and friends itself so that
 * no ws2_32 dependency is introduced. */
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <bcrypt.h>

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>

#include "compat.h"

/* ================================================================== *
 * Mapping registry
 *
 * Win32 has two unrelated ways of getting memory that POSIX presents as
 * mmap(): VirtualAlloc() for anonymous memory and CreateFileMapping() +
 * MapViewOfFile() for file-backed memory. They are released by different
 * calls, so munmap() has to know which it is looking at.
 *
 * A registry is used rather than VirtualQuery() because MapViewOfFile()
 * requires the offset to be a multiple of the allocation granularity (64 KiB)
 * whereas lrzip maps at page-aligned (4 KiB) offsets. We therefore map from a
 * lower, granularity-aligned base and hand back an interior pointer; the
 * registry remembers the real base so it can be unmapped correctly.
 * ================================================================== */

#define MAX_MAPPINGS 64

struct map_entry {
	void	*ptr;		/* pointer handed back to the caller */
	void	*base;		/* real view / allocation base */
	size_t	 len;		/* usable length from ptr */
	int	 anon;		/* 1 = VirtualAlloc, 0 = MapViewOfFile */
	int	 lazy;		/* anonymous range reserved but not committed */
	DWORD	 prot;		/* page protection, for deferred commits */
	int	 used;
};

static struct map_entry mappings[MAX_MAPPINGS];
static CRITICAL_SECTION mappings_cs;
static INIT_ONCE mappings_once = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK init_mappings_cs(PINIT_ONCE once, PVOID param, PVOID *ctx)
{
	(void)once; (void)param; (void)ctx;
	InitializeCriticalSection(&mappings_cs);
	return TRUE;
}

static void mappings_lock(void)
{
	InitOnceExecuteOnce(&mappings_once, init_mappings_cs, NULL, NULL);
	EnterCriticalSection(&mappings_cs);
}

static void mappings_unlock(void)
{
	LeaveCriticalSection(&mappings_cs);
}

static int mapping_add(void *ptr, void *base, size_t len, int anon, int lazy, DWORD prot)
{
	int i;

	mappings_lock();
	for (i = 0; i < MAX_MAPPINGS; i++) {
		if (!mappings[i].used) {
			mappings[i].ptr  = ptr;
			mappings[i].base = base;
			mappings[i].len  = len;
			mappings[i].anon = anon;
			mappings[i].lazy = lazy;
			mappings[i].prot = prot;
			mappings[i].used = 1;
			mappings_unlock();
			return 0;
		}
	}
	mappings_unlock();
	return -1;
}

/* Exact match on the pointer previously returned by mmap(). */
static struct map_entry *mapping_find(void *ptr)
{
	int i;

	for (i = 0; i < MAX_MAPPINGS; i++)
		if (mappings[i].used && mappings[i].ptr == ptr)
			return &mappings[i];
	return NULL;
}

/* Any mapping whose range covers ADDR. */
static struct map_entry *mapping_containing(void *addr)
{
	int i;

	for (i = 0; i < MAX_MAPPINGS; i++) {
		if (!mappings[i].used)
			continue;
		if ((char *)addr >= (char *)mappings[i].ptr &&
		    (char *)addr <  (char *)mappings[i].ptr + mappings[i].len)
			return &mappings[i];
	}
	return NULL;
}

static DWORD allocation_granularity(void)
{
	static DWORD gran;

	if (!gran) {
		SYSTEM_INFO si;

		GetSystemInfo(&si);
		gran = si.dwAllocationGranularity;
	}
	return gran;
}

void *mmap(void *addr, size_t len, int prot, int flags, int fd, int64_t offset)
{
	HANDLE h, fm;
	LARGE_INTEGER fsize;
	uint64_t end, aligned;
	size_t delta;
	DWORD page_prot, access;
	void *view, *ret;

	/* The address is only ever a hint here; MAP_FIXED is not supported and
	 * lrzip does not need it. */
	(void)addr;

	if (!len) {
		errno = EINVAL;
		return MAP_FAILED;
	}

	if (flags & MAP_ANONYMOUS) {
		if (prot & PROT_EXEC)
			page_prot = (prot & PROT_WRITE) ? PAGE_EXECUTE_READWRITE
							: PAGE_EXECUTE_READ;
		else if (prot & PROT_WRITE)
			page_prot = PAGE_READWRITE;
		else if (prot & PROT_READ)
			page_prot = PAGE_READONLY;
		else
			page_prot = PAGE_NOACCESS;

		/* Reserve the address space but do not charge it against the
		 * system commit limit yet. Linux anonymous mappings are lazy
		 * under overcommit, and lrzip leans on that: it sizes the
		 * STDIN buffer to the whole compression window, which is tens
		 * of gigabytes on a large-memory machine, and then usually
		 * reads far less into it. Pages are committed on demand by
		 * lrzip_win32_read(). */
		ret = VirtualAlloc(NULL, len, MEM_RESERVE, page_prot);
		if (!ret) {
			errno = ENOMEM;
			return MAP_FAILED;
		}
		if (mapping_add(ret, ret, len, 1, 1, page_prot)) {
			VirtualFree(ret, 0, MEM_RELEASE);
			errno = ENOMEM;
			return MAP_FAILED;
		}
		return ret;
	}

	h = (HANDLE)_get_osfhandle(fd);
	if (h == INVALID_HANDLE_VALUE) {
		errno = EBADF;
		return MAP_FAILED;
	}
	if (!GetFileSizeEx(h, &fsize)) {
		errno = EBADF;
		return MAP_FAILED;
	}

	/* Windows refuses to create a read-only section that extends past the
	 * end of the file, where POSIX would simply zero-fill the final page.
	 * Clamp instead of failing. Callers must not read past EOF; lrzip's
	 * sliding window tracks the real length separately. */
	end = (uint64_t)offset + (uint64_t)len;
	if ((uint64_t)fsize.QuadPart < end) {
		if ((uint64_t)offset >= (uint64_t)fsize.QuadPart) {
			errno = EINVAL;
			return MAP_FAILED;
		}
		if (getenv("LRZIP_WIN32_DEBUG"))
			fprintf(stderr, "[compat] mmap CLAMPED: off=%lld asked=%zu -> %llu (filesize=%lld)\n",
				(long long)offset, len,
				(unsigned long long)((uint64_t)fsize.QuadPart - (uint64_t)offset),
				(long long)fsize.QuadPart);
		len = (size_t)((uint64_t)fsize.QuadPart - (uint64_t)offset);
		end = (uint64_t)fsize.QuadPart;
	}

	/* MapViewOfFile() offsets must be allocation-granularity aligned. */
	aligned = (uint64_t)offset & ~(uint64_t)(allocation_granularity() - 1);
	delta   = (size_t)((uint64_t)offset - aligned);

	if (prot & PROT_WRITE) {
		if (flags & MAP_PRIVATE) {
			page_prot = PAGE_WRITECOPY;
			access    = FILE_MAP_COPY;
		} else {
			page_prot = PAGE_READWRITE;
			access    = FILE_MAP_WRITE;
		}
	} else {
		page_prot = PAGE_READONLY;
		access    = FILE_MAP_READ;
	}

	fm = CreateFileMappingA(h, NULL, page_prot,
				(DWORD)(end >> 32), (DWORD)(end & 0xFFFFFFFFu), NULL);
	if (!fm) {
		errno = ENOMEM;
		return MAP_FAILED;
	}

	view = MapViewOfFile(fm, access,
			     (DWORD)(aligned >> 32), (DWORD)(aligned & 0xFFFFFFFFu),
			     delta + len);
	/* The section stays alive as long as a view references it. */
	CloseHandle(fm);
	if (!view) {
		errno = ENOMEM;
		return MAP_FAILED;
	}

	ret = (char *)view + delta;
	if (mapping_add(ret, view, len, 0, 0, page_prot)) {
		UnmapViewOfFile(view);
		errno = ENOMEM;
		return MAP_FAILED;
	}
	return ret;
}

int munmap(void *addr, size_t len)
{
	struct map_entry *e;
	BOOL ok;

	if (!addr) {
		errno = EINVAL;
		return -1;
	}
	/* Shrinking to exactly the current size is a no-op, not an error. */
	if (!len)
		return 0;

	mappings_lock();

	e = mapping_find(addr);
	if (e) {
		ok = e->anon ? VirtualFree(e->base, 0, MEM_RELEASE)
			     : UnmapViewOfFile(e->base);
		e->used = 0;
		mappings_unlock();
		if (!ok) {
			errno = EINVAL;
			return -1;
		}
		return 0;
	}

	/* Not a base pointer: this is a partial unmap. */
	e = mapping_containing(addr);
	if (!e) {
		mappings_unlock();
		errno = EINVAL;
		return -1;
	}

	if (!e->anon) {
		/* UnmapViewOfFile() would happily accept an interior address and
		 * tear down the ENTIRE view, leaving the caller holding a
		 * dangling base pointer. Refuse instead of corrupting. */
		mappings_unlock();
		errno = EINVAL;
		return -1;
	}

	/* Anonymous mapping: releasing the tail is legitimate and is how
	 * shrinking is implemented. */
	ok = VirtualFree(addr, len, MEM_DECOMMIT);
	if (ok)
		e->len = (size_t)((char *)addr - (char *)e->ptr);
	mappings_unlock();

	if (!ok) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

int msync(void *addr, size_t len, int flags)
{
	(void)flags;

	if (!FlushViewOfFile(addr, len)) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

/* ================================================================== *
 * Positional I/O
 * ================================================================== */

/* POSIX pread()/pwrite() leave the file offset untouched. On a synchronous
 * Windows handle an OVERLAPPED offset performs the I/O at the right place but
 * *does* move the file pointer, so save and restore it. */
static ssize_t pio(int fd, void *buf, size_t count, int64_t offset, int write_op)
{
	HANDLE h;
	LARGE_INTEGER saved, zero, target;
	size_t done = 0;
	int rc = 0;

	h = (HANDLE)_get_osfhandle(fd);
	if (h == INVALID_HANDLE_VALUE) {
		errno = EBADF;
		return -1;
	}

	zero.QuadPart = 0;
	if (!SetFilePointerEx(h, zero, &saved, FILE_CURRENT)) {
		errno = ESPIPE;
		return -1;
	}

	while (done < count) {
		DWORD chunk = (DWORD)((count - done > 0x7ffff000u)
				      ? 0x7ffff000u : (count - done));
		DWORD moved = 0;
		OVERLAPPED ov;
		uint64_t at = (uint64_t)offset + done;

		memset(&ov, 0, sizeof ov);
		ov.Offset     = (DWORD)(at & 0xFFFFFFFFu);
		ov.OffsetHigh = (DWORD)(at >> 32);

		if (write_op) {
			if (!WriteFile(h, (const char *)buf + done, chunk, &moved, &ov)) {
				errno = EIO;
				rc = -1;
				break;
			}
		} else {
			if (!ReadFile(h, (char *)buf + done, chunk, &moved, &ov)) {
				if (GetLastError() == ERROR_HANDLE_EOF)
					break;
				errno = EIO;
				rc = -1;
				break;
			}
			if (!moved)	/* EOF */
				break;
		}
		done += moved;
		if (!moved)
			break;
	}

	target.QuadPart = saved.QuadPart;
	SetFilePointerEx(h, target, NULL, FILE_BEGIN);

	return rc ? -1 : (ssize_t)done;
}

ssize_t pread(int fd, void *buf, size_t count, int64_t offset)
{
	return pio(fd, buf, count, offset, 0);
}

ssize_t pwrite(int fd, const void *buf, size_t count, int64_t offset)
{
	return pio(fd, (void *)buf, count, offset, 1);
}

/* ================================================================== *
 * Filesystem
 * ================================================================== */

int fsync(int fd)
{
	return _commit(fd);
}

static int statvfs_from_root(const wchar_t *root, struct statvfs *buf)
{
	ULARGE_INTEGER avail, total, freebytes;

	if (!GetDiskFreeSpaceExW(root, &avail, &total, &freebytes)) {
		errno = EACCES;
		return -1;
	}

	/* Report sizes in bytes with a unit block size. Callers compute
	 * f_bsize * f_bavail, which then yields the exact free byte count
	 * without any cluster-rounding error. */
	memset(buf, 0, sizeof *buf);
	buf->f_bsize  = 1;
	buf->f_frsize = 1;
	buf->f_blocks = (uint64_t)total.QuadPart;
	buf->f_bfree  = (uint64_t)freebytes.QuadPart;
	buf->f_bavail = (uint64_t)avail.QuadPart;
	return 0;
}

/* Preferred route: ask the volume directly through the handle.
 *
 * GetFinalPathNameByHandleW() is not universally supported - some filesystem
 * drivers (RAM disks in particular) fail it with ERROR_INVALID_FUNCTION - so
 * resolving the handle back to a path first is not dependable. This query is
 * answered by the filesystem itself and works everywhere tested.
 */
typedef struct {
	LARGE_INTEGER	TotalAllocationUnits;
	LARGE_INTEGER	AvailableAllocationUnits;
	ULONG		SectorsPerAllocationUnit;
	ULONG		BytesPerSector;
} lrzip_ffs_size_info;

typedef struct {
	union {
		LONG	Status;
		PVOID	Pointer;
	} u;
	ULONG_PTR	Information;
} lrzip_io_status_block;

typedef LONG (WINAPI *lrzip_nt_query_volume_fn)(HANDLE, lrzip_io_status_block *,
						PVOID, ULONG, int);

#define LRZIP_FileFsSizeInformation 3

static lrzip_nt_query_volume_fn resolve_nt_query_volume(void)
{
	static lrzip_nt_query_volume_fn fn;
	static int resolved;

	if (!resolved) {
		HMODULE ntdll = GetModuleHandleA("ntdll.dll");

		if (ntdll)
			fn = (lrzip_nt_query_volume_fn)(void *)
				GetProcAddress(ntdll, "NtQueryVolumeInformationFile");
		resolved = 1;
	}
	return fn;
}

static int statvfs_by_handle(HANDLE h, struct statvfs *buf)
{
	lrzip_nt_query_volume_fn query = resolve_nt_query_volume();
	lrzip_ffs_size_info info;
	lrzip_io_status_block iosb;
	uint64_t unit;

	if (!query)
		return -1;

	memset(&info, 0, sizeof info);
	memset(&iosb, 0, sizeof iosb);

	if (query(h, &iosb, &info, sizeof info, LRZIP_FileFsSizeInformation) < 0)
		return -1;

	unit = (uint64_t)info.SectorsPerAllocationUnit * (uint64_t)info.BytesPerSector;
	if (!unit)
		return -1;

	memset(buf, 0, sizeof *buf);
	buf->f_bsize  = 1;
	buf->f_frsize = 1;
	buf->f_blocks = (uint64_t)info.TotalAllocationUnits.QuadPart * unit;
	buf->f_bfree  = (uint64_t)info.AvailableAllocationUnits.QuadPart * unit;
	buf->f_bavail = buf->f_bfree;
	return 0;
}

int fstatvfs(int fd, struct statvfs *buf)
{
	HANDLE h;
	wchar_t path[MAX_PATH * 4];
	wchar_t root[MAX_PATH];
	DWORD n;

	if (!buf) {
		errno = EFAULT;
		return -1;
	}

	h = (HANDLE)_get_osfhandle(fd);
	if (h == INVALID_HANDLE_VALUE) {
		errno = EBADF;
		return -1;
	}

	if (!statvfs_by_handle(h, buf))
		return 0;

	/* Fallback: resolve to a path and ask about the volume that way. */
	n = GetFinalPathNameByHandleW(h, path, (DWORD)(sizeof path / sizeof path[0]),
				      FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
	if (!n || n >= sizeof path / sizeof path[0]) {
		errno = EBADF;
		return -1;
	}

	if (!GetVolumePathNameW(path, root, (DWORD)(sizeof root / sizeof root[0]))) {
		errno = EACCES;
		return -1;
	}
	return statvfs_from_root(root, buf);
}

int statvfs(const char *path, struct statvfs *buf)
{
	wchar_t wpath[MAX_PATH * 4];
	wchar_t root[MAX_PATH];

	if (!path || !buf) {
		errno = EFAULT;
		return -1;
	}
	if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath,
				 (int)(sizeof wpath / sizeof wpath[0]))) {
		errno = EINVAL;
		return -1;
	}
	if (!GetVolumePathNameW(wpath, root, (DWORD)(sizeof root / sizeof root[0]))) {
		errno = EACCES;
		return -1;
	}
	return statvfs_from_root(root, buf);
}

/* Windows has no POSIX permission or ownership model that maps usefully onto
 * these. Succeed silently so that callers which treat failure as fatal are
 * not broken; the file's ACL is inherited from the destination directory. */
int fchmod(int fd, mode_t mode)
{
	(void)fd; (void)mode;
	return 0;
}

int fchown(int fd, int owner, int group)
{
	(void)fd; (void)owner; (void)group;
	return 0;
}

int mkstemp(char *tmpl)
{
	static const char letters[] =
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	size_t len;
	char *suffix;
	int attempt;

	if (!tmpl) {
		errno = EINVAL;
		return -1;
	}
	len = strlen(tmpl);
	if (len < 6 || strcmp(tmpl + len - 6, "XXXXXX")) {
		errno = EINVAL;
		return -1;
	}
	suffix = tmpl + len - 6;

	for (attempt = 0; attempt < 512; attempt++) {
		int i, fd;

		for (i = 0; i < 6; i++)
			suffix[i] = letters[(unsigned long)random() % (sizeof letters - 1)];

		/* Deliberately via lrzip_win32_open() so the temporary file is
		 * opened with delete sharing and can be unlinked while open. */
		fd = lrzip_win32_open(tmpl, _O_RDWR | _O_CREAT | _O_EXCL | _O_BINARY);
		if (fd >= 0)
			return fd;
		if (errno != EEXIST)
			return -1;
	}

	memcpy(suffix, "XXXXXX", 6);
	errno = EEXIST;
	return -1;
}

/* ================================================================== *
 * Scheduling priority
 * ================================================================== */

int getpriority(int which, int who)
{
	DWORD cls;

	(void)which; (void)who;

	cls = GetPriorityClass(GetCurrentProcess());
	switch (cls) {
	case IDLE_PRIORITY_CLASS:		return 19;
	case BELOW_NORMAL_PRIORITY_CLASS:	return 10;
	case NORMAL_PRIORITY_CLASS:		return 0;
	case ABOVE_NORMAL_PRIORITY_CLASS:	return -5;
	case HIGH_PRIORITY_CLASS:		return -10;
	case REALTIME_PRIORITY_CLASS:		return -20;
	default:				return 0;
	}
}

int setpriority(int which, int who, int prio)
{
	DWORD cls;

	(void)which; (void)who;

	if (prio >= 15)
		cls = IDLE_PRIORITY_CLASS;
	else if (prio >= 5)
		cls = BELOW_NORMAL_PRIORITY_CLASS;
	else if (prio > -5)
		cls = NORMAL_PRIORITY_CLASS;
	else if (prio > -10)
		cls = ABOVE_NORMAL_PRIORITY_CLASS;
	else
		cls = HIGH_PRIORITY_CLASS;

	if (!SetPriorityClass(GetCurrentProcess(), cls)) {
		errno = EACCES;
		return -1;
	}
	return 0;
}

/* ================================================================== *
 * Resource limits - nothing on Windows corresponds to RLIMIT_DATA, so report
 * "unlimited" and accept any attempt to change it.
 * ================================================================== */

int getrlimit(int resource, struct rlimit *rlim)
{
	(void)resource;

	if (!rlim) {
		errno = EFAULT;
		return -1;
	}
	rlim->rlim_cur = RLIM_INFINITY;
	rlim->rlim_max = RLIM_INFINITY;
	return 0;
}

int setrlimit(int resource, const struct rlimit *rlim)
{
	(void)resource; (void)rlim;
	return 0;
}

/* ================================================================== *
 * sysconf
 * ================================================================== */

long sysconf(int name)
{
	SYSTEM_INFO si;
	MEMORYSTATUSEX ms;

	switch (name) {
	case _SC_PAGESIZE:
		GetSystemInfo(&si);
		return (long)si.dwPageSize;

	case _SC_PHYS_PAGES:
		memset(&ms, 0, sizeof ms);
		ms.dwLength = sizeof ms;
		if (!GlobalMemoryStatusEx(&ms))
			return -1;
		GetSystemInfo(&si);
		return (long)(ms.ullTotalPhys / si.dwPageSize);

	case _SC_NPROCESSORS_ONLN:
	case _SC_NPROCESSORS_CONF: {
		/* Respect the process affinity mask where one applies, matching
		 * the affinity-aware behaviour of the POSIX implementations. */
		DWORD_PTR proc_mask = 0, sys_mask = 0;

		if (GetProcessAffinityMask(GetCurrentProcess(), &proc_mask, &sys_mask)
		    && proc_mask) {
			int count = 0;

			while (proc_mask) {
				count += (int)(proc_mask & 1);
				proc_mask >>= 1;
			}
			if (count > 0)
				return count;
		}
		return (long)GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
	}

	default:
		errno = EINVAL;
		return -1;
	}
}

/* ================================================================== *
 * random()
 *
 * MinGW's rand() has RAND_MAX == 32767, which is far too narrow for building
 * the rzip hash index. This is splitmix64, which is small, fast and has good
 * distribution in its low bits.
 * ================================================================== */

static uint64_t rng_state;
static int rng_seeded;

static void rng_seed_once(void)
{
	LARGE_INTEGER pc;

	if (rng_seeded)
		return;
	QueryPerformanceCounter(&pc);
	rng_state = (uint64_t)pc.QuadPart
		  ^ ((uint64_t)GetCurrentProcessId() << 32)
		  ^ (uint64_t)GetTickCount64();
	rng_seeded = 1;
}

void srandom(unsigned int seed)
{
	rng_state = seed;
	rng_seeded = 1;
}

long random(void)
{
	uint64_t z;

	rng_seed_once();
	rng_state += 0x9E3779B97F4A7C15ULL;
	z = rng_state;
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
	z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
	z =  z ^ (z >> 31);

	/* POSIX random() returns a non-negative value below 2^31. */
	return (long)(z & 0x7FFFFFFFu);
}

/* ================================================================== *
 * Bounded read()/write()
 * ================================================================== */

/* Upper bound on a single transfer.
 *
 * MSVCRT cannot exceed INT_MAX at all, and Linux silently caps at 0x7ffff000,
 * so any value below that is legal - callers must already cope with short
 * transfers and every loop in lrzip does. A modest cap is chosen deliberately:
 * read() commits the span it is about to fill in a lazily reserved mapping, so
 * this also bounds how much commit charge a small STDIN stream pulls in.
 */
#define LRZIP_IO_MAX (64u * 1024u * 1024u)

/* Back a span of a lazily reserved anonymous mapping with real pages.
 *
 * Anonymous mappings are handed out reserved-only (see mmap above), so the
 * region a read() is about to fill has to be committed first. Doing it here
 * rather than up front means a small STDIN stream costs a small commit
 * charge instead of the whole multi-gigabyte compression window, while the
 * window itself stays at full size - shrinking it would directly cost
 * compression ratio, since rzip can only match within one window.
 *
 * Anything not inside a lazily reserved mapping is left alone.
 */
static void commit_if_lazy(void *addr, size_t len)
{
	struct map_entry *e;

	if (!addr || !len)
		return;

	mappings_lock();
	e = mapping_containing(addr);
	if (e && e->anon && e->lazy) {
		size_t avail = (size_t)((char *)e->ptr + e->len - (char *)addr);

		if (len > avail)
			len = avail;
		/* VirtualAlloc rounds to page boundaries and committing an
		 * already-committed page is a no-op, so this is idempotent. */
		VirtualAlloc(addr, len, MEM_COMMIT, e->prot);
	}
	mappings_unlock();
}

ssize_t lrzip_win32_read(int fd, void *buf, size_t count)
{
	if (count > LRZIP_IO_MAX)
		count = LRZIP_IO_MAX;
	commit_if_lazy(buf, count);
	return _read(fd, buf, (unsigned int)count);
}

ssize_t lrzip_win32_write(int fd, const void *buf, size_t count)
{
	if (count > LRZIP_IO_MAX)
		count = LRZIP_IO_MAX;
	return _write(fd, buf, (unsigned int)count);
}

/* ================================================================== *
 * open() with POSIX unlink semantics
 * ================================================================== */

int lrzip_win32_open(const char *path, int flags, ...)
{
	DWORD access = 0, disposition, attrs = FILE_ATTRIBUTE_NORMAL;
	const DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
	int osf_flags = 0;
	HANDLE h;
	int fd;

	switch (flags & (_O_RDONLY | _O_WRONLY | _O_RDWR)) {
	case _O_WRONLY:
		access = GENERIC_WRITE;
		break;
	case _O_RDWR:
		access = GENERIC_READ | GENERIC_WRITE;
		break;
	default:
		access = GENERIC_READ;
		osf_flags |= _O_RDONLY;
		break;
	}
	if (flags & _O_APPEND) {
		access |= FILE_APPEND_DATA;
		osf_flags |= _O_APPEND;
	}

	/* DELETE access lets the file be renamed or marked for deletion while
	 * still open; combined with FILE_SHARE_DELETE this is what gives POSIX
	 * unlink-while-open behaviour. */
	access |= DELETE;

	if ((flags & _O_CREAT) && (flags & _O_EXCL))
		disposition = CREATE_NEW;
	else if ((flags & _O_CREAT) && (flags & _O_TRUNC))
		disposition = CREATE_ALWAYS;
	else if (flags & _O_CREAT)
		disposition = OPEN_ALWAYS;
	else if (flags & _O_TRUNC)
		disposition = TRUNCATE_EXISTING;
	else
		disposition = OPEN_EXISTING;

	if (flags & _O_TEMPORARY)
		attrs |= FILE_FLAG_DELETE_ON_CLOSE;

	h = CreateFileA(path, access, share, NULL, disposition, attrs, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		switch (GetLastError()) {
		case ERROR_FILE_EXISTS:
		case ERROR_ALREADY_EXISTS:	errno = EEXIST; break;
		case ERROR_FILE_NOT_FOUND:
		case ERROR_PATH_NOT_FOUND:	errno = ENOENT; break;
		case ERROR_ACCESS_DENIED:	errno = EACCES; break;
		case ERROR_SHARING_VIOLATION:	errno = EACCES; break;
		default:			errno = EINVAL; break;
		}
		return -1;
	}

	/* Text/binary follows the process default set by
	 * win32_init_binary_mode() unless _O_TEXT was asked for explicitly. */
	if (flags & _O_TEXT)
		osf_flags |= _O_TEXT;

	fd = _open_osfhandle((intptr_t)h, osf_flags);
	if (fd < 0) {
		CloseHandle(h);
		errno = EMFILE;
		return -1;
	}
	return fd;
}

/* ================================================================== *
 * Binary I/O
 * ================================================================== */

void win32_init_binary_mode(void)
{
	/* Default for everything opened from here on. */
	_set_fmode(_O_BINARY);

	/* The standard streams are already open and need converting
	 * individually; lrzip compresses from stdin and to stdout. */
	_setmode(_fileno(stdin),  _O_BINARY);
	_setmode(_fileno(stdout), _O_BINARY);
	_setmode(_fileno(stderr), _O_BINARY);
}

/* ================================================================== *
 * Cryptographically secure entropy, standing in for /dev/urandom.
 * ================================================================== */

#ifndef BCRYPT_USE_SYSTEM_PREFERRED_RNG
# define BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002
#endif

int win32_secure_random(void *buf, size_t len)
{
	while (len) {
		ULONG chunk = (ULONG)(len > 0xffffffffu ? 0xffffffffu : len);

		if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, (PUCHAR)buf, chunk,
						    BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
			errno = EIO;
			return -1;
		}
		buf  = (char *)buf + chunk;
		len -= chunk;
	}
	return 0;
}

/* ================================================================== *
 * Pinning key material so it cannot be written to the pagefile.
 *
 * VirtualLock() is subject to the process working-set quota, so failure is
 * plausible and reported; lrzip treats mlock() failure as non-fatal.
 * ================================================================== */

int mlock(const void *addr, size_t len)
{
	if (!VirtualLock((LPVOID)addr, len)) {
		errno = EAGAIN;
		return -1;
	}
	return 0;
}

int munlock(const void *addr, size_t len)
{
	if (!VirtualUnlock((LPVOID)addr, len)) {
		errno = EAGAIN;
		return -1;
	}
	return 0;
}

/* ================================================================== *
 * Terminal echo
 * ================================================================== */

static HANDLE console_handle(int fd)
{
	HANDLE h = (HANDLE)_get_osfhandle(fd);
	DWORD mode;

	if (h == INVALID_HANDLE_VALUE || !GetConsoleMode(h, &mode))
		return INVALID_HANDLE_VALUE;
	return h;
}

int tcgetattr(int fd, struct termios *t)
{
	HANDLE h = console_handle(fd);
	DWORD mode = 0;

	if (!t) {
		errno = EFAULT;
		return -1;
	}
	memset(t, 0, sizeof *t);

	if (h == INVALID_HANDLE_VALUE) {
		errno = ENOTTY;
		return -1;
	}
	GetConsoleMode(h, &mode);
	if (mode & ENABLE_ECHO_INPUT)
		t->c_lflag |= ECHO;
	return 0;
}

int tcsetattr(int fd, int actions, const struct termios *t)
{
	HANDLE h = console_handle(fd);
	DWORD mode = 0;

	(void)actions;

	if (!t) {
		errno = EFAULT;
		return -1;
	}
	if (h == INVALID_HANDLE_VALUE) {
		errno = ENOTTY;
		return -1;
	}
	if (!GetConsoleMode(h, &mode))
		return -1;

	if (t->c_lflag & ECHO)
		mode |= ENABLE_ECHO_INPUT;
	else
		mode &= ~(DWORD)ENABLE_ECHO_INPUT;

	if (!SetConsoleMode(h, mode)) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

/* ================================================================== *
 * Signals - enough of sigaction() to drive lrzip's handler installation.
 * ================================================================== */

int sigemptyset(sigset_t *set)
{
	if (!set) {
		errno = EFAULT;
		return -1;
	}
	*set = 0;
	return 0;
}

int sigfillset(sigset_t *set)
{
	if (!set) {
		errno = EFAULT;
		return -1;
	}
	*set = ~0UL;
	return 0;
}

int sigaddset(sigset_t *set, int signum)
{
	if (!set) {
		errno = EFAULT;
		return -1;
	}
	*set |= 1UL << (signum & 31);
	return 0;
}

int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
	void (*prev)(int);

	/* Job-control signals do not exist on Windows; pretend the handler was
	 * installed so callers do not treat it as an error. */
	if (signum == SIGTTIN || signum == SIGTTOU) {
		if (oldact)
			memset(oldact, 0, sizeof *oldact);
		return 0;
	}

	if (!act) {
		if (oldact)
			memset(oldact, 0, sizeof *oldact);
		return 0;
	}

	prev = signal(signum, act->sa_handler);
	if (prev == SIG_ERR) {
		errno = EINVAL;
		return -1;
	}
	if (oldact) {
		memset(oldact, 0, sizeof *oldact);
		oldact->sa_handler = prev;
	}
	return 0;
}

#endif /* _WIN32 */
