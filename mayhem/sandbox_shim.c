/* Linked into the fuzz binary only (build.sh, CFLAGS_busybox). ash, awk and sed interpret fuzz-supplied
 * scripts, so each input must not start programs, leave files behind or signal processes outside its own
 * tree or outlive it, or one input would change what later ones see. These definitions take over libc's
 * for the calls busybox makes; they change no applet code. */
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define DENY(ret, err) do { errno = (err); return (ret); } while (0)

/* Starting programs: nothing is reachable through PATH or a path. */
int execve(const char *p, char *const a[], char *const e[]) { (void)p; (void)a; (void)e; DENY(-1, ENOENT); }
int execv(const char *p, char *const a[]) { (void)p; (void)a; DENY(-1, ENOENT); }
int execvp(const char *p, char *const a[]) { (void)p; (void)a; DENY(-1, ENOENT); }
int execvpe(const char *p, char *const a[], char *const e[]) { (void)p; (void)a; (void)e; DENY(-1, ENOENT); }
int fexecve(int fd, char *const a[], char *const e[]) { (void)fd; (void)a; (void)e; DENY(-1, ENOENT); }
int execl(const char *p, const char *a, ...) { (void)p; (void)a; DENY(-1, ENOENT); }
int execlp(const char *p, const char *a, ...) { (void)p; (void)a; DENY(-1, ENOENT); }
int execle(const char *p, const char *a, ...) { (void)p; (void)a; DENY(-1, ENOENT); }
int posix_spawn(pid_t *pid, const char *p, const posix_spawn_file_actions_t *fa,
		const posix_spawnattr_t *at, char *const a[], char *const e[])
{ (void)pid; (void)p; (void)fa; (void)at; (void)a; (void)e; return ENOENT; }
int posix_spawnp(pid_t *pid, const char *p, const posix_spawn_file_actions_t *fa,
		 const posix_spawnattr_t *at, char *const a[], char *const e[])
{ (void)pid; (void)p; (void)fa; (void)at; (void)a; (void)e; return ENOENT; }
int system(const char *cmd) { (void)cmd; DENY(-1, ENOENT); }
FILE *popen(const char *cmd, const char *mode) { (void)cmd; (void)mode; DENY(NULL, ENOENT); }

/* Files: the only thing an input may open for writing is a device that holds no state. The std streams
 * and /dev/fd/N are only names for an fd the input may have opened itself (`exec 3</tmp`, or the seed on
 * stdin), so they pass only while that fd is a character device, pipe or socket. */
static int stateless_fd(const char *digits)
{
	struct stat st;
	long fd = 0;
	size_t i;
	if (!digits[0] || strlen(digits) > 9)
		return 0;
	for (i = 0; digits[i]; i++) {
		if (digits[i] < '0' || digits[i] > '9')
			return 0;
		fd = fd * 10 + (digits[i] - '0');
	}
	if (fstat((int)fd, &st) != 0)
		return 0;
	return S_ISCHR(st.st_mode) || S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode);
}

static int writable_path(const char *path)
{
	static const char *const ok[] = {
		"/dev/null", "/dev/zero", "/dev/full", "/dev/tty",
	};
	unsigned i;
	if (!path)
		return 0;
	for (i = 0; i < sizeof(ok) / sizeof(ok[0]); i++)
		if (strcmp(path, ok[i]) == 0)
			return 1;
	if (strcmp(path, "/dev/stdin") == 0)
		return stateless_fd("0");
	if (strcmp(path, "/dev/stdout") == 0)
		return stateless_fd("1");
	if (strcmp(path, "/dev/stderr") == 0)
		return stateless_fd("2");
	if (strncmp(path, "/dev/fd/", 8) == 0)
		return stateless_fd(path + 8);
	return 0;
}

static int opens_for_write(int flags)
{
	return (flags & O_ACCMODE) != O_RDONLY || (flags & (O_CREAT | O_TRUNC | O_APPEND)) ||
	       (flags & O_TMPFILE) == O_TMPFILE;
}

static int checked_openat(int dirfd, const char *path, int flags, mode_t mode)
{
	if (opens_for_write(flags) && !writable_path(path))
		DENY(-1, EACCES);
	return (int)syscall(SYS_openat, dirfd, path, flags, mode);
}

#define OPEN_VARIANT(name)                                                 \
	int name(const char *path, int flags, ...)                         \
	{                                                                  \
		mode_t mode = 0;                                           \
		if (flags & (O_CREAT | O_TMPFILE)) {                       \
			va_list ap;                                        \
			va_start(ap, flags);                               \
			mode = va_arg(ap, mode_t);                         \
			va_end(ap);                                        \
		}                                                          \
		return checked_openat(AT_FDCWD, path, flags, mode);        \
	}
#define OPENAT_VARIANT(name)                                               \
	int name(int dirfd, const char *path, int flags, ...)              \
	{                                                                  \
		mode_t mode = 0;                                           \
		if (flags & (O_CREAT | O_TMPFILE)) {                       \
			va_list ap;                                        \
			va_start(ap, flags);                               \
			mode = va_arg(ap, mode_t);                         \
			va_end(ap);                                        \
		}                                                          \
		return checked_openat(dirfd, path, flags, mode);           \
	}
OPEN_VARIANT(open)
OPEN_VARIANT(open64)
OPENAT_VARIANT(openat)
OPENAT_VARIANT(openat64)
int creat(const char *path, mode_t mode) { return checked_openat(AT_FDCWD, path, O_WRONLY | O_CREAT | O_TRUNC, mode); }
int creat64(const char *path, mode_t mode) { return creat(path, mode); }

static FILE *checked_fopen(const char *path, const char *mode)
{
	int flags, fd;
	FILE *f;
	if (!path || !mode)
		DENY(NULL, EINVAL);
	switch (mode[0]) {
	case 'r': flags = O_RDONLY; break;
	case 'w': flags = O_WRONLY | O_CREAT | O_TRUNC; break;
	case 'a': flags = O_WRONLY | O_CREAT | O_APPEND; break;
	default: DENY(NULL, EINVAL);
	}
	if (strchr(mode, '+'))
		flags = (flags & ~O_ACCMODE) | O_RDWR;
	if (strchr(mode, 'e'))
		flags |= O_CLOEXEC;
	if (strchr(mode, 'x'))
		flags |= O_EXCL;
	fd = checked_openat(AT_FDCWD, path, flags, 0666);
	if (fd < 0)
		return NULL;
	f = fdopen(fd, mode);
	if (!f)
		close(fd);
	return f;
}
FILE *fopen(const char *path, const char *mode) { return checked_fopen(path, mode); }
FILE *fopen64(const char *path, const char *mode) { return checked_fopen(path, mode); }

/* Signals: only the process itself and its own children, never a group, the parent or the fuzzer. */
static int own_tree(pid_t pid)
{
	char buf[256], name[64];
	ssize_t n;
	int fd;
	char *p;
	long ppid;
	if (pid == (pid_t)syscall(SYS_getpid))
		return 1;
	if (pid <= 1)
		return 0;
	snprintf(name, sizeof name, "/proc/%ld/stat", (long)pid);
	fd = (int)syscall(SYS_openat, AT_FDCWD, name, O_RDONLY, 0);
	if (fd < 0)
		return 0;
	n = read(fd, buf, sizeof buf - 1);
	close(fd);
	if (n <= 0)
		return 0;
	buf[n] = 0;
	p = strrchr(buf, ')');
	if (!p || p[1] != ' ' || p[2] == 0 || p[3] != ' ')
		return 0;
	ppid = strtol(p + 4, NULL, 10);
	return ppid == (long)syscall(SYS_getpid);
}
int kill(pid_t pid, int sig)
{
	if (!own_tree(pid))
		DENY(-1, EPERM);
	return (int)syscall(SYS_kill, pid, sig);
}
int killpg(int pgrp, int sig) { (void)pgrp; (void)sig; DENY(-1, EPERM); }

/* Background jobs: an input's own children must not outlive it and burn CPU through later inputs, so a
 * process that exits stops and kills its whole subtree first (a stopped process can't fork more). The
 * common case, no live child, costs one waitid(); only then is /proc scanned for descendants. */
#define MAX_PROCS 16384
#define MAX_TREE 1024

static int proc_table(pid_t *pid, pid_t *ppid)
{
	static char dents[8192];
	char name[64], buf[256];
	int dfd = (int)syscall(SYS_openat, AT_FDCWD, "/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
	int n = 0;
	long got;
	if (dfd < 0)
		return 0;
	while (n < MAX_PROCS && (got = syscall(SYS_getdents64, dfd, dents, sizeof dents)) > 0) {
		long off;
		for (off = 0; off < got && n < MAX_PROCS; ) {
			struct dirent64 *de = (struct dirent64 *)(dents + off);
			long v = strtol(de->d_name, NULL, 10);
			char *p;
			long len;
			int fd;
			off += de->d_reclen;
			if (v <= 1 || de->d_name[0] < '0' || de->d_name[0] > '9')
				continue;
			snprintf(name, sizeof name, "/proc/%ld/stat", v);
			fd = (int)syscall(SYS_openat, AT_FDCWD, name, O_RDONLY | O_CLOEXEC, 0);
			if (fd < 0)
				continue;
			len = syscall(SYS_read, fd, buf, sizeof buf - 1);
			syscall(SYS_close, fd);
			if (len <= 0)
				continue;
			buf[len] = 0;
			p = strrchr(buf, ')');
			if (!p || p[1] != ' ' || p[2] == 0 || p[3] != ' ')
				continue;
			pid[n] = (pid_t)v;
			ppid[n] = (pid_t)strtol(p + 4, NULL, 10);
			n++;
		}
	}
	syscall(SYS_close, dfd);
	return n;
}

static void kill_subtree(void)
{
	static pid_t pid[MAX_PROCS], ppid[MAX_PROCS], tree[MAX_TREE];
	siginfo_t si;
	pid_t self = (pid_t)syscall(SYS_getpid);
	int n = 0, stopped = 0, round, i, j, k;
	if (syscall(SYS_waitid, P_ALL, 0, &si, WEXITED | WNOHANG | WNOWAIT, NULL) != 0 && errno == ECHILD)
		return;
	tree[n++] = self;
	for (round = 0; round < 3; round++) {
		int procs = proc_table(pid, ppid), grew = 0;
		for (i = 0; i < n; i++)
			for (j = 0; j < procs && n < MAX_TREE; j++) {
				if (ppid[j] != tree[i])
					continue;
				for (k = 0; k < n && tree[k] != pid[j]; k++)
					;
				if (k == n) {
					tree[n++] = pid[j];
					grew = 1;
				}
			}
		for (; stopped < n; stopped++)
			if (tree[stopped] != self)
				syscall(SYS_kill, tree[stopped], SIGSTOP);
		if (!grew)
			break;
	}
	for (i = 0; i < n; i++)
		if (tree[i] != self)
			syscall(SYS_kill, tree[i], SIGKILL);
}

/* However the input's process dies (exit, `kill -9 $$`, an ASan/UBSan abort, Mayhem's timeout SIGKILL), no
 * exit path runs, so every child asks the kernel to kill it when its parent goes away. Nothing in this
 * build execs, so the setting is never cleared. The parent pid is re-checked after the prctl() in case
 * the parent died between fork() and it. */
pid_t fork(void)
{
	static pid_t (*real_fork)(void);
	pid_t parent = (pid_t)syscall(SYS_getpid), pid;
	if (!real_fork)
		real_fork = (pid_t (*)(void))dlsym(RTLD_NEXT, "fork");
	pid = real_fork ? real_fork() : (pid_t)syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0);
	if (pid == 0) {
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		if ((pid_t)syscall(SYS_getppid) != parent)
			for (;;)
				syscall(SYS_exit_group, 137);
	}
	return pid;
}

/* ash ends every shell, subshell and background job with _exit(), which skips atexit handlers; busybox
 * calls it directly, so defining it here is enough. exit() paths are covered by the atexit handler. */
void _exit(int status)
{
	kill_subtree();
	for (;;)
		syscall(SYS_exit_group, status);
}
void _Exit(int status) { _exit(status); }
__attribute__((constructor)) static void shim_init(void) { atexit(kill_subtree); }
