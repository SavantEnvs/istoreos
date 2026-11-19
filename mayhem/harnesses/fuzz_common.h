/*
 * Shared helpers for the istoreos CLI-tool harnesses.
 *
 * The firmware tools under package/utils/ read their input from a file named
 * on the command line, so each harness stages the fuzz input in a scratch file
 * under $TMPDIR (mkstemp; never a fixed or absolute image path) and calls the
 * tool's own main() (renamed with -Dmain=<tool>_main) with a fixed argv.
 *
 * State kept across inputs on purpose: the scratch file path (its contents are
 * rewritten for every input) and stdout redirected to /dev/null (the tools
 * print what they parse; that output is not part of the oracle). getopt's
 * optind is reset before every call.
 */
#ifndef ISTOREOS_FUZZ_COMMON_H
#define ISTOREOS_FUZZ_COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>

static char fuzz_scratch[4096];

/* Create the per-process scratch file once. */
static const char *fuzz_scratch_path(void)
{
	if (!fuzz_scratch[0]) {
		const char *dir = getenv("TMPDIR");
		int fd;

		if (!dir || !*dir)
			dir = "/tmp";
		snprintf(fuzz_scratch, sizeof(fuzz_scratch), "%s/istoreos-fuzz-XXXXXX", dir);
		fd = mkstemp(fuzz_scratch);
		if (fd < 0) {
			perror("mkstemp");
			abort();
		}
		close(fd);
	}
	return fuzz_scratch;
}

/* (Re)write the scratch file with exactly `size` bytes of `data`. */
static const char *fuzz_write_input(const uint8_t *data, size_t size)
{
	const char *path = fuzz_scratch_path();
	int fd = open(path, O_WRONLY | O_TRUNC);
	size_t off = 0;

	if (fd < 0) {
		perror("open scratch");
		abort();
	}
	while (off < size) {
		ssize_t n = write(fd, data + off, size - off);
		if (n <= 0) {
			perror("write scratch");
			abort();
		}
		off += (size_t)n;
	}
	close(fd);
	return path;
}

static void fuzz_quiet_stdout(void)
{
	static int done;

	if (!done) {
		done = 1;
		if (!freopen("/dev/null", "w", stdout))
			abort();
	}
}

/* Run a tool main() with a fresh getopt state. */
#define FUZZ_RUN_MAIN(fn, ...) do {                                    \
	char *fuzz_argv_[] = { __VA_ARGS__, NULL };                    \
	optind = 1;                                                    \
	opterr = 0;                                                    \
	errno = 0;                                                     \
	(void)fn((int)(sizeof(fuzz_argv_) / sizeof(fuzz_argv_[0])) - 1, \
		 fuzz_argv_);                                          \
} while (0)

#endif
