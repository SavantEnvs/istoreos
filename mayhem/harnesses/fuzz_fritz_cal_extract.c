/*
 * fritz_cal_extract: AVM calibration-data extractor
 * (package/utils/fritz-tools/src/fritz_cal_extract.c): walks the
 * calibration entry table and zlib-inflates the matching entry.
 *
 * Input layout: byte 0 selects the entry id passed with -e (the tool's
 * documented argument: which calibration entry to extract), byte 1 holds
 * flags: bit 0 adds -r (reverse), bit 1 adds -l 4096, bit 2 adds -s <byte 2>
 * (seek offset of the entry table) and bit 3 adds -i <byte 3> (bytes to skip
 * in the inflated data); the rest is the flash dump. Run as
 * `fritz_cal_extract -e <id> [-r] [-l 4096] [-s N] [-i N] -o /dev/null <file>`.
 *
 * errno is reset before every call: the tool checks `errno` after each
 * get_num() as a fresh process would see it (0), so a value left over from
 * the previous input would make option parsing fail.
 *
 * The inflate itself runs in the system zlib (a dependency, uninstrumented
 * like every dependency); the fuzzed code is the entry-table walk and the
 * limit/skip/reverse buffer arithmetic around it.
 */
#include <errno.h>
#include "fuzz_common.h"

#define main fritz_cal_extract_main
#include "../../package/utils/fritz-tools/src/fritz_cal_extract.c"
#undef main

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const char *p;
	char path[4096], entry[8], seek[8], skip[8];
	char *argv[16];
	int argc = 0;

	if (size < 4)
		return -1;
	snprintf(entry, sizeof(entry), "%u", (unsigned)data[0]);
	snprintf(seek, sizeof(seek), "%u", (unsigned)data[2]);
	snprintf(skip, sizeof(skip), "%u", (unsigned)data[3]);
	p = fuzz_write_input(data + 4, size - 4);
	snprintf(path, sizeof(path), "%s", p);

	argv[argc++] = "fritz_cal_extract";
	argv[argc++] = "-e";
	argv[argc++] = entry;
	if (data[1] & 1)
		argv[argc++] = "-r";
	if (data[1] & 2) {
		argv[argc++] = "-l";
		argv[argc++] = "4096";
	}
	if (data[1] & 4) {
		argv[argc++] = "-s";
		argv[argc++] = seek;
	}
	if (data[1] & 8) {
		argv[argc++] = "-i";
		argv[argc++] = skip;
	}
	argv[argc++] = "-o";
	argv[argc++] = "/dev/null";
	argv[argc++] = path;
	argv[argc] = NULL;

	optind = 1;
	opterr = 0;
	errno = 0;
	(void)fritz_cal_extract_main(argc, argv);
	return 0;
}
