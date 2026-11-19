/*
 * osafeloader: TP-Link SafeLoader firmware parser
 * (package/utils/osafeloader/src/osafeloader.c).
 *
 * The fuzz input is the SafeLoader file, run as `osafeloader info <file>` and
 * `osafeloader extract <file> -p <partition> -o /dev/null`.
 *
 * Checksum fix-up: `info` only parses the partition table after a salted MD5
 * of the body (md5_salt, then imagesize bytes from offset 20) matches hdr.md5.
 * A whole-body digest cannot survive mutation, so the harness recomputes it
 * over the mutated body exactly as osafeloader_info() does (same in-tree md5.c,
 * same salt, same length) and stores it in hdr.md5. imagesize, the only header
 * field the tool reads, is left as the fuzzer wrote it; the only path given up
 * is the "invalid MD5" return. Crashes reproduce with
 * fuzz_osafeloader-standalone, which applies the same fix-up.
 */
#include "fuzz_common.h"
#include <stddef.h>

#define main osafeloader_main
#include "../../package/utils/osafeloader/src/osafeloader.c"
#undef main

/* Recompute hdr.md5 in a copy of the input; returns the (malloc'd) copy. */
static uint8_t *fixup_md5(const uint8_t *data, size_t size)
{
	uint8_t *img = malloc(size ? size : 1);
	struct safeloader_header hdr;
	size_t imagesize;
	MD5_CTX ctx;

	if (!img)
		abort();
	memcpy(img, data, size);
	if (size < sizeof(hdr))
		return img;	/* "Couldn't read header" */
	memcpy(&hdr, img, sizeof(hdr));
	imagesize = be32_to_cpu(hdr.imagesize);
	imagesize = osafeloader_min(imagesize, size - sizeof(hdr));
	MD5_Init(&ctx);
	MD5_Update(&ctx, md5_salt, sizeof(md5_salt));
	MD5_Update(&ctx, img + sizeof(hdr), imagesize);
	MD5_Final(img + offsetof(struct safeloader_header, md5), &ctx);
	return img;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t *img;
	const char *p;
	char path[4096];

	fuzz_quiet_stdout();
	img = fixup_md5(data, size);
	p = fuzz_write_input(img, size);
	free(img);
	snprintf(path, sizeof(path), "%s", p);

	safeloader_path = partition_name = out_path = NULL;
	FUZZ_RUN_MAIN(osafeloader_main, "osafeloader", "info", path);
	safeloader_path = partition_name = out_path = NULL;
	FUZZ_RUN_MAIN(osafeloader_main, "osafeloader", "extract", path,
		      "-p", "os-image", "-o", "/dev/null");
	return 0;
}
