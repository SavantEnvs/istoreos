/*
 * bcm4908img: Broadcom BCM4908 firmware image parser
 * (package/utils/bcm4908img/src/bcm4908img.c).
 *
 * The fuzz input is the image file. Each input is run through the tool's own
 * command-line entry points, exactly as `bcm4908img <cmd> -i <file>`:
 *   info, extract -t {cferom,bootfs,rootfs,firmware}, bootfs ls, bootfs mv
 * (mv rewrites the scratch copy in place; it is rewritten for the next run).
 *
 * Checksum fix-up: bcm4908img_parse() ends with a CRC32 over the whole
 * firmware area (cferom/bootfs .. tail) compared with tail->crc32, and every
 * command bails out with -EPROTO on a mismatch. A whole-image checksum cannot
 * survive mutation (shipping seeds does not help), so the harness recomputes
 * it over the mutated bytes and stores it in the tail, locating the tail
 * exactly as bcm4908img_parse() does (chk vendor header, optional LINKSYS
 * tail) and using the tool's own bcm4908img_crc32(). It is not a format gate:
 * no field the parser dispatches on is touched, every input still reaches the
 * parser, and the only path given up is the "Invalid data crc32" return.
 * Crashes reproduce with fuzz_bcm4908img-standalone, which applies the same
 * fix-up.
 */
#include "fuzz_common.h"
#include <stddef.h>

#define main bcm4908img_main
#include "../../package/utils/bcm4908img/src/bcm4908img.c"
#undef main

/* Recompute tail->crc32 in a copy of the input; returns the (malloc'd) copy. */
static uint8_t *fixup_crc32(const uint8_t *data, size_t size)
{
	uint8_t *img = malloc(size ? size : 1);
	size_t cferom = 0, tail_off;
	uint32_t v, crc;

	if (!img)
		abort();
	memcpy(img, data, size);
	/* bcm4908img_parse() needs 1024 B of header and of trailer. */
	if (size < 1024)
		return img;
	tail_off = size - sizeof(struct bcm4908img_tail);
	memcpy(&v, img, sizeof(v));
	if (be32_to_cpu(v) == 0x2a23245e) {
		memcpy(&v, img + offsetof(struct chk_header, header_len), sizeof(v));
		cferom = be32_to_cpu(v);
	}
	if (!memcmp(img + size - sizeof(struct linksys_tail), ".LINKSYS.", 9))
		tail_off -= sizeof(struct linksys_tail);
	if (cferom > tail_off)
		return img;	/* the parser rejects it before the CRC */
	crc = cpu_to_le32(bcm4908img_crc32(0xffffffff, img + cferom, tail_off - cferom));
	memcpy(img + tail_off + offsetof(struct bcm4908img_tail, crc32), &crc, sizeof(crc));
	return img;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t *img;
	const char *p;
	char path[4096];
	static const char *types[] = { "cferom", "bootfs", "rootfs", "firmware" };

	fuzz_quiet_stdout();
	img = fixup_crc32(data, size);
	p = fuzz_write_input(img, size);
	free(img);
	snprintf(path, sizeof(path), "%s", p);

	FUZZ_RUN_MAIN(bcm4908img_main, "bcm4908img", "info", "-i", path);
	for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++)
		FUZZ_RUN_MAIN(bcm4908img_main, "bcm4908img", "extract", "-i", path,
			      "-t", (char *)types[i]);
	FUZZ_RUN_MAIN(bcm4908img_main, "bcm4908img", "bootfs", "-i", path, "ls");
	FUZZ_RUN_MAIN(bcm4908img_main, "bcm4908img", "bootfs", "-i", path, "mv",
		      "cferom.000", "cferom.001");
	return 0;
}
