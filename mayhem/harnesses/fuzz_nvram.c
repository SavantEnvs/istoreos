/*
 * libnvram: Broadcom NVRAM partition parser (package/utils/nvram/src/nvram.c),
 * through its public API: nvram_open() on a partition image, then
 * nvram_getall / nvram_get / nvram_set / nvram_unset / nvram_close.
 *
 * nvram_open() mmaps `nvram_part_size` bytes, which the CLI takes from the MTD
 * partition size (nvram_find_mtd); real partitions are at least
 * NVRAM_MIN_SPACE (0x8000). The harness models a partition of 0x8000 or
 * 0x10000 bytes: the input is the start of the partition and the rest is
 * zero-filled. Inputs larger than 0x10000 are rejected.
 */
#include "fuzz_common.h"
#include "../../package/utils/nvram/src/nvram.h"

extern size_t nvram_part_size;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static uint8_t img[0x10000];
	size_t part = size <= NVRAM_MIN_SPACE ? NVRAM_MIN_SPACE : 0x10000;
	nvram_handle_t *h;
	nvram_tuple_t *t;
	unsigned n = 0;

	if (size > sizeof(img))
		return -1;
	memset(img, 0, part);
	memcpy(img, data, size);
	fuzz_write_input(img, part);

	nvram_part_size = part;
	h = nvram_open(fuzz_scratch_path(), NVRAM_RO);
	if (!h)
		return 0;

	for (t = nvram_getall(h); t; ) {
		nvram_tuple_t *next = t->next;
		n += (unsigned)strlen(t->name) + (unsigned)strlen(t->value);
		free(t);
		t = next;
	}
	(void)nvram_get(h, "sdram_init");
	(void)nvram_get(h, "boardtype");
	nvram_set(h, "fuzz", "value");
	nvram_unset(h, "sdram_ncdl");
	nvram_unset(h, "fuzz");
	nvram_close(h);
	(void)n;
	return 0;
}
