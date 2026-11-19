/*
 * Known-answer test for libnvram (package/utils/nvram/src/nvram.c), built by
 * build.sh with normal flags and run by test.sh: opens an NVRAM partition
 * image read-only and prints every variable as name=value, sorted, plus a
 * get/set/unset round trip. test.sh diffs the output against nvram.expected.
 * Usage: nvram_selftest <image>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "../../package/utils/nvram/src/nvram.h"

extern size_t nvram_part_size;

static int cmp(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

int main(int argc, char **argv)
{
	struct stat st;
	nvram_handle_t *h;
	nvram_tuple_t *t;
	char *lines[256];
	int n = 0;

	if (argc != 2 || stat(argv[1], &st))
		return 2;
	nvram_part_size = st.st_size;
	h = nvram_open(argv[1], NVRAM_RO);
	if (!h) {
		printf("open failed\n");
		return 1;
	}
	for (t = nvram_getall(h); t && n < 256; t = t->next) {
		size_t l = strlen(t->name) + strlen(t->value) + 2;
		lines[n] = malloc(l);
		snprintf(lines[n], l, "%s=%s", t->name, t->value);
		n++;
	}
	qsort(lines, n, sizeof(lines[0]), cmp);
	for (int i = 0; i < n; i++)
		printf("%s\n", lines[i]);
	printf("get lan_ipaddr: %s\n", nvram_get(h, "lan_ipaddr"));
	nvram_set(h, "lan_ipaddr", "10.0.0.1");
	printf("after set: %s\n", nvram_get(h, "lan_ipaddr"));
	nvram_unset(h, "lan_ipaddr");
	printf("after unset: %s\n", nvram_get(h, "lan_ipaddr") ? "present" : "absent");
	nvram_close(h);
	return 0;
}
