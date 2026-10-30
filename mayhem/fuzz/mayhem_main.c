// SPDX-License-Identifier: GPL-2.0+
// Host-side glue linked into the sandbox u-boot fuzz binary (compiled outside kbuild).
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Leak detection is off by default for this fleet's fuzz builds. */
int __lsan_is_turned_off(void)
{
	return 1;
}

static const char *const tests[] = {
	"fuzz_vring", "fuzz_fdt", "fuzz_fdt_overlay", "fuzz_fit", "fuzz_gzip",
	"fuzz_bzip2", "fuzz_lzma", "fuzz_lz4", "fuzz_lzo", "fuzz_zstd",
	"fuzz_x509", "fuzz_pkcs7", "fuzz_env", "fuzz_charset",
};

/*
 * One binary, many targets: the file name it is run as (hard links made by
 * build.sh) selects the FUZZ_TEST, and the sandbox is started from the build
 * directory because it looks up ./arch/sandbox/dts/test.dtb relative to cwd.
 */
__attribute__((constructor)) static void mayhem_select_test(void)
{
	const char *name = program_invocation_short_name;
	char exe[PATH_MAX], dir[PATH_MAX + 16];
	ssize_t n;
	size_t i;

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		if (!strcmp(name, tests[i]))
			setenv("UBOOT_SB_FUZZ_TEST", tests[i], 1);
	}
	setenv("UBOOT_SB_FUZZ_TEST", "fuzz_vring", 0);

	n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
	if (n <= 0)
		return;
	exe[n] = 0;
	while (n > 0 && exe[n - 1] != '/')
		exe[--n] = 0;
	snprintf(dir, sizeof(dir), "%sbuild-fuzz", exe);
	if (chdir(dir))
		perror("mayhem: chdir to build-fuzz");
}
