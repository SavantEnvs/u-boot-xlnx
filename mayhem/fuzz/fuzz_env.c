// SPDX-License-Identifier: GPL-2.0+
#include <os.h>
#include <search.h>
#include <string.h>
#include <test/fuzz.h>

/* Input: byte 0 = separator choice / flags, rest = environment text */
static int fuzz_env(const uint8_t *data, size_t size)
{
	static const char seps[] = { '\0', '\n', ' ', ';' };
	struct hsearch_data htab;
	char *buf;
	int flags;

	if (size < 2)
		return -1;
	buf = os_malloc(size - 1);
	if (!buf)
		return 0;
	memcpy(buf, data + 1, size - 1);

	memset(&htab, 0, sizeof(htab));
	if (hcreate_r(32, &htab)) {
		flags = H_NOCLEAR | ((data[0] & 0x04) ? H_FORCE : 0);
		himport_r(&htab, buf, size - 1, seps[data[0] & 3], flags,
			  !!(data[0] & 0x08), 0, NULL);
		himport_r(&htab, buf, size - 1, seps[data[0] & 3], 0,
			  !!(data[0] & 0x10), 0, NULL);
		hdestroy_r(&htab);
	}
	os_free(buf);
	return 0;
}
FUZZ_TEST(fuzz_env, 0);
