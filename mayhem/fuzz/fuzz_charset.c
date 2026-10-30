// SPDX-License-Identifier: GPL-2.0+
#include <charset.h>
#include <os.h>
#include <string.h>
#include <test/fuzz.h>

/* Byte 0 selects the direction: even = UTF-8 in, odd = UTF-16 in */
static int fuzz_charset(const uint8_t *data, size_t size)
{
	if (!size)
		return -1;
	data++;
	size--;

	if (!((data[-1]) & 1)) {
		char *s8 = os_malloc(size + 1);
		u16 *s16;
		size_t n;

		if (!s8)
			return 0;
		memcpy(s8, data, size);
		s8[size] = 0;
		n = utf8_utf16_strlen(s8);
		s16 = os_malloc((n + 1) * sizeof(u16));
		if (s16) {
			u16 *p = s16;

			utf8_utf16_strcpy(&p, s8);
			utf16_utf8_strlen(s16);
			u16_strlen(s16);
			u16_strcasecmp(s16, s16);
		}
		os_free(s16);
		os_free(s8);
	} else {
		size_t n = size / 2;
		u16 *s16 = os_malloc((n + 1) * sizeof(u16));
		char *s8;
		size_t m;

		if (!s16)
			return 0;
		memcpy(s16, data, n * 2);
		s16[n] = 0;
		m = utf16_utf8_strlen(s16);
		s8 = os_malloc(m + 1);
		if (s8) {
			char *p = s8;

			utf16_utf8_strcpy(&p, s16);
			utf8_utf16_strlen(s8);
		}
		for (size_t i = 0; i < n; i++) {
			utf_to_lower(s16[i]);
			utf_to_upper(s16[i]);
		}
		u16_strsize(s16);
		os_free(s8);
		os_free(s16);
	}
	return 0;
}
FUZZ_TEST(fuzz_charset, 0);
