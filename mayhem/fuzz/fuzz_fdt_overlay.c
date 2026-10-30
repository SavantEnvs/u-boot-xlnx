// SPDX-License-Identifier: GPL-2.0+
#include <fdt_support.h>
#include <linux/libfdt.h>
#include <os.h>
#include <string.h>
#include <test/fuzz.h>

/* Input: be32 length of base tree, base tree, overlay tree */
static int fuzz_fdt_overlay(const uint8_t *data, size_t size)
{
	size_t base_len, ovl_len, room;
	void *base, *ovl, *work;
	uint32_t len;

	if (size < 4)
		return -1;
	len = ((uint32_t)data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
	if (len > size - 4)
		return -1;
	base_len = len;
	ovl_len = size - 4 - base_len;

	base = os_malloc(base_len ? base_len : 1);
	ovl = os_malloc(ovl_len ? ovl_len : 1);
	if (!base || !ovl)
		goto out;
	memcpy(base, data + 4, base_len);
	memcpy(ovl, data + 4 + base_len, ovl_len);

	if (fdt_check_full(base, base_len) || fdt_check_full(ovl, ovl_len))
		goto out;

	room = base_len + ovl_len + 4096;
	work = os_malloc(room);
	if (work && fdt_open_into(base, work, room) == 0) {
		void *ovl_copy = os_malloc(ovl_len);

		if (ovl_copy) {
			memcpy(ovl_copy, ovl, ovl_len);
			fdt_overlay_apply(work, ovl_copy);
			fdt_check_full(work, room);
		}
		os_free(ovl_copy);
	}
	os_free(work);
out:
	os_free(base);
	os_free(ovl);
	return 0;
}
FUZZ_TEST(fuzz_fdt_overlay, 0);
