// SPDX-License-Identifier: GPL-2.0+
#include <image.h>
#include <linux/libfdt.h>
#include <os.h>
#include <string.h>
#include <test/fuzz.h>

static int fuzz_fit(const uint8_t *data, size_t size)
{
	void *fit = os_malloc(size ? size : 1);
	int images, confs, off;

	if (!fit)
		return 0;
	if (size)
		memcpy(fit, data, size);

	if (fit_check_format(fit, size))
		goto out;

	images = fdt_path_offset(fit, FIT_IMAGES_PATH);
	if (images >= 0) {
		fdt_for_each_subnode(off, fit, images) {
			const void *p;
			ulong val;
			size_t len;
			int sz;
			uint8_t os, arch, type, comp;

			fit_image_verify(fit, off);
			fit_image_get_data(fit, off, &p, &len);
			fit_image_get_data_size(fit, off, &sz);
			fit_image_get_data_offset(fit, off, &sz);
			fit_image_get_load(fit, off, &val);
			fit_image_get_entry(fit, off, &val);
			fit_image_get_os(fit, off, &os);
			fit_image_get_arch(fit, off, &arch);
			fit_image_get_type(fit, off, &type);
			fit_image_get_comp(fit, off, &comp);
		}
	}
	fit_all_image_verify(fit);

	confs = fdt_path_offset(fit, FIT_CONFS_PATH);
	if (confs >= 0) {
		const char *def = fdt_getprop(fit, confs, FIT_DEFAULT_PROP, NULL);

		fdt_for_each_subnode(off, fit, confs) {
			fit_config_verify(fit, off);
			fit_conf_get_prop_node(fit, off, FIT_KERNEL_PROP,
					       IH_PHASE_NONE);
			fit_conf_get_prop_node(fit, off, FIT_FDT_PROP,
					       IH_PHASE_NONE);
		}
		(void)def;
		fit_conf_get_node(fit, NULL);
	}
	fit_image_get_node(fit, "kernel");
out:
	os_free(fit);
	return 0;
}
FUZZ_TEST(fuzz_fit, 0);
