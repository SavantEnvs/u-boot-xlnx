// SPDX-License-Identifier: GPL-2.0+
#include <linux/libfdt.h>
#include <os.h>
#include <string.h>
#include <test/fuzz.h>

static void *dup_input(const uint8_t *data, size_t size)
{
	void *p = os_malloc(size ? size : 1);

	if (p && size)
		memcpy(p, data, size);
	return p;
}

static void walk_tree(const void *fdt)
{
	char path[256];
	int depth = 0;
	int off;

	for (off = fdt_next_node(fdt, -1, &depth); off >= 0 && depth >= 0;
	     off = fdt_next_node(fdt, off, &depth)) {
		int prop, len;

		fdt_get_name(fdt, off, &len);
		fdt_get_path(fdt, off, path, sizeof(path));
		fdt_get_phandle(fdt, off);
		fdt_getprop(fdt, off, "compatible", &len);
		fdt_getprop(fdt, off, "reg", &len);
		fdt_getprop(fdt, off, "phandle", &len);
		fdt_stringlist_count(fdt, off, "compatible");
		fdt_node_check_compatible(fdt, off, "sandbox,test");
		fdt_address_cells(fdt, off);
		fdt_size_cells(fdt, off);
		fdt_for_each_property_offset(prop, fdt, off) {
			const struct fdt_property *p;
			const char *name;

			p = fdt_get_property_by_offset(fdt, prop, &len);
			if (p)
				fdt_string(fdt, fdt32_to_cpu(p->nameoff));
			fdt_getprop_by_offset(fdt, prop, &name, &len);
		}
	}
	fdt_path_offset(fdt, "/chosen");
	fdt_path_offset(fdt, "/aliases");
	fdt_path_offset(fdt, "/a/b/c");
	fdt_subnode_offset(fdt, 0, "chosen");
	fdt_node_offset_by_compatible(fdt, -1, "sandbox,test");
	fdt_node_offset_by_phandle(fdt, 1);
	fdt_get_alias(fdt, "serial0");
	fdt_num_mem_rsv(fdt);
}

static int fuzz_fdt(const uint8_t *data, size_t size)
{
	void *fdt = dup_input(data, size);
	size_t bufsize = size + 1024;
	void *copy;
	int off;

	if (!fdt)
		return 0;
	if (fdt_check_header(fdt) == 0)
		fdt_check_full(fdt, size);
	if (fdt_check_full(fdt, size) == 0) {
		walk_tree(fdt);

		copy = os_malloc(bufsize);
		if (copy && fdt_open_into(fdt, copy, bufsize) == 0) {
			off = fdt_add_subnode(copy, 0, "fuzz-node");
			if (off >= 0) {
				fdt_setprop_u32(copy, off, "fuzz-prop", 42);
				fdt_setprop_string(copy, off, "str", "value");
				fdt_appendprop(copy, off, "str", "more", 4);
				fdt_delprop(copy, off, "fuzz-prop");
				fdt_del_node(copy, off);
			}
			fdt_add_mem_rsv(copy, 0x1000, 0x1000);
			fdt_del_mem_rsv(copy, 0);
			fdt_setprop_u32(copy, 0, "root-prop", 1);
			walk_tree(copy);
			fdt_pack(copy);
			fdt_check_full(copy, bufsize);
		}
		os_free(copy);
	}
	os_free(fdt);
	return 0;
}
FUZZ_TEST(fuzz_fdt, 0);
