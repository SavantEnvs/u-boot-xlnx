// SPDX-License-Identifier: GPL-2.0+
#include <abuf.h>
#include <bzlib.h>
#include <gzip.h>
#include <linux/lzo.h>
#include <linux/zstd.h>
#include <lzma/LzmaTools.h>
#include <os.h>
#include <string.h>
#include <test/fuzz.h>
#include <u-boot/lz4.h>

#define OUT_SIZE	(256 * 1024)

static void *dup_input(const uint8_t *data, size_t size)
{
	void *p = os_malloc(size ? size : 1);

	if (p && size)
		memcpy(p, data, size);
	return p;
}

static int fuzz_gzip(const uint8_t *data, size_t size)
{
	unsigned char *src = dup_input(data, size);
	unsigned char *dst = os_malloc(OUT_SIZE);
	unsigned long len;

	if (!src || !dst)
		goto out;
	len = size;
	gunzip(dst, OUT_SIZE, src, &len);
	len = size;
	zunzip(dst, OUT_SIZE, src, &len, 1, 0);
	gzip_parse_header(src, size);
out:
	os_free(src);
	os_free(dst);
	return 0;
}
FUZZ_TEST(fuzz_gzip, 0);

static int fuzz_bzip2(const uint8_t *data, size_t size)
{
	char *src;
	char *dst;
	unsigned int dstlen = OUT_SIZE;

	if (!size)
		return -1;
	src = dup_input(data + 1, size - 1);
	dst = os_malloc(OUT_SIZE);
	if (src && dst)
		BZ2_bzBuffToBuffDecompress(dst, &dstlen, src, size - 1,
					   data[0] & 1, 0);
	os_free(src);
	os_free(dst);
	return 0;
}
FUZZ_TEST(fuzz_bzip2, 0);

static int fuzz_lzma(const uint8_t *data, size_t size)
{
	unsigned char *src = dup_input(data, size);
	unsigned char *dst = os_malloc(OUT_SIZE);
	SizeT dstlen = OUT_SIZE;

	if (src && dst)
		lzmaBuffToBuffDecompress(dst, &dstlen, src, size);
	os_free(src);
	os_free(dst);
	return 0;
}
FUZZ_TEST(fuzz_lzma, 0);

static int fuzz_lz4(const uint8_t *data, size_t size)
{
	void *src = dup_input(data, size);
	void *dst = os_malloc(OUT_SIZE);
	size_t dstlen = OUT_SIZE;

	if (src && dst)
		ulz4fn(src, size, dst, &dstlen);
	os_free(src);
	os_free(dst);
	return 0;
}
FUZZ_TEST(fuzz_lz4, 0);

static int fuzz_lzo(const uint8_t *data, size_t size)
{
	unsigned char *src = dup_input(data, size);
	unsigned char *dst = os_malloc(OUT_SIZE);
	size_t dstlen = OUT_SIZE;

	if (src && dst)
		lzo1x_decompress_safe(src, size, dst, &dstlen);
	os_free(src);
	os_free(dst);
	return 0;
}
FUZZ_TEST(fuzz_lzo, 0);

static int fuzz_zstd(const uint8_t *data, size_t size)
{
	void *src = dup_input(data, size);
	void *dst = os_malloc(OUT_SIZE);
	struct abuf in, out;

	if (src && dst) {
		abuf_init_set(&in, src, size);
		abuf_init_set(&out, dst, OUT_SIZE);
		zstd_decompress(&in, &out);
	}
	os_free(src);
	os_free(dst);
	return 0;
}
FUZZ_TEST(fuzz_zstd, 0);
