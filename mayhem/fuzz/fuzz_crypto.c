// SPDX-License-Identifier: GPL-2.0+
#include <linux/types.h>
#include <os.h>
#include <string.h>
#include <crypto/pkcs7.h>
#include <crypto/x509_parser.h>
#include <linux/err.h>
#include <test/fuzz.h>

static void *dup_input(const uint8_t *data, size_t size)
{
	void *p = os_malloc(size ? size : 1);

	if (p && size)
		memcpy(p, data, size);
	return p;
}

/*
 * lib/mbedtls/x509_cert_parser.c returns ERR_PTR(<mbedtls error>), which is outside the -MAX_ERRNO range, so
 * IS_ERR() does not recognise it. Treat any pointer in the top 32 KiB of the address space as an error here.
 */
static bool bad_ptr(const void *p)
{
	return !p || (unsigned long)p >= (unsigned long)-0x8000;
}

static int fuzz_x509(const uint8_t *data, size_t size)
{
	void *buf = dup_input(data, size);
	struct x509_certificate *cert;

	if (!buf)
		return 0;
	cert = x509_cert_parse(buf, size);
	if (!bad_ptr(cert))
		x509_free_certificate(cert);
	os_free(buf);
	return 0;
}
FUZZ_TEST(fuzz_x509, 0);

static int fuzz_pkcs7(const uint8_t *data, size_t size)
{
	void *buf = dup_input(data, size);
	struct pkcs7_message *msg;

	if (!buf)
		return 0;
	msg = pkcs7_parse_message(buf, size);
	if (!bad_ptr(msg))
		pkcs7_free_message(msg);
	os_free(buf);
	return 0;
}
FUZZ_TEST(fuzz_pkcs7, 0);
