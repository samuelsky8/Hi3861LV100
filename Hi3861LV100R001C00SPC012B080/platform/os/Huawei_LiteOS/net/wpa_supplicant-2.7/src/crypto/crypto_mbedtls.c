/*
 * Wrapper functions for mbedtls libcrypto
 * Copyright (c) 2004-2017, Jouni Malinen <j@w1.fi>
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
/****************************************************************************
 * Notice of Export Control Law
 * ===============================================
 * Huawei LiteOS may be subject to applicable export control laws and regulations,
 * which might include those applicable to Huawei LiteOS of U.S. and the country in
 * which you are located.
 * Import, export and usage of Huawei LiteOS in any manner by you shall be in
 * compliance with such applicable export control laws and regulations.
 ****************************************************************************/

#include "crypto_mbedtls.h"
#include "securec.h"
#include "common.h"
#include "crypto.h"
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/dhm.h"
#include "mbedtls/md.h"
#include "mbedtls/cmac.h"
#include "mbedtls/aes.h"
#include "mbedtls/pkcs5.h"
#include "hi_watchdog.h"

#if defined(MBEDTLS_NIST_KW_C)
#include "mbedtls/nist_kw.h"
#endif
#include "utils/const_time.h"

#include "drv_pke_common.h"
#include "hi_cipher.h"
static int get_trng(void *p_rng, unsigned char *output, size_t output_len)
{
	(void)p_rng;
	int ret = hi_cipher_trng_get_random_bytes(output, output_len);
	return ret;
}

int crypto_get_random(void *buf, size_t len)
{
	if (hi_cipher_trng_get_random_bytes(buf, len) != 0)
		return -1;
	return 0;
}

static int mbedtls_digest_vector(const mbedtls_md_info_t *md_info, size_t num_elem,
                                 const u8 *addr[], const size_t *len, u8 *mac)
{
	mbedtls_md_context_t ctx;
	size_t i;
	int ret;

	if (md_info == NULL || addr == NULL || len == NULL || mac == NULL)
		return MBEDTLS_ERR_MD_BAD_INPUT_DATA;

	mbedtls_md_init(&ctx);

	if ((ret = mbedtls_md_setup(&ctx, md_info, 1)) != 0)
		goto cleanup;

	if ((ret = mbedtls_md_starts(&ctx)) != 0)
		goto cleanup;

	for (i = 0; i < num_elem; i++) {
		if ((ret = mbedtls_md_update(&ctx, addr[i], len[i])) != 0)
			goto cleanup;
	}

	if ((ret = mbedtls_md_finish(&ctx, mac)) != 0)
		goto cleanup;

cleanup:
	mbedtls_md_free(&ctx);

	return ret;
}

#ifndef CONFIG_FIPS
int md4_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
	return mbedtls_digest_vector(mbedtls_md_info_from_type(MBEDTLS_MD_MD4), num_elem, addr, len, mac);
}
#endif /* CONFIG_FIPS */

#ifndef CONFIG_FIPS
int md5_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
	return mbedtls_digest_vector(mbedtls_md_info_from_type(MBEDTLS_MD_MD5), num_elem, addr, len, mac);
}
#endif /* CONFIG_FIPS */

int sha1_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
	return mbedtls_digest_vector(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), num_elem, addr, len, mac);
}

#ifndef NO_SHA256_WRAPPER
int sha256_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
	return mbedtls_digest_vector(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), num_elem, addr, len, mac);
}
#endif

#ifndef NO_SHA384_WRAPPER
int sha384_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
	return mbedtls_digest_vector(mbedtls_md_info_from_type(MBEDTLS_MD_SHA384), num_elem, addr, len, mac);
}
#endif

#ifndef NO_SHA512_WRAPPER
int sha512_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
	return mbedtls_digest_vector(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), num_elem, addr, len, mac);
}
#endif

int mbedtls_hmac_vector(const mbedtls_md_info_t *md_info,
                        const u8 *key, size_t keylen, size_t num_elem,
                        const u8 *addr[], const size_t *len, u8 *mac)
{
	mbedtls_md_context_t ctx;
	size_t i;
	int ret;

	if (md_info == NULL || key == NULL || addr == NULL || len == NULL || mac == NULL)
		return MBEDTLS_ERR_MD_BAD_INPUT_DATA;

	mbedtls_md_init(&ctx);

	if ((ret = mbedtls_md_setup(&ctx, md_info, 1)) != 0)
		goto cleanup;

	if ((ret = mbedtls_md_hmac_starts(&ctx, key, keylen)) != 0)
		goto cleanup;

	for (i = 0; i < num_elem; i++) {
		if ((ret = mbedtls_md_hmac_update(&ctx, addr[i], len[i])) != 0)
			goto cleanup;
	}

	if ((ret = mbedtls_md_hmac_finish(&ctx, mac)) != 0)
		goto cleanup;

cleanup:
	mbedtls_md_free(&ctx);

	return ret;
}

#ifndef CONFIG_FIPS
int hmac_md5_vector(const u8 *key, size_t key_len, size_t num_elem,
	const u8 *addr[], const size_t *len, u8 *mac)
{
	return mbedtls_hmac_vector(mbedtls_md_info_from_type(MBEDTLS_MD_MD5), key, key_len, num_elem, addr, len, mac);
}
int hmac_md5(const u8 *key, size_t key_len, const u8 *data, size_t data_len, u8 *mac)
{
	return hmac_md5_vector(key, key_len, 1, &data, &data_len, mac);
}
#endif /* CONFIG_FIPS */

int pbkdf2_sha1(const char *passphrase, const u8 *ssid, size_t ssid_len, int iterations, u8 *buf, size_t buflen)
{
	mbedtls_md_context_t sha1_ctx;
	const mbedtls_md_info_t *info_sha1 = NULL;
	int ret;
	mbedtls_md_init(&sha1_ctx);
	info_sha1 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
	if (info_sha1 == NULL) {
		ret = -1;
		goto cleanup;
	}
	if ((ret = mbedtls_md_setup(&sha1_ctx, info_sha1, 1)) != 0) {
		ret = -1;
		goto cleanup;
	}

	if (mbedtls_pkcs5_pbkdf2_hmac(&sha1_ctx, (const unsigned char *)passphrase, os_strlen(passphrase),
		ssid, ssid_len, iterations, buflen, buf) != 0) {
		ret =  -1;
		goto cleanup;
	}
cleanup:
	mbedtls_md_free(&sha1_ctx);
	return ret;
}

int hmac_sha1_vector(const u8 *key, size_t key_len, size_t num_elem,
	const u8 *addr[], const size_t *len, u8 *mac)
{
	return mbedtls_hmac_vector(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), key ,key_len, num_elem, addr, len, mac);
}
int hmac_sha1(const u8 *key, size_t key_len, const u8 *data, size_t data_len, u8 *mac)
{
	return hmac_sha1_vector(key, key_len, 1, &data, &data_len, mac);
}

#ifdef CONFIG_SHA256
int hmac_sha256_vector(const u8 *key, size_t key_len, size_t num_elem,
	const u8 *addr[], const size_t *len, u8 *mac)
{
	return mbedtls_hmac_vector(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key ,key_len, num_elem, addr, len, mac);
}
int hmac_sha256(const u8 *key, size_t key_len, const u8 *data, size_t data_len, u8 *mac)
{
	return hmac_sha256_vector(key, key_len, 1, &data, &data_len, mac);
}
#endif /* CONFIG_SHA256 */

#ifdef CONFIG_SHA384
int hmac_sha384_vector(const u8 *key, size_t key_len, size_t num_elem,
	const u8 *addr[], const size_t *len, u8 *mac)
{
	return mbedtls_hmac_vector(mbedtls_md_info_from_type(MBEDTLS_MD_SHA384), key ,key_len, num_elem, addr, len, mac);
}

int hmac_sha384(const u8 *key, size_t key_len, const u8 *data, size_t data_len, u8 *mac)
{
	return hmac_sha384_vector(key, key_len, 1, &data, &data_len, mac);
}
#endif /* CONFIG_SHA384 */

#ifdef CONFIG_SHA512
int hmac_sha512_vector(const u8 *key, size_t key_len, size_t num_elem,
	const u8 *addr[], const size_t *len, u8 *mac)
{
	return mbedtls_hmac_vector(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), key ,key_len, num_elem, addr, len, mac);
}

int hmac_sha512(const u8 *key, size_t key_len, const u8 *data, size_t data_len, u8 *mac)
{
	return hmac_sha512_vector(key, key_len, 1, &data, &data_len, mac);
}
#endif /* CONFIG_SHA512 */

#ifdef CONFIG_OPENSSL_CMAC
int omac1_aes_vector(const u8 *key, size_t key_len, size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
	mbedtls_cipher_context_t ctx;
	size_t i;
	int ret;
	mbedtls_cipher_info_t *cipher_info = NULL;

	if (len == NULL || key == NULL || addr == NULL || mac == NULL)
		return(MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA);

	if (key_len == AES_256_ALT_BLOCK_SIZE)
		cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC);
	else if (key_len == AES_128_ALT_BLOCK_SIZE)
		cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC);
	else
		goto cleanup;

	mbedtls_cipher_init(&ctx);

	if ((ret = mbedtls_cipher_setup(&ctx, cipher_info)) != 0)
		goto cleanup;

	ret = mbedtls_cipher_cmac_starts(&ctx, key, key_len);
	if (ret != 0)
		goto cleanup;

	for (i = 0; i < num_elem; i++) {
		if ((ret = mbedtls_cipher_cmac_update(&ctx, addr[i], len[i])) != 0)
			goto cleanup;
	}

	ret = mbedtls_cipher_cmac_finish(&ctx, mac);

cleanup:
	mbedtls_cipher_free(&ctx);

	return ret;

}

int omac1_aes_128_vector(const u8 *key, size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
	return omac1_aes_vector(key, AES_128_ALT_BLOCK_SIZE, num_elem, addr, len, mac);
}

int omac1_aes_128(const u8 *key, const u8 *data, size_t data_len, u8 *mac)
{
	return omac1_aes_128_vector(key, 1, &data, &data_len, mac);
}

int omac1_aes_256(const u8 *key, const u8 *data, size_t data_len, u8 *mac)
{
	return omac1_aes_vector(key, AES_256_ALT_BLOCK_SIZE, 1, &data, &data_len, mac);
}
#endif /* CONFIG_OPENSSL_CMAC */

static void get_group5_prime(mbedtls_mpi *p)
{
	static const unsigned char RFC3526_PRIME_1536[] = {
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,
		0x21,0x68,0xC2,0x34,0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
		0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,0x02,0x0B,0xBE,0xA6,
		0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
		0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,
		0xF2,0x5F,0x14,0x37,0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,
		0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,0xF4,0x4C,0x42,0xE9,
		0xA6,0x37,0xED,0x6B,0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
		0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,0xAE,0x9F,0x24,0x11,
		0x7C,0x4B,0x1F,0xE6,0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D,
		0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,0x98,0xDA,0x48,0x36,
		0x1C,0x55,0xD3,0x9A,0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
		0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96,0x1C,0x62,0xF3,0x56,
		0x20,0x85,0x52,0xBB,0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D,
		0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,0xF1,0x74,0x6C,0x08,
		0xCA,0x23,0x73,0x27,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	};
	mbedtls_mpi_init(p);
	mbedtls_mpi_read_binary(p, RFC3526_PRIME_1536, sizeof(RFC3526_PRIME_1536));
	return;
}

void * aes_encrypt_init(const u8 *key, size_t len)
{
	mbedtls_aes_context *ctx = NULL;
	ctx = os_zalloc(sizeof(mbedtls_aes_context));
	if (ctx == NULL)
		return NULL;

	mbedtls_aes_setkey_enc(ctx, key, (len * 8));
	return ctx;
}

int aes_encrypt(void *ctx, const u8 *plain, u8 *crypt)
{
	return mbedtls_internal_aes_encrypt(ctx, plain, crypt);
}

void aes_encrypt_deinit(void *ctx)
{
	(void)memset_s(ctx, sizeof(mbedtls_aes_context), 0x00, sizeof(mbedtls_aes_context));
	os_free(ctx);
}

void * aes_decrypt_init(const u8 *key, size_t len)
{
	mbedtls_aes_context *ctx;
	ctx = os_zalloc(sizeof(mbedtls_aes_context));
	if (ctx == NULL)
		return NULL;

	mbedtls_aes_setkey_dec(ctx, key, (len * 8));
	return ctx;
}

int aes_decrypt(void *ctx, const u8 *crypt, u8 *plain)
{
	return mbedtls_internal_aes_decrypt(ctx, crypt, plain);
}

void aes_decrypt_deinit(void *ctx)
{
	(void)memset_s(ctx, sizeof(mbedtls_aes_context), 0x00, sizeof(mbedtls_aes_context));
	os_free(ctx);
}

int aes_128_cbc_encrypt(const u8 *key, const u8 *iv, u8 *data, size_t data_len)
{
	mbedtls_aes_context ctx = { 0 };
	u8 temp_iv[16] = { 0 };  /* 16: iv length */
	if (iv == NULL)
		return -1;
	if (memcpy_s(temp_iv, sizeof(temp_iv), iv, 16) != EOK)
		return -1;

	mbedtls_aes_setkey_enc(&ctx, key, AES_128_CRYPTO_LEN);
	return mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, data_len, temp_iv, data, data);
}

int aes_128_cbc_decrypt(const u8 *key, const u8 *iv, u8 *data, size_t data_len)
{
	mbedtls_aes_context ctx = { 0 };
	u8 temp_iv[16] = { 0 };  /* 16: iv length */
	if (iv == NULL)
		return -1;
	if (memcpy_s(temp_iv, sizeof(temp_iv), iv, 16) != EOK)
		return -1;

	mbedtls_aes_setkey_dec(&ctx, key, AES_128_CRYPTO_LEN);
	return mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, data_len, temp_iv, data, data);
}

void * dh5_init(struct wpabuf **priv, struct wpabuf **publ)
{
	mbedtls_dhm_context *dh = NULL;
	struct wpabuf *pubkey = NULL;
	struct wpabuf *privkey = NULL;
	size_t publen, privlen;
	unsigned char *export = NULL;
	size_t exportlen;
	if (*priv != NULL) {
		wpabuf_free(*priv);
		*priv = NULL;
	}
	if (*publ != NULL) {
		wpabuf_free(*publ);
		*publ = NULL;
	}
	dh = os_zalloc(sizeof(*dh));
	if (dh == NULL)
		return NULL;

	mbedtls_dhm_init(dh);
	mbedtls_mpi_init(&dh->G);
	mbedtls_mpi_lset(&dh->G, DHM_PARM_G_LEN);
	get_group5_prime(&dh->P);
	export = os_zalloc(DHM_PARM_MEM); // check result in mbedtls_dhm_make_params
	if (mbedtls_dhm_make_params(dh, (int)mbedtls_mpi_size(&dh->P), export, &exportlen, get_trng, NULL) != 0)
		goto err;

	os_free(export);
	export = NULL;
	publen = mbedtls_mpi_size((const mbedtls_mpi *)&(dh->GX));
	pubkey = wpabuf_alloc(publen);
	if (pubkey == NULL)
		goto err;

	privlen = mbedtls_mpi_size((const mbedtls_mpi *)&dh->X);
	privkey = wpabuf_alloc(privlen);
	if (privkey == NULL)
		goto err;

	mbedtls_mpi_write_binary((const mbedtls_mpi *)&dh->GX, wpabuf_put(pubkey, publen), publen);
	mbedtls_mpi_write_binary((const mbedtls_mpi *)&dh->X, wpabuf_put(privkey, privlen), privlen);
	*priv = privkey;
	*publ = pubkey;
	return dh;
err:
	wpabuf_clear_free(pubkey);
	wpabuf_clear_free(privkey);
	mbedtls_dhm_free(dh);
	os_free(dh);
	return NULL;
}

void * dh5_init_fixed(const struct wpabuf *priv, const struct wpabuf *publ)
{
	mbedtls_dhm_context *dh = NULL;
	unsigned char *export = NULL;
	size_t exportlen;
	struct wpabuf *pubkey = NULL;
	struct wpabuf *privkey = NULL;
	size_t publen, privlen;
	dh = os_zalloc(sizeof(*dh));
	if (dh == NULL)
		return NULL;

	mbedtls_dhm_init(dh);
	mbedtls_mpi_init(&dh->G);
	mbedtls_mpi_lset(&dh->G, DHM_PARM_G_LEN);
	get_group5_prime(&dh->P);

	if (mbedtls_mpi_read_binary(&dh->X, wpabuf_head(priv), wpabuf_len(priv)) != 0)
		goto err;

	if (mbedtls_mpi_read_binary(&dh->GX, wpabuf_head(publ), wpabuf_len(publ)) != 0)
		goto err;

	export = os_zalloc(DHM_PARM_MEM); // check result in mbedtls_dhm_make_params
	if (mbedtls_dhm_make_params(dh, (int)mbedtls_mpi_size(&dh->P), export, &exportlen, get_trng, NULL) != 0)
		goto err;

	os_free(export);
	export = NULL;
	publen = mbedtls_mpi_size((const mbedtls_mpi *)&(dh->GX));
	pubkey = wpabuf_alloc(publen);
	if (pubkey == NULL)
		goto err;

	privlen = mbedtls_mpi_size((const mbedtls_mpi *)&dh->X);
	privkey = wpabuf_alloc(privlen);
	if (privkey == NULL)
		goto err;

	mbedtls_mpi_write_binary((const mbedtls_mpi *)&dh->GX, wpabuf_put(pubkey, publen), publen);
	mbedtls_mpi_write_binary((const mbedtls_mpi *)&dh->X, wpabuf_put(privkey, privlen), privlen);
	wpabuf_clear_free(pubkey);
	wpabuf_clear_free(privkey);
	return dh;
err:
	wpabuf_clear_free(pubkey);
	wpabuf_clear_free(privkey);
	mbedtls_dhm_free(dh);
	os_free(dh);
	return NULL;
}

struct wpabuf * dh5_derive_shared(void *ctx, const struct wpabuf *peer_public, const struct wpabuf *own_private)
{
	struct wpabuf *res = NULL;
	size_t rlen;
	mbedtls_dhm_context *dh = ctx;
	size_t keylen;
	(void)own_private;
	if (ctx == NULL)
		return NULL;
	if (mbedtls_mpi_read_binary(&dh->GY,wpabuf_head(peer_public), wpabuf_len(peer_public)) != 0)
		goto err;

	rlen = mbedtls_mpi_size((const mbedtls_mpi *)&(dh->P));
	res = wpabuf_alloc(rlen);
	if (res == NULL)
		goto err;

	if (mbedtls_dhm_calc_secret(dh, wpabuf_mhead(res), rlen, &keylen, NULL,NULL) != 0)
		goto err;

	wpabuf_put(res, keylen);
	mbedtls_mpi_free(&dh->GY);
	return res;
err:
	mbedtls_mpi_free(&dh->GY);
	wpabuf_clear_free(res);
	return NULL;
}

void dh5_free(void *ctx)
{
	mbedtls_dhm_context *dh = NULL;
	if (ctx == NULL)
		return;
	dh = ctx;
	mbedtls_dhm_free(dh);
	os_free(dh);
}


struct crypto_bignum *crypto_bignum_init(void)
{
	mbedtls_mpi *p = NULL;
	p = os_zalloc(sizeof(*p));
	if (p == NULL)
		return NULL;

	mbedtls_mpi_init(p);
	return p;
}

struct crypto_bignum *crypto_bignum_init_set(const u8 *buf, size_t len)
{
	int ret;
	mbedtls_mpi *p = NULL;
	p = crypto_bignum_init();
	if (p == NULL)
		return NULL;

	ret = mbedtls_mpi_read_binary(p, buf, len);
	if (ret != 0) {
		crypto_bignum_deinit(p, 1);
		p = NULL;
	}
	return p;
}

void crypto_bignum_deinit(struct crypto_bignum *n, int clear)
{
	(void)clear;
	if (n == NULL)
		return;

	mbedtls_mpi_free(n);
	os_free(n);
}

int crypto_bignum_to_bin(const struct crypto_bignum *a, u8 *buf, size_t buflen, size_t padlen)
{
	int ret;
	int num_bytes, offset;

	if (a == NULL || buf == NULL || padlen > buflen)
		return -1;

	num_bytes = mbedtls_mpi_size((const mbedtls_mpi *)a);
	if ((size_t)num_bytes > buflen)
		return -1;

	if (padlen > (size_t)num_bytes)
		offset = padlen - num_bytes;
	else
		offset = 0;

	if ((memset_s(buf, offset, 0, offset)) != EOK)
		return -1;
	ret = mbedtls_mpi_write_binary((const mbedtls_mpi *)a, buf + offset, num_bytes);
	if (ret)
		return -1;

	return num_bytes + offset;
}

int crypto_bignum_add(const struct crypto_bignum *a, const struct crypto_bignum *b, struct crypto_bignum *c)
{
	return mbedtls_mpi_add_mpi((mbedtls_mpi *)c, (const mbedtls_mpi *)a, (const mbedtls_mpi *)b);
}

int crypto_bignum_mod(const struct crypto_bignum *a, const struct crypto_bignum *b, struct crypto_bignum *c)
{
	return mbedtls_mpi_mod_mpi((mbedtls_mpi *)c, (const mbedtls_mpi *)a, (const mbedtls_mpi *)b);
}

int crypto_bignum_exptmod(const struct crypto_bignum *a, const struct crypto_bignum *b,
                          const struct crypto_bignum *c, struct crypto_bignum *d)
{
	/* It takes 2.7 seconds for two basic boards to interact at one time.
	   If 10 basic boards interact at the same time, the watchdog cannot be feeded in time,
	   resulting in system abnormality. */
	hi_watchdog_feed();
	return mbedtls_mpi_exp_mod((mbedtls_mpi *)d, (const mbedtls_mpi *)a,
	                           (const mbedtls_mpi *)b, (const mbedtls_mpi *)c,
	                           NULL);
}

int crypto_bignum_inverse(const struct crypto_bignum *a, const struct crypto_bignum *b, struct crypto_bignum *c)
{
	return mbedtls_mpi_inv_mod((mbedtls_mpi *)c, (const mbedtls_mpi *)a, (const mbedtls_mpi *)b);
}

int crypto_bignum_sub(const struct crypto_bignum *a, const struct crypto_bignum *b, struct crypto_bignum *c)
{
	return mbedtls_mpi_sub_mpi((mbedtls_mpi *)c, (const mbedtls_mpi *)a, (const mbedtls_mpi *)b);
}

int crypto_bignum_div(const struct crypto_bignum *a, const struct crypto_bignum *b, struct crypto_bignum *c)
{
	return mbedtls_mpi_div_mpi((mbedtls_mpi *)c, NULL, (const mbedtls_mpi *)a, (const mbedtls_mpi *)b);
}

int crypto_bignum_mulmod(const struct crypto_bignum *a, const struct crypto_bignum *b,
                         const struct crypto_bignum *c, struct crypto_bignum *d)
{
	int ret;
	mbedtls_mpi mul;
	mbedtls_mpi_init(&mul);
	ret = mbedtls_mpi_mul_mpi(&mul, (const mbedtls_mpi *)a, (const mbedtls_mpi *)b);
	if (ret == 0)
		ret = mbedtls_mpi_mod_mpi((mbedtls_mpi *)d, &mul, (const mbedtls_mpi *)c);

	mbedtls_mpi_free(&mul);
	return ret;
}

int crypto_bignum_rshift(const struct crypto_bignum *a, int n, struct crypto_bignum *r)
{
	int ret;
	ret = mbedtls_mpi_copy((mbedtls_mpi *)r, (const mbedtls_mpi *)a);
	if (ret == 0)
		ret = mbedtls_mpi_shift_r((mbedtls_mpi *)r, n);

	return ret;
}

int crypto_bignum_cmp(const struct crypto_bignum *a, const struct crypto_bignum *b)
{
	return mbedtls_mpi_cmp_mpi((const mbedtls_mpi *)a, (const mbedtls_mpi *)b);
}

int crypto_bignum_bits(const struct crypto_bignum *a)
{
	return mbedtls_mpi_bitlen((const mbedtls_mpi *)a);
}

int crypto_bignum_is_zero(const struct crypto_bignum *a)
{
	return (mbedtls_mpi_cmp_int((const mbedtls_mpi *)a, 0) == 0) ? 1 : 0;
}

int crypto_bignum_is_one(const struct crypto_bignum *a)
{
	return (mbedtls_mpi_cmp_int((const mbedtls_mpi *)a, 1) == 0) ? 1 : 0;
}

int crypto_bignum_legendre(const struct crypto_bignum *a, const struct crypto_bignum *p)
{
	int ret;
	int res = -2;
	unsigned int mask;
	mbedtls_mpi t;
	mbedtls_mpi exp;
	mbedtls_mpi_init(&t);
	mbedtls_mpi_init(&exp);

	/* exp = (p-1) / 2 */
	ret = mbedtls_mpi_sub_int(&exp, (const mbedtls_mpi *)p, 1);
	if (ret == 0)
		ret = mbedtls_mpi_shift_r(&exp, 1);

	if (ret == 0)
		ret = crypto_bignum_exptmod(a, (const struct crypto_bignum *)&exp,
									p, (struct crypto_bignum *)&t);

	if (ret == 0) {
		/* Return 1 if tmp == 1, 0 if tmp == 0, or -1 otherwise. Need to use
		 * constant time selection to avoid branches here. */
		res = -1;
		mask = const_time_eq(crypto_bignum_is_one((const struct crypto_bignum *)&t), 1);
		res = const_time_select_int(mask, 1, res);
		mask = const_time_eq(crypto_bignum_is_zero((const struct crypto_bignum *)&t), 1);
		res = const_time_select_int(mask, 0, res);
	}

	mbedtls_mpi_free(&exp);
	mbedtls_mpi_free(&t);
	return res;
}

/* convert IANA ECC group ID to Mbedtls ECC group ID */
static mbedtls_ecp_group_id crypto_ec_group_id(int group)
{
	mbedtls_ecp_group_id id;
	switch (group) {
		case 19:
			id = MBEDTLS_ECP_DP_SECP256R1;
			break;
		case 20:
			id = MBEDTLS_ECP_DP_SECP384R1;
			break;
		case 21:
			id = MBEDTLS_ECP_DP_SECP521R1;
			break;
		case 25:
			id = MBEDTLS_ECP_DP_SECP192R1;
			break;
		case 26:
			id = MBEDTLS_ECP_DP_SECP224R1;
			break;
		case 28:
			id = MBEDTLS_ECP_DP_BP256R1;
			break;
		case 29:
			id = MBEDTLS_ECP_DP_BP384R1;
			break;
		case 30:
			id = MBEDTLS_ECP_DP_BP512R1;
			break;
		default:
			id =  MBEDTLS_ECP_DP_NONE;
	}
	return id;
}

struct crypto_ec *crypto_ec_init(int group)
{
	mbedtls_ecp_group_id id = crypto_ec_group_id(group);
	if (id == MBEDTLS_ECP_DP_NONE)
		return NULL;

	struct crypto_ec *e = os_zalloc(sizeof(struct crypto_ec));
	if (e == NULL)
		return NULL;

	e->grp = os_zalloc(sizeof(mbedtls_ecp_group));
	if (e->grp == NULL) {
		os_free(e);
		return NULL;
	}
	mbedtls_ecp_group_init(e->grp);
	mbedtls_ecp_group_load(e->grp, id);

	e->ecc = os_zalloc(sizeof(hi_cipher_ecc_param));
	if (e->ecc == NULL) {
		os_free(e->grp);
		os_free(e);
		return NULL;
	}
	e->ecc->p  = (const hi_u8 *)(e->grp->P.p);
	e->ecc->a  = (const hi_u8 *)(e->grp->A.p);
	e->ecc->b  = (const hi_u8 *)(e->grp->B.p);
	e->ecc->gx = (const hi_u8 *)(e->grp->G.X.p);
	e->ecc->gy = (const hi_u8 *)(e->grp->G.Y.p);
	e->ecc->n  = (const hi_u8 *)(e->grp->N.p);
	e->ecc->h  = 1;
	e->ecc->ksize = PKE_LEN_32_BYTES;

	drv_pke_init(TRUE);
	return e;
}

void crypto_ec_deinit(struct crypto_ec *e)
{
	if (e == NULL)
		return;

	if (e->ecc != NULL) {
		os_free(e->ecc);
		e->ecc = NULL;
	}
	if (e->grp != NULL) {
		mbedtls_ecp_group_free(e->grp);
		os_free(e->grp);
		e->grp = NULL;
	}
	os_free(e);
}

struct crypto_ec_point *crypto_ec_point_init(struct crypto_ec *e)
{
	if (e == NULL)
		return NULL;

	mbedtls_ecp_point *p = NULL;
	p = os_zalloc(sizeof(*p));
	if (p == NULL)
		return NULL;

	mbedtls_ecp_point_init(p);
	return (struct crypto_ec_point *)p;
}

void crypto_ec_point_deinit(struct crypto_ec_point *e, int clear)
{
	(void)clear;
	if (e == NULL)
		return;

	mbedtls_ecp_point_free(e);
	os_free(e);
}

size_t crypto_ec_prime_len(struct crypto_ec *e)
{
	if (e == NULL)
		return 0;

	const mbedtls_ecp_group *group = (const mbedtls_ecp_group *)(e->grp);
	return mbedtls_mpi_size(&group->P);
}

size_t crypto_ec_prime_len_bits(struct crypto_ec *e)
{
	if (e == NULL)
		return 0;

	const mbedtls_ecp_group *group = (const mbedtls_ecp_group *)(e->grp);
	return mbedtls_mpi_bitlen(&group->P);
}

size_t crypto_ec_order_len(struct crypto_ec *e)
{
	if (e == NULL)
		return 0;

	const mbedtls_ecp_group *group = (const mbedtls_ecp_group *)(e->grp);
	return mbedtls_mpi_size(&group->N);
}

const struct crypto_bignum *crypto_ec_get_prime(struct crypto_ec *e)
{
	if (e == NULL)
		return NULL;

	return (const struct crypto_bignum *)&e->grp->P;
}

const struct crypto_bignum *crypto_ec_get_order(struct crypto_ec *e)
{
	if (e == NULL)
		return NULL;

	return (const struct crypto_bignum *)&e->grp->N;
}

int crypto_ec_point_to_bin(struct crypto_ec *e, const struct crypto_ec_point *point, u8 *x, u8 *y)
{
	int ret = -1;
	size_t len;
	if (e == NULL || point == NULL)
		return -1;

	const mbedtls_ecp_group *group = (const mbedtls_ecp_group *)(e->grp);
	len = mbedtls_mpi_size(&group->P);
	if (x != NULL) {
		ret = mbedtls_mpi_write_binary(&(((const mbedtls_ecp_point *)point)->X), x, len);
		if (ret)
			return ret;
	}
	if (y != NULL) {
		ret = mbedtls_mpi_write_binary(&(((const mbedtls_ecp_point *)point)->Y), y, len);
		if (ret)
			return ret;
	}

	return ret;
}

struct crypto_ec_point *crypto_ec_point_from_bin(struct crypto_ec *e, const u8 *val)
{
	int ret;
	size_t len;
	if (e == NULL)
		return NULL;

	const mbedtls_ecp_group *group = (const mbedtls_ecp_group *)(e->grp);
	mbedtls_ecp_point *p = (mbedtls_ecp_point *)crypto_ec_point_init(e);
	if (p == NULL)
		return NULL;

	len = mbedtls_mpi_size(&group->P);
	ret = mbedtls_mpi_read_binary(&p->X, val, len);
	if (ret == 0)
		ret = mbedtls_mpi_read_binary(&p->Y, val + len, len);

	if (ret == 0)
		ret = mbedtls_mpi_lset(&p->Z, 1);

	if (ret) {
		mbedtls_ecp_point_free(p);
		os_free(p);
		p = NULL;
		return NULL;
	}
	return (struct crypto_ec_point *)p;
}

int crypto_ec_point_add(struct crypto_ec *e, const struct crypto_ec_point *a,
                        const struct crypto_ec_point *b, struct crypto_ec_point *c)
{
	int ret;
	if (e == NULL)
		return -1;

	mbedtls_mpi one;
	mbedtls_mpi_init(&one);
	ret = mbedtls_mpi_lset(&one, 1);
	if (ret == 0)
		ret = mbedtls_ecp_muladd(e->grp, c, &one, a, &one, b);

	mbedtls_mpi_free(&one);
	return ret;
}

/*
 * Multiplication res = b * p
 */
int crypto_ec_point_mul(struct crypto_ec *e, const struct crypto_ec_point *p,
                        const struct crypto_bignum *b,
                        struct crypto_ec_point *res)
{
	int ret;
	errno_t rc;
	unsigned char k[PKE_LEN_32_BYTES] = { 0 };
	unsigned char px[PKE_LEN_32_BYTES] = { 0 };
	unsigned char py[PKE_LEN_32_BYTES] = { 0 };
	if (e == NULL)
		return -1;

	rc = memcpy_s(k, PKE_LEN_32_BYTES, (const unsigned char *)b->p, mbedtls_mpi_size(b));
	rc |= memcpy_s(px, PKE_LEN_32_BYTES, (const unsigned char *)p->X.p, mbedtls_mpi_size(&p->X));
	rc |= memcpy_s(py, PKE_LEN_32_BYTES, (const unsigned char *)p->Y.p, mbedtls_mpi_size(&p->Y));
	if (rc != EOK) {
		wpa_error_log0(MSG_ERROR, "crypto_ec_point_mul memcpy_s fail!");
		return HISI_FAIL;
	}
	mbedtls_ecp_point_free(res);
	mbedtls_mpi_init(&res->X);
	mbedtls_mpi_init(&res->Y);
	mbedtls_mpi_init(&res->Z);
	ret = mbedtls_mpi_lset(&res->Z, 1);
	if (ret == 0)
		ret = mbedtls_mpi_grow(&res->X, PKE_LEN_32_BYTES / sizeof(mbedtls_mpi_uint));

	if (ret == 0)
		ret = mbedtls_mpi_grow(&res->Y, PKE_LEN_32_BYTES / sizeof(mbedtls_mpi_uint));

	if (ret == 0) {
		pke_mul_dot para;
		para.k = (const unsigned char *)k;
		para.px = (const unsigned char *)px;
		para.py = (const unsigned char *)py;
		para.rx = (unsigned char *)res->X.p;
		para.ry = (unsigned char *)res->Y.p;
		para.klen = e->ecc->ksize;
		crypto_mutex_ctx *pke_mutex = drv_pke_get_mutex();
		ret = crypto_mutex_lock(pke_mutex);
		if (ret != 0)
			return ret;

		cipher_clk_switch(TRUE);
		ret = drv_pke_mul_dot(&para, e->ecc, ROTATE_DIABLE);
		cipher_clk_switch(FALSE);
		(void)crypto_mutex_unlock(pke_mutex);
	}
	return ret;
}

int crypto_ec_point_invert(struct crypto_ec *e, struct crypto_ec_point *p)
{
	if (e == NULL || p == NULL)
		return -1;

	const mbedtls_ecp_group *group = (const mbedtls_ecp_group *)(e->grp);
	return mbedtls_mpi_sub_mpi(&p->Y, (const mbedtls_mpi *)&group->P, &p->Y);
}

// y_bit (first byte of compressed point) mod 2 odd : r = p - r
int crypto_ec_point_solve_y_coord(struct crypto_ec *e,
								  struct crypto_ec_point *p,
								  const struct crypto_bignum *x, int y_bit)
{
	int ret;
	mbedtls_mpi n;
	if (e == NULL || p == NULL)
		return -1;

	// Calculate quare root of r over finite field P:
	//   r = sqrt(x^3 + ax + b) = (x^3 + ax + b) ^ ((P + 1) / 4) (mod P)
	struct crypto_bignum *y_sqr = crypto_ec_point_compute_y_sqr(e, x);
	if (y_sqr == NULL)
		return -1;

	mbedtls_mpi_init(&n);
	const mbedtls_ecp_group *grp = (const mbedtls_ecp_group *)(e->grp);

	ret = mbedtls_mpi_add_int(&n, &grp->P, 1);
	if (ret == 0)
		ret = mbedtls_mpi_shift_r(&n, 2);

	if (ret == 0)
		ret = mbedtls_mpi_exp_mod(y_sqr, y_sqr, &n, &grp->P, NULL);

	if (y_bit && (ret == 0))
		// r = p - r
		ret = mbedtls_mpi_sub_mpi(y_sqr, &grp->P, y_sqr);

	if (ret == 0) {
		mbedtls_mpi_copy(&p->X, x);
		mbedtls_mpi_copy(&p->Y, y_sqr);
		static mbedtls_mpi_uint one[] = {1};
		p->Z.s = 1;
		p->Z.n = 1;
		p->Z.p = one;
	}
	mbedtls_mpi_free(&n);
	crypto_bignum_deinit(y_sqr, 1);

	return ret;
}

struct crypto_bignum *crypto_ec_point_compute_y_sqr(struct crypto_ec *e, const struct crypto_bignum *x)
{
	int ret;
	if (e == NULL)
		return NULL;

	const mbedtls_ecp_group *grp = (const mbedtls_ecp_group *)(e->grp);
	mbedtls_mpi *y2 = (mbedtls_mpi *)crypto_bignum_init();
	if (y2 == NULL)
		return NULL;

	ret = mbedtls_mpi_mul_mpi(y2, x, x);
	if (ret == 0)
		ret = mbedtls_mpi_mod_mpi(y2, y2, &grp->P);

	if (ret == 0) {
		if (grp->A.p == NULL)
			// Special case where a is -3
			ret = mbedtls_mpi_sub_int(y2, y2, 3);
		else
			ret = mbedtls_mpi_add_mpi(y2, y2, &grp->A);

		if (ret == 0)
			ret = mbedtls_mpi_mod_mpi(y2, y2, &grp->P);
	}
	if (ret == 0)
		ret = mbedtls_mpi_mul_mpi(y2, y2, x);

	if (ret == 0)
		ret = mbedtls_mpi_mod_mpi(y2, y2, &grp->P);

	if (ret == 0)
		ret = mbedtls_mpi_add_mpi(y2, y2, &grp->B);

	if (ret == 0)
		ret = mbedtls_mpi_mod_mpi(y2, y2, &grp->P);

	if (ret) {
		crypto_bignum_deinit((struct crypto_bignum *)y2, 1);
		return NULL;
	}

	return (struct crypto_bignum *)y2;
}

int crypto_ec_point_is_at_infinity(struct crypto_ec *e,
								   const struct crypto_ec_point *p)
{
	if (e == NULL)
		return -1;

	// ref openssl
	return mbedtls_ecp_is_zero((struct crypto_ec_point *)p);
}

int crypto_ec_point_is_on_curve(struct crypto_ec *e, const struct crypto_ec_point *p)
{
	int ret;
	mbedtls_mpi y2_left;
	mbedtls_mpi y2_right;

	if (e == NULL || p == NULL)
		return -1;

	mbedtls_mpi_init(&y2_left);
	mbedtls_mpi_init(&y2_right);

	/*
	 * YY = Y^2
	 * RHS = X (X^2 + A) + B = X^3 + A X + B
	 */
	ret = mbedtls_mpi_mul_mpi(&y2_left, &p->Y, &p->Y);
	if (ret == 0)
		ret = mbedtls_mpi_mod_mpi(&y2_left, &y2_left, &e->grp->P);

	if (ret == 0)
		ret = mbedtls_mpi_mul_mpi(&y2_right, &p->X, &p->X);

	if (ret == 0)
		ret = mbedtls_mpi_mod_mpi(&y2_right, &y2_right, &e->grp->P);

	/* Special case for A = -3 */
	if (e->grp->A.p == NULL)
		ret = mbedtls_mpi_sub_int(&y2_right, &y2_right, 3);
	else
		ret = mbedtls_mpi_add_mpi(&y2_right, &y2_right, &e->grp->A);

	if (ret == 0)
		ret = mbedtls_mpi_mod_mpi(&y2_right, &y2_right, &e->grp->P);

	if (ret == 0)
		ret = mbedtls_mpi_mul_mpi(&y2_right, &y2_right, &p->X);

	if (ret == 0)
		ret = mbedtls_mpi_mod_mpi(&y2_right, &y2_right, &e->grp->P);

	if (ret == 0)
		ret = mbedtls_mpi_add_mpi(&y2_right, &y2_right, &e->grp->B);

	if (ret == 0)
		ret = mbedtls_mpi_mod_mpi(&y2_right, &y2_right, &e->grp->P);

	if (ret == 0)
		ret = mbedtls_mpi_cmp_mpi(&y2_left, &y2_right);

	mbedtls_mpi_free(&y2_left);
	mbedtls_mpi_free(&y2_right);
	return (ret == 0);
}

int crypto_ec_point_cmp(const struct crypto_ec *e,
						const struct crypto_ec_point *a,
						const struct crypto_ec_point *b)
{
	if (e == NULL)
		return -1;

	return mbedtls_ecp_point_cmp(a, b);
}
