/**
* @file hi_cipher.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved. \n
* Description: Encryption and decryption interfaces. \n
* Author: Hisilicon \n
* Create: 2019-05-29
*/

/** @defgroup iot_cipher Cipher APIs
 * @ingroup iot_romboot
 */
#ifndef __HI_CIPHER_H__
#define __HI_CIPHER_H__

#include <hi_types.h>
#include <hi_boot_err.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif  /* __cplusplus */

#define PKE_LEN_32_BYTES             32
#define PKE_LEN_256_BYTES            256
#define PKE_LEN_384_BYTES            384
#define PKE_LEN_512_BYTES            512
#define RSA_KEY_LEN_2048             256
#define AES_MAX_KEY_IN_WORD          16
#define AES_IV_LEN_IN_WORD           4
#define KDF_KEY_LEN_IN_BYTES         32

/**
* @ingroup iot_cipher
* Rsa sign and veriry scheme
*/
typedef enum {
    HI_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_V15_SHA256 = 0x00,   /* PKCS#1 RSASSA_PKCS1_V15_SHA256 signature */
    HI_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_PSS_SHA256,          /* PKCS#1 RSASSA_PKCS1_PSS_SHA256 signature */
    HI_CIPHER_RSA_SIGN_SCHEME_MAX,
    HI_CIPHER_RSA_SIGN_SCHEME_INVALID = 0xffffffff,
}hi_cipher_rsa_sign_scheme;

/**
* @ingroup iot_cipher
* Aes key from
*/
typedef enum {
    HI_CIPHER_AES_KEY_FROM_CPU = 0x00,
    HI_CIPHER_AES_KEY_FROM_KDF,
    HI_CIPHER_AES_KEY_FROM_MAX,
    HI_CIPHER_AES_KEY_FROM_INVALID = 0xffffffff,
}hi_cipher_aes_key_from;

/**
* @ingroup iot_cipher
* Aes work mode
*/
typedef enum {
    HI_CIPHER_AES_WORK_MODE_ECB = 0x00,    /* Electronic codebook (ECB) mode, ECB has been considered insecure and
                                               it is recommended not to use it. */
    HI_CIPHER_AES_WORK_MODE_CBC,            /* Cipher block chaining (CBC) mode. */
    HI_CIPHER_AES_WORK_MODE_CTR,            /* Counter (CTR) mode. */
    HI_CIPHER_AES_WORK_MODE_XTS,            /* XTS-AES (XTS) mode. */
    HI_CIPHER_AES_WORK_MODE_MAX,
    HI_CIPHER_AES_WORK_MODE_INVALID = 0xffffffff,
}hi_cipher_aes_work_mode;

/**
* @ingroup iot_cipher
* Aes key length
*/
typedef enum {
    HI_CIPHER_AES_KEY_LENGTH_128BIT  = 0x00,
    HI_CIPHER_AES_KEY_LENGTH_192BIT,
    HI_CIPHER_AES_KEY_LENGTH_256BIT,
    HI_CIPHER_AES_KEY_LENGTH_512BIT,             /* 512bit, just used for xts. */
    HI_CIPHER_AES_KEY_LENGTH_MAX,
    HI_CIPHER_AES_KEY_LENGTH_INVALID = 0xffffffff,
}hi_cipher_aes_key_length;

/**
* @ingroup iot_cipher
* Rsa public key verify
*/
typedef struct {
    hi_cipher_rsa_sign_scheme scheme;  /* The rsa sign type */
    hi_u8 *e;                          /* The public exponent */
    hi_u8 *n;                          /* The modulus */
    hi_u32 klen;                       /* The key length */
} hi_cipher_rsa_verify;

/**
* @ingroup iot_cipher
* Struct of ecc curves parameters
*/
typedef struct {
    const hi_u8 *p;   /* Finite field: equal to p in case of prime field curves or equal to 2^n in case of binary
                         field curves. */
    const hi_u8 *a;   /* Curve parameter a (q-3 in Suite B). */
    const hi_u8 *b;   /* Curve parameter b. */
    const hi_u8 *gx;  /* X coordinates of G which is a base point on the curve. */
    const hi_u8 *gy;  /* Y coordinates of G which is a base point on the curve. */
    const hi_u8 *n;   /* Prime which is the order of G point. */
    hi_u32 h;         /* Cofactor, which is the order of the elliptic curve divided by the order of the point G. For
                         the Suite B curves, h = 1. */
    hi_u32 ksize;     /* Ecc key size in bytes. It corresponds to the size in bytes of the prime, should be 32bytes. */
}hi_cipher_ecc_param;

/**
* @ingroup iot_cipher
* Struct of ecc verify
*/
typedef struct {
    const hi_u8 *px;   /* Ecdh X coordinates of the generated public key, the caller ensures it is padded with leading
                          zeros if the effective size of this key is smaller than ecc key size. */
    const hi_u8 *py;   /* Ecdh Y coordinates of the generated public key, the caller ensures it is padded with leading
                          zeros if the effective size of this key is smaller than ecc key size. */
    const hi_u8 *hash; /* Input hash data for ecc verify. */
    hi_u32 hash_len;   /* The length of hash data, just 32 bytes is valid data. */
    const hi_u8 *r;    /* Output ecc sign result R, its length is ecc key size. */
    const hi_u8 *s;    /* Output ecc sign result S, its length is ecc key size. */
    hi_u8 *out_r;      /* Output verify r data for security. */
}hi_cipher_ecc_verify;

/**
* @ingroup iot_cipher
* Struct of rsa verify
*/
typedef struct {
    hi_u8 *hash;        /* The input hash value will be changed after hi_cipher_rsa_verify_hash execution,
                           the correct value should be input before each verification */
    hi_u8 *out_hash;
    hi_u32 hash_len;
    const hi_u8 *sign;
    hi_u32 sign_len;
} hi_cipher_rsa_data;

/**
* @ingroup iot_cipher
* Aes ctrl struct
*/
typedef struct {
    hi_u32 key[AES_MAX_KEY_IN_WORD];     /* Key input. */
    hi_u32 iv[AES_IV_LEN_IN_WORD];       /* Initialization vector (IV). */
    hi_bool random_en;                   /* Enable random delay or not. */
    hi_cipher_aes_key_from key_from;     /* Key from, When using kdf key, no nead to configure the input key. */
    hi_cipher_aes_work_mode work_mode;   /* Work mode. */
    hi_cipher_aes_key_length key_len;    /* Key length. aes-ecb/cbc/ctr support 128/192/256 bits key, ccm just support
                                            128 bits key, xts just support 256/512 bits key. */
}hi_cipher_aes_ctrl;

/**
* @ingroup iot_cipher
* Kdf key type
*/
typedef enum {
    HI_CIPHER_SSS_KDF_KEY_DEVICE  = 0x0, /* kdf device key derivation. */
    HI_CIPHER_SSS_KDF_KEY_STORAGE,       /* kdf storage key derivation. */
    HI_CIPHER_SSS_KDF_KEY_MAX,
    HI_CIPHER_SSS_KDF_KEY_INVALID = 0xFFFFFFFF,
}hi_cipher_kdf_mode;

/**
* @ingroup iot_cipher
* Kdf ctrl struct
*/
typedef struct {
    const hi_u8 *salt;                   /* salt for kdf key derivation. */
    hi_u32 salt_len;                     /* salt_len should be 16 bytes for kdf device key derivation,
                                            32 bytes for kdf storage key derivation. */
    hi_u8 key[KDF_KEY_LEN_IN_BYTES];     /* just used for kdf device key. */
    hi_cipher_kdf_mode kdf_mode;         /* kdf mode for key derivation. */
    hi_u32 kdf_cnt;                      /* kdf cnt for iteration. It is recommended that the number of iterations be
                                            not less than 1000 times, and not more than 0xffff times. */
    hi_u8 result[KDF_KEY_LEN_IN_BYTES];  /* output for kdf device key derivation. */
}hi_cipher_kdf_ctrl;

/**
* @ingroup        iot_cipher
* @brief          Initializes the Cipher module. CNcomment:Cipher ģ���ʼ����CNend
*
* @par ����:
*                 Initializes the Cipher module.
CNcomment:Cipherģ���ʼ����CNend
*
* @attention      This function must be called before using cipher module.
CNcomment:ʹ��Cipherģ���㷨ǰ���ñ��ӿڳ�ʼ����CNend
* @param          None
*
* @retval #HI_ERR_SUCCESS   Success
* @retval #Other            Failure. For details, see hi_boot_err.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_init��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_init(hi_void);

/**
* @ingroup        iot_cipher
* @brief          Deinitializes the Cipher module. CNcomment:Cipher ģ��ȥ��ʼ����CNend
*
* @par ����:
*                 Deinitializes the Cipher module, does NOT support multi-tasks.
CNcomment:Cipherģ��ȥ��ʼ��,��֧�ֶ�����CNend
*
* @attention      This function could be called after using Cipher module finished.
CNcomment:����ʹ��Cipherģ���㷨����ñ��ӿ�ȥ��ʼ����CNend
* @param          None
*
* @retval #HI_ERR_SUCCESS   Success
* @retval #Other            Failure. For details, see hi_boot_err.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_deinit��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_deinit(hi_void);

/**
* @ingroup        iot_cipher
* @brief          Settings of AES. CNcomment:AES�㷨�������á�CNend
*
* @par ����:
*                 Configure of AES. CNcomment:AES�㷨�������á�CNend
*
* @attention      None
* @param          ctrl        [IN]  type #hi_cipher_aes_ctrl *��AES parameters. CNcomment:AES�㷨�������á�CNend
*
* @retval #HI_ERR_SUCCESS   Success
* @retval #Other            Failure. For details, see hi_boot_err.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_aes_config��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_aes_config(hi_cipher_aes_ctrl *ctrl);

/**
* @ingroup        iot_cipher
* @brief          Encryption/Decryption of AES, if execution fails, hi_cipher_aes_destroy_config must be called to
release resources.
CNcomment:AES�㷨�ӽ��ܣ����ִ��ʧ�ܣ��������hi_cipher_aes_destroy_config�ӿ��ͷ���Դ��CNend
*
* @par ����:
*                 Encryption/Decryption of AES. CNcomment:AES�㷨�ӽ��ܡ�CNend
*
* @attention      �ޡ�
* @param          src_addr    [IN]  type #uintptr_t��Input data source address.
CNcomment:�����ܻ���ܵ�Դ���������ַ����ַҪ��4���롣CNend
* @param          dest_addr   [OUT] type #uintptr_t��output data physical address, the address must be
aligned in 4 bytes.
CNcomment:���ܻ���ܽ�����������ַ����ַҪ��4���롣CNend
* @param          length      [IN]  type #hi_u32��data length, ECB/CBC/CTR/XTS must be aligned in 16 bytes.
CNcomment:���ݳ��ȣ� ECB/CBC/CTR/XTSҪ��16bytes���롣CNend
* @param          encrypt     [IN]  type #hi_bool��options of encryption/decryption, HI_TRUE is for encryption,
HI_FALSE is for decryption.CNcomment:�ӽ�������ѡ�����HI_TRUEΪ���ܣ�����HI_FALSEΪ���ܡ�CNend
*
* @retval #HI_ERR_SUCCESS   Success
* @retval #Other            Failure. For details, see hi_boot_err.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_aes_crypto��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_aes_crypto(uintptr_t src_addr, uintptr_t dest_addr, hi_u32 length, hi_bool encrypt);

/**
* @ingroup        iot_cipher
* @brief          Destory AES configures. CNcomment:AES�㷨�������õĲ���CNend
*
* @par ����:
*                 Destory AES configures. CNcomment:AES�㷨�������õĲ���CNend
*
* @attention      In pair with hi_cipher_aes_config.CNcomment:��������óɶ�ʹ��CNend
* @param          None

* @retval #HI_ERR_SUCCESS   Success
* @retval #Other            Failure. For details, see hi_boot_err.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_aes_destroy_config��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_aes_destroy_config(hi_void);

/**
* @ingroup        iot_cipher
* @brief          Settings of HASH.CNcomment:HASH�㷨��������CNend
*
* @par ����:
*                 Settings of HASH, this function should be called before calculating.
CNcomment:HASH�㷨�������ã�HASH����ǰ����
*
* @attention      None
* @param  atts    [IN]        type #const hi_cipher_hash_atts *��HASH attribute.CNcomment:HASH�㷨�������á�CNend

* @retval #HI_ERR_SUCCESS   Success
* @retval #Other            Failure. For details, see hi_boot_err.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_hash_start��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_hash_start(hi_void);

/**
* @ingroup        iot_cipher
* @brief          Calculating by HASH.CNcomment:HASH����CNend
*
* @par ����:
*                 Hash calculation. Multiple segments can be calculated��Maximum 10KB per segment.
CNcomment:HASH���㣬֧�ֶ�μ��㣬ÿ���10KB��CNend
*
* @attention      None
* @param          src_addr    [IN]  type #uintptr_t��Data address to be calculated by HASH.
CNcomment:��HASH��������ݵ�ַ��CNend
* @param          length      [IN]  type #hi_u32��Data length to be calculated by HASH��maximum is 10KB.
CNcomment:��HASH��������ݳ���,�10KB��CNend
*
* @retval #HI_ERR_SUCCESS   Success
* @retval #Other            Failure. For details, see hi_boot_err.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_hash_update��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_hash_update(uintptr_t src_addr, hi_u32 length);

/**
* @ingroup        iot_cipher
* @brief          HASH calculation finished.CNcomment:HASH�������CNend
*
* @par ����:
*                 Ouput results after HASH finished calculating.CNcomment:HASH���������
�����������CNend
*
* @attention      None
*
* @param          out          [OUT]  type #hi_u8 *��Pointer to the output of the HASH calculation result.
CNcomment:HASH���������ָ�롣CNend
* @param          out_len      [IN]   type #hi_u32��HASH The output pointer of the calculation result points to
*                              the space length. The output length must be greater than or equal to 32 bytes.
CNcomment:HASH���������ָ��ָ��ռ䳤��,Ҫ������������㲻С��32bytes��CNend
*
* @retval #HI_ERR_SUCCESS   Success
* @retval #Other            Failure. For details, see hi_boot_err.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_hash_final��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_hash_final(hi_u8 *out, hi_u32 out_len);

/**
* @ingroup        iot_cipher
* @brief          HASH calculation.CNcomment:HASH����CNend
*
* @par ����:
*                 Performs hash calculation on a segment of data and outputs the hash result.
CNcomment:��һ��������HASH���㣬�����HASH�����CNend
*
* @attention      None
*
* @param          input        [IN]  type #uintptr_t��Enter the data address. The address must be 4-bytes-aligned.
CNcomment:�������ݵ�ַ����ַҪ��4���롣CNend
* @param          input_len    [IN]  type #hi_u32�� Input data length.CNcomment:�������ݳ��ȡ�CNend
* @param          hash         [OUT] type #hi_u8 *��Output the hash result. The length is 32 bytes.
CNcomment:���HASH����� ����Ϊ 32 bytes��CNend
* @param          hash_len     [IN]  type #hi_u32�� BUF length of the hash result. The value must be greater than or
*                              equal to 32 bytes.CNcomment:���HASH�����BUF���ȣ���Ҫ���㲻С��32bytes��CNend
*
* @retval #HI_ERR_SUCCESS   Success
* @retval #Other            Failure. For details, see hi_boot_err.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_hash_sha256��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_hash_sha256(uintptr_t input, hi_u32 input_len, hi_u8 *hash, hi_u32 hash_len);

/**
* @ingroup        iot_cipher
* @brief          KDF calculation.CNcomment:KDF�㷨���㡣CNend
*
* @par ����:
*                 KDF calculation.CNcomment:KDF�㷨���㡣CNend
*
* @attention      None
* @param          ctrl        [IN] type  #hi_cipher_kdf_ctrl*��Poninter to KDF algorithm parameter configuration
                              control structure.CNcomment:KDF�㷨�������ÿ��ƽṹ�塣CNend
*
* @retval #HI_ERR_SUCCESS   Success
* @retval #Other            Failure. For details, see hi_boot_err.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_kdf_key_derive��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_kdf_key_derive(hi_cipher_kdf_ctrl *ctrl);

/**
* @ingroup        iot_cipher
* @brief          Rsa Signature Verification.CNcomment:Rsa ǩ�����У��CNend
*
* @par ����:
*                 Rsa Signature Verification.CNcomment:Rsa ǩ�����У�顣CNend
*
* @attention      None
* @param          rsa_verify  [IN]   type #hi_cipher_rsa_verify *��Structure of the Rsa signature result
*                              verification algorithm.CNcomment:Rsaǩ�����У���㷨�ṹ�塣CNend
* @param          hash        [IN]   type #const hi_u8 *��Hash data to be checked.
CNcomment:��У���HASH���ݡ�CNend
* @param          hash_len    [IN]   type #hi_u32�� Indicates the length of the hash data to be verified.
*                              The value is 32 bytes valid data.
CNcomment:��У���HASH���ݵĳ��ȣ�Ϊ32bytes��Ч���ݡ�CNend
* @param          sign        [IN]   type #const hi_u8 *��Signature input pointer.CNcomment:ǩ������ָ�롣CNend
* @param          sign_len    [IN]   type #hi_u32��Length of the signature result. The length is the same as the
*                              length of the key.CNcomment:ǩ���������, ������key�ĳ�����ͬ��CNend
*
* @retval #HI_ERR_SUCCESS   Success
* @retval #Other            Failure. For details, see hi_boot_err.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_rsa_verify_hash��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_rsa_verify_hash(const hi_cipher_rsa_verify *rsa_verify, hi_cipher_rsa_data *pack);

/**
* @ingroup        iot_cipher
* @brief          Ecdsa Signature Verification.CNcomment:Ecdsa ǩ�����У��CNend
*
* @par ����:
*                 Ecdsa Signature Verification.CNcomment:Ecdsa ǩ�����У�顣CNend
*
* @attention      None
* @param          ecc          [IN]   type #const hi_cipher_ecc_param *��ECC elliptic curve parameter. If the length
*                              is less than the size of the key, add 0 before the key.
CNcomment:ECC��Բ���߲��������Ȳ���Key�Ĵ�С��ǰ�油0��CNend
* @param          verify       [IN]   type #const hi_cipher_ecc_verify *��Pointer to structure of the ECC public key
*                              verification parameter.CNcomment:ECC��Կ��֤�����ṹ�塣CNend
*
* @retval #HI_ERR_SUCCESS   Success
* @retval #Other            Failure. For details, see hi_boot_err.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_ecc_sign_hash��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_ecc_verify_hash(hi_cipher_ecc_param *ecc, hi_cipher_ecc_verify *verify);

/**
* @ingroup        iot_cipher
* @brief          TRNG Obtain a random number.CNcomment:TRNG��ȡ�����CNend
*
* @par ����:
*                 TRNG Obtain a random number. Only one word size can be obtained at a time.
CNcomment:TRNG��ȡ�������ÿ��ֻ�ܻ�ȡһ��WORD��С���������CNend
*
* @attention      None
* @param          randnum      [OUT]  type #hi_u32 *��Random number output pointer.
CNcomment:��������ָ�롣CNend
*
* @retval #HI_ERR_SUCCESS   Success
* @retval #Other            Failure. For details, see hi_boot_err.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_trng_get_random��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_trng_get_random(hi_u32 *randnum);

/**
* @ingroup        iot_cipher
* @brief          TRNG Obtain a random number.CNcomment:TRNG��ȡ�����CNend
*
* @par ����:
*                 The TRNG obtains the random number and obtains the random number of multiple bytes at a time.
CNcomment:TRNG��ȡ�������ÿ�λ�ȡ���byte���������CNend
*
* @attention      None
* @param          randbyte     [OUT]  type #hi_u8 *��Random number output pointer.
CNcomment:��������ָ�롣CNend
* @param          size         [IN]   type #hi_u32��Length of the obtained random number.
CNcomment:��ȡ����������ȡ�CNend
*
* @retval #HI_ERR_SUCCESS   Success
* @retval #Other            Failure. For details, see hi_boot_err.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_trng_get_random��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_trng_get_random_bytes(hi_u8 *randbyte, hi_u32 size);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif  /* __cplusplus */

#endif /* __HI_CIPHER_H__ */
