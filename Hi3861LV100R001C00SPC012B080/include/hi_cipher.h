/**
* @file hi_cipher.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.   \n
* Description: Encryption and decryption interfaces.   \n
* Author: Hisilicon   \n
* Create: 2019-05-29
*/

/**
 * @defgroup iot_cipher Encryption and Decryption.
 * @ingroup drivers
 */
#ifndef __HI_CIPHER_H__
#define __HI_CIPHER_H__

#include <hi_types.h>

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
* Hash algrithm type
*/
typedef enum {
    HI_CIPHER_HASH_TYPE_SHA256       = 0x0,
    HI_CIPHER_HASH_TYPE_HMAC_SHA256,
    HI_CIPHER_HASH_TYPE_MAX,
    HI_CIPHER_HASH_TYPE_INVALID      = 0xffffffff,
}hi_cipher_hash_type;

/**
* @ingroup iot_cipher
* Rsa sign and veriry scheme
*/
typedef enum {
    HI_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_V15_SHA256 = 0x00,  /**< PKCS#1 RSASSA_PKCS1_V15_SHA256 signature */
    HI_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_PSS_SHA256,         /**< PKCS#1 RSASSA_PKCS1_PSS_SHA256 signature */
    HI_CIPHER_RSA_SIGN_SCHEME_MAX,
    HI_CIPHER_RSA_SIGN_SCHEME_INVALID = 0xffffffff,
}hi_cipher_rsa_sign_scheme;

/**
* @ingroup iot_cipher
* Aes key from
*/
typedef enum {
    HI_CIPHER_AES_KEY_FROM_CPU  = 0x00,
    HI_CIPHER_AES_KEY_FROM_KDF,
    HI_CIPHER_AES_KEY_FROM_MAX,
    HI_CIPHER_AES_KEY_FROM_INVALID = 0xffffffff,
}hi_cipher_aes_key_from;

/**
* @ingroup iot_cipher
* Aes work mode
*/
typedef enum {
    HI_CIPHER_AES_WORK_MODE_ECB  = 0x00,    /**< Electronic codebook (ECB) mode, ECB has been considered insecure and
                                               it is recommended not to use it. */
    HI_CIPHER_AES_WORK_MODE_CBC,            /**< Cipher block chaining (CBC) mode. */
    HI_CIPHER_AES_WORK_MODE_CTR,            /**< Counter (CTR) mode. */
    HI_CIPHER_AES_WORK_MODE_CCM,            /**< Counter (CCM) mode. */
    HI_CIPHER_AES_WORK_MODE_XTS,            /**< XTS-AES (XTS) mode. */
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
    HI_CIPHER_AES_KEY_LENGTH_512BIT,             /**< 512bit, just used for xts. */
    HI_CIPHER_AES_KEY_LENGTH_MAX,
    HI_CIPHER_AES_KEY_LENGTH_INVALID = 0xffffffff,
}hi_cipher_aes_key_length;

/**
* @ingroup iot_cipher
* Rsa private key sign
*/
typedef struct {
    hi_cipher_rsa_sign_scheme scheme;  /**< The rsa sign type */
    hi_u8 *d;                          /**< The private exponent */
    hi_u8 *n;                          /**< The modulus */
    hi_u32 klen;                       /**< The key length */
} hi_cipher_rsa_sign;

/**
* @ingroup iot_cipher
* Rsa public key verify
*/
typedef struct {
    hi_cipher_rsa_sign_scheme scheme;  /**< The rsa sign type */
    hi_u8 *e;                          /**< The public exponent */
    hi_u8 *n;                          /**< The modulus */
    hi_u32 klen;                       /**< The key length */
} hi_cipher_rsa_verify;

/**
* @ingroup iot_cipher
* cipher struct for output
*/
typedef struct {
    hi_u8 *out;                        /**< Point for output */
    hi_u32 out_buf_len;                /**< Length of output buffer */
    hi_u32 *out_len;                   /**< Length of valid output data */
} hi_cipher_output;

/**
* @ingroup iot_cipher
* Struct of ecc curves parameters
*/
typedef struct {
    const hi_u8 *p;   /**< Finite field: equal to p in case of prime field curves or equal to 2^n in case of binary
                         field curves. */
    const hi_u8 *a;   /**< Curve parameter a (q-3 in Suite B). */
    const hi_u8 *b;   /**< Curve parameter b. */
    const hi_u8 *gx;  /**< X coordinates of G which is a base point on the curve. */
    const hi_u8 *gy;  /**< Y coordinates of G which is a base point on the curve. */
    const hi_u8 *n;   /**< Prime which is the order of G point. */
    hi_u32 h;         /**< Cofactor, which is the order of the elliptic curve divided by the order of the point G. For
                         the Suite B curves, h = 1. */
    hi_u32 ksize;   /**< Ecc key size in bytes. It corresponds to the size in bytes of the prime, should be 32bytes. */
}hi_cipher_ecc_param;

/**
* @ingroup iot_cipher
* Struct of ecc sign
*/
typedef struct {
    const hi_u8 *d;  /**< Ecdh private key, the caller ensures it is padded with leading zeros if the effective size of
                          this key is smaller than ecc key size. */
    const hi_u8 *hash; /**< Hash data for ecc sign. */
    hi_u32 hash_len;   /**< The length of hash data, just 32 bytes is valid data. */
    hi_u8 *r;          /**< Output ecc sign result R, its length is ecc key size. */
    hi_u8 *s;          /**< Output ecc sign result S, its length is ecc key size. */
}hi_cipher_ecc_sign;

/**
* @ingroup iot_cipher
* Struct of ecc verify
*/
typedef struct {
    const hi_u8 *px;  /**< Ecdh X coordinates of the generated public key, the caller ensures it is padded with leading
                         zeros if the effective size of this key is smaller than ecc key size. */
    const hi_u8 *py;  /**< Ecdh Y coordinates of the generated public key, the caller ensures it is padded with leading
                         zeros if the effective size of this key is smaller than ecc key size. */
    const hi_u8 *hash; /**< Hash data for ecc verify. */
    hi_u32 hash_len;   /**< The length of hash data, just 32 bytes is valid data. */
    const hi_u8 *r;    /**< Output ecc sign result R, its length is ecc key size. */
    const hi_u8 *s;    /**< Output ecc sign result S, its length is ecc key size. */
}hi_cipher_ecc_verify;

/**
* @ingroup iot_cipher
* Aes ccm struct
*/
typedef struct {
    hi_u8 *n;            /**< Nonce. */
    hi_u32 n_len;        /**< Nonce length for CCM, which is an element of {7,8,9,10,11,12,13}. */
    hi_u32 tag_len;      /**< Tag lenght for CCM which is an element of {4,6,8,10,12,14,16}. */
    hi_u32 aad_len;      /**< Associated data length for CCM. */
    uintptr_t aad_addr;  /**< Physical address of Associated data for CCM. */
}hi_cipher_aes_ccm;

/**
* @ingroup iot_cipher
* Aes ctrl struct
*/
typedef struct {
    hi_u32 key[AES_MAX_KEY_IN_WORD];    /**< Key input. */
    hi_u32 iv[AES_IV_LEN_IN_WORD];      /**< Initialization vector (IV). */
    hi_bool random_en;                  /**< Enable random delay or not. */
    hi_u8 resv[3];                      /* 3 byte�����ֶ� */
    hi_cipher_aes_key_from key_from;    /**< Key from, When using kdf key, no nead to configure the input key. */
    hi_cipher_aes_work_mode work_mode;  /**< Work mode. */
    hi_cipher_aes_key_length key_len;   /**< Key length. aes-ecb/cbc/ctr support 128/192/256 bits key, ccm just support
                                            128 bits key, xts just support 256/512 bits key. */
    hi_cipher_aes_ccm *ccm;             /**< Struct for ccm. */
}hi_cipher_aes_ctrl;

/**
* @ingroup iot_cipher
* Kdf key type
*/
typedef enum {
    HI_CIPHER_SSS_KDF_KEY_DEVICE  = 0x0, /**< kdf device key derivation. */
    HI_CIPHER_SSS_KDF_KEY_STORAGE,       /**< kdf storage key derivation. */
    HI_CIPHER_SSS_KDF_KEY_MAX,
    HI_CIPHER_SSS_KDF_KEY_INVALID = 0xFFFFFFFF,
}hi_cipher_kdf_mode;

/**
* @ingroup iot_cipher
* Kdf ctrl struct
*/
typedef struct {
    const hi_u8 *salt;                   /**< salt for kdf key derivation. */
    hi_u32 salt_len;                     /**< salt_len should be 16 bytes for kdf device key derivation,
                                            32 bytes for kdf storage key derivation. */
    hi_u8 key[KDF_KEY_LEN_IN_BYTES];
    hi_cipher_kdf_mode kdf_mode;         /**< kdf mode for key derivation. */
    hi_u32 kdf_cnt;                      /**< kdf cnt for iteration. It is recommended that the number of iterations be
                                            not less than 1000 times, and not more than 0xffff times. */
    hi_u8 result[KDF_KEY_LEN_IN_BYTES];
}hi_cipher_kdf_ctrl;

/**
* @ingroup iot_cipher
* Hash/hmac init struct input
*/
typedef struct {
    const hi_u8 *hmac_key;               /**< hmac_key, just used for hmac. */
    hi_u32 hmac_key_len;                 /**< hmac_key_len, just used for hmac. */
    hi_cipher_hash_type sha_type;        /**< sha_type, hash or hmac type. */
}hi_cipher_hash_atts;

/**
* @ingroup        iot_cipher
* @brief          Initializes the Cipher module. CNcomment:Cipher ģ���ʼ����CNend
*
* @par ����:
*                 Initializes the Cipher module, does NOT support multi-tasks.
CNcomment:Cipherģ���ʼ��,��֧�ֶ�����CNend
*
* @attention      This function must be called before using cipher module.
CNcomment:ʹ��Cipherģ���㷨ǰ���ñ��ӿڳ�ʼ����CNend
* @param          None
*
* @retval         #0          Success
* @retval         #Other      Failure, for details, see file hi_errno.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_init��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_init(hi_void);

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
* @retval         #0          Success
* @retval         #Other      Failure, for details, see file hi_errno.h.
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
* @param          length      [IN]  type #hi_u32��data length, ECB/CBC/CTR must be aligned in 16 bytes,
CCM doesn't need to.
CNcomment:���ݳ��ȣ� ECB/CBC/CTRҪ��16bytes���룬 CCM���Բ�Ҫ��16bytes���롣CNend
* @param          encrypt     [IN]  type #hi_bool��options of encryption/decryption, HI_TRUE is for encryption,
HI_FALSE is for decryption.CNcomment:�ӽ�������ѡ�����HI_TRUEΪ���ܣ�����HI_FALSEΪ���ܡ�CNend
*
* @retval         #0          Success
* @retval         #Other      Failure, for details, see file hi_errno.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_aes_crypto��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_aes_crypto(uintptr_t src_addr, uintptr_t dest_addr, hi_u32 length, hi_bool encrypt);

/**
* @ingroup        iot_cipher
* @brief          Output Tag, if execution fails, hi_cipher_aes_destroy_config must be called to release resources.
CNcomment:���Tag�����ִ��ʧ�ܣ��������hi_cipher_aes_destroy_config�ӿ��ͷ���Դ��CNend
*
* @par ����:
*                 Output Tag, AES and CCM will output Tag after encrypting or decrypting.
CNcomment:���Tag, AES CCM ģʽ���ܻ���ܼ�����ɺ����Tagֵ��CNend
*
* @attention      None
* @param          tag         [OUT] type #hi_u8 *��Pointer to output Tag. CNcomment:���Tagָ�롣CNend
* @param          tag_buf_len [IN]  type #hi_u32��Length of the buffer which tag points to.
CNcomment:tagָ��ָ������buff���ȡ�CNend
* @param          tag_len     [OUT] type #hi_u32*��Length of the output tag.
CNcomment: �����tag���ݳ��ȡ�CNend.
*
* @retval         #0          Success
* @retval         #Other      Failure, for details, see file hi_errno.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_aes_get_tag��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_aes_get_tag(hi_u8 *tag, hi_u32 tag_buf_len, hi_u32 *tag_len);

/**
* @ingroup        iot_cipher
* @brief          Destory AES configures. CNcomment:AES�㷨�������õĲ���CNend
*
* @par ����:
*                 Destory AES configures. CNcomment:AES�㷨�������õĲ���CNend
*
* @attention      In pair with hi_cipher_aes_config.CNcomment:��������óɶ�ʹ��CNend
* @param          None

* @retval         #0          Success
* @retval         #Other      Failure, for details, see file hi_errno.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_aes_destroy_config��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_aes_destroy_config(hi_void);

/**
* @ingroup        iot_cipher
* @brief          Settings of HASH/HMAC.CNcomment:HASH/HMAC�㷨��������CNend
*
* @par ����:
*                 Settings of HASH/HMAC, this function should be called before calculating.
CNcomment:HASH/HMAC�㷨�������ã�HASH/HMAC����ǰ����
*
* @attention      None
* @param  atts    [IN]        type #const hi_cipher_hash_atts *��HASH attribute.CNcomment:HASH�㷨�������á�CNend

* @retval         #0          Success
* @retval         #Other      Failure, for details, see file hi_errno.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_hash_start��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_hash_start(const hi_cipher_hash_atts *atts);

/**
* @ingroup        iot_cipher
* @brief          Calculating by HASH/HMAC.CNcomment:HASH/HMAC����CNend
*
* @par ����:
*                 Hash calculation. Multiple segments can be calculated. HMAC calculation supports only single-segment
calculation.CNcomment:HASH���㣬֧�ֶ�μ��㣬HMAC����ֻ֧�ֵ��μ��㡣CNend
*
* @attention      None
* @param          src_addr    [IN]  type #uintptr_t��Data address to be calculated by HASH.
CNcomment:��HASH��������ݵ�ַ��CNend
* @param          length      [IN]  type #hi_u32��Data length to be calculated by HASH.
CNcomment:��HASH��������ݳ��ȡ�CNend
*
* @retval         #0          Success
* @retval         #Other      Failure, for details, see file hi_errno.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_hash_update��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_hash_update(uintptr_t src_addr, hi_u32 length);

/**
* @ingroup        iot_cipher
* @brief          HASH/HMAC calculation finished.CNcomment:HASH/HMAC�������CNend
*
* @par ����:
*                 Ouput results after HASH/HMAC finished calculating.CNcomment:HASH/HMAC���������
�����������CNend
*
* @attention      None
*
* @param          out          [OUT]  type #hi_u8 *��Pointer to the output of the HASH/HMAC calculation result.
CNcomment:HASH/HMAC���������ָ�롣CNend
* @param          out_len      [IN]   type #hi_u32��HASH/HMAC The output pointer of the calculation result points to
*                              the space length. The output length must be greater than or equal to 32 bytes.
CNcomment:HASH/HMAC���������ָ��ָ��ռ䳤��,Ҫ������������㲻С��32bytes��CNend
*
* @retval         #0          Success
* @retval         #Other      Failure, for details, see file hi_errno.h.
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
* @retval         #0          Success
* @retval         #Other      Failure, for details, see file hi_errno.h.
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
* @retval         #0          Success
* @retval         #Other      Failure, for details, see file hi_errno.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_kdf_key_derive��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_kdf_key_derive(hi_cipher_kdf_ctrl *ctrl);

/**
* @ingroup        iot_cipher
* @brief          Rsa signature.CNcomment:Rsa ǩ��CNend
*
* @par ����:
*                 Rsa signature and output of the signature result.CNcomment:Rsaǩ�������ǩ�������CNend
*
* @attention      None
* @param          rsa_sign     [IN]  type  #hi_cipher_rsa_sign *��Pointer to RSA signature structure.
CNcomment:Rsaǩ���㷨�ṹ�塣CNend
* @param          hash_data    [IN]  type  #const hi_u8 *��Indicates the hash data to be signed.
CNcomment:��ǩ����HASH���ݡ�CNend
* @param          hash_data_len [IN] type  #hi_u32�� Length of the hash data to be signed, 32 bytes data.
CNcomment:��ǩ����HASH���ݵĳ��ȣ�32bytes���ݡ�CNend
* @param          sign         [OUT] type  #const hi_cipher_output *��Signature result output structure. The length
*                              of the output signature result is the length of the key.
CNcomment:ǩ���������ṹ�壬�����ǩ���������Ϊkey�ĳ��ȡ�CNend
*
* @retval         #0          Success
* @retval         #Other      Failure, for details, see file hi_errno.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_rsa_sign_hash��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_rsa_sign_hash(const hi_cipher_rsa_sign *rsa_sign, const hi_u8 *hash_data, hi_u32 hash_data_len,
    const hi_cipher_output *sign);

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
* @retval         #0          Success
* @retval         #Other      Failure, for details, see file hi_errno.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_rsa_verify_hash��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_rsa_verify_hash(const hi_cipher_rsa_verify *rsa_verify, const hi_u8 *hash, hi_u32 hash_len,
    const hi_u8 *sign, hi_u32 sign_len);

/**
* @ingroup        iot_cipher
* @brief          Ecdsa signature.CNcomment:Ecdsa ǩ��CNend
*
* @par ����:
*            Ecdsa signature and output of the signature result.CNcomment:Ecdsa ǩ�������ǩ�������CNend
*
* @attention      None
* @param          ecc          [IN]         type #const hi_cipher_ecc_param *��ECC elliptic curve parameter. If the
*                              length is less than the size of the key, add 0 before the key.CNcomment:ECC��Բ����
���������Ȳ���Key�Ĵ�С��ǰ�油0��CNend
* @param          sign         [IN/OUT]     type #const hi_cipher_ecc_sign *��Pointer to private key of ECDH.
CNcomment:ECDH˽Կǩ���ṹ�塣CNend
*
* @retval         #0          Success
* @retval         #Other      Failure, for details, see file hi_errno.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_ecc_sign_hash��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_ecc_sign_hash(const hi_cipher_ecc_param *ecc, const hi_cipher_ecc_sign *sign);

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
* @retval         #0          Success
* @retval         #Other      Failure, for details, see file hi_errno.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_ecc_sign_hash��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_ecc_verify_hash(const hi_cipher_ecc_param *ecc, const hi_cipher_ecc_verify *verify);

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
* @retval         #0          Success
* @retval         #Other      Failure, for details, see file hi_errno.h.
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
* @retval         #0          Success
* @retval         #Other      Failure, for details, see file hi_errno.h.
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_trng_get_random��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cipher_trng_get_random_bytes(hi_u8 *randbyte, hi_u32 size);

/**
* @ingroup        iot_cipher
* @brief          Set the clock switch of cipher module.CNcomment:����cipherģ��ʱ���л����ء�CNend
*
* @par ����:
*                 Set the clock switch of cipher module, which is false by default, The clock is always on.
When it is true, clock will be turned on when cipher algorithm is used and turned off when calculation is finished.
CNcomment:����cipherģ��ʱ���л����أ�Ĭ��ΪFALSE��ʱ�ӳ�������ΪTRUE����ʹ��cipher�㷨ʱ�򿪣����������رա�CNend
*
* @attention      None
* @param          enable       [IN]  type #hi_bool��Random number output pointer.
CNcomment:��������ָ�롣CNend
*
* @retval         None
* @par ����:
*                 @li hi_cipher.h��Describes Cipher module APIs.
CNcomment:�ļ���������Cipherģ����ؽӿڡ�CNend
* @see            hi_cipher_set_clk_ctrl��
* @since Hi3861_V100R001C00
*/
hi_void hi_cipher_set_clk_switch(hi_bool enable);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif  /* __cplusplus */

#endif /* __HI_CIPHER_H__ */

