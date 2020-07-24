/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Upgrade file structure.
 * Author: Hisilicon
 * Create: 2019-12-10
 */

#ifndef __HI_BURN_FILE_H__
#define __HI_BURN_FILE_H__

#include <hi_types.h>

/**
 *
 * Initial vector length.CNcomment:��ʼ�������ȡ�CNend
 */
#define IV_BYTE_LEN   16

/**
 *
 * RSA2048 parameter length.CNcomment:RSA2048�������ȡ�CNend
 */
#define RSA_2048_LEN  256

/**
 *
 * RSA2048 parameter E length.CNcomment:RSA2048����E���ȡ�CNend
 */
#define RSA_EXP_E_LEN 4

/**
 *
 * ECC parameter length.CNcomment:ECC�������ȡ�CNend
 */
#define ECC_32_BYTES  32

/**
 *
 * SHA256 hash length.CNcomment:SHA256��ϣֵ���ȡ�CNend
 */
#define SHA_256_LEN   32

/**
 *
 * Kernel upgrade file.CNcomment:Kernel�����ļ���CNend
 */
#define HI_UPG_FILE_KERNEL 0xF0 /* Kernel upgrade file. */

/**
 *
 * FlashBoot upgrade file.CNcomment:FlashBoot�����ļ���CNend
 */
#define HI_UPG_FILE_BOOT   0xE1 /* FlashBoot upgrade file. */

/**
 *
 * Parameter of sign algorithm.CNcomment:ǩ���㷨������CNend
 */
typedef struct {
    hi_u32 hash_alg : 16; /**< HASH algorithm:0:SHA256.CNcomment:HASH�㷨��CNend */
    hi_u32 sign_alg : 6; /**< Sign algorithm:0:RSA-PKCS;1:RSA-PSS;0x10:ECDSA256;0x3F:SHA256.CNcomment:ǩ���㷨��CNend */
    hi_u32 sign_param : 10; /**< Sign parameter, default '0'.CNcomment:HASH�㷨��CNend */
} sign_alg_param;

typedef struct {
    hi_u8 mod_n[RSA_2048_LEN];  /**< Mod N.CNcomment:RSA����N��CNend */
    hi_u8 exp_e[RSA_EXP_E_LEN]; /**< Exp E.CNcomment:RSA����E��CNend */
    hi_u8 padding[28];          /**< Padding field:28.CNcomment:����ֶΡ�CNend */
} upg_rsa_key;

typedef struct {
    hi_u8 sign[RSA_2048_LEN]; /**< RSA signature.CNcomment:RSAǩ����CNend */
} upg_rsa_sign;

typedef struct {
    hi_u8 px[ECC_32_BYTES]; /**< Pubkey x.CNcomment:ECC��Կx��CNend */
    hi_u8 py[ECC_32_BYTES]; /**< Pubkey y.CNcomment:ECC��Կy��CNend */
    hi_u8 padding[224];     /**< Padding field:224. CNcomment:����ֶΡ�CNend */
} upg_ecc_key;

typedef struct {
    hi_u8 r[ECC_32_BYTES]; /**< Signature of ECC.CNcomment:ECCǩ����Ϣr��CNend */
    hi_u8 s[ECC_32_BYTES]; /**< Signature of ECC.CNcomment:ECCǩ����Ϣs��CNend */
    hi_u8 padding[192];    /**< Padding field:192.CNcomment:����ֶΡ�CNend */
} upg_ecc_sign;

typedef struct {
    hi_u8 padding[288]; /**< Padding field:288.CNcomment:����ֶΡ�CNend */
} upg_sha256_key;

typedef struct {
    hi_u8 check_sum[SHA_256_LEN]; /**< Hash value of SHA256.CNcomment:SHA256�㷨��ϣֵ��CNend */
    hi_u8 padding[224];           /**< Padding field:224.CNcomment:����ֶΡ�CNend */
} upg_sha256_sign;

typedef struct {
    hi_u8 reserved[32];    /**< 32:Reserved for user.CNcomment:�û��ֶζ����ֶΡ�CNend */
}hi_upg_user_info;

typedef struct {
    hi_u32 image_id;       /**< Identity of upgrade file Key Area.CNcomment:�����ļ�ħ���֡�CNend */
    hi_u32 struct_version; /**< The structure of upgrade file version.CNcomment:�����ļ��ṹ��汾�š�CNend */
    hi_u32 section_offset; /**< Offset of upgrade Section.CNcomment:Section��ƫ�ơ�CNend */
    hi_u32 section_len;    /**< Length of upgrade Section.CNcomment:Section�γ��ȡ�CNend */
    hi_upg_user_info user_info; /**< Reserved for user.CNcomment:�û��Զ����ֶΡ�CNend */
    hi_u8 file_type;       /**< Upgrade file type:0xF0: kernel file; 0xE1: boot file.CNcomment:�����ļ����͡�CNend */
    hi_u8 file_version;    /**< File Version, for anti-rollback. [0, 16] for boot file and [0, 48] for kernel file.
                                CNcomment:�����ļ��ṹ��汾�š�CNend */
    hi_u8 encrypt_flag;    /**< 0x42: Section Area is not encrypted; other: Section Area is encrypted.
                                CNcomment:Section�μ��ܱ�־��CNend */
    hi_u8 file_attr;            /**< File Attributes.CNcomment:�ļ����ԡ�CNend */
    hi_u32 file_len;            /**< Entire file length.CNcomment:�����ļ����ȡ�CNend */
    hi_u32 key_len;             /**< Length of Key(288Bytes).True length:RSA2048: 272 Bytes, ECDSA: 64Bytes.
                                     CNcomment:��Կ���ȡ�CNend */
    sign_alg_param param;       /**< Parma of the signature algorithm.CNcomment:ǩ���㷨������CNend */
    hi_u8 aes_key[IV_BYTE_LEN]; /**< Part of key factor.CNcomment:AES��Կ��CNend */
    hi_u8 aes_iv[IV_BYTE_LEN];  /**< The IV (AES-256 CBC-mode) to encrypt Section.CNcomment:AES��ʼ������CNend */
} hi_upg_common_head;

typedef struct {
    hi_u32 image_id;           /**< Identity of upgrade file Key Area.CNcomment:�����ļ�ħ���֡�CNend */
    hi_u32 struct_version;     /**< The structure of upgrade file Section Area.CNcomment:�����ļ��ṹ��汾�š�CNend */
    sign_alg_param param;      /**< The signature algorithm.CNcomment:ǩ���㷨������CNend */
    hi_u8 section_count;       /**< The number of sections.CNcomment:Section�θ�����CNend */
    hi_u8 reserved[27];        /**< 27 bytes reserved.CNcomment:�����ֶΡ�CNend */
    hi_u8 section0_compress;   /**< Whether section 0 is compressed.CNcomment:Section0�Ƿ�ѹ����CNend */
    hi_u8 pad0[3];             /**< 3 bytes padding.CNcomment:����ֶΡ�CNend */
    hi_u32 section0_offset;    /**< Offset of Section0.CNcomment:Section0��ƫ�ơ�CNend */
    hi_u32 section0_len;       /**< Length of Section0, aligned to 16 bytes.CNcomment:Section0�γ��ȡ�CNend */
    hi_u8 section1_compress;   /**< Whether section 1 is compressed.CNcomment:Section1�Ƿ�ѹ���CNend */
    hi_u8 pad1[3];             /**< 3 bytes padding.CNcomment:����ֶΡ�CNend */
    hi_u32 section1_offset;    /**< Offset of Section1.CNcomment:Section1��ƫ�ơ�CNend */
    hi_u32 section1_len;       /**< Length of Section1, aligned to 16 bytes.CNcomment:Section1�γ��ȡ�CNend */
} hi_upg_section_head;

typedef struct {
    upg_rsa_key key;    /**< Key of rsa.CNcomment:RSA�㷨��Կ��CNend */
    upg_rsa_sign sign;  /**< Sign of rsa.CNcomment:RSA�㷨ǩ����CNend */
} hi_upg_rsa_alg;

typedef struct {
    upg_ecc_key key;    /**< Key of ecc.CNcomment:ECC�㷨��Կ��CNend */
    upg_ecc_sign sign;  /**< Sign of ecc.CNcomment:ECC�㷨ǩ����CNend */
} hi_upg_ecc_alg;

typedef struct {
    upg_sha256_key key;    /**< Padding field.CNcomment:����ֶΡ�CNend */
    upg_sha256_sign sign;  /**< Hash of sha256.CNcomment:SHA256�㷨��ϣֵ��CNend */
} hi_upg_sha256_alg;

typedef struct {
    union {
        upg_rsa_key rsa;    /**< Key of rsa.CNcomment:rsa��Կ��CNend */
        upg_ecc_key ecc;    /**< Key of ecc.CNcomment:ecc��Կ��CNend */
        upg_sha256_key sha; /**< Padding field.CNcomment:����ֶΡ�CNend */
    } key;
}hi_upg_key;

typedef struct {
    union {
        upg_rsa_sign rsa; /**< Sign of rsa.CNcomment:rsaǩ����CNend */
        upg_ecc_sign ecc; /**< Sign of ecc.CNcomment:eccǩ����CNend */
        upg_sha256_sign sha; /**< Hash of sha256.CNcomment:SHA256��ϣ��CNend */
    } sign;
}hi_upg_sign;

typedef struct {
    hi_upg_common_head common; /**< Common head of upg file.CNcomment:�����ļ�ͷ��CNend */
    union {
        hi_upg_rsa_alg rsa; /**< Key and sign of RSA.CNcomment:RSA��Կ��ǩ����Ϣ��CNend */
        hi_upg_ecc_alg ecc; /**< Key and sign of ECC.CNcomment:ECC��Կ��ǩ����Ϣ��CNend */
        hi_upg_sha256_alg sha;/**< Key and sign of SHA256.CNcomment:SHA256��Կ��ǩ����Ϣ��CNend */
    } sign_alg;
} hi_upg_head;


hi_void loaderboot_get_start_addr_offset(hi_u32 addr, hi_u32 *offset);

#endif