/**
 * @file hks_client.h
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved. \n
 * Description: Contains key generation, signature verify,
 * encryption and decryption, key derivation, key agreement, etc. \n
 * Author: Huawei \n
 * Create: 2019-06-19
 */

/**
 * @defgroup iot_hks
 * @ingroup hks
 */

#ifndef HKS_CLIENT_H
#define HKS_CLIENT_H

#include "hks_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
* @ingroup  iot_hks
* @brief Hks get sdk version.CNcomment:��ȡHKS sdk�汾�š�CNend
*
* @par ����:
*           Hks get sdk version.CNcomment:��ȡHKS sdk�汾�š�CNend
*
* @attention None
* @param  sdk_version      [OUT] type #struct hks_blob *��get sdk version.CNcomment:HKS sdk�汾�š�CNend
*
* @retval None
* @par ����:
*            @li hks_types.h��describes hks_types SDK interfaces.CNcomment:����hks_types SDK�Ľӿڡ�CNend
* @see hks_get_sdk_version
* @since Hi3861_V100R001C00
*/
HKS_DLL_API_PUBLIC void hks_get_sdk_version(struct hks_blob *sdk_version);

/**
* @ingroup  iot_hks
* @brief Hks init.CNcomment:hks ��ʼ����CNend
*
* @par ����:
*           Hks init.CNcomment:hks ��ʼ����CNend
*
* @attention None
* @param  None
*
* @retval #0       Success.
* @retval #Other   Failure.
* @par ����:
*            @li hks_types.h��describes hks_types SDK interfaces.CNcomment:����hks_types SDK�Ľӿڡ�CNend
* @see hks_init
* @since Hi3861_V100R001C00
*/
HKS_DLL_API_PUBLIC int32_t hks_init(void);

/**
* @ingroup  iot_hks
* @brief Hks destroy.CNcomment:���� hks��CNend
*
* @par ����:
*           Hks destroy.CNcomment:���� hks��CNend
*
* @attention None
* @param  None
*
* @retval None
* @par ����:
*            @li hks_types.h��describes hks_types SDK interfaces.CNcomment:����hks_types SDK�Ľӿڡ�CNend
* @see hks_destroy
* @since Hi3861_V100R001C00
*/
HKS_DLL_API_PUBLIC void hks_destroy(void);

/**
* @ingroup  iot_hks
* @brief Refresh key info and root key info.CNcomment:ˢ����Կ��Ϣ�͸���Կ��Ϣ��CNend
*
* @par ����:
*           Refresh key info and root key info.CNcomment:ˢ����Կ��Ϣ�͸���Կ��Ϣ��CNend
*
* @attention None
* @param  None
*
* @retval #0       Success.
* @retval #Other   Failure.
* @par ����:
*            @li hks_types.h��describes hks_types SDK interfaces.CNcomment:����hks_types SDK�Ľӿڡ�CNend
* @see hks_refresh_key_info
* @since Hi3861_V100R001C00
*/
HKS_DLL_API_PUBLIC int32_t hks_refresh_key_info(void);

/**
* @ingroup  iot_hks
* @brief Generate key Only ED25519 algorithm key pair generation is supported The number of local storage keys.
  CNcomment:������Կ��֧��ED25519�㷨��Կ�����ɱ��ش洢��Կ��CNend
*
* @par ����:
*           Generate key Only ED25519 algorithm key pair generation is supported The number of local storage keys
  (including generated ED25519 public-private key pairs imported ED25519 public keys) is limited to 16.
  CNcomment:������Կ��֧��ED25519�㷨��Կ�����ɱ��ش洢��Կ
  �����������ED25519������Կ��˽��ED25519���ɵ�ED25519������Կ�ԣ�����������Ϊ16����CNend
*
* @attention None
* @param  key_alias      [IN] type #const struct hks_blob *��key alias, constraint condition:key_alias->size <= 64.
  CNcomment:��Կ������Լ��������key_alias-> size <= 64��CNend
* @param  key_param      [IN] type #const struct hks_key_param *��The parameter of the key which need to generate
  constraint condition: key_param cannot be NULL & key_param->key_type must be HKS_KEY_TYPE_EDDSA_KEYPAIR_ED25519.
  CNcomment:��Ҫ���ɵ���Կ���� Լ��������
  key_param����ΪNULL �� key_param-> key_type����ΪHKS_KEY_TYPE_EDDSA_KEYPAIR_ED25519��CNend
* @retval #0       Success.
* @retval #Other   Failure.
* @par ����:
*            @li hks_types.h��describes hks_types SDK interfaces.CNcomment:����hks_types SDK�Ľӿڡ�CNend
* @see hks_generate_key
* @since Hi3861_V100R001C00
*/
HKS_DLL_API_PUBLIC int32_t hks_generate_key(const struct hks_blob *key_alias,
    const struct hks_key_param *key_param);

/**
* @ingroup  iot_hks
* @brief Generate the X25519 algorithm key pair and return it to the caller. The generated key pair is not saved in HKS.
  CNcomment:����X25519�㷨��Կ�Բ����ظ������ߣ����ɵ���Կ�Բ���hks���档CNend
*
* @par ����:
*           Generate the X25519 algorithm key pair and return it to the caller.
  The generated key pair is not saved in HKS.
  CNcomment:����X25519�㷨��Կ�Բ����ظ������ߣ����ɵ���Կ�Բ���hks���档CNend
*
* @attention None
* @param  key_param      [IN] type #const struct hks_key_param *��Used to specify related parameters that affect
  key generation, constraint condition: key_param.key_type must be HKS_KEY_TYPE_ECC_KEYPAIR_CURVE25519
  key_param.usage must be hks_alg_ecdh(HKS_ALG_SELECT_RAW).
  CNcomment:����ָ��Ӱ����Կ���ɵ���ز���, Լ��������key_param.key_type����ΪHKS_KEY_TYPE_ECC_KEYPAIR_CURVE25519
   key_param.usage����Ϊhks_alg_ecdh��HKS_ALG_SELECT_RAW����CNend
* @param  pri_key        [OUT] type #struct hks_blob *��Used to save the generated private key
  CNcomment:���ڱ������ɵ�˽Կ��CNend
* @param  pub_key        [OUT] type #struct hks_blob *��Used to save the generated public key.
  CNcomment:���ڱ������ɵĹ�Կ��CNend
* @param
* @retval #0       Success.
* @retval #Other   Failure.
* @par ����:
*            @li hks_types.h��describes hks_types SDK interfaces.CNcomment:����hks_types SDK�Ľӿڡ�CNend
* @see hks_generate_asymmetric_key
* @since Hi3861_V100R001C00
*/
HKS_DLL_API_PUBLIC int32_t hks_generate_asymmetric_key(
    const struct hks_key_param *key_param, struct hks_blob *pri_key,
    struct hks_blob *pub_key);

/**
* @ingroup  iot_hks
* @brief Associate the ED25519 algorithm public key and the parameters of the public key with the alias and
  import it into HKS to save. CNcomment:��ED25519�㷨��Կ�Լ���Կ�Ĳ�����������������뵽hks�б��档CNend
*
* @par ����:
*           Associate the ED25519 algorithm public key and the parameters of the public key with the alias and
  import it into HKS to save. CNcomment:��ED25519�㷨��Կ�Լ���Կ�Ĳ�����������������뵽hks�б��档CNend
*
* @attention None
* @param  key_alias      [IN] type #const struct hks_blob *��Alias to specify to save the ED25519 public key.
  CNcomment:����ָ������ED25519��Կ�ı�����CNend
* @param  key_param      [IN] type #const struct hks_key_param *��The key parameters associated with
  the public key are saved to the HKS together with the public key, constraint condition: key_param.key_type must be
  HKS_KEY_TYPE_EDDSA_PUBLIC_KEY_ED25519
  CNcomment:�͹�Կ��������Կ�������빫Կһ�𱣴浽hks��, Լ��������key_param.key_type����Ϊ
  HKS_KEY_TYPE_EDDSA_PUBLIC_KEY_ED25519��CNend
* @param  key           [IN] type #const struct hks_blob *��Public key to be imported into hks.
  CNcomment:��Ҫ���뵽hks�еĹ�Կ��CNend
* @param
* @retval #0       Success.
* @retval #Other   Failure.
* @par ����:
*            @li hks_types.h��describes hks_types SDK interfaces.CNcomment:����hks_types SDK�Ľӿڡ�CNend
* @see hks_import_public_key
* @since Hi3861_V100R001C00
*/
HKS_DLL_API_PUBLIC int32_t hks_import_public_key(
    const struct hks_blob *key_alias,
    const struct hks_key_param *key_param, const struct hks_blob *key);

/**
* @ingroup  iot_hks
* @brief Export the public key associated with the file name saved in the HKS system.
  CNcomment:����������hksϵͳ�����ļ��������Ĺ�Կ��CNend
*
* @par ����:
*           Export the public key associated with the file name saved in the HKS system.
  CNcomment:����������hksϵͳ�����ļ��������Ĺ�Կ��CNend
*
* @attention None
* @param  key_alias    [IN] type #const struct hks_blob * Alias used to associate with the exported public key,
  constraint condition: key_alias->size <= 64.
  CNcomment:�����뵼����Կ�����ı���, Լ��������key_alias-> size <= 64��CNend
* @param  key          [OUT] type #struct hks_blob * Cache of hks public key.CNcomment:��� hks��Կ�Ļ��档CNend
* @retval #0       Success.
* @retval #Other   Failure.
* @par ����:
*            @li hks_types.h��describes hks_types SDK interfaces.CNcomment:����hks_types SDK�Ľӿڡ�CNend
* @see hks_export_public_key
* @since Hi3861_V100R001C00
*/
HKS_DLL_API_PUBLIC int32_t hks_export_public_key(
    const struct hks_blob *key_alias, struct hks_blob *key);

/**
* @ingroup  iot_hks
* @brief Delete the public key associated with the alias saved in the HKS system.
  CNcomment:ɾ��������hksϵͳ������������Ĺ�Կ��CNend
*
* @par ����:
*           Delete the public key associated with the alias saved in the HKS system.
  CNcomment:ɾ��������hksϵͳ������������Ĺ�Կ��CNend
*
* @attention None
* @param  key_alias    [IN] type #const struct hks_blob * The alias associated with the delete key,
  constraint condition: key_alias->size <= 64.
  CNcomment:��ɾ����Կ�����ı���, Լ��������key_alias-> size <= 64��CNend
* @retval #0       Success.
* @retval #Other   Failure.
* @par ����:
*            @li hks_types.h��describes hks_types SDK interfaces.CNcomment:����hks_types SDK�Ľӿڡ�CNend
* @see hks_delete_key
* @since Hi3861_V100R001C00
*/
HKS_DLL_API_PUBLIC int32_t hks_delete_key(const struct hks_blob *key_alias);

/**
* @ingroup  iot_hks
* @brief Export key attributes associated with aliases stored in the HKS system.
  CNcomment:����������hksϵͳ���������������Կ���ԡ�CNend
*
* @par ����:
*           Export key attributes associated with aliases stored in the HKS system.
  CNcomment:����������hksϵͳ���������������Կ���ԡ�CNend
*
* @attention None
* @param  key_alias    [IN] type #const struct hks_blob * Alias used to associate with the exported public key,
  constraint condition: key_alias->size <= 64.
  CNcomment:�����뵼����Կ�����ı���, Լ��������key_alias-> size <= 64��CNend
* @param  key_param    [OUT] type #struct hks_key_param * Pointer to key attribute. CNcomment:�����Կ���Ե�ָ�롣CNend
* @retval #0       Success.
* @retval #Other   Failure.
* @par ����:
*            @li hks_types.h��describes hks_types SDK interfaces.CNcomment:����hks_types SDK�Ľӿڡ�CNend
* @see hks_get_key_param
* @since Hi3861_V100R001C00
*/
HKS_DLL_API_PUBLIC int32_t hks_get_key_param(const struct hks_blob *key_alias,
    struct hks_key_param *key_param);

/**
* @ingroup  iot_hks
* @brief Determine if there is a public or secret key pair associated with the alias in hks.
  CNcomment:�ж�hks���Ƿ��������������Ĺ�Կ����Կ�ԡ�CNend
*
* @par ����:
*           Determine if there is a public or secret key pair associated with the alias in hks.
  CNcomment:�ж�hks���Ƿ��������������Ĺ�Կ����Կ�ԡ�CNend
*
* @attention None
* @param  key_alias    [IN] type #const struct hks_blob * The alias associated with the delete key,
  constraint condition: key_alias->size <= 64.
  CNcomment:��ɾ����Կ�����ı���, Լ��������key_alias-> size <= 64��CNend
* @retval #0       Success.
* @retval #Other   Failure.
* @par ����:
*            @li hks_types.h��describes hks_types SDK interfaces.CNcomment:����hks_types SDK�Ľӿڡ�CNend
* @see hks_is_key_exist
* @since Hi3861_V100R001C00
*/
HKS_DLL_API_PUBLIC int32_t hks_is_key_exist(const struct hks_blob *key_alias);

/**
* @ingroup  iot_hks
* @brief Generate a secure random number, no longer than 1024 bytes. CNcomment:���ɰ�ȫ�����,���Ȳ�����1024�ֽڡ�CNend
*
* @par ����:
*           Generate a secure random number, no longer than 1024 bytes.
  CNcomment:���ɰ�ȫ�����,���Ȳ�����1024�ֽڡ�CNend
*
* @attention None
* @param  random    [OUT] type #struct hks_blob * Used to save generated random numbers,
  random->size must be specified by the caller ,constraint condition: random->size <= 1024.
  CNcomment:���ڱ������ɵ������, random-> size�����ɵ��÷�ָ����Լ��������random-> size <= 1024��CNend
* @retval #0       Success.
* @retval #Other   Failure.
* @par ����:
*            @li hks_types.h��describes hks_types SDK interfaces.CNcomment:����hks_types SDK�Ľӿڡ�CNend
* @see hks_generate_random
* @since Hi3861_V100R001C00
*/
HKS_DLL_API_PUBLIC int32_t hks_generate_random(struct hks_blob *random);

/**
* @ingroup  iot_hks
* @brief Generate a data signature using the ED25519 private key associated with the alias in hks.
  CNcomment:ʹ��hks�������������ED25519˽Կ��������ǩ����CNend
*
* @par ����:
*           Generate a data signature using the ED25519 private key associated with the alias in hks.
  CNcomment:ʹ��hks�������������ED25519˽Կ��������ǩ����CNend
*
* @attention None
* @param  key_alias    [IN] type #const struct hks_blob * Sign using alias of secret key,
  constraint condition: key_alias->size <= 64.
  CNcomment:ǩ��ʹ����Կ�ı���, Լ��������key_alias-> size <= 64��CNend
* @param  key_param    [IN] type #const struct hks_key_param *��Attributes of the key associated with key_alias.
  CNcomment:��key_alias��������Կ�����ԡ�CNend
* @param  hash         [IN]  type #const struct hks_blob *��Data to be signed. CNcomment:��ǩ�������ݡ�CNend
* @param  signature    [OUT] type #struct hks_blob *��Output data signature, constraint condition:
  signature->size bigger & equal  64��
  CNcomment:���������ǩ��,Լ��������ǩ����С> = 64��CNend
* @retval #0       Success.
* @retval #Other   Failure.
* @par ����:
*            @li hks_types.h��describes hks_types SDK interfaces.CNcomment:����hks_types SDK�Ľӿڡ�CNend
* @see hks_asymmetric_sign
* @since Hi3861_V100R001C00
*/
HKS_DLL_API_PUBLIC int32_t hks_asymmetric_sign(
    const struct hks_blob *key_alias,
    const struct hks_key_param *key_param, const struct hks_blob *hash,
    struct hks_blob *signature);

/**
* @ingroup  iot_hks
* @brief Verify data signature using ED25519 public key. CNcomment:ʹ��ED25519��Կ��֤����ǩ����CNend
*
* @par ����:
*           Verify data signature using ED25519 public key. CNcomment:ʹ��ED25519��Կ��֤����ǩ����CNend
*
* @attention None
* @param  key        [IN] type #const struct hks_blob * The alias or ED25519 public key associated with the ED25519 key.
  CNcomment:��ED25519��Կ�����ı�����ED25519��Կ��CNend
* @param  key_param  [IN] type #const struct hks_key_param *��The attributes of the key associated with the key.
  CNcomment:��key��������Կ�����ԡ�CNend
* @param  hash       [IN]  type #const struct hks_blob *��Signed data. CNcomment:ǩ�������ݡ�CNend
* @param  signature  [IN]  type #const struct hks_blob *��Data signature,constraint condition:
  signature->size  bigger & equal  64��
  CNcomment:����ǩ��, Լ��������ǩ����С> = 64��CNend
* @retval #0       Success.
* @retval #Other   Failure.
* @par ����:
*            @li hks_types.h��describes hks_types SDK interfaces.CNcomment:����hks_types SDK�Ľӿڡ�CNend
* @see hks_asymmetric_verify
* @since Hi3861_V100R001C00
*/
HKS_DLL_API_PUBLIC int32_t hks_asymmetric_verify(const struct hks_blob *key,
    const struct hks_key_param *key_param, const struct hks_blob *hash,
    const struct hks_blob *signature);

/**
* @ingroup  iot_hks
* @brief Data encryption using AES-128-GCM algorithm. CNcomment:ʹ��AES-128-GCM�㷨�����ݼ��ܡ�CNend
*
* @par ����:
*           Data encryption using AES-128-GCM algorithm. CNcomment:ʹ��AES-128-GCM�㷨�����ݼ��ܡ�CNend
*
* @attention None
* @param  key         [IN] type #const struct hks_blob *��The key used to encrypt the plaintext.
  CNcomment:���ڼ������ĵ���Կ��CNend
* @param  key_param   [IN] type #const struct hks_key_param *��The attributes of the key associated with the key.
  constraint condition: key_param.key_type is HKS_KEY_TYPE_AES, key_param.key_len is 128 or 192 or 256;
  key_param.key_usage is HKS_KEY_USAGE_ENCRYPT, key_param.key_mode is HKS_ALG_GCM;
  key_param.key_pad is HKS_PADDING_NONE
  CNcomment:��key��������Կ������,Լ��������key_param.key_typeΪHKS_KEY_TYPE_AES��key_param.key_lenΪ128��192��256��
  key_param.key_usage��HKS_KEY_USAGE_ENCRYPT��key_param.key_mode��HKS_ALG_GCM��
  key_param.key_padΪHKS_PADDING_NONE��CNend
* @param  crypt_param      [IN]  type #const struct hks_crypt_param *��Vectors and additional data used for encryption.
  CNcomment:����ʹ�õ������͸������ݡ�CNend
* @param  plain_text       [IN]  type #const struct hks_blob *��Data plaintext��CNcomment:�������ġ�CNend
* @param  cipher_text_with_tag    [OUT]  type #struct hks_blob *��Data ciphertext CNcomment:�������ġ�CNend
* @retval #0       Success.
* @retval #Other   Failure.
* @par ����:
*            @li hks_types.h��describes hks_types SDK interfaces.CNcomment:����hks_types SDK�Ľӿڡ�CNend
* @see hks_aead_encrypt
* @since Hi3861_V100R001C00
*/
HKS_DLL_API_PUBLIC int32_t hks_aead_encrypt(const struct hks_blob *key,
    const struct hks_key_param *key_param,
    const struct hks_crypt_param *crypt_param,
    const struct hks_blob *plain_text,
    struct hks_blob *cipher_text_with_tag);

/**
* @ingroup  iot_hks
* @brief Decrypt ciphertext using AES-128-GCM algorithm. CNcomment:ʹ��AES-128-GCM�㷨�����Ľ��ܡ�CNend
*
* @par ����:
*           Decrypt ciphertext using AES-128-GCM algorithm. CNcomment:ʹ��AES-128-GCM�㷨�����Ľ��ܡ�CNend
*
* @attention None
* @param  key         [IN] type #const struct hks_blob *��Secret key for decryption. CNcomment:���ڽ��ܵ���Կ��CNend
* @param  key_param   [IN] type #const struct hks_key_param *��The attributes of the key associated with the key.
  constraint condition: key_param.key_type is HKS_KEY_TYPE_AES, key_param.key_len is 128 or 192 or 256;
  key_param.key_usage is HKS_KEY_USAGE_DECRYPT, key_param.key_mode is HKS_ALG_GCM;
  key_param.key_pad is HKS_PADDING_NONE;
  CNcomment:��key��������Կ������,Լ��������key_param.key_typeΪHKS_KEY_TYPE_AES��key_param.key_lenΪ128��192��256��
   key_param.key_usage��HKS_KEY_USAGE_DECRYPT��key_param.key_mode��HKS_ALG_GCM��
   key_param.key_padΪHKS_PADDING_NONE��CNend
* @param  crypt_param      [IN]  type #const struct hks_crypt_param *��Vector and additional data used for decryption.
  CNcomment:����ʹ�õ������͸������ݡ�CNend
* @param  plain_text       [OUT]  type #struct hks_blob *��Data plaintext��CNcomment:�������ġ�CNend
* @param  cipher_text_with_tag    [IN]  type #const struct hks_blob *��Data ciphertext CNcomment:�������ġ�CNend
* @retval #0       Success.
* @retval #Other   Failure.
* @par ����:
*            @li hks_types.h��describes hks_types SDK interfaces.CNcomment:����hks_types SDK�Ľӿڡ�CNend
* @see hks_aead_decrypt
* @since Hi3861_V100R001C00
*/
HKS_DLL_API_PUBLIC int32_t hks_aead_decrypt(const struct hks_blob *key,
    const struct hks_key_param *key_param,
    const struct hks_crypt_param *crypt_param,
    struct hks_blob *plain_text,
    const struct hks_blob *cipher_text_with_tag);

/**
* @ingroup  iot_hks
* @brief Key negotiation using X25519 algorithm. CNcomment:ʹ��X25519�㷨������ԿЭ�̡�CNend
*
* @par ����:
*           Key negotiation using X25519 algorithm. CNcomment:ʹ��X25519�㷨������ԿЭ�̡�CNend
*
* @attention None
* @param  agreed_key         [OUT] type #struct hks_blob *��Negotiation key calculated through X25519.
  CNcomment:ͨ��X25519���������Э����Կ��CNend
* @param  private_key_param  [IN]  type #const struct hks_key_param *��Local private key private_key attributes.
  constraint condition:private_key_param.key_type is HKS_KEY_TYPE_ECC_KEYPAIR_CURVE25519
  private_key_param.key_usage is HKS_KEY_USAGE_DERIVE
  private_key_param.key_mode is the same as agreement_alg
  CNcomment:����˽Կprivate_key������,Լ��������private_key_param.key_typeΪHKS_KEY_TYPE_ECC_KEYPAIR_CURVE25519
   private_key_param.key_usage��HKS_KEY_USAGE_DERIVE
   private_key_param.key_mode��Agreement_alg��ͬ��CNend
* @param  agreement_alg      [IN]  type #const uint32_t��
  Algorithm for further deriving secret key based on negotiation secret key.
  CNcomment:����Э����Կ��һ��������Կ���㷨��CNend
* @param  private_key        [IN]  type #const struct hks_blob *��Local X25519 private key��
  CNcomment:����X25519˽Կ��CNend
* @param  peer_public_key    [IN]  type #const struct hks_blob *��Peer X25519 public key
  CNcomment:�Զ�X25519��Կ��CNend
* @retval #0       Success.
* @retval #Other   Failure.
* @par ����:
*            @li hks_types.h��describes hks_types SDK interfaces.CNcomment:����hks_types SDK�Ľӿڡ�CNend
* @see hks_key_agreement
* @since Hi3861_V100R001C00
*/
HKS_DLL_API_PUBLIC int32_t hks_key_agreement(struct hks_blob *agreed_key,
    const struct hks_key_param *private_key_param,
    const uint32_t agreement_alg, const struct hks_blob *private_key,
    const struct hks_blob *peer_public_key);

/**
* @ingroup  iot_hks
* @brief Key derivation. CNcomment:��Կ������CNend
*
* @par ����:
*           Derive the key using HKD512 algorithm based on SHA512.
  The currently derived key is only used for AES encryption and decryption.
  CNcomment:ʹ�û���SHA512��HKDF�㷨������Կ����ǰ��������Կ������AES�ӽ��ܡ�CNend
*
* @attention None
* @param  derived_key   [OUT] type #struct hks_blob *��Derived key calculated through HKDF ��
  derived_key and data cannot be null, and size >= 16.
  CNcomment:ͨ��HKDF���������������Կ named_key��data����Ϊnull���Ҵ�С> = 16��CNend
* @param  key_param     [IN]  type #const struct hks_key_param *��Properties for derived keys constraint condition:
  key_param.key_type is HKS_KEY_TYPE_DERIVE��key_param.key_usage is HKS_KEY_USAGE_DERIVE
  key_param.key_mode is hks_alg_hkdf(HKS_ALG_HASH_SHA_256) or hks_alg_hkdf(HKS_ALG_HASH_SHA_512)
  key_param.key_len is 128 or 256.
  CNcomment:������Կ��Ӧ�����ԣ�Լ��������
   key_param.key_typeΪHKS_KEY_TYPE_DERIVE��key_param.key_usageΪHKS_KEY_USAGE_DERIVE
   key_param.key_modeΪhks_alg_hkdf��HKS_ALG_HASH_SHA_256����hks_alg_hkdf��HKS_ALG_HASH_SHA_512��
   key_param.key_len��128��256����CNend
* @param  kdf_key       [IN]  type #const struct hks_blob *��The base key used to derive the key.
  CNcomment:����������Կ�Ļ�����Կ��CNend
* @param  salt          [IN]  type #const struct hks_blob *��
  Derived salt value,salt.size must be greater than or equal to 16��
  CNcomment:����ʹ�õ���ֵ,salt.size������ڻ����16��CNend
* @param  label         [IN]  type #const struct hks_blob *��Derived label��constraint condition:
  lable.size must be greater than or equal to 16
  CNcomment:����ʹ�õ�label��Լ��������lable.size������ڻ����16��CNend
* @retval #0       Success.
* @retval #Other   Failure.
* @par ����:
*            @li hks_types.h��describes hks_types SDK interfaces.CNcomment:����hks_types SDK�Ľӿڡ�CNend
* @see hks_key_derivation
* @since Hi3861_V100R001C00
*/
HKS_DLL_API_PUBLIC int32_t hks_key_derivation(struct hks_blob *derived_key,
    const struct hks_key_param *key_param, const struct hks_blob *kdf_key,
    const struct hks_blob *salt, const struct hks_blob *label);

/**
* @ingroup  iot_hks
* @brief Generate message authentication code (MAC) based on SHA256 or SHA512.
  CNcomment:����SHA256��SHA512������Ϣ��֤��(MAC)��CNend
*
* @par ����:
*           Generate message authentication code (MAC) based on SHA256 or SHA512.
  CNcomment:����SHA256��SHA512������Ϣ��֤��(MAC)��CNend
*
* @attention None
* @param  key         [IN]  type #const struct hks_blob *��Keys involved in calculating HMAC,
  data cannot be null,and size > 0.
  CNcomment:�������HMAC����Կ,���ݲ���Ϊnull����С> 0��CNend
* @param  alg         [IN]  type #const uint32_t��HMAC algorithm hks_alg_hmac(HKS_ALG_HASH_SHA_256) or
  (HKS_ALG_HASH_SHA_512).
  CNcomment:HMAC�㷨, hks_alg_hmac��HKS_ALG_HASH_SHA_256���� ��HKS_ALG_HASH_SHA_512����CNend
* @param  src_data    [IN]  type #const struct hks_blob *��src data data cannot be null, and size > 0.
  CNcomment:Դ���ݣ����ݲ���Ϊnull����С> 0��CNend
* @param  output      [OUT]  type #struct hks_blob *��Generated message verification code,
  output and output->data cannot be null constraint condition:
  when alg is hks_alg_hmac(HKS_ALG_HASH_SHA_256), output->size must be greater than or
  equal to 32 when alg is hks_alg_hmac(HKS_ALG_HASH_SHA_512), output->size must be greater than or equal to 64
  CNcomment:���ɵ���Ϣ��֤��,��������->���ݲ���Ϊ��Լ��������
   ��algΪhks_alg_hmac��HKS_ALG_HASH_SHA_256��ʱ��output-> size������ڻ�
   ��algΪhks_alg_hmac��HKS_ALG_HASH_SHA_512��ʱ����32����output-> size������ڻ����64��CNend
* @retval #0       Success.
* @retval #Other   Failure.
* @par ����:
*            @li hks_types.h��describes hks_types SDK interfaces.CNcomment:����hks_types SDK�Ľӿڡ�CNend
* @see hks_hmac
* @since Hi3861_V100R001C00
*/
HKS_DLL_API_PUBLIC int32_t hks_hmac(const struct hks_blob *key,
    const uint32_t alg, const struct hks_blob *src_data,
    struct hks_blob *output);

/**
* @ingroup  iot_hks
* @brief Calculate the hash value of the data based on SHA256 or SHA512.
  CNcomment:����SHA256��SHA512�������ݵ�ɢ��ֵ��CNend
*
* @par ����:
*           Calculate the hash value of the data based on SHA256 or SHA512.
  CNcomment:����SHA256��SHA512�������ݵ�ɢ��ֵ��CNend
*
* @attention None
* @param  alg         [IN]  type #const uint32_t��Hash algorithm, Only spuuort SHA256/SHA512.
  CNcomment:��ϣ�㷨����֧��SHA256 / SHA512��CNend
* @param  src_data    [IN]  type #const struct hks_blob *��src data data cannot be null, and size > 0.
  CNcomment:Դ���ݣ����ݲ���Ϊnull����С> 0��CNend
* @param  hash        [OUT]  type #struct hks_blob *��Generated message verification code ,
  hash and hash->data cannot be null constraint condition:
  when alg is HKS_ALG_HASH_SHA_256, hash->size must be greater than or equal to 32 when alg is HKS_ALG_HASH_SHA_512,
  hash->size must be greater than or equal to 64.
  CNcomment:���ɵ���Ϣ��֤��,hash��hash-> data����ΪnullԼ����������algΪHKS_ALG_HASH_SHA_256ʱ��
  ��algΪHKS_ALG_HASH_SHA_512ʱ��hash-> size������ڻ����32��hash-> size������ڻ����64��CNend
* @retval #0       Success.
* @retval #Other   Failure.
* @par ����:
*            @li hks_types.h��describes hks_types SDK interfaces.CNcomment:����hks_types SDK�Ľӿڡ�CNend
* @see hks_hash
* @since Hi3861_V100R001C00
*/
HKS_DLL_API_PUBLIC int32_t hks_hash(const uint32_t alg,
    const struct hks_blob *src_data, struct hks_blob *hash);

/**
* @ingroup  iot_hks
* @brief Unsigned large integer modulo operation. CNcomment:�޷��Ŵ�����ģ���㡣CNend
*
* @par ����:
*           Unsigned large integer modulo operation. CNcomment:�޷��Ŵ�����ģ���㡣CNend
*
* @attention None
* @param  x    [OUT] type #struct hks_blob *��Modular result,x and x->data cannot be null, x->size >= n.size.
  CNcomment:ģ������,x��x-> data����Ϊnull��x-> size> = n.size��CNend
* @param  a    [IN]  type #const struct hks_blob *��Base data data cannot be null, size > 0.
  CNcomment:����, ���ݲ���Ϊnull����С> 0��CNend
* @param  e    [IN]  type #const struct hks_blob *��data cannot be null, size > 0.
  CNcomment:��, ���ݲ���Ϊnull����С> 0��CNend
* @param  n    [IN]  type #const struct hks_blob *��Modulus, data cannot be null, size > 0.
  CNcomment:ģ��, ���ݲ���Ϊnull����С> 0��CNend
* @retval #0       Success.
* @retval #Other   Failure.
* @par ����:
*            @li hks_types.h��describes hks_types SDK interfaces.CNcomment:����hks_types SDK�Ľӿڡ�CNend
* @see hks_bn_exp_mod
* @since Hi3861_V100R001C00
*/
HKS_DLL_API_PUBLIC int32_t hks_bn_exp_mod(struct hks_blob *x,
    const struct hks_blob *a, const struct hks_blob *e,
    const struct hks_blob *n);

/**
* @ingroup  iot_hks
* @brief Get public key alias list Interface. CNcomment:��ȡ��Կ�����б�ӿڡ�CNend
*
* @par ����:
*           Get public key alias list Interface. CNcomment:��ȡ��Կ�����б�ӿڡ�CNend
*
* @attention None
* @param  key_alias_list    [OUT] type #struct hks_blob *��struct hks_blob array, alloc and free memory by the caller.
  CNcomment:���ڴ�ű���,struct hks_blob���飬�����߷�����ͷ��ڴ档CNend
* @param  list_count        [IN] type #uint32_t *��Indicates the number of available hks_blob_t caches,
  public key alias number, alloc and free memory by the caller.
  CNcomment:��ʾ���õ�hks_blob_t��������,���÷��Ĺ�Կ�����ţ�����Ϳ����ڴ档CNend
* @retval #0       Success.
* @retval #Other   Failure.
* @par ����:
*            @li hks_types.h��describes hks_types SDK interfaces.CNcomment:����hks_types SDK�Ľӿڡ�CNend
* @see hks_get_pub_key_alias_list
* @since Hi3861_V100R001C00
*/
HKS_DLL_API_PUBLIC int32_t hks_get_pub_key_alias_list(
    struct hks_blob *key_alias_list, uint32_t *list_count);

#ifdef __cplusplus
}
#endif

#endif /* HKS_CLIENT_H */
