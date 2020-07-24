/**
 * @file hichain.h
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved. \n
 * Description: Providing HiChain SDK interfaces \n
 * Author: wudi \n
 * Create: 2019-5-26
 */

/**
 * @defgroup iot_hichain HICHAIN
 * @ingroup hichain
 */

#ifndef __HICHAIN_H__
#define __HICHAIN_H__

#include <stdint.h>

#if defined(_WINDOWS)
#ifdef DLL_EXPORT
#define DLL_API_PUBLIC __declspec(dllexport)
#else
#define DLL_API_PUBLIC __declspec(dllimport)
#endif
#else
#define DLL_API_PUBLIC __attribute__ ((visibility("default")))
#endif

#ifdef HILINK_E2E_SECURITY_CONFIG
#define _SCANTY_MEMORY_
#endif

enum hc_error {
    HC_OK = 0,
    HC_INPUT_ERROR,
    HC_INNER_ERROR,
    HC_STATE_ERROR,
    HC_SERVICE_CONFIRM_ERROR,
    HC_UNKNOW_MESSAGE,
    HC_NO_MESSAGE_TO_SEND,
    HC_REPEATED_REFERENCE,
    HC_NEED_DEPEND,
    HC_BUILD_OBJECT_FAILED,
    HC_BUILD_SEND_DATA_FAILED,
    HC_MALLOC_FAILED,
    HC_VERSION_UNSUPPORT,
    HC_LARGE_PRIME_NUMBER_LEN_UNSUPPORT,
    HC_CAL_BIGNUM_EXP_FAILED,
    HC_INTERNAL_ERROR,
    HC_IMPORT_AUTH_DATA_FAILED,
    HC_VERIFY_PROOF_FAILED,
    HC_GENERATE_PROOF_FAILED,
    HC_GENERATE_SESSION_KEY_FAILED,
    HC_ST_KEY_PAIR_FAILED,
    HC_COMPUTE_STS_SHARED_SECRET_FAILED,
    HC_COMPUTE_HKDF_FAILED,
    HC_PAKE_SESSION_KEY_ERROR,
    HC_PAKE_OBJECT_ERROR,
    HC_STS_OBJECT_ERROR,
    HC_DECRYPT_FAILED,
    HC_ENCRYPT_FAILED,
    HC_SIGN_TOO_SHORT,
    HC_VERIFY_EXCHANGE_FAILED,
    HC_SIGN_EXCHANGE_FAILED,
    HC_SAVE_LTPK_FAILED,
    HC_DELETE_LTPK_FAILED,
    HC_GET_LTPK_FAILED,
    HC_GEN_ALIAS_FAILED,
    HC_GEN_SERVICE_ID_FAILED,
    HC_GEN_RANDOM_FAILED,
    HC_UNSUPPORT,
    HC_MESSAGE_INCONSISTENCY,
    HC_OPERATION_CODE_ERROR,
    HC_MEMCPY_ERROR,
    PROTOCOL_STATE_ERROR,
    PROTOCOL_SET_STATE_ERROR,
    PROTOCOL_TIMEOUT_ERROR,
    PROTOCOL_SAHRED_SECRET_FAIL,
    PROTOCOL_HKDF_FAIL,
    PROTOCOL_SHA_FAIL,
    PROTOCOL_RAND_FAIL,
    PROTOCOL_ENCRYPT_FAIL,
    PROTOCOL_DECRYPT_FAIL,
    PROTOCOL_VERIFY_DATA_FAIL,
    PROTOCOL_KEY_ALG_FAIL,
    PROTOCOL_RESULT_ERROR,
    KEK_NOT_EXIST,
    DEK_NOT_EXIST,
    TEMP_KEY_GEN_FAILED,
};

enum hc_type {
    HC_CENTRE = 1,
    HC_ACCESSORY,
};

enum hc_user_type {
    HC_USER_TYPE_ACCESSORY = 0,
    HC_USER_TYPE_CONTROLLER = 1
};

enum hc_operation {
    INVALID_OPERATION_CODE = -1,
    NO_OPERATION_CODE = 0,
    BIND = 1,
    AUTHENTICATE,
    ADD_AUTHINFO,
    REMOVE_AUTHINFO,
    UNBIND,
    AUTH_KEY_AGREEMENT,
    REGISTER,
    SEC_CLONE_OP,
    GENERATE_KEY_PAIR = 99
};

enum hc_result {
    END_SUCCESS = 0,
    END_FAILED,
    KEY_AGREEMENT_PROCESSING,
    KEY_AGREEMENT_END,
    OPERATION_PROCESSING,
    OPERATION_END,
};

enum hc_export_type {
    EXPORT_DATA_FULL_AUTH_INFO   = 0,
    EXPORT_DATA_LITE_AUTH_INFO   = 1,
    EXPORT_DATA_SIGNED_AUTH_INFO = 2
};

#define HC_AUTH_ID_BUFF_LEN 64
#define HC_SALT_BUFF_LEN    16
#define HC_PIN_BUFF_LEN     16
#define HC_SESSION_KEY_LEN  128
#define HC_KEY_TYPE_LEN     2

#if !defined(_SCANTY_MEMORY_)
#define HC_PACKAGE_NAME_BUFF_LEN    256
#define HC_SERVICE_TYPE_BUFF_LEN    256
#else /* _SCANTY_MEMORY_ */
#define HC_PACKAGE_NAME_BUFF_LEN    16
#define HC_SERVICE_TYPE_BUFF_LEN    16
#endif /* _SCANTY_MEMORY_ */
#define HC_KEY_ALIAS_MAX_LEN        64

enum hc_trust_peer_result {
    HC_NOT_TRUST_PEER = 0,
    HC_BINDED_TRUST_PEER,
    HC_AUTHED_TRUST_PEER,
    HC_ACCESSORY_TRUST_PEER
};

typedef void *hc_handle;

struct uint8_buff {
    uint8_t *val;
    uint32_t size;
    uint32_t length;
};

struct hc_pin {
    uint32_t length;
    uint8_t pin[HC_PIN_BUFF_LEN];
};

struct hc_salt {
    uint32_t length;
    uint8_t salt[HC_SALT_BUFF_LEN];
};

struct hc_auth_id {
    uint32_t length;
    uint8_t auth_id[HC_AUTH_ID_BUFF_LEN];
};

struct hc_session_key {
    uint32_t length;
    uint8_t session_key[HC_SESSION_KEY_LEN];
};

struct hc_package_name {
    uint32_t length;
    uint8_t name[HC_PACKAGE_NAME_BUFF_LEN];
};

struct hc_service_type {
    uint32_t length;
    uint8_t type[HC_SERVICE_TYPE_BUFF_LEN];
};

struct hc_user_info {
    struct hc_auth_id auth_id;
    int32_t user_type;
};

struct operation_parameter {
    struct hc_auth_id self_auth_id;
    struct hc_auth_id peer_auth_id;
    uint32_t key_length;
};

struct key_alias {
    uint32_t length;
    uint8_t key_alias[HC_KEY_ALIAS_MAX_LEN];
};

struct session_identity {
    uint32_t session_id;
    struct hc_package_name package_name;
    struct hc_service_type service_type;
    void *context;
};

typedef void (*transmit_cb)(const struct session_identity *identity, const void *data, uint32_t length);
typedef void (*get_protocol_params_cb)(const struct session_identity *identity, int32_t operation_code,
                                       struct hc_pin *pin, struct operation_parameter *para);
typedef void (*set_session_key_func)(const struct session_identity *identity,
                                     const struct hc_session_key *session_key);
typedef void (*set_service_result_func)(const struct session_identity *identity, int32_t result);
typedef int32_t (*confirm_receive_request_func)(const struct session_identity *identity, int32_t operation_code);

struct hc_call_back {
    transmit_cb transmit;
    get_protocol_params_cb get_protocol_params;
    set_session_key_func set_session_key;
    set_service_result_func set_service_result;
    confirm_receive_request_func confirm_receive_request;
};

typedef void (*log_func)(const char *tag, const char *func_name, const char *format, ...);

struct log_func_group {
    log_func log_d;
    log_func log_i;
    log_func log_w;
    log_func log_e;
};

#ifdef __cplusplus
extern "C" {
#endif

/**
* @ingroup  iot_hichain
* @brief Register log operation callback.CNcomment:注册log操作回调函数。CNend
*
* @par 描述:
*           Register log operation callback.CNcomment:注册log操作回调函数。CNend
*
* @attention None
* @param  log      [IN] type #struct log_func_group *，log information.CNcomment:log 信息。CNend
*
* @retval None
* @par 依赖:
*            @li hichain.h：describes HiChain SDK interfaces.CNcomment:描述HiChain SDK的接口。CNend
* @see registe_log
* @since Hi3861_V100R001C00
*/
DLL_API_PUBLIC void registe_log(struct log_func_group *log);

/**
* @ingroup  iot_hichain
* @brief Get hichain instance.CNcomment:获取hichain。CNend
*
* @par 描述:
*           Get hichain instance.CNcomment:获取hichain。CNend
*
* @attention None
* @param  identity      [IN] type #const struct session_identity *，basic information of session.
  CNcomment:结构体基本信息。CNend
* @param  type          [IN] type #enum hc_type，hichain device type.CNcomment:hichain设备类型。CNend
* @param  call_back     [IN] type #const struct hc_call_back *，hichain callback functions.
  CNcomment:hichain 回调函数。CNend
*
* @retval hichain instance
* @par 依赖:
*            @li hichain.h：describes HiChain SDK interfaces.CNcomment:描述HiChain SDK的接口。CNend
* @see get_instance
* @since Hi3861_V100R001C00
*/
DLL_API_PUBLIC hc_handle get_instance(const struct session_identity *identity, enum hc_type type,
    const struct hc_call_back *call_back);

/**
* @ingroup  iot_hichain
* @brief Destroy hichain instance.CNcomment:销毁hichain。CNend
*
* @par 描述:
*           Destroy hichain instance.CNcomment:销毁hichain。CNend
*
* @attention None
* @param  handle      [IN] type #hc_handle *，hichain instance. CNcomment:HiChain SDK实例的handle。CNend
*
* @retval None
* @par 依赖:
*            @li hichain.h：describes HiChain SDK interfaces.CNcomment:描述HiChain SDK的接口。CNend
* @see destroy
* @since Hi3861_V100R001C00
*/
DLL_API_PUBLIC void destroy(hc_handle *handle);

/**
* @ingroup  iot_hichain
* @brief Set context in handle.CNcomment:设置handle信息。CNend
*
* @par 描述:
*           Set context in handle.CNcomment:设置handle信息。CNend
*
* @attention None
* @param  handle      [IN] type #hc_handle，hichain instance. CNcomment:HiChain SDK实例的handle。CNend
* @param  context     [IN] type #void *，put in an object in instance.CNcomment:示例对象。CNend
*
* @retval None
* @par 依赖:
*            @li hichain.h：describes HiChain SDK interfaces.CNcomment:描述HiChain SDK的接口。CNend
* @see set_context
* @since Hi3861_V100R001C00
*/
DLL_API_PUBLIC void set_context(hc_handle handle, void *context);

/**
* @ingroup  iot_hichain
* @brief Hichain receives message data.CNcomment:Hichain 接收数据。CNend
*
* @par 描述:
*           Hichain receives message data.CNcomment:Hichain 接收数据。CNend
*
* @attention None
* @param  handle      [IN] type #hc_handle，hichain instance. CNcomment:HiChain SDK实例的handle。CNend
* @param  data        [IN] type #struct uint8_buff *，message data.CNcomment:消息数据。CNend
*
* @retval #0       Success.
* @retval #Other   Failure.
* @par 依赖:
*            @li hichain.h：describes HiChain SDK interfaces.CNcomment:描述HiChain SDK的接口。CNend
* @see receive_data
* @since Hi3861_V100R001C00
*/
DLL_API_PUBLIC int32_t receive_data(hc_handle handle, struct uint8_buff *data);

/**
* @ingroup  iot_hichain
* @brief Hichain receives message data , data is json object.CNcomment:Hichain 接收数据，数据为json类型。CNend
*
* @par 描述:
*           Hichain receives message data , data is json object.CNcomment:Hichain 接收数据，数据为json类型。CNend
*
* @attention None
* @param  handle           [IN] type #hc_handle，hichain instance. CNcomment:HiChain SDK实例的handle。CNend
* @param  json_object      [IN] type #const void *，message data.CNcomment:消息数据。CNend
*
* @retval #0       Success.
* @retval #Other   Failure.
* @par 依赖:
*            @li hichain.h：describes HiChain SDK interfaces.CNcomment:描述HiChain SDK的接口。CNend
* @see receive_data_with_json_object
* @since Hi3861_V100R001C00
*/
DLL_API_PUBLIC int32_t receive_data_with_json_object(hc_handle handle, const void *json_object);

#ifndef _CUT_API_

/**
* @ingroup  iot_hichain
* @brief Initialize the center device.CNcomment:初始化中央设备。CNend
*
* @par 描述:
*           Initialize the center device.CNcomment:初始化中央设备。CNend
*
* @attention None
* @param  package_name     [IN] type #const struct hc_package_name *，the package name of the product.
  CNcomment:产品的包装名称。CNend
* @param  service_type     [IN] type #const struct hc_service_type *，the type of the product.CNcomment:产品类型。CNend
* @param  auth_id          [IN] type #const struct hc_auth_id *，the auth id of controller.
  CNcomment:控制器的授权ID。CNend
* @param  dek              [IN] type #struct key_alias *，
  the alias of secret key used for encryption and decryption of data.
  CNcomment:用于数据加密和解密的密钥。CNend
*
* @retval #0       Success.
* @retval #Other   Failure.
* @par 依赖:
*            @li hichain.h：describes HiChain SDK interfaces.CNcomment:描述HiChain SDK的接口。CNend
* @see init_center
* @since Hi3861_V100R001C00
*/
DLL_API_PUBLIC int32_t init_center(const struct hc_package_name *package_name,
    const struct hc_service_type *service_type, const struct hc_auth_id *auth_id, struct key_alias *dek);

/**
* @ingroup  iot_hichain
* @brief Start pake module.CNcomment:启动pake模块。CNend
*
* @par 描述:
*           Start pake module.CNcomment:启动pake模块。CNend
*
* @attention None
* @param  handle           [IN] type #hc_handle，hichain instance. CNcomment:HiChain SDK实例的handle。CNend
* @param  params           [IN] type #const struct operation_parameter *，operating parameter.CNcomment:运行参数。CNend
*
* @retval #0       Success.
* @retval #Other   Failure.
* @par 依赖:
*            @li hichain.h：describes HiChain SDK interfaces.CNcomment:描述HiChain SDK的接口。CNend
* @see start_pake
* @since Hi3861_V100R001C00
*/
DLL_API_PUBLIC int32_t start_pake(hc_handle handle, const struct operation_parameter *params);

/**
* @ingroup  iot_hichain
* @brief  Authenticate peer identity and build session key.CNcomment:验证对等身份并建立会话密钥。CNend
*
* @par 描述:
*           Authenticate peer identity and build session key.CNcomment:验证对等身份并建立会话密钥。CNend
*
* @attention None
* @param  handle           [IN] type #hc_handle，hichain instance. CNcomment:HiChain SDK实例的handle。CNend
* @param  params           [IN] type #struct operation_parameter *，operating parameter.CNcomment:运行参数。CNend
*
* @retval #0       Success.
* @retval #Other   Failure.
* @par 依赖:
*            @li hichain.h：describes HiChain SDK interfaces.CNcomment:描述HiChain SDK的接口。CNend
* @see authenticate_peer
* @since Hi3861_V100R001C00
*/
DLL_API_PUBLIC int32_t authenticate_peer(hc_handle handle, struct operation_parameter *params);

/**
* @ingroup  iot_hichain
* @brief  Delete local saved authentication.CNcomment:删除本地保存的身份验证。CNend
*
* @par 描述:
*           Delete local saved authentication.CNcomment:删除本地保存的身份验证。CNend
*
* @attention None
* @param  handle           [IN] type #hc_handle，hichain instance. CNcomment:HiChain SDK实例的handle。CNend
* @param  user_info        [IN] type #struct hc_user_info *，user to be deleted.CNcomment:要删除的用户。CNend
*
* @retval #0       Success.
* @retval #Other   Failure.
* @par 依赖:
*            @li hichain.h：describes HiChain SDK interfaces.CNcomment:描述HiChain SDK的接口。CNend
* @see delete_local_auth_info
* @since Hi3861_V100R001C00
*/
DLL_API_PUBLIC int32_t delete_local_auth_info(hc_handle handle, struct hc_user_info *user_info);

/**
* @ingroup  iot_hichain
* @brief  Import auth info of bounded trust accessory.CNcomment:导入确认的身份验证信息。CNend
*
* @par 描述:
*           Import auth info of bounded trust accessory.CNcomment:导入确认的身份验证信息。CNend
*
* @attention None
* @param  handle           [IN] type #hc_handle，hichain instance. CNcomment:HiChain SDK实例的handle。CNend
* @param  user_info        [IN] type #struct hc_user_info *，the information of Authorized user.
  CNcomment:授权用户的信息。CNend
* @param  auth_id          [IN] type #struct hc_auth_id *，the auth id of device. CNcomment:设备的认证ID。CNend
* @param  auth_info_type   [IN] type #enum hc_export_type，the export auth info type.
                                                   CNcomment: 0: full authentication data
*                                                  1: lite authentication data
*                                                  2: signed authentication data
                                                   CNcomment:导出身份验证信息类型：0：完整的身份验证数据
*                                                  1：精简认证数据
*                                                  2：签名的认证数据。CNend
* @param  auth_info       [IN] type #struct uint8_buff *，auth info of accessory. CNcomment:配件的认证信息。CNend
*
* @retval #0       Success.
* @retval #Other   Failure.
* @par 依赖:
*            @li hichain.h：describes HiChain SDK interfaces.CNcomment:描述HiChain SDK的接口。CNend
* @see import_auth_info
* @since Hi3861_V100R001C00
*/
DLL_API_PUBLIC int32_t import_auth_info(hc_handle handle, struct hc_user_info *user_info, struct hc_auth_id *auth_id,
    enum hc_export_type auth_info_type, struct uint8_buff *auth_info);

/**
* @ingroup  iot_hichain
* @brief  Share the bound device to other users.CNcomment:与其他用户共享绑定的设备。CNend
*
* @par 描述:
*           Share the bound device to other users.CNcomment:与其他用户共享绑定的设备。CNend
*
* @attention None
* @param  handle           [IN] type #hc_handle，hichain instance. CNcomment:HiChain SDK实例的handle。CNend
* @param  params           [IN] type #const struct operation_parameter *，
  operating parameter, self_auth_id: controller auth id, peer_auth_id: peer auth id.
  CNcomment:操作参数，self_auth_id：控制器身份验证ID，peer_auth_id：对等身份验证ID。CNend
* @param  auth_id          [IN] type #const struct hc_auth_id *，authorized auth id. CNcomment:授权身份验证。CNend
* @param  user_type        [IN] type #int32_t，authorized user type. 0 : ACCESSORY ; 1 : CONTROLLER.
  CNcomment:授权的用户类型。 0：配件; 1：控制器。CNend
*
* @retval #0       Success.
* @retval #Other   Failure.
* @par 依赖:
*            @li hichain.h：describes HiChain SDK interfaces.CNcomment:描述HiChain SDK的接口。CNend
* @see add_auth_info
* @since Hi3861_V100R001C00
*/
int32_t add_auth_info(hc_handle handle, const struct operation_parameter *params,
    const struct hc_auth_id *auth_id, int32_t user_type);

/**
* @ingroup  iot_hichain
* @brief  Remove user authorization of an accessory.CNcomment:删除附件的用户授权。CNend
*
* @par 描述:
*           Remove user authorization of an accessory.CNcomment:删除附件的用户授权。CNend
*
* @attention None
* @param  handle           [IN] type #hc_handle，hichain instance. CNcomment:HiChain SDK实例的handle。CNend
* @param  params           [IN] type #const struct operation_parameter *，
  operating parameter, self_auth_id: controller auth id, peer_auth_id: peer auth id.
  CNcomment:操作参数，self_auth_id：控制器身份验证ID，peer_auth_id：对等身份验证ID。CNend
* @param  auth_id          [IN] type #const struct hc_auth_id *，unauthorized auth id.
  CNcomment:未经授权的身份验证。CNend
* @param  user_type        [IN] type #int32_t，unauthorized user type. 0 : ACCESSORY ; 1 : CONTROLLER.
  CNcomment:未经授权的用户类型。 0：配件; 1：控制器。CNend
*
* @retval #0       Success.
* @retval #Other   Failure.
* @par 依赖:
*            @li hichain.h：describes HiChain SDK interfaces.CNcomment:描述HiChain SDK的接口。CNend
* @see remove_auth_info
* @since Hi3861_V100R001C00
*/
int32_t remove_auth_info(hc_handle handle, const struct operation_parameter *params,
    const struct hc_auth_id *auth_id, int32_t user_type);

/**
* @ingroup  iot_hichain
* @brief  Delete local saved authentication.CNcomment:删除本地保存的身份验证。CNend
*
* @par 描述:
*           Delete local saved authentication.CNcomment:删除本地保存的身份验证。CNend
*
* @attention None
* @param  handle           [IN] type #hc_handle，hichain instance. CNcomment:HiChain SDK实例的handle。CNend
* @param  user_info        [IN] type #struct hc_user_info *，user to be deleted. CNcomment:要删除的用户。CNend
*
* @retval #0       Success.
* @retval #Other   Failure.
* @par 依赖:
*            @li hichain.h：describes HiChain SDK interfaces.CNcomment:描述HiChain SDK的接口。CNend
* @see delete_local_auth_info
* @since Hi3861_V100R001C00
*/
int32_t delete_local_auth_info(hc_handle handle, struct hc_user_info *user_info);

/**
* @ingroup  iot_hichain
* @brief  Judge trusted peer.CNcomment:判断可信任用户。CNend
*
* @par 描述:
*           Judge trusted peer.CNcomment:判断可信任用户。CNend
*
* @attention None
* @param  handle           [IN] type #hc_handle，hichain instance. CNcomment:HiChain SDK实例的handle。CNend
* @param  user_info        [IN] type #struct hc_user_info *，Peer user information to be queried.
  CNcomment:所要查询的对端用户信息。CNend
*
* @retval #1       trusted.
* @retval #Other   untrusted.
* @par 依赖:
*            @li hichain.h：describes HiChain SDK interfaces.CNcomment:描述HiChain SDK的接口。CNend
* @see is_trust_peer
* @since Hi3861_V100R001C00
*/
DLL_API_PUBLIC int32_t is_trust_peer(hc_handle handle, struct hc_user_info *user_info);

/**
* @ingroup  iot_hichain
* @brief  List trusted peers.CNcomment:信任用户清单。CNend
*
* @par 描述:
*           List trusted peers.CNcomment:信任用户清单。CNend
*
* @attention None
* @param  handle             [IN] type #hc_handle，hichain instance. CNcomment:HiChain SDK实例的handle。CNend
* @param  trust_user_type    [IN] type #int32_t，the type of peer. 0 : ACCESSORY ; 1 : CONTROLLER.
  CNcomment:对用户的类型。 0：配件; 1：控制器。CNend
* @param  owner_auth_id      [IN] type #struct hc_auth_id *，
  input null, output binding list; input owner, output auth list;others, output null.
  CNcomment:输入null，输出绑定列表； 输入认证ID，输出其身份验证列表；其他，输出null。CNend
* @param  auth_id_list       [IN] type #struct hc_auth_id **，list to receive auth id.
  CNcomment:接收身份验证ID清单。CNend
*
* @retval number of trusted peers.
* @par 依赖:
*            @li hichain.h：describes HiChain SDK interfaces.CNcomment:描述HiChain SDK的接口。CNend
* @see list_trust_peers
* @since Hi3861_V100R001C00
*/
DLL_API_PUBLIC uint32_t list_trust_peers(hc_handle handle, int32_t trust_user_type,
    struct hc_auth_id *owner_auth_id, struct hc_auth_id **auth_id_list);
#endif /* _CUT_XXX_ */

/**
* @ingroup  iot_hichain
* @brief  Set self authId.CNcomment:设置自身认证ID。CNend
*
* @par 描述:
*           Set self authId.CNcomment:设置自身认证ID。CNend
*
* @attention None
* @param  handle           [IN] type #hc_handle，hichain instance. CNcomment:HiChain SDK实例的handle。CNend
* @param  data             [IN] type #struct uint8_buff *，the data of auth id. CNcomment:认证id数据。CNend
*
* @retval None.
* @par 依赖:
*            @li hichain.h：describes HiChain SDK interfaces.CNcomment:描述HiChain SDK的接口。CNend
* @see set_self_auth_id
* @since Hi3861_V100R001C00
*/
DLL_API_PUBLIC void set_self_auth_id(hc_handle handle, struct uint8_buff *data);

#ifdef __cplusplus
}
#endif

#endif /* __HICHAIN_H__ */
