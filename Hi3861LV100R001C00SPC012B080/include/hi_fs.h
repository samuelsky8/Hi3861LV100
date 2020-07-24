/**
* @file hi_fs.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved. \n
* Description: filesystem  API.CNcomment:�ļ�ϵͳ�ӿڡ�CNend \n
* Author: Hisilicon \n
* Create: 2019-03-04
*/

/**
 * @defgroup iot_fs Filesystem
 * @ingroup osa
 */
#ifndef __HI_FS_H__
#define __HI_FS_H__

#include <hi_types.h>

typedef struct {
    hi_u32  size;
    hi_u32  next_offset;
    hi_char name[1];
}hi_file_list;


#define HI_FS_SEEK_SET                 (0)  /**< set file offset to offset */
#define HI_FS_SEEK_CUR                 (1)  /**< set file offset to current plus offset */
#define HI_FS_SEEK_END                 (2)  /**< set file offset to EOF plus offset */

#define HI_FS_O_RDONLY       00
#define HI_FS_O_WRONLY       01
#define HI_FS_O_RDWR         02

#define HI_FS_O_CREAT        0100
#define HI_FS_O_EXCL         0200
#define HI_FS_O_TRUNC        01000
#define HI_FS_O_APPEND       02000
#define HI_FS_O_PATH         010000000


#define HI_FS_O_SEARCH       HI_FS_O_PATH
#define HI_FS_O_ACCMODE      (HI_FS_O_RDONLY | HI_FS_O_WRONLY | HI_FS_O_RDWR | HI_FS_O_SEARCH)

/**
* @ingroup  iot_fs
* @brief Get filesystem error code.CNcomment:��ȡ�����롣CNend
*
* @par ����:
*           @li Returns the filesystem's most recent error code value.CNcomment:�����ļ�ϵͳ����Ĵ������ֵ��CNend
*
* @attention None
* @param  None
*
* @retval None
* @par ����:
*            @li hi_fs.h��describes the filesystem APIs.CNcomment:�ļ����������ļ�ϵͳ��ؽӿڡ�CNend
* @see hi_get_fs_error
* @since Hi3861_V100R001C00
*/
hi_s32 hi_get_fs_error(hi_void);

/**
* @ingroup  iot_fs
* @brief Initialize virtual filesystem.CNcomment:��ʼ�������ļ�ϵͳ��CNend
*
* @par ����:
*           @li Initialize virtual file system configuration related parameters.
             CNcomment:��ʼ�������ļ�ϵͳ������ز�����CNend
*           @li Mount partition to virtual file system work buffer.CNcomment:���ط����������ļ�ϵͳ������������CNend
*
* @attention None
* @param  None
*
* @retval None
* @par ����:
*            @li hi_fs.h��describes the file system APIs.CNcomment:�ļ����������ļ�ϵͳ��ؽӿڡ�CNend
* @see hi_fs_init
* @since Hi3861_V100R001C00
*/
hi_void hi_fs_init(hi_void);

/**
* @ingroup  iot_fs
* @brief  Open or create a file.CNcomment:�򿪻򴴽��ļ��� CNend
*
* @par ����:
*         Open or create a file.CNcomment:�򿪻򴴽�ָ�����ļ���CNend
*
* @attention The path length is less than 31 bytes, excluding the terminator.
             Maximum support for opening 32 files at the same time.

* @param  path      [IN] type  #const hi_char*��file name  CNcomment:Ҫ�򿪻򴴽���Ŀ���ļ���CNend
*
* @param flags      [IN] type #hi_u32,The flag combination is as follows:
*             HI_FS_O_RDONLY:Open file as read-only.CNcomment:��ֻ���ķ�ʽ���ļ���CNend
*             HI_FS_O_WRONLY:Open the file in write-only mode.CNcomment:��ֻд�ķ�ʽ���ļ���CNend
*             HI_FS_O_RDWR:Open file in read-write mode.CNcomment:�Զ�д�ķ�ʽ���ļ���CNend
*             HI_FS_O_CREAT:If the file you want to open does not exist, the file will be created automatically.
                  CNcomment:���Ҫ�򿪵��ļ����������Զ��������ļ���CNend
*             HI_FS_O_EXCL:If HI_FS_O_CREAT is also set, this command will check to see if the file exists.
                  If the file does not exist, create the file, otherwise it will cause a file error to open.
                  CNcomment:���HI_FS_O_CREATҲ�����ã���ָ���ȥ����ļ��Ƿ���ڡ�
                            �ļ����������������ļ������򽫵��´��ļ�����CNend
*             HI_FS_O_TRUNC:If the file exists and is opened in write mode, this flag will make the file length
                            clear to 0, and the data originally stored in the file will disappear.
              CNcomment:���ļ����ڲ����Կ�д��ģʽ��ʱ���˱�־�����ļ�������Ϊ0����ԭ�����ڸ��ļ�������Ҳ����ʧ��CNend
*             HI_FS_O_APPEND:When reading and writing a file, it will start moving from the end of the file, that is,
                              the written data will be added to the file in an additional way.
                   CNcomment:����д�ļ�ʱ����ļ�β��ʼ�ƶ���Ҳ������д������ݻ��Ը��ӵķ�ʽ���뵽�ļ����档CNend
*             CNcomment:���ļ�ʱ�����Դ���������ѡ�CNend
*
* @retval #>0     Success. Return file descriptor
* @retval #-1     Failure. For details,Get error code by hi_get_fs_error.
* @par ����:
@li hi_fs.h��describes the filesystem APIs.CNcomment:�ļ����������ļ�ϵͳ��ؽӿڡ�CNend
* @see  hi_open
* @since Hi3861_V100R001C00
*/
hi_s32 hi_open(const hi_char* path, hi_u32 flags);

/**
* @ingroup  iot_fs
* @brief  Close an open file.CNcomment:�ر��Ѿ��򿪵��ļ��� CNend
*
* @par ����:
*         Close an open file.CNcomment:�ر�һ���Ѿ��򿪵��ļ���CNend
*
* @attention None
* @param  fd      [IN] type  #hi_s32��file descriptor  CNcomment:��Ҫ�رյ��ļ���������CNend
*
*
* @retval #0     Success.
* @retval #-1     Failure. For details,Get error code by hi_get_fs_error.
* @par ����:
@li hi_fs.h��describes the filesystem APIs.CNcomment:�ļ����������ļ�ϵͳ��ؽӿڡ�CNend
* @see  hi_open
* @since Hi3861_V100R001C00
*/
hi_s32 hi_close(hi_s32 fd);

/**
* @ingroup  iot_fs
* @brief  Read file data of the specified size:���ļ��У���ȡָ����С���ļ����ݡ�CNend
*
* @par ����:
*         Read file data of the specified size:���ļ��У���ȡָ����С���ļ����ݡ�CNend
*
* @attention None
* @param  fd       [IN] type  #hi_s32��file descriptor  CNcomment:��Ҫ���ļ����ļ���������CNend
* @param  buf      [OUT] type #hi_char*��save read data buffer  CNcomment:��������ݻ�������CNend
* @param  len      [IN] type  #hi_u32��The number of bytes requested to be read
                              CNcomment:��Ҫ��ȡ���ݵĳ��ȡ�CNend
*
*
* @retval #>=0     Success. Returns the number of bytes read, if it returns 0, it means that the end of the file
                   has been reached or there is no data to be read.
                   CNcomment:���ض�ȡ���ֽ������������0����ʾ�ѵ����ļ�β���޿ɶ�ȡ�����ݡ�CNend
* @retval #-1     Failure. For details,Get error code by hi_get_fs_error.
* @par ����:
@li hi_fs.h��describes the filesystem APIs.CNcomment:�ļ����������ļ�ϵͳ��ؽӿڡ�CNend
* @see  hi_open
* @since Hi3861_V100R001C00
*/
hi_s32 hi_read(hi_s32 fd, hi_char* buf, hi_u32 len);

/**
* @ingroup  iot_fs
* @brief  Write file data of the specified size:���ļ��У�д��ָ����С���ļ����ݡ�CNend
*
* @par ����:
*         Write file data of the specified size:���ļ��У�д��ָ����С���ļ����ݡ�CNend
*
* @attention None
* @param  fd      [IN] type  #hi_s32��file descriptor  CNcomment:��Ҫд�ļ����ļ���������CNend
* @param  buf     [IN] type  #hi_char*��Store data that needs to be written to a file.
                             CNcomment:�����Ҫд���ļ������ݡ�CNend
* @param  len     [IN] type  #hi_u32��The number of bytes requested to be write  CNcomment:��Ҫд�����ݵĳ��ȡ�CNend
*
*
* @retval #>=0     Success. Returns the number of bytes actually written, if it returns 0, it means nothing to do.
                   reached or there is no data to be read.
                   CNcomment:����ʵ��д����ֽ������������0����ʾʲôҲû������CNend
* @retval #-1     Failure. For details,Get error code by hi_get_fs_error.
* @par ����:
@li hi_fs.h��describes the filesystem APIs.CNcomment:�ļ����������ļ�ϵͳ��ؽӿڡ�CNend
* @see  hi_open
* @since Hi3861_V100R001C00
*/
hi_s32 hi_write(hi_s32 fd, const hi_char* buf, hi_u32 len);

/**
* @ingroup  iot_fs
* @brief  Delete a file.CNcomment:ɾ��ָ�����ļ��� CNend
*
* @par ����:
*         Delete a file.CNcomment:ɾ��ָ�����ļ���CNend
*
* @attention If the number of file descriptors currently open has reached the upper limit (32),
*            then one of the file descriptors must be closed, otherwise the file will not be deleted.
*            CNcomment:�����ǰ�Ѿ��򿪵��ļ����������Ѵ����ޣ�32������
*                      ��ô����Ҫ�ر�����һ���ļ��������������ļ������ܱ�ɾ����CNend
* @attention The path length is less than 31 bytes, excluding the terminator.
*
* @param  path      [IN] type  #const hi_char*��file name  CNcomment:Ҫɾ����Ŀ���ļ���CNend
*
*
* @retval #0     Success.
* @retval #-1     Failure. For details,Get error code by hi_get_fs_error.
* @par ����:
@li hi_fs.h��describes the filesystem APIs.CNcomment:�ļ����������ļ�ϵͳ��ؽӿڡ�CNend
* @see  hi_open
* @since Hi3861_V100R001C00
*/
hi_s32 hi_unlink(const hi_char *path);

/**
* @ingroup  iot_fs
* @brief  Relocate read/write file offsets.CNcomment:���¶�λ�ļ��Ķ�/дƫ������ CNend
*
* @par ����:
*         Relocate read/write file offsets.CNcomment:���¶�λ�ļ��Ķ�/дƫ������ CNend
*
* @attention whence is one of the following:
             SEEK_SET Point the read and write position to the file header and then increase the offset amount.
                      CNcomment:����дλ��ָ���ļ�ͷ��������offset��λ������CNend
             SEEK_CUR Increase the offset by the current read and write position.
                      CNcomment:��Ŀǰ�Ķ�дλ����������offset��λ������ CNend
             SEEK_END Point the read and write position to the end of the file and then increase the offset amount,
                      only support offset values can only be negative.
                      CNcomment:����дλ��ָ���ļ�β��������offset��λ������ֻ֧��offset��ֵΪ������CNend
             When the whennce value is SEEK_CUR or SEEK_END, the parameter offet allows
                      the occurrence of a negative value.
                      CNcomment:��whence ֵΪSEEK_CUR ��SEEK_ENDʱ������offet����ֵ�ĳ��֡�CNend

* @param  fd      [IN] type  #hi_s32��file descriptor  CNcomment:��Ҫ���¶�λ��/дƫ�������ļ���������CNend
* @param  offs    [IN] type  #hi_s32��Move the number of displacements of the read/write position
*                  according to the parameter whence  CNcomment:���ݲ���whence���ƶ���дλ�õ�λ������CNend
* @param  whence      [IN] type  #hi_u32
*
* @retval #>=0    Success. Returns the current read and write position,
*                          which is how many bytes from the beginning of the file
* @retval #-1     Failure. For details,Get error code by hi_get_fs_error.
* @par ����:
@li hi_fs.h��describes the filesystem APIs.CNcomment:�ļ����������ļ�ϵͳ��ؽӿڡ�CNend
* @see  hi_open
* @since Hi3861_V100R001C00
*/
hi_s32 hi_lseek(hi_s32 fd, hi_s32 offs, hi_u32 whence);

/**
* @ingroup  iot_fs
* @brief  Relocate Enumerate all files in the directory, the file system does not support multi-level directories.
*         CNcomment:ö��Ŀ¼�µ������ļ����ļ�ϵͳ��֧�ֶ༶Ŀ¼�� CNend
*
* @par ����:
*         Relocate Enumerate all files in the directory, the file system does not support multi-level directories.
*         CNcomment:ö��Ŀ¼�µ������ļ����ļ�ϵͳ��֧�ֶ༶Ŀ¼��CNend
*
* @attention
*
* @param  buf      [OUT] type  #hi_char**,Buf stores information about all files and is released by the user.
*         CNcomment:buf�д�������ļ�����Ϣ�����û��ͷš�CNend
*
* @retval #>=0     Success.
* @retval #-1     Failure. For details,Get error code by hi_get_fs_error.
* @par ����:
@li hi_fs.h��describes the filesystem APIs.CNcomment:�ļ����������ļ�ϵͳ��ؽӿڡ�CNend
* @see  hi_open
* @since Hi3861_V100R001C00
*/
hi_s32 hi_enum_file(hi_char** buf);

/**
* @ingroup  iot_fs
* @brief  Relocate Get file size. CNcomment:��ȡָ���ļ��Ĵ�С�� CNend
*
* @par ����:
*         Relocate Get file size. CNcomment:��ȡָ���ļ��Ĵ�С��CNend
*
* @attention
*
* @param  file_name      [IN] type  #const hi_char*,file name  CNcomment:�ļ�����CNend
* @param  file_size      [OUT] type  #hi_u32*,file size. CNcomment:�����ļ��Ĵ�С��CNend
*
* @retval #>=0     Success.
* @retval #-1     Failure. For details,Get error code by hi_get_fs_error.
* @par ����:
@li hi_fs.h��describes the filesystem APIs.CNcomment:�ļ����������ļ�ϵͳ��ؽӿڡ�CNend
* @see  hi_open
* @since Hi3861_V100R001C00
*/
hi_s32 hi_stat(const hi_char *file_name, hi_u32* file_size);
#endif

