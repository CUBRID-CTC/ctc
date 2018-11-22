/*
 * Copyright (C) 2018 CUBRID Corporation. All right reserved by CUBRID.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 *  1st version written by Sungryong Cho
 */


/*
 * ctcp.h : ctc protocol(CTCP) header
 *
 */

#ifndef _CTCP_H_
#define _CTCP_H_ 1


#include "ctcl.h"

/****************************************************************************
 *  CTCP Common Header: (byte)
 *           _________________________________________
 *          | OpID(1) | Param(1) | job descriptor (2) |
 *          |_________|__________|____________________|
 *          |           Session group ID (4)          |
 *          |_________________________________________|
 *          |           Protocol version (4)          |
 *          |_________________________________________|
 *          |            Length of data (4)           |
 *          |_________________________________________|
 *
 * --------------------------------------------------------------------*/

/* CTCP protocol version settings */
#define CTCP_VER_MAJOR                      (1)
#define CTCP_VER_MINOR                      (0)
#define CTCP_VER_PATCH                      (0)
#define CTCP_VER_TAG                        (0)

#define CTCP_VER_MAJOR_POS                  (24)
#define CTCP_VER_MINOR_POS                  (16)
#define CTCP_VER_PATCH_POS                  (8)

#define CTCP_VERSION                        ((CTCP_VER_MAJOR<<(CTCP_VER_MAJOR_POS))|  \
                                             (CTCP_VER_MINOR<<(CTCP_VER_MINOR_POS))|  \
                                             (CTCP_VER_PATCH<<(CTCP_VER_PATCH_POS))|  \
                                             (CTCP_VER_TAG))

#define SET_CTCP_VER_MAJOR(v,a)             (v) |= ((a)<<(CTC_VER_MAJOR_POS))
#define SET_CTCP_VER_MINOR(v,a)             (v) |= ((a)<<(CTC_VER_MINOR_POS))
#define SET_CTCP_VER_PATCH(v,a)             (v) |= ((a)<<(CTC_VER_PATCH_POS))
#define SET_CTCP_VER_TAG(v,a)               (v) |= (a)

#define IS_VALID_CTCP_VERSION(v)            (v) == (CTCP_VERSION) ? true : false

#define CTCP_SGID_NULL                      (0)

#define CTCP_HDR_OPID_LEN                   (1)
#define CTCP_HDR_OP_PARAM_LEN               (1)
#define CTCP_HDR_JOB_DESC_LEN               (2)
#define CTCP_HDR_SESSION_GROUP_ID_LEN       (4)
#define CTCP_HDR_PROTOCOL_VER_LEN               (4)
#define CTCP_HDR_DATA_LEN                   (4)
#define CTCP_HDR_LEN                        (CTCP_HDR_OPID_LEN              + \
                                             CTCP_HDR_OP_PARAM_LEN          + \
                                             CTCP_HDR_JOB_DESC_LEN          + \
                                             CTCP_HDR_SESSION_GROUP_ID_LEN  + \
                                             CTCP_HDR_PROTOCOL_VER_LEN      + \
                                             CTCP_HDR_DATA_LEN)

#define CTCP_PACKET_BLK_SIZE_K              (4)
#define CTCP_PACKET_DATA_MAX_LEN            (((1024) * CTCP_PACKET_BLK_SIZE_K)\
                                             - CTCP_HDR_LEN)

/* define CTCP common header flags for sending protocols */
#define CTCP_PACKET_PARAM_NOT_USED          (0xFF)
#define CTCP_PACKET_PARAM_NOT_FRAGMENTED    (0x00)
#define CTCP_PACKET_PARAM_FRAGMENTED        (0x01)
#define CTCP_PACKET_PARAM_FORCE             (0x02)
#define CTCP_PACKET_PARAM_NORMAL            (0x03)

#define CTCP_PACKET_FLAGS_NOT_USED          (0x00)
#define CTCP_PACKET_FLAGS_SET_( aFlags )    ( (aFlags) |= 0x01 )
#define CTCP_PACKET_FLAGS_UNSET_( aFlags )  ( (aFlags) &= (0xFE) )
#define CTCP_PACKET_FLAGS_IS_( aFlags )     \
    ( ( ((aFlags) & 0x01) == 0x01 )? ID_TRUE : ID_FALSE )

#define CTCP_PACKET_RESERVED_NOT_USED       (0x00)

#define CTCP_RESULT_OPID_VALIDATION_FACTOR  (2)


/****************************************************************************
 * CTCP(CTC Protocol) Operation 
 *
 *  Operation ID(8bit):
 *         _______________________
 *        | T|  |  |  |  |  |  |  |
 *        |__|__|__|__|__|__|__|__|
 *          |  
 *          V  
 *          Operation Type 
 *              0: Control
 *              1: Data
 *          1~7 bit: Operation identifier
 *
 ****************************************************************************/

/* ctcp operations */
typedef enum ctcp_opid
{
    /* control operations */
    CTCP_OPID_CTRL_MIN = 0x00,
    CTCP_CREATE_CONTROL_SESSION = 0x01,         /* 0x01 */
    CTCP_CREATE_CONTROL_SESSION_RESULT,         /* 0x02 */
    CTCP_DESTROY_CONTROL_SESSION,               /* 0x03 */
    CTCP_DESTROY_CONTROL_SESSION_RESULT,        /* 0x04 */
    CTCP_CREATE_JOB_SESSION,                    /* 0x05 */
    CTCP_CREATE_JOB_SESSION_RESULT,             /* 0x06 */
    CTCP_DESTROY_JOB_SESSION,                   /* 0x07 */
    CTCP_DESTROY_JOB_SESSION_RESULT,            /* 0x08 */
    CTCP_REQUEST_JOB_STATUS,                    /* 0x09 */
    CTCP_REQUEST_JOB_STATUS_RESULT,             /* 0x0a */
    CTCP_REQUEST_SERVER_STATUS,                 /* 0x0b */
    CTCP_REQUEST_SERVER_STATUS_RESULT,          /* 0x0c */
    CTCP_REGISTER_TABLE,                        /* 0x0d */
    CTCP_REGISTER_TABLE_RESULT,                 /* 0x0e */
    CTCP_UNREGISTER_TABLE,                      /* 0x0f */
    CTCP_UNREGISTER_TABLE_RESULT,               /* 0x10 */
    CTCP_SET_JOB_ATTRIBUTE,                     /* 0x11 */
    CTCP_SET_JOB_ATTRIBUTE_RESULT,              /* 0x12 */
    CTCP_OPID_CTRL_MAX,

    /* operation separator */
    CTCP_UNKNOWN_OPERATION = 0x7f,              /* 0x7f */

    /* data operations */
    CTCP_START_CAPTURE,                         /* 0x80 */
    CTCP_START_CAPTURE_RESULT,                  /* 0x81 */
    CTCP_CAPTURED_DATA_RESULT,                  /* 0x82 */
    CTCP_STOP_CAPTURE,                          /* 0x83 */
    CTCP_STOP_CAPTURE_RESULT,                   /* 0x84 */
    CTCP_OPID_DATA_MAX
} CTCP_OPID;

/* ctcp result code */
typedef enum ctcp_result_code
{
    CTCP_RC_SUCCESS = 0x00,                     /* 0x00 */             
    CTCP_RC_SUCCESS_FRAGMENTED,                 /* 0x01 */                              
    CTCP_RC_FAILED,                             /* 0x02 */                                          
    CTCP_RC_FAILED_WRONG_PACKET,                /* 0x03 */                             
    CTCP_RC_FAILED_OUT_OF_RANGE,                /* 0x04 */                             
    CTCP_RC_FAILED_UNKNOWN_OPERATION,           /* 0x05 */                        
    CTCP_RC_FAILED_INVALID_HANDLE,              /* 0x06 */
    CTCP_RC_FAILED_INSUFFICIENT_SERVER_RESOURCE,/* 0x07 */                             
    CTCP_RC_FAILED_CREATE_SESSION,              /* 0x08 */
    CTCP_RC_FAILED_SESSION_NOT_EXIST,           /* 0x09 */
    CTCP_RC_FAILED_SESSION_IS_BUSY,             /* 0x0A */
    CTCP_RC_FAILED_SESSION_CLOSE,               /* 0x0B */
    CTCP_RC_FAILED_NO_MORE_JOB_ALLOWED,         /* 0x0C */
    CTCP_RC_FAILED_INVALID_JOB,                 /* 0x0D */
    CTCP_RC_FAILED_INVALID_JOB_STATUS,          /* 0x0E */
    CTCP_RC_FAILED_INVALID_TABLE_NAME,          /* 0x0F */
    CTCP_RC_FAILED_TABLE_ALREADY_EXIST,         /* 0x10 */
    CTCP_RC_FAILED_UNREGISTERED_TABLE,          /* 0x11 */
    CTCP_RC_FAILED_JOB_ATTR_NOT_EXIST,          /* 0x12 */
    CTCP_RC_FAILED_INVALID_JOB_ATTR_VALUE,      /* 0x13 */
    CTCP_RC_FAILED_NOT_SUPPORTED_FILTER,        /* 0x14 */
    CTCP_RC_FAILED_JOB_ALREADY_STARTED,         /* 0x15 */
    CTCP_RC_FAILED_JOB_ALREADY_STOPPED,         /* 0x16 */

    CTCP_RC_MAX                          
} CTCP_RESULT_CODE;


typedef enum ctcp_connection_type 
{
    CTCP_CONNECTION_TYPE_DEFAULT = 0,
    CTCP_CONNECTION_TYPE_CTRL_ONLY
} CTCP_CONNECTION_TYPE;

typedef enum ctcp_stop_capture_cond
{
    CTCP_STOP_CAPTURE_COND_IMMEDIATELY = 0,
    CTCP_STOP_CAPTURE_COND_AFTER_TRANS
} CTCP_STOP_CAPTURE_COND;


/* common header of CTCP packet */
typedef struct ctcp_common_header CTCP_HEADER;
struct ctcp_common_header
{
    unsigned char op_id;
    char op_param;
    unsigned short job_desc;
    int session_group_id;
    int protocol_ver;
    int data_len;
};


typedef struct ctcp_log_item CTCP_LOG_ITEM;
struct ctcp_log_item
{
    char *db_user;
    char *table_name;
    int log_type;
    int item_type;
    int stmt_type;

//    DB_VALUE key; 
    void *key;

    CTCP_LOG_ITEM *next;
    CTCP_LOG_ITEM *prev;
};


/* 
 * ctc protocol functions
 *
 */
extern void ctcp_initialize (void);
extern void ctcp_finalize (void);

/* protocol header */
extern int ctcp_analyze_protocol_header (void *inlink, 
                                         unsigned char opid,
                                         CTCP_HEADER *read_header);

extern int ctcp_check_opid_range (int opid);
extern int ctcp_validate_op_id (int opid, int cmp_opid);

extern int ctcp_make_protocol_header (void *link, 
                                      unsigned char opid, 
                                      unsigned char result_code,
                                      unsigned short job_desc,
                                      int sgid,
                                      int data_len);

extern char ctcp_header_get_op_id (CTCP_HEADER *header);
extern char ctcp_header_get_op_param (CTCP_HEADER *header);
extern unsigned short ctcp_header_get_job_desc (CTCP_HEADER *header);
extern int ctcp_header_get_sgid (CTCP_HEADER *header);
extern int ctcp_header_get_data_len (CTCP_HEADER *header);

/* 
 * ctc protocol operation functions 
 *
 */
extern int ctcp_process_protocol (void *link, int sgid);


/* control session */
extern int ctcp_do_create_ctrl_session (void *link,
                                        CTCP_HEADER *header,
                                        int *sgid,
                                        int *result_code);

extern int ctcp_send_create_ctrl_session_result (void *link,
                                                    int result_code,
                                                    int sgid);

extern int ctcp_do_destroy_ctrl_session (int sgid, int *result_code);

extern int ctcp_send_destroy_ctrl_session_result (void *link, 
                                                  int result_code, 
                                                  int sgid);

/* job session */
extern int ctcp_do_create_job_session (void *link,
                                       int sgid,
                                       CTCP_HEADER *header,
                                       unsigned short *job_desc,
                                       int *result_code);

extern int ctcp_send_create_job_session_result (void *link,
                                                int result_code,
                                                unsigned short job_desc,
                                                int sgid);

extern int ctcp_do_destroy_job_session (void *link, 
                                        int sgid,
                                        CTCP_HEADER *header,
                                        unsigned short job_desc,
                                        int *result_code);

extern int ctcp_send_destroy_job_session_result (void *link,
                                                 int result_code,
                                                 unsigned short job_desc,
                                                 int sgid);

/* job status */
extern int ctcp_do_request_job_status (void *link,
                                       int sgid,
                                       CTCP_HEADER *header,
                                       unsigned short job_desc,
                                       int *status,
                                       int *result_code);

extern int ctcp_send_request_job_status_result (void *link,
                                                int result_code,
                                                unsigned short job_desc,
                                                int sgid,
                                                int status);

/* server status */
extern int ctcp_do_request_server_status (void *link,
                                          int sgid,
                                          CTCP_HEADER *header,
                                          int *status,
                                          int *result_code);

extern int ctcp_send_request_server_status_result (void *link,
                                                   int result_code,
                                                   int sgid,
                                                   int status);

/* register table */
extern int ctcp_do_register_table (void *link,
                                   int sgid,
                                   CTCP_HEADER *header,
                                   unsigned short job_desc,
                                   char *user_name,
                                   char *table_name,
                                   int *result_code);

extern int ctcp_send_register_table_result (void *link,
                                            int result_code,
                                            unsigned short job_desc,
                                            int sgid);


extern int ctcp_do_unregister_table (void *link,
                                     int sgid,
                                     CTCP_HEADER *header,
                                     unsigned short job_desc,
                                     char *user_name,
                                     char *table_name,
                                     int *result_code);

extern int ctcp_send_unregister_table_result (void *link,
                                              int result_code,
                                              unsigned short job_desc,
                                              int sgid);

/* set attribute */
extern int ctcp_do_set_job_attribute (void *link,
                                      int sgid,
                                      CTCP_HEADER *header,
                                      unsigned short job_desc,
                                      void *job_attr,
                                      int *result_code);

extern int ctcp_send_set_job_attribute_result (void *link,
                                               int result_code,
                                               unsigned short job_desc,
                                               int sgid);

/* capture */
extern int ctcp_do_start_capture (void *link,
                                  int sgid,
                                  CTCP_HEADER *header,
                                  unsigned short job_desc,
                                  int *result_code);

extern int ctcp_send_start_capture_result (void *link,
                                           int result_code,
                                           unsigned short job_desc,
                                           int sgid);

extern int ctcp_send_captured_data_result (void *link,
                                           unsigned short job_desc,
                                           int sgid,
                                           int trans_cnt,
                                           void **trans_list);

extern int ctcp_do_stop_capture (void *link,
                                 int sgid,
                                 CTCP_HEADER *header,
                                 unsigned short job_desc,
                                 int close_cond,
                                 int *result_code);

extern int ctcp_send_stop_capture_result (void *link,
                                          int result_code,
                                          unsigned short job_desc,
                                          int sgid);

#endif /* _CTCP_H_ */
