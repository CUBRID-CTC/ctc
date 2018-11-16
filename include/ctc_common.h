/*
 *  Copyright (C) 2018 CUBRID Corporation. All right reserved by CUBRID.
 *  
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *        
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *                
 */

/*
 * ctc_common.h : ctc common definitions header file
 *
 */

#ifndef _CTC_COMMON_H_
#define _CTC_COMMON_H_ 1


#define CTC_PATH_MAX                (256)
#define CTC_NAME_LEN                (128)
#define CTC_SUCCESS                 (0)
#define CTC_FAILURE                 (-1)

/* exception handling */
#define CTC_TEST_EXCEPTION(expr, label) \
    do { \
        if ((expr) != CTC_SUCCESS) { goto label; } \
    } while(0)

#define CTC_COND_EXCEPTION(cond, label) \
    do { \
        if ((cond)) { goto label; } \
    } while(0)

#define CTC_EXCEPTION(label) goto EXCEPTION_LABEL; label:

#define EXCEPTION_END \
EXCEPTION_LABEL: \
do {} while(0);

#define CTC_LISTEN_TIMEOUT          (30 * 1000 * 1000)


/* ctc server module error definition */
typedef enum ctc_err
{
    CTC_ERR_ALLOC_FAILED = 10000,               /* 10000 */
    CTC_ERR_INVALID_TYPE_FAILED,                /* 10001 */
    CTC_ERR_INIT_FAILED,                        /* 10002 */
    CTC_ERR_TIMEOUT_FAILED,                     /* 10003 */
    CTC_ERR_ADD_LIST_FAILED,                    /* 10004 */
    CTC_ERR_LOCK_FAILED,                        /* 10005 */
    CTC_ERR_UNLOCK_FAILED,                      /* 10006 */
    CTC_ERR_EXCEED_MAX_FAILED,                  /* 10007 */
    CTC_ERR_INSUFFICIENT_SYS_RESOURCE_FAILED,   /* 10008 */
    CTC_ERR_BUFFER_OVERFLOW_FAILED,             /* 10009 */
    CTC_ERR_CREATE_SESSION_GROUP_FAILED,        /* 10010 */
    CTC_ERR_DELETE_SESSION_GROUP_FAILED,        /* 10011 */
    CTC_ERR_DESTROY_SESSION_GROUP_FAILED,       /* 10012 */
    CTC_ERR_STOP_CAPTURE_FAILED,                /* 10013 */
    CTC_ERR_JOB_NOT_EXIST_FAILED,               /* 10014 */
    CTC_ERR_INVALID_JOB_FAILED,                 /* 10015 */
    CTC_ERR_INVALID_JOB_STATUS_FAILED,          /* 10016 */
    CTC_ERR_NOT_REGISTERED_TABLE_FAILED,        /* 10017 */
    CTC_ERR_ALREADY_EXIST_TABLE_FAILED,         /* 10018 */
    CTC_ERR_INVALID_TABLE_NAME_FAILED,          /* 10019 */
    CTC_ERR_INVALID_USER_NAME_FAILED,           /* 10020 */
    CTC_ERR_INVALID_ATTR_FAILED,                /* 10021 */
    CTC_ERR_INVALID_VALUE_FAILED,               /* 10022 */
    CTC_ERR_JOB_ALREADY_STARTED,                /* 10023 */
    CTC_ERR_JOB_ALREADY_STOPPED,                /* 10024 */
    CTC_ERR_NULL_LINK_FAILED,                   /* 10025 */
    CTC_ERR_LINK_RECV_FAILED,                   /* 10026 */
    CTC_ERR_LINK_SEND_FAILED,                   /* 10027 */
    CTC_ERR_FILE_NOT_EXIST_FAILED,              /* 10028 */
    CTC_ERR_PAGE_CORRUPTED_FAILED,              /* 10029 */
    CTC_ERR_BAD_PAGE_FAILED,                    /* 10030 */ 
    CTC_ERR_READ_FROM_DISK_FAILED,              /* 10031 */
    CTC_ERR_LOG_NOT_EXIST_FAILED,               /* 10032 */
    CTC_ERR_NOT_READY_FAILED                    /* 10033 */

}CTC_ERR;

/* ctc server status */
typedef enum ctc_server_status
{
    CTC_SERV_STATUS_NOT_READY = 0,
    CTC_SERV_STATUS_RUNNING,
    CTC_SERV_STATUS_CLOSING
} CTC_SERV_STATUS;

/* ctc statistics */
typedef struct ctc_statistics CTC_STATISTICS;
struct ctc_statistics
{
    int ins_stmt_cnt;
    int upd_stmt_cnt;
    int del_stmt_cnt;
};

/* ctc server information */
typedef struct ctc_server_info CTC_SERVER_INFO;
struct ctc_server_info
{
    int status;
    CTC_STATISTICS statistics;
};


#endif /* _CTC_COMMON_H_ */
