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
 */


/*
 * ctcj_def.h : ctc job manager definitions header
 *
 */

#ifndef _CTCJ_DEF_H_
#define _CTCJ_DEF_H_ 1

#include <pthread.h>

#include "ctcg_list.h"
#include "ctc_common.h"

#define CTCJ_JOB_COUNT_PER_GROUP_MAX                (10)
#define CTCJ_NULL_JOB_DESCRIPTOR                    (-1)

#define CTC_JOB_QUEUE_SIZE                          (1000)
#define JOB_QUEUE_LEFT_SPACE(a) \
                (CTC_JOB_QUEUE_SIZE - (a)) > 0 ? (CTC_JOB_QUEUE_SIZE - (a)) : 0;


/* job status */
typedef enum ctcj_job_status 
{
    CTCJ_JOB_NONE = 0,
    CTCJ_JOB_READY,
    CTCJ_JOB_PROCESSING,
    CTCJ_JOB_STOPPED,
    CTCJ_JOB_IMMEDIATE_STOPPED,
    CTCJ_JOB_CLOSING
} CTCJ_JOB_STATUS;

typedef enum ctcj_job_attr_id
{
    CTCJ_JOB_ATTR_ID_START = 0,
    CTCJ_JOB_ATTR_ID_JOB_QUEUE_SIZE,
    CTCJ_JOB_ATTR_ID_LONG_TRAN_QUEUE_SIZE,
    CTCJ_JOB_ATTR_ID_LAST
} CTCJ_JOB_ATTR_ID;

/* ctc job close condition */
typedef enum ctcj_close_cond 
{
    CTCJ_CLOSE_IMMEDIATELY = 0,
    CTCJ_CLOSE_AFTER_TRANSACTION
} CTCJ_CLOSE_COND;


/* ctc job table info */
typedef struct ctcj_job_tab_info CTCJ_JOB_TAB_INFO;
struct ctcj_job_tab_info
{
    char name[CTC_NAME_LEN];
    char user[CTC_NAME_LEN];
    /* TODO: schema info add */
    CTCG_LIST_NODE node;
};

/* ctc job info */
typedef struct ctcj_job_info CTCJ_JOB_INFO;
struct ctcj_job_info
{
    /* permanent */
    unsigned short job_desc;
    int session_group_id;       /* mother session group */
    int start_tid;              /* this job's start transaction id */
    int table_cnt;              /* the number of registered table on this job */
    CTCG_LIST table_list;       /* job table info list */
    int job_qsize;
    int long_tran_qsize;
    unsigned long *job_queue;   /* NOTE: get queue alloc size from conf */

    /* dynamic */
    int status;
    int last_processed_tid;     /* last tid sent to client */
    int enqueued_item_num;
    int dequeued_item_num;

    CTCG_LIST_NODE node;
};


/* table info being managed in ctc_job_ref_table by list */
typedef struct ctc_ref_tab_info CTC_REF_TAB_INFO;
struct ctc_ref_tab_info
{
    int ref_cnt;
    char name[CTC_NAME_LEN];
    char user[CTC_NAME_LEN];

    CTCG_LIST_NODE node;
};


/* ctc job reference table (GLOBAL)*/
typedef struct ctc_job_ref_table CTC_JOB_REF_TABLE;
struct ctc_job_ref_table
{
    /* job info */
    int total_job_cnt;          /* added job total count */
    int cur_job_cnt;            /* current processing job(started) count */
    CTCG_LIST job_info_list;    /* all jobs list */
    pthread_mutex_t job_lock;

    /* table info */
    int total_tbl_cnt;          /* total table count registered in CTC server */
    CTCG_LIST table_list;       /* all tables registered in CTC serer */
    pthread_mutex_t table_lock;
};

/* ctc job attribute */
typedef struct ctcj_job_attr CTCJ_JOB_ATTR;
struct ctcj_job_attr
{
    int id;
    int value;
};


#endif /* _CTCJ_H_ */
