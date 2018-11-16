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
 * ctcs_def.h : ctc session manager definitions header
 *
 */

#ifndef _CTCS_DEF_H_
#define _CTCS_DEF_H_ 1

#include "ctcn_link.h"
#include "ctcj_def.h"


#define CTC_JOB_SESSION_PER_GROUP                   (10)
#define CTCS_JOB_SESSION_COUNT_MAX                  CTC_JOB_SESSION_PER_GROUP 
#define CTCS_NULL_SESSION_ID                        (-1)
#define CTCS_JOB_THREAD_NULL_ID                     (-1)

#define JOB_SESSION_POSITION_0_MASK                 (1)
#define JOB_SESSION_POSITION_1_MASK                 (2)
#define JOB_SESSION_POSITION_2_MASK                 (4)
#define JOB_SESSION_POSITION_3_MASK                 (8)
#define JOB_SESSION_POSITION_4_MASK                 (16)
#define JOB_SESSION_POSITION_5_MASK                 (32)
#define JOB_SESSION_POSITION_6_MASK                 (64)
#define JOB_SESSION_POSITION_7_MASK                 (128)
#define JOB_SESSION_POSITION_8_MASK                 (256)
#define JOB_SESSION_POSITION_9_MASK                 (512)

#define JOB_SESSION_POSITION_MASK                   (1)
#define JOB_SESSION_POSITION_EMPTY_MASK             (0)
#define JOB_SESSION_POSITION_NULL                   (0x00000000)

#define SET_JOB_POSITION_FLAG(a, b)                 ((a) |= (b))
#define UNSET_JOB_POSITION_FLAG(a, b)               ((a) = ((a) & ~(b)))

#define GET_JOB_SESSION_POSITION_MASK(a) \
        (a) == 0 ? JOB_SESSION_POSITION_0_MASK : ( \
        (a) == 1 ? JOB_SESSION_POSITION_1_MASK : ( \
        (a) == 2 ? JOB_SESSION_POSITION_2_MASK : ( \
        (a) == 3 ? JOB_SESSION_POSITION_3_MASK : ( \
        (a) == 4 ? JOB_SESSION_POSITION_4_MASK : ( \
        (a) == 5 ? JOB_SESSION_POSITION_5_MASK : ( \
        (a) == 6 ? JOB_SESSION_POSITION_6_MASK : ( \
        (a) == 7 ? JOB_SESSION_POSITION_7_MASK : ( \
        (a) == 8 ? JOB_SESSION_POSITION_8_MASK : ( \
        (a) == 9 ? JOB_SESSION_POSITION_9_MASK : -1 )))))))))

#define GET_JOB_SESSION_POS_FROM_JOB_DESC(a)        ((a) - 1)
#define GET_JOB_DESC_FROM_JOB_SESSION_POS(a)        ((a) + 1)
#define CTCS_INVALID_JOB_SESSION_POSITION           (-1)


/* ctc control session status */
typedef enum ctcs_ctrl_session_status 
{
    CTCS_CTRL_SESSION_INIT = 0,
    CTCS_CTRL_SESSION_READY,     
    CTCS_CTRL_SESSION_DISCONNECTED, 
    CTCS_CTRL_SESSION_CLOSING
} CTCS_CTRL_SESSION_STATUS;

/* ctc job session status */
typedef enum ctcs_job_session_status 
{
    CTCS_JOB_SESSION_FREE = 0,       /* job_session allocated */
    CTCS_JOB_SESSION_OPEN,           /* after create */
    CTCS_JOB_SESSION_CONNECTED,      /* connected with application, ready to start capture */
    CTCS_JOB_SESSION_JOB_ADDED,      /* after table registered */
    CTCS_JOB_SESSION_DISCONNECTED,   /* stop capture or network error */
    CTCS_JOB_SESSION_CLOSING         /* destroy job session */
} CTCS_JOB_SESSION_STATUS;

/* ctc session group close condition */
typedef enum ctcs_close_cond 
{
    CTCS_CLOSE_IMMEDIATELY = 0,
    CTCS_CLOSE_AFTER_TRANSACTION
} CTCS_CLOSE_COND;

/* ctc open connection type */
typedef enum ctcs_conn_type 
{
    CTCS_CONN_TYPE_DEFAULT = 0,     /* 1 control session & 10 job_session */
    CTCS_CONN_TYPE_CTRL_ONLY = 1    /* 1 control session only */
} CTCS_CONN_TYPE;


/* ctc control session */
typedef struct ctcs_ctrl_session CTCS_CTRL_SESSION;
struct ctcs_ctrl_session
{
    CTCN_LINK *link;
    int status;
    int sgid;
    pthread_t thread;
};


/* ctc job attribute */
typedef struct ctcs_job_attr CTCS_JOB_ATTR;
struct ctcs_job_attr
{
    int id;
    int value;      /* TODO: int --> void* */
};

/* ctc job session */
typedef struct ctcs_job_session CTCS_JOB_SESSION;
struct ctcs_job_session
{
    CTCN_LINK *link;
    int status;
    int sgid;
    int job_qsize;
    int long_tran_qsize;
    pthread_t thread;       /* thread matching with job(session) by 1:1 */
    CTCJ_JOB_INFO *job;     /* job info including job's status */

    pthread_mutex_t lock;
};

/* ctc session group */
typedef struct ctcs_session_group CTCS_SESSION_GROUP;
struct ctcs_session_group
{
    int sgid;                               /* session group id */
    int added_job_cnt;                      /* the number of added job */
    unsigned short job_sessions_status_flag;/* all job sessions' avilable status */
    CTCS_CTRL_SESSION ctrl_session;          /* control session */
    CTCS_JOB_SESSION job_session[CTC_JOB_SESSION_PER_GROUP];   /* job session array */
    CTCG_LIST_NODE node;
};

/* session manager */
typedef struct ctcs_mgr CTCS_MGR;
struct ctcs_mgr
{
    int total_session_cnt;
    int sg_max_cnt;                 /* configuration item */
    int sg_cnt;                     /* current session group count */
    CTCG_LIST sg_list;             /* session group list */
    pthread_mutex_t sg_list_lock;   /* lock for sg_list */
};


#endif /* _CTCS_DEF_H_ */
