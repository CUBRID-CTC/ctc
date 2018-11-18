/*
 * Copyright (C) 2018 CUBRID Corporation. All right reserved by CUBRID.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
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
 * ctcl.h : ctc log manager header
 *
 */

#ifndef _CTCL_H_
#define _CTCL_H_ 1

#include <pthread.h>
#include "ctc_types.h"
#include "ctcg_list.h"
#include "dbtype.h"


#define CTCL_DEFAULT_CACHE_BUFFER_SIZE            (100)
#define CTCL_DEFAULT_LOG_PAGE_SIZE                (4096)
#define CTCL_RETRY_COUNT                          (50)
#define CTCL_TRANS_LOG_LIST_COUNT                 (100)
#define CTCL_NULL_VOLDES                          (-1)
#define CTCL_NULL_OFFSET                          (-1)

#define CTCL_PAGE_ID_MAX                          INT_MAX
#define CTCL_PAGE_NULL_ID                         (-1)
#define CTCL_PAGE_NOT_EXIST                       (0)
#define CTCL_PAGE_EXST_IN_ACTIVE_LOG              (1)
#define CTCL_PAGE_EXST_IN_ARCHIVE_LOG             (2)
#define CTCL_LOGPAGEID_MAX                        (0x7fffffffffffLL)
#define CTCL_LOGPB_HEADER_PAGE_ID                 (-9)

#define CTCL_IO_DEFAULT_PAGE_SIZE                 (16 * 1024)
#define CTCL_IO_MIN_PAGE_SIZE                     (4 * 1024)
#define CTCL_IO_MAX_PAGE_SIZE                     (16 * 1024)

#define CTCL_TRAN_NULL_ID                         (-1)
#define CTCL_TRAN_NULL_INDEX                      (-1)

#define CTCL_STATUS_BUSY                          (1)
#define CTCL_STATUS_IDLE                          (0)
#define CTCL_QUERY_BUF_SIZE                       (2048)
#define CTCL_LOG_ITEM_MAX                         (1000)
#define CTCL_DELAY_CNT                            (10)
#define CTCL_NUM_REPL_FILTER                      (50)
#define CTCL_LOG_PATH_MAX                         (1024)
#define CTCL_NAME_MAX                             (255)

#define CTCL_ACTIVE_LOG_FILE_SUFFIX               "_lgat"
#define CTCL_LOGINFO_FILE_SUFFIX                  "_lginf"
#define CTCL_CUBRID_MAGIC_MAX_LENGTH              (25)
#define CTCL_CUBRID_MAGIC_LOG_ACTIVE              "CUBRID/LogActive"

#define CTCL_RETRY_ON_ERROR(error) \
    ((error == ER_LK_UNILATERALLY_ABORTED)              || \
     (error == ER_LK_OBJECT_TIMEOUT_SIMPLE_MSG)         || \
     (error == ER_LK_OBJECT_TIMEOUT_CLASS_MSG)          || \
     (error == ER_LK_OBJECT_TIMEOUT_CLASSOF_MSG)        || \
     (error == ER_LK_PAGE_TIMEOUT)                      || \
     (error == ER_PAGE_LATCH_TIMEDOUT)                  || \
     (error == ER_PAGE_LATCH_ABORTED)                   || \
     (error == ER_LK_OBJECT_DL_TIMEOUT_SIMPLE_MSG)      || \
     (error == ER_LK_OBJECT_DL_TIMEOUT_CLASS_MSG)       || \
     (error == ER_LK_OBJECT_DL_TIMEOUT_CLASSOF_MSG)     || \
     (error == ER_LK_DEADLOCK_CYCLE_DETECTED))

#define PATH_SEPARATOR_STRING       "/"
#define PATH_SEPARATOR_CHAR         '/'

#define CTC_PATH_SEPARATOR(path) \
        (path[strlen(path) - 1] == PATH_SEPARATOR_CHAR ? "" : PATH_SEPARATOR_STRING)

/* log record's statement type */
typedef enum ctcl_stmt_type
{
    CTCL_STMT_TYPE_NONE = 0, 
    CTCL_STMT_TYPE_INSERT,
    CTCL_STMT_TYPE_UPDATE,
    CTCL_STMT_TYPE_DELETE,
    CTCL_STMT_TYPE_COMMIT
} CTCL_STMT_TYPE;


/* ctc log lsa */
typedef struct ctcl_log_lsa CTCL_LOG_LSA;
struct ctcl_log_lsa
{
    SINT_64 pageid:48;
    SINT_64 offset:16;
};


/* configuration items for ctc log manager */
typedef struct ctcl_conf_items CTCL_CONF_ITEMS;
struct ctcl_conf_items
{
    int max_mem_size;
    char db_name[CTCL_NAME_MAX];
    char log_path[CTCL_LOG_PATH_MAX];
};


/* ctcl column description */
typedef struct ctcl_column CTCL_COLUMN;
struct ctcl_column
{
    int name_len;
    char name[CTCL_NAME_MAX];
    int type;
    int val_len;
    void *val;

    CTCG_LIST_NODE node;
};


/* ctcl update log info */
typedef struct ctcl_update_log_info CTCL_UPDATE_LOG_INFO;
struct ctcl_update_log_info
{
    CTCL_COLUMN key_col;
    int set_col_cnt;
    CTCG_LIST set_col_list;
};


/* ctcl insert log info */
typedef struct ctcl_insert_log_info CTCL_INSERT_LOG_INFO;
struct ctcl_insert_log_info
{
    int set_col_cnt;
    CTCG_LIST set_col_list;
};


/* ctcl delete log info */
typedef struct ctcl_delete_log_info CTCL_DELETE_LOG_INFO;
struct ctcl_delete_log_info
{
    CTCL_COLUMN key_col;
};


typedef struct ctcl_item CTCL_ITEM;
struct ctcl_item
{
    char *db_user;
    char *table_name;
    int log_type;
    int stmt_type;
    CTCL_LOG_LSA lsa;     
    CTCL_LOG_LSA target_lsa;

    DB_VALUE key; 

    CTCL_UPDATE_LOG_INFO update_log_info;
    CTCL_INSERT_LOG_INFO insert_log_info;
    CTCL_DELETE_LOG_INFO delete_log_info;

    CTCL_ITEM *next;
    CTCL_ITEM *prev;
};


/* long term transaction log item list */
typedef struct ctcl_long_trans_log_list CTCL_LONG_TRANS_LOG_LIST;
struct ctcl_long_trans_log_list
{
    int fd;                 /* long_trans_file_descriptor */
    BOOL need_to_save;      /* true when max log count meet */
    char long_tran_log_path[CTCL_LOG_PATH_MAX];

    CTCL_ITEM* head;
    CTCL_ITEM* tail;
};


typedef struct ctcl_trans_log_list CTCL_TRANS_LOG_LIST;
struct ctcl_trans_log_list
{
    int tid;                /* transaction id */
    int ref_cnt;            /* reference count of this list */
    int max_item;           /* from configuration */
    int item_num;           /* current number of log items */
    BOOL is_committed;      /* did get commit log */
    BOOL long_tx_flag;      /* is long term transaction */

    CTCL_LOG_LSA start_lsa;
    CTCL_LOG_LSA last_lsa;

    CTCL_ITEM *head;
    CTCL_ITEM *tail;

    CTCL_LONG_TRANS_LOG_LIST *long_trans_log_list;
};


/* ctcl functions */
extern int ctcl_initialize (CTCL_CONF_ITEMS *conf_items, 
                            pthread_t *la_thr_id,
                            pthread_t *tr_thr_id);

extern void ctcl_finalize(void);

/* log manager functions */
extern int ctcl_mgr_get_extracted_log_cnt (void);
extern int ctcl_mgr_lock (void);
extern int ctcl_mgr_unlock (void);
extern int ctcl_mgr_get_status_nolock (void);
extern int ctcl_mgr_set_first_tid (void);
extern int ctcl_mgr_get_first_tid_nolock (void);
extern int ctcl_mgr_get_last_tid_nolock (void);
extern int ctcl_mgr_get_cur_trans_index (void);
extern CTCL_TRANS_LOG_LIST **ctcl_mgr_get_trans_log_list (void);
extern int ctcl_mgr_get_cur_job_cnt (void);
extern int ctcl_mgr_inc_cur_job_cnt (void);
extern int ctcl_mgr_dec_cur_job_cnt (void);
extern void ctcl_mgr_set_need_stop_analyzer (void);
extern void ctcl_mgr_set_end_of_record (BOOL is_end);

extern BOOL ctcl_is_started_job(void);

static int ctcl_get_conf (void);
static void ctcl_info_final (void);

static void ctcl_remove_trans_log_list (int tid);


/* functions for long term transaction */
extern BOOL ctcl_is_long_term_transaction (int tid);
extern BOOL ctcl_need_to_save (int tid);



#endif /* _CTCL_H_ */
