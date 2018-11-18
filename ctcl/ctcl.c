/*
 * Copyright (C) 2018 CUBRID Corporation. All rights reserved by CUBRID.
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
 * ctcl.c : ctc log manager implementation
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <pthread.h>

#include "porting.h"
#include "utility.h"
#include "environment_variable.h"
#include "message_catalog.h"
#include "log_compress.h"
#include "parser.h"
#include "object_print.h"
#include "db.h"
#include "object_accessor.h"
#include "locator_cl.h"
#include "connection_cl.h"
#include "network_interface_cl.h"
#include "transform.h"
#include "file_io.h"
#include "memory_hash.h"
#include "schema_manager.h"
#include "log_applier_sql_log.h"
#include "log_applier_plugin_config.h"
#include "log_applier_plugin.h"

#include "util_func.h"

#include "ctcl.h"
#include "ctc_common.h"


#define CTCL_LSA_COPY(lsa_ptr1, lsa_ptr2) *(lsa_ptr1) = *(lsa_ptr2)

#define CTCL_LSA_SET_NULL(lsa_ptr)                          \
    do {                                                    \
        (lsa_ptr)->pageid = CTCL_PAGE_NULL_ID;              \
        (lsa_ptr)->offset = CTCL_NULL_OFFSET;               \
    } while(0)

#define CTCL_LSA_ISNULL(lsa_ptr) ((lsa_ptr)->pageid == CTCL_PAGE_NULL_ID)

#define CTCL_LSA_EQ(lsa_ptr1, lsa_ptr2)                     \
    ((lsa_ptr1) == (lsa_ptr2) ||                          \
     ((lsa_ptr1)->pageid == (lsa_ptr2)->pageid &&         \
      (lsa_ptr1)->offset == (lsa_ptr2)->offset))

#define CTCL_LSA_LE(lsa_ptr1, lsa_ptr2) (!LSA_LT(lsa_ptr2, lsa_ptr1))
#define CTCL_LSA_GT(lsa_ptr1, lsa_ptr2) LSA_LT(lsa_ptr2, lsa_ptr1)
#define CTCL_LSA_GE(lsa_ptr1, lsa_ptr2) LSA_LE(lsa_ptr2, lsa_ptr1)


#define SSIZEOF(val) ((ssize_t) sizeof(val))

#define CTCL_LOGAREA_SIZE \
    (ctcl_Mgr.log_info.act_log.db_logpagesize - SSIZEOF(CTCL_LOG_HDRPAGE))

#define CTCL_LOG_IS_IN_ARCHIVE(pageid) \
    ((pageid) < ctcl_Mgr.log_info.act_log.log_hdr->nxarv_pageid)

#define SIZEOF_CTCL_CACHE_LOG_BUFFER(io_size) \
    (offsetof(CTCL_CACHE_BUFFER, logpage) + (io_size))

#define CTCL_LOG_READ_ADVANCE(result, length, offset, pageid, pgptr)    \
    do {                                                                \
        if ((offset)+(length) >= CTCL_LOGAREA_SIZE) {                   \
            if (((pgptr) = ctcl_get_page(++(pageid))) == NULL) {        \
                result = ER_IO_READ;                                    \
            }                                                           \
            (offset) = 0;                                               \
        }                                                               \
    } while(0)

#define CTCL_ALIGN(offset, align) \
    (((offset) + (align) - 1) & ~((align) - 1))

#define CTCL_LOG_READ_ALIGN(result, offset, pageid, log_pgptr)          \
    do {                                                                \
        (offset) = CTCL_ALIGN((offset), sizeof(double));                \
        while ((offset) >= CTCL_LOGAREA_SIZE) {                         \
            if (((log_pgptr) = ctcl_get_page(++(pageid))) == NULL) {    \
                result = CTC_ERR_READ_FROM_DISK_FAILED;                 \
            }                                                           \
            (offset) -= CTCL_LOGAREA_SIZE;                              \
            (offset) = CTCL_ALIGN((offset), sizeof(double));            \
        }                                                               \
    } while(0)

#define CTCL_LOG_READ_ADD_ALIGN(result, add, offset, pageid, log_pgptr) \
    do {                                                                \
        (offset) += (add);                                              \
        CTCL_LOG_READ_ALIGN(result, (offset), (pageid), (log_pgptr));   \
    } while(0)


#define CTCL_GET_LOG_RECORD_HEADER(log_page_p, lsa)                      \
    ((CTCL_LOG_RECORD_HEADER *)((log_page_p)->area + (lsa)->offset))


#define CTCL_SLEEP(sec, usec)                                           \
    do {                                                                \
        struct timeval sleep_time_val;                                  \
        sleep_time_val.tv_sec = (sec);                                  \
        sleep_time_val.tv_usec = (usec);                                \
        select (0, 0, 0, 0, &sleep_time_val);                           \
    } while(0);


/* log manager's status */
typedef enum ctcl_mgr_status
{
    CTCL_MGR_STATUS_INIT = 0,
    CTCL_MGR_STATUS_PROCESSING,
    CTCL_MGR_STATUS_STOPPED
} CTCL_MGR_STATUS;

/* log analyzer's status */
typedef enum ctcl_log_analyzer_status
{
    CTCL_LOG_ANALYZER_STATUS_NONE = 0,
    CTCL_LOG_ANALYZER_STATUS_STARTED,
    CTCL_LOG_ANALYZER_STATUS_STOPPED
} CTCL_LOG_ANALYZER_STATUS;


/* log record's statement type */
/*
typedef enum ctcl_stmt_type
{
    CTCL_STMT_TYPE_NONE = 0,
    CTCL_STMT_TYPE_INSERT,
    CTCL_STMT_TYPE_UPDATE,
    CTCL_STMT_TYPE_DELETE,
    CTCL_STMT_TYPE_COMMIT
} CTCL_STMT_TYPE;
*/

typedef enum ctcl_log_rectype
{
    CTCL_LOG_SMALLER_LOGREC_TYPE = 0,     
    CTCL_LOG_CLIENT_NAME = 1,             
    CTCL_LOG_UNDOREDO_DATA = 2,   
    CTCL_LOG_UNDO_DATA = 3,              
    CTCL_LOG_REDO_DATA = 4,             
    CTCL_LOG_DBEXTERN_REDO_DATA = 5,      
    CTCL_LOG_POSTPONE = 6,               
    CTCL_LOG_RUN_POSTPONE = 7,         
    CTCL_LOG_COMPENSATE = 8,              
    CTCL_LOG_LCOMPENSATE = 9,           
    CTCL_LOG_CLIENT_USER_UNDO_DATA = 10, 
    CTCL_LOG_CLIENT_USER_POSTPONE_DATA = 11,     
    CTCL_LOG_RUN_NEXT_CLIENT_UNDO = 12,   
    CTCL_LOG_RUN_NEXT_CLIENT_POSTPONE = 13,  
    CTCL_LOG_WILL_COMMIT = 14,           
    CTCL_LOG_COMMIT_WITH_POSTPONE = 15, 
    CTCL_LOG_COMMIT_WITH_CLIENT_USER_LOOSE_ENDS = 16,     
    CTCL_LOG_COMMIT = 17,         /* A commit record                 */
    CTCL_LOG_COMMIT_TOPOPE_WITH_POSTPONE = 18,   
    CTCL_LOG_COMMIT_TOPOPE_WITH_CLIENT_USER_LOOSE_ENDS = 19,
    CTCL_LOG_COMMIT_TOPOPE = 20, 
    CTCL_LOG_ABORT_WITH_CLIENT_USER_LOOSE_ENDS = 21,      /* Aborting client loose ends      */
    CTCL_LOG_ABORT = 22,          /* An abort record                 */
    CTCL_LOG_ABORT_TOPOPE_WITH_CLIENT_USER_LOOSE_ENDS = 23,
    CTCL_LOG_ABORT_TOPOPE = 24,  
    CTCL_LOG_START_CHKPT = 25,            /* Start a checkpoint              */
    CTCL_LOG_END_CHKPT = 26,              /* Checkpoint information          */
    CTCL_LOG_SAVEPOINT = 27,              /* A user savepoint record         */
    CTCL_LOG_2PC_PREPARE = 28,            /* A prepare to commit record      */
    CTCL_LOG_2PC_START = 29,            
    CTCL_LOG_2PC_COMMIT_DECISION = 30,   
    CTCL_LOG_2PC_ABORT_DECISION = 31,  
    CTCL_LOG_2PC_COMMIT_INFORM_PARTICPS = 32, 
    CTCL_LOG_2PC_ABORT_INFORM_PARTICPS = 33,     
    CTCL_LOG_2PC_RECV_ACK = 34,   
    CTCL_LOG_END_OF_LOG = 35,             /* End of log                      */
    CTCL_LOG_DUMMY_HEAD_POSTPONE = 36,    /* A dummy log record. No-op       */
    CTCL_LOG_DUMMY_CRASH_RECOVERY = 37,   
    CTCL_LOG_DUMMY_FILLPAGE_FORARCHIVE = 38,      
    CTCL_LOG_REPLICATION_DATA = 39,       /* Replicaion log for insert, delete or update */
    CTCL_LOG_REPLICATION_SCHEMA = 40,    
    CTCL_LOG_UNLOCK_COMMIT = 41,
    CTCL_LOG_UNLOCK_ABORT = 42,   
    CTCL_LOG_DIFF_UNDOREDO_DATA = 43,     /* diff undo redo data             */
    CTCL_LOG_DUMMY_HA_SERVER_STATE = 44,  /* HA server state */
    CTCL_LOG_DUMMY_OVF_RECORD = 45,       /* indicator of the first part of an overflow record */
    CTCL_LOG_LARGER_LOGREC_TYPE   /* A higher bound for checks       */
} CTCL_LOG_RECTYPE;


typedef SINT_64 CTCL_LOG_PAGEID;
typedef SINT_32 CTCL_LOG_PHY_PAGEID;
typedef INT_16 CTCL_PAGE_LENGTH;
typedef struct ctcl_log_hdrpage CTCL_LOG_HDRPAGE;
typedef struct ctcl_thread CTCL_THREAD;
typedef struct ctcl_args CTCL_ARGS;
typedef struct ctc_log_item CTC_LOG_ITEM;
typedef struct ctcl_cache_buffer CTCL_CACHE_BUFFER;
typedef struct ctcl_cache_buffer_area CTCL_CACHE_BUFFER_AREA;
typedef struct ctcl_repl_filter CTCL_REPL_FILTER;
typedef struct ctcl_act_log CTCL_ACT_LOG;
typedef struct ctcl_commit CTCL_COMMIT;
typedef struct ctcl_ovf_first_part CTCL_OVF_FIRST_PART;
typedef struct ctcl_ovf_rest_parts CTCL_OVF_REST_PARTS;
typedef struct ctcl_ovf_page_list CTCL_OVF_PAGE_LIST;


typedef struct ctcl_log_donetime CTCL_LOG_DONETIME;
struct ctcl_log_donetime
{
    SINT_64 at_time;
};


/* ctc log analyzer thread */
struct ctcl_thread
{
    BOOL need_stop;
    int status;
    pthread_t id;
    pthread_cond_t cond;
    pthread_mutex_t lock;
};

/* arguments for log analyzer thread */
struct ctcl_args
{
    int max_mem_size;
    char database_name[CTCL_NAME_MAX];
    char log_path[CTCL_LOG_PATH_MAX];
    char local_db_name[CTCL_NAME_MAX];
};


typedef union ctcl_db_data CTCL_DB_DATA;
union ctcl_db_data
{
    int i;
    short sh;
    int64_t bi;
    float f;
    double d;
//    MYSQL_TIME t;
    void *p;
};


typedef struct ctcl_db_value CTCL_DB_VALUE;
struct ctcl_db_value
{
    unsigned short db_type;
    BOOL is_null;
    void *buf;                    /* data pointer */
    CTCL_DB_DATA data;
    unsigned long size;
    BOOL need_clear;
};

/* ctc log item */
struct ctc_log_item
{
    char *db_user;
    char *table_name;
    int stmt_type;
    int attr_num;

    CTCL_DB_VALUE key;

    CTC_LOG_ITEM *prev;
    CTC_LOG_ITEM *next;
};

struct ctcl_log_hdrpage
{
    CTCL_LOG_PAGEID logical_pageid;
    CTCL_PAGE_LENGTH offset;
    short dummy1;
    int dummy2;
};

typedef struct ctcl_log_page CTCL_LOG_PAGE;
struct ctcl_log_page
{
    CTCL_LOG_HDRPAGE hdr;
    char area[1];
};

struct ctcl_cache_buffer
{
    int fix_count;
    BOOL recently_free;
    BOOL in_archive;

    CTCL_LOG_PAGEID pageid; /* Logical page of the log */
    CTCL_LOG_PHY_PAGEID phy_pageid;

    CTCL_LOG_PAGE logpage;
};

struct ctcl_cache_buffer_area
{
    CTCL_CACHE_BUFFER *buffer_area;
    CTCL_CACHE_BUFFER_AREA *next;
};

typedef struct ctcl_cache_pb CTCL_CACHE_PB;
struct ctcl_cache_pb
{
    int num_buffers;
    MHT_TABLE *hash_table;
    CTCL_CACHE_BUFFER **log_buffer; /* buffer pool */
    CTCL_CACHE_BUFFER_AREA *buffer_area;
};

typedef struct ctcl_log_replication CTCL_LOG_REPLICATION;
struct ctcl_log_replication
{
    CTCL_LOG_LSA lsa;
    int length;
    int rcvindex;
};


typedef struct ctcl_log_rec_header CTCL_LOG_RECORD_HEADER;
struct ctcl_log_rec_header
{
    CTCL_LOG_LSA prev_tranlsa;
    CTCL_LOG_LSA back_lsa;
    CTCL_LOG_LSA forw_lsa;
    int trid;
    CTCL_LOG_RECTYPE type;
};


struct ctcl_act_log
{
    char path[PATH_MAX];
    int log_vdes;
    CTCL_LOG_PAGE *hdr_page;
    struct log_header *log_hdr;
    int db_iopagesize;
    int db_logpagesize;
};


struct ctcl_commit
{
    CTCL_COMMIT *next;
    CTCL_COMMIT *prev;

    int type;                     /* LOG_COMMIT or LOG_UNLOCK_COMMIT */
    int tranid;
    CTCL_LOG_LSA log_lsa;
    time_t log_record_time;       /* commit time at the server side */
};



/* ctcl log info structure */
typedef struct ctcl_info CTCL_INFO;
struct ctcl_info 
{
    BOOL is_end_of_record;
    char log_path[CTCL_LOG_PATH_MAX];
    char loginf_path[CTCL_LOG_PATH_MAX];

    CTCL_ACT_LOG act_log;

    CTCL_LOG_LSA final_lsa;              /* last processed log lsa */

    CTCL_LOG_LSA committed_lsa;          /* last committed commit log lsa */
    CTCL_LOG_LSA last_committed_lsa;    

    CTCL_LOG_LSA committed_rep_lsa;    
    CTCL_LOG_LSA last_committed_rep_lsa;    


    CTCL_TRANS_LOG_LIST **trans_log_list;
    int trans_cnt;                  /* the number of transactions */
    int cur_trans;                  /* the index of the current transaction */
    time_t log_record_time;         /* time of the last commit log record */

    CTCL_COMMIT *commit_head;       /* queue list head */
    CTCL_COMMIT *commit_tail;       /* queue list tail */

    char *log_data;
    char *rec_type;
    LOG_ZIP *undo_unzip_ptr;
    LOG_ZIP *redo_unzip_ptr;

    int apply_state;
    int max_mem_size;

    int cache_buffer_size;
    CTCL_CACHE_PB *cache_pb;

    CTCL_LOG_LSA append_lsa;             /* append lsa of active log header */
    CTCL_LOG_LSA eof_lsa;                /* eof lsa of active log header */
    CTCL_LOG_LSA required_lsa;           /* start lsa of the first transaction to be applied */

    unsigned long commit_counter;
};

/* ctc log manager */
typedef struct ctcl_mgr CTCL_MGR;
struct ctcl_mgr
{
    BOOL need_stop_analyzer;
    int status;             /* log manager's status */
    int first_tid;          /* first job started transaction id */
    int last_tid;           /* last read transaction id */
    int cur_job_cnt;        /* started job count */
    int read_log_cnt;
    pthread_mutex_t lock;

    char src_db_name[CTCL_NAME_MAX];

    CTCL_ARGS thr_args;
    CTCL_INFO log_info;
    pthread_t analyzer_thr;  
    pthread_t trans_remover_thr;  
//    CTCL_THREAD analyzer_thr;   
//    CTC_JOB_REF_TABLE *job_ref_tbl;   /* job reference table */
};

struct ctcl_ovf_first_part
{
    VPID next_vpid;
    int length;
    char data[1];                 /* Really more than one */
};


struct ctcl_ovf_rest_parts
{
    VPID next_vpid;
    char data[1];                 /* Really more than one */
};

/* use overflow page list to reduce memory copy overhead. */
struct ctcl_ovf_page_list
{
    char *rec_type;               /* record type */
    char *data;                   /* overflow page data: header + real data */
    int length;                   /* total length of data */
    CTCL_OVF_PAGE_LIST *next;       /* next page */
};


typedef struct ctcl_ha_apply_info CTCL_HA_APPLY_INFO;
struct ctcl_ha_apply_info
{
    char db_name[256];
    char copied_log_path[4096];
    CTCL_LOG_LSA committed_lsa;        /* last committed commit log lsa */
    CTCL_LOG_LSA committed_rep_lsa;    /* last committed replication log lsa */
    CTCL_LOG_LSA append_lsa;           /* append lsa of active log header */
    CTCL_LOG_LSA eof_lsa;              /* eof lsa of active log header */
    CTCL_LOG_LSA final_lsa;            /* last processed log lsa */
    CTCL_LOG_LSA required_lsa;         /* start lsa of the first transaction to be applied */
};



/* Global variable for LA */
CTCL_MGR ctcl_Mgr;


/* static functions */
static void *ctcl_trans_remover_thr_func (void);
static void *ctcl_log_analyzer_thr_func (void *ctcl_args);
static int ctcl_start_log_analyzer (CTCL_ARGS *ctcl_args);
static void ctcl_stop_log_analyzer (void);

static CTCL_LOG_PHY_PAGEID ctcl_get_log_phypageid (CTCL_LOG_PAGEID lpageid);

static void ctcl_thr_args_init (CTCL_CONF_ITEMS *conf_items, 
                                CTCL_ARGS *args);

static int ctcl_read_log_page_from_disk (char *vname, 
                                         int vdes, 
                                         void *io_pgptr, 
                                         CTCL_LOG_PHY_PAGEID pageid, 
                                         int pagesize);

static int ctcl_read_log_page_from_disk_retry (char *vname, 
                                               int vdes, 
                                               void *io_pgptr, 
                                               CTCL_LOG_PHY_PAGEID pageid, 
                                               int pagesize, 
                                               int retry);

static int ctcl_log_fetch (CTCL_LOG_PAGEID pageid, 
                           CTCL_CACHE_BUFFER *cache_buffer);

static int ctcl_expand_cache_log_buffer (CTCL_CACHE_PB *cache_pb, 
                                         int slb_cnt, 
                                         int slb_size);

static CTCL_CACHE_BUFFER *ctcl_cache_buffer_replace (CTCL_CACHE_PB *cache_pb, 
                                                     CTCL_LOG_PAGEID pageid, 
                                                     int io_pagesize, 
                                                     int buffer_size);

static CTCL_CACHE_BUFFER *ctcl_get_page_buffer (CTCL_LOG_PAGEID pageid);
static CTCL_LOG_PAGE *ctcl_get_page (CTCL_LOG_PAGEID pageid);

static void ctcl_release_page_buffer (CTCL_LOG_PAGEID pageid);
static void ctcl_release_all_page_buffers (CTCL_LOG_PAGEID except_pageid);

static void ctcl_decache_page_buffer (CTCL_CACHE_BUFFER * cache_buffer);

static void ctcl_decache_page_buffer_range (CTCL_LOG_PAGEID from, 
                                            CTCL_LOG_PAGEID to);

static void ctcl_find_lowest_required_lsa (CTCL_LOG_LSA *required_lsa);

static CTCL_CACHE_PB *ctcl_init_cache_pb (void);

static int ctcl_init_cache_log_buffer (CTCL_CACHE_PB *cache_pb,
                                       int slb_cnt,
                                       int slb_size);

static int ctcl_get_last_ha_applied_info (void);

static int ctcl_get_ha_apply_info (const char *log_path, 
                                   const char *prefix_name, 
                                   CTCL_HA_APPLY_INFO *ha_apply_info);

static int ctcl_fetch_log_hdr (CTCL_ACT_LOG *act_log);

static void ctcl_adjust_lsa (CTCL_ACT_LOG *act_log);

static int ctcl_find_log_pagesize (CTCL_ACT_LOG *act_log, 
                                   const char *logpath, 
                                   const char *dbname);

static int ctcl_info_pre_alloc (void);

static int ctcl_check_page_exist (CTCL_LOG_PAGEID pageid);
static int ctcl_init_trans_log_list (BOOL is_need_realloc);

static BOOL ctcl_is_trans_log_list_empty (void);

static CTCL_TRANS_LOG_LIST *ctcl_get_trans_log_list_set_tid (int tid);
static CTCL_TRANS_LOG_LIST *ctcl_find_trans_log_list (int tid);

static void ctcl_log_copy_fromlog (char *rec_type, 
                                   char *area, 
                                   int length, 
                                   CTCL_LOG_PAGEID log_pageid, 
                                   CTCL_PAGE_LENGTH log_offset, 
                                   CTCL_LOG_PAGE *log_pgptr);

static CTCL_ITEM *ctcl_new_item (CTCL_LOG_LSA *lsa, CTCL_LOG_LSA *target_lsa);

static void ctcl_add_log_item_list (CTCL_TRANS_LOG_LIST *trans_log_list, 
                                    CTCL_ITEM *item);

static CTCL_ITEM *ctcl_make_item (CTCL_LOG_PAGE *log_pg, 
                                  int log_type, 
                                  int tid, 
                                  CTCL_LOG_LSA *lsa);

static void ctcl_unlink_log_item (CTCL_TRANS_LOG_LIST *trans_log_list, 
                                  CTCL_ITEM *item);

static void ctcl_free_log_item (CTCL_TRANS_LOG_LIST *trans_log_list, 
                                CTCL_ITEM *item);

static void ctcl_free_all_log_items_except_head (CTCL_TRANS_LOG_LIST *trans_log_list);

static void ctcl_free_all_log_items (CTCL_TRANS_LOG_LIST *trans_log_list);

static void ctcl_clear_trans_log_list (CTCL_TRANS_LOG_LIST *trans_log_list);

static int ctcl_insert_log_item (CTCL_LOG_PAGE *log_pg, 
                                 int log_type, 
                                 int tid,
                                 CTCL_LOG_LSA *lsa);

static int ctcl_add_unlock_commit_log (int tid, CTCL_LOG_LSA *lsa);

static int ctcl_add_abort_log (int tid, CTCL_LOG_LSA *lsa);

static time_t ctcl_retrieve_eot_time (CTCL_LOG_PAGE *pg, CTCL_LOG_LSA *lsa);

static int ctcl_set_commit_log (int tid, int type, CTCL_LOG_LSA *lsa, time_t rec_time);

static char *ctcl_get_zipped_data (char *undo_data, 
                                   int undo_length, 
                                   BOOL is_diff, 
                                   BOOL is_undo_zip, 
                                   BOOL is_overflow, 
                                   char **rec_type, 
                                   char **data, 
                                   int *length);

static void ctcl_item_update_log_info_init (CTCL_ITEM *item);
static void ctcl_item_insert_log_info_init (CTCL_ITEM *item);
static void ctcl_item_delete_log_info_init (CTCL_ITEM *item);

static int ctcl_get_update_current (OR_BUF *buf, 
                                    SM_CLASS *sm_class, 
                                    int bound_bit_flag, 
                                    DB_OTMPL *def, 
                                    CTCL_ITEM *item, 
                                    int offset_size);

static int ctcl_get_insert_current (OR_BUF *buf, 
                                    SM_CLASS *sm_class, 
                                    int bound_bit_flag, 
                                    DB_OTMPL *def, 
                                    CTCL_ITEM *item, 
                                    int offset_size);

static int ctcl_get_undoredo_diff (CTCL_LOG_PAGE **pgptr, 
                                   CTCL_LOG_PAGEID *pageid, 
                                   CTCL_PAGE_LENGTH *offset, 
                                   BOOL *is_undo_zip, 
                                   char **undo_data, 
                                   int *undo_length);

static int ctcl_get_log_data (CTCL_LOG_RECORD_HEADER *lrec, 
                              CTCL_LOG_LSA *lsa, 
                              CTCL_LOG_PAGE *pgptr, 
                              unsigned int match_rcvindex, 
                              unsigned int *rcvindex, 
                              void **logs, 
                              INT_16 *old_type, 
                              char **old_data, 
                              int *old_length, 
                              char **rec_type, 
                              char **data, 
                              int *d_length);

static int ctcl_get_overflow_recdes (CTCL_LOG_RECORD_HEADER *lrec, 
                                     void *logs, 
                                     char **area, 
                                     int *length, 
                                     unsigned int rcvindex);

static int ctcl_get_next_update_log (CTCL_LOG_RECORD_HEADER *prev_lrec, 
                                     CTCL_LOG_PAGE *pgptr, 
                                     void **logs, 
                                     char **rec_type, 
                                     char **data, 
                                     int *d_length);

static int ctcl_get_relocation_recdes (CTCL_LOG_RECORD_HEADER *lrec, 
                                       CTCL_LOG_PAGE *pgptr, 
                                       unsigned int match_rcvindex, 
                                       void **logs, 
                                       char **rec_type, 
                                       char **data, 
                                       int *d_length);

static int ctcl_get_recdes (CTCL_LOG_LSA *lsa, 
                            CTCL_LOG_PAGE *pg, 
                            RECDES *old_recdes, 
                            RECDES *recdes, 
                            unsigned int *rcvindex, 
                            char *log_data, 
                            char *rec_type, 
                            BOOL *is_overflow);

static int ctcl_apply_commit_list (CTCL_LOG_LSA *lsa, 
                                   CTCL_LOG_PAGEID final_pageid);

static void ctcl_free_log_items_by_tranid (int tid);
static void ctcl_free_long_trans_log_list (CTCL_TRANS_LOG_LIST *list);

static int ctcl_log_record_process (CTCL_LOG_RECORD_HEADER *lrec, 
                                    CTCL_LOG_LSA *final, 
                                    CTCL_LOG_PAGE *pg_ptr);

static int ctcl_process_update_log (CTCL_ITEM *item);
static int ctcl_process_insert_log (CTCL_ITEM *item);
static int ctcl_process_delete_log (CTCL_ITEM *item);

static int ctcl_disk_to_obj (MOBJ classobj, 
                             RECDES *record, 
                             DB_OTMPL *def, 
                             CTCL_ITEM *item);

static void ctcl_info_init (const char *log_path, 
                            const int max_mem_size);

static void ctcl_shutdown (void);

static CTCL_ITEM *ctcl_get_next_log_item (CTCL_ITEM *item, 
                                          BOOL is_long_trans, 
                                          CTCL_LOG_LSA *last_lsa);

static CTCL_ITEM *ctcl_get_next_log_item_from_list (CTCL_ITEM *item);
static CTCL_ITEM *ctcl_get_next_log_item_from_log (CTCL_ITEM *item, 
                                                   CTCL_LOG_LSA *last_lsa);


/* inline functions */
static inline void ctcl_mgr_inc_last_tid(void);
static inline void ctcl_mgr_dec_last_tid(void);

static inline void ctcl_trans_log_set_committed (CTCL_TRANS_LOG_LIST *trans_log_list);
static inline int ctcl_get_trans_ref_cnt (CTCL_TRANS_LOG_LIST *trans_log_list);
static inline void ctcl_inc_trans_ref_cnt (CTCL_TRANS_LOG_LIST *trans_log_list);
static inline void ctcl_dec_trans_ref_cnt (CTCL_TRANS_LOG_LIST *trans_log_list);


extern int ctcl_initialize (CTCL_CONF_ITEMS *conf_items, 
                            pthread_t *la_thr_id, 
                            pthread_t *tr_thr_id)
{
    int result;
    int stage = 0;

    pthread_mutex_init(&ctcl_Mgr.lock, NULL);

    ctcl_Mgr.need_stop_analyzer = CTC_FALSE;

    ctcl_Mgr.status = CTCL_MGR_STATUS_INIT;
    ctcl_Mgr.first_tid = CTCL_TRAN_NULL_ID;
    ctcl_Mgr.last_tid = CTCL_TRAN_NULL_ID;
    ctcl_Mgr.cur_job_cnt = 0;
    ctcl_Mgr.read_log_cnt = 0;

    memset (ctcl_Mgr.src_db_name, 0, CTCL_NAME_MAX);

    strncpy (ctcl_Mgr.src_db_name, 
             conf_items->db_name, 
             strlen (conf_items->db_name));

    /* init log analyzer thread arguments */
    ctcl_thr_args_init (conf_items, &ctcl_Mgr.thr_args);

    /* init LZO */
    CTC_COND_EXCEPTION (lzo_init () != LZO_E_OK, err_lzo_init_failed_label);

    /* init log info */
    ctcl_info_init (conf_items->log_path, conf_items->max_mem_size);

    /* init cache buffer */
    ctcl_Mgr.log_info.cache_pb = ctcl_init_cache_pb ();
    CTC_COND_EXCEPTION (ctcl_Mgr.log_info.cache_pb == NULL,
                        err_alloc_failed_label);

    /* get log header info. page size. start_page id, etc */
    result = ctcl_find_log_pagesize (&ctcl_Mgr.log_info.act_log, 
                                     ctcl_Mgr.log_info.log_path, 
                                     ctcl_Mgr.src_db_name);

    CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                        err_find_log_pagesize_failed_label);

    result = ctcl_init_cache_log_buffer (ctcl_Mgr.log_info.cache_pb, 
                                         ctcl_Mgr.log_info.cache_buffer_size, 
                                         SIZEOF_CTCL_CACHE_LOG_BUFFER(
                                             ctcl_Mgr.log_info.act_log.db_logpagesize));

    CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                        err_init_cache_log_buffer_failed_label);
    
    sprintf (ctcl_Mgr.log_info.loginf_path, "%s%s%s%s", 
             ctcl_Mgr.log_info.log_path, 
             CTC_PATH_SEPARATOR (ctcl_Mgr.log_info.log_path), 
             ctcl_Mgr.src_db_name,
             CTCL_LOGINFO_FILE_SUFFIX);

    AU_DISABLE_PASSWORDS ();
    db_set_client_type (DB_CLIENT_TYPE_CTC);

    if (db_login ("DBA", NULL) != CTC_SUCCESS)
    {
        printf ("db login failed\n");
    }

    if (db_restart ("cub_ctc", 1, ctcl_Mgr.src_db_name) != CTC_SUCCESS)
    {
        printf ("db restart failed\n");
    }

    //db_Connect_status = DB_CONNECTION_STATUS_CONNECTED;

    //result = ctcl_get_last_ha_applied_info ();

    //db_shutdown ();


    /* initialize final_lsa */
    /*
    CTCL_LSA_COPY (&ctcl_Mgr.log_info.committed_lsa, 
                   &ctcl_Mgr.log_info.required_lsa);
                   */

    /* start log analyzer */
    result = ctcl_start_log_analyzer (&ctcl_Mgr.thr_args);
    *la_thr_id = ctcl_Mgr.analyzer_thr;
    *tr_thr_id = ctcl_Mgr.trans_remover_thr;

    ctcl_Mgr.status = CTCL_MGR_STATUS_PROCESSING;

    CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                        err_start_log_analyzer_thr_failed_label);
    stage = 2;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_log_info_init_failed_label)
    {
        /* error info set from sub-function */
    }
    CTC_EXCEPTION (err_lzo_init_failed_label)
    {
        fprintf (stdout, "\n ERROR: lzo init failed \n\t");
        fflush (stdout);

        result = CTC_FAILURE;
    }
    CTC_EXCEPTION (err_alloc_failed_label)
    {
        result = CTC_ERR_ALLOC_FAILED;
    }
    CTC_EXCEPTION (err_find_log_pagesize_failed_label)
    {
        /* error info set from sub-function */
    }
    CTC_EXCEPTION (err_init_cache_log_buffer_failed_label)
    {
        fprintf (stdout, "\n ERROR: cache log buffer init failed \n\t");
        fflush (stdout);

        /* error info set from sub-function */
    }
    CTC_EXCEPTION (err_start_log_analyzer_thr_failed_label)
    {
        /* error info set from sub-function */
    }
    EXCEPTION_END;

    return result;
}


extern int ctcl_mgr_get_extracted_log_cnt (void)
{
    return ctcl_Mgr.read_log_cnt;
}


extern int ctcl_mgr_lock (void)
{
    int result;

    CTC_TEST_EXCEPTION (pthread_mutex_lock (&ctcl_Mgr.lock),
                        err_mutex_lock_failed_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_mutex_lock_failed_label)
    {    
        /* EINVAL, EDEADLK or EAGAIN */
        result = CTC_ERR_LOCK_FAILED;
    }    
    EXCEPTION_END;

    return result;
}


extern int ctcl_mgr_unlock (void)
{
    int result;

    CTC_TEST_EXCEPTION (pthread_mutex_unlock (&ctcl_Mgr.lock),
                        err_mutex_unlock_failed_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_mutex_unlock_failed_label)
    {    
        /* EINVAL, EDEADLK or EAGAIN */
        result = CTC_ERR_UNLOCK_FAILED;
    }    
    EXCEPTION_END;

    return result;
}


static int ctcl_get_last_ha_applied_info (void)
{
    int result;
    CTCL_ACT_LOG *act_log;
    CTCL_HA_APPLY_INFO apply_info;

    act_log = &ctcl_Mgr.log_info.act_log;

    result = ctcl_get_ha_apply_info (ctcl_Mgr.log_info.log_path, 
                                     act_log->log_hdr->prefix_name, 
                                     &apply_info);

    if (result == CTC_SUCCESS)
    {
        CTCL_LSA_COPY (&ctcl_Mgr.log_info.committed_lsa, 
                       &apply_info.committed_lsa);

        CTCL_LSA_COPY (&ctcl_Mgr.log_info.committed_rep_lsa, 
                       &apply_info.committed_rep_lsa);

        CTCL_LSA_COPY (&ctcl_Mgr.log_info.append_lsa, 
                       &apply_info.append_lsa);

        CTCL_LSA_COPY (&ctcl_Mgr.log_info.eof_lsa, 
                       &apply_info.eof_lsa);

        CTCL_LSA_COPY (&ctcl_Mgr.log_info.final_lsa, 
                       &apply_info.final_lsa);

        CTCL_LSA_COPY (&ctcl_Mgr.log_info.required_lsa, 
                       &apply_info.required_lsa);

        if (CTCL_LSA_ISNULL (&ctcl_Mgr.log_info.required_lsa))
        {
            /* DEBUG */
            printf ("required_lsa cannot be NULL");
            return CTC_FAILURE;
        }
    }

    if (CTCL_LSA_ISNULL (&ctcl_Mgr.log_info.required_lsa))
    {
        CTCL_LSA_COPY (&ctcl_Mgr.log_info.required_lsa, 
                       (CTCL_LOG_LSA *)&act_log->log_hdr->eof_lsa);
    }

    if (CTCL_LSA_ISNULL (&ctcl_Mgr.log_info.committed_lsa))
    {
        CTCL_LSA_COPY (&ctcl_Mgr.log_info.committed_lsa, 
                       &ctcl_Mgr.log_info.required_lsa);
    }

    if (CTCL_LSA_ISNULL (&ctcl_Mgr.log_info.committed_rep_lsa))
    {
        CTCL_LSA_COPY (&ctcl_Mgr.log_info.committed_rep_lsa, 
                       &ctcl_Mgr.log_info.required_lsa);
    }

    if (CTCL_LSA_ISNULL (&ctcl_Mgr.log_info.final_lsa))
    {
        CTCL_LSA_COPY (&ctcl_Mgr.log_info.final_lsa, 
                       &ctcl_Mgr.log_info.required_lsa);
    }

    CTCL_LSA_COPY (&ctcl_Mgr.log_info.last_committed_lsa, 
                   &ctcl_Mgr.log_info.committed_lsa);

    CTCL_LSA_COPY (&ctcl_Mgr.log_info.last_committed_rep_lsa, 
                   &ctcl_Mgr.log_info.committed_rep_lsa);

    return result;
}


static int ctcl_get_ha_apply_info (const char *log_path, 
                                   const char *prefix_name, 
                                   CTCL_HA_APPLY_INFO *ha_apply_info)
{
#define CTCL_IN_VALUE_COUNT       2
#define CTCL_OUT_VALUE_COUNT      12

    int i;
    int result;
    int col_cnt;
    int in_value_idx;
    int out_value_idx;
    char query_buf[CTCL_QUERY_BUF_SIZE];
    char db_name[DB_MAX_IDENTIFIER_LENGTH + 1];
    DB_VALUE in_value[CTCL_IN_VALUE_COUNT];
    DB_VALUE out_value[CTCL_OUT_VALUE_COUNT];
    DB_DATETIME *db_time;
    DB_QUERY_ERROR query_error;
    DB_QUERY_RESULT *query_result = NULL;

    /* initialize language parameters  */
    /*
    if (lang_init () != CTC_SUCCESS)
    {
        //CTC_COND_EXCEPTION (CTC_TRUE, err_lang_init_failed_label);
    }
    */
/*
    if (lang_set_charset_lang (LANG_NAME_DEFAULT) != CTC_SUCCESS)
    {    
        //CTC_COND_EXCEPTION (CTC_TRUE, err_lang_set_failed_label);
    }*/
/*
    if (db_find_class ("db_ha_apply_info") == NULL)
    {
        printf ("ERROR: cannot find db_ha_apply_info table.\n");
        return CTC_FAILURE;
    }
*/
    snprintf (query_buf, 
              sizeof (query_buf), 
              "SELECT "	                  
              "   committed_lsa_pageid, "	/* 1 */
              "   committed_lsa_offset, "	/* 2 */
              "   committed_rep_pageid, "	/* 3 */
              "   committed_rep_offset, "	/* 4 */
              "   append_lsa_pageid, "	        /* 5 */
              "   append_lsa_offset, "	        /* 6 */
              "   eof_lsa_pageid, "	        /* 7 */
              "   eof_lsa_offset, "	        /* 8 */
              "   final_lsa_pageid, "	        /* 9 */
              "   final_lsa_offset, "	        /* 10 */
              "   required_lsa_pageid, "	/* 11 */
              "   required_lsa_offset "	        /* 12 */
              " FROM db_ha_apply_info "
              " WHERE db_name = \'%s\' ;",
              prefix_name);

    in_value_idx = 0;
/*
    db_make_varchar (&in_value[in_value_idx++], 255,
                     (char *)prefix_name, strlen (prefix_name),
                     LANG_SYS_CODESET, LANG_SYS_COLLATION);

    db_make_varchar (&in_value[in_value_idx++], 4096,
                     (char *)log_path, strlen (log_path),
                     LANG_SYS_CODESET, LANG_SYS_COLLATION);

    assert_release (in_value_idx == CTCL_IN_VALUE_COUNT);
*/
    /*
    result = db_execute_with_values (query_buf, 
                                     &query_result, 
                                     &query_error, 
                                     in_value_idx, 
                                     &in_value[0]);
                                     */
    result = db_execute_with_values (query_buf, 
                                     &query_result, 
                                     &query_error, 
                                     in_value_idx, 
                                     NULL);
    if (result > 0)
    {
        int pos;

        pos = db_query_first_tuple (query_result);

        switch (pos)
        {
            case DB_CURSOR_SUCCESS:

                col_cnt = db_query_column_count (query_result);
                assert_release (col_cnt == CTCL_OUT_VALUE_COUNT);

                result = db_query_get_tuple_valuelist (query_result, 
                                                       CTCL_OUT_VALUE_COUNT, 
                                                       out_value);

                if (result != CTC_SUCCESS)
                {
                    break;
                }

                out_value_idx = 0;

                /* committed_lsa */
                if (DB_IS_NULL (&out_value[out_value_idx]) || 
                    DB_IS_NULL (&out_value[out_value_idx + 1]))
                {
                    LSA_SET_NULL (&ha_apply_info->committed_lsa);
                    out_value_idx += 2;
                }
                else
                {
                    ha_apply_info->committed_lsa.pageid =
                        DB_GET_BIGINT (&out_value[out_value_idx++]);
                    ha_apply_info->committed_lsa.offset =
                        DB_GET_INTEGER (&out_value[out_value_idx++]);
                }

                /* committed_rep_lsa */
                if (DB_IS_NULL (&out_value[out_value_idx]) || 
                    DB_IS_NULL (&out_value[out_value_idx + 1]))
                {
                    LSA_SET_NULL (&ha_apply_info->committed_rep_lsa);
                    out_value_idx += 2;
                }
                else
                {
                    ha_apply_info->committed_rep_lsa.pageid =
                        DB_GET_BIGINT (&out_value[out_value_idx++]);
                    ha_apply_info->committed_rep_lsa.offset =
                        DB_GET_INTEGER (&out_value[out_value_idx++]);
                }

                /* append_lsa */
                ha_apply_info->append_lsa.pageid =
                    DB_GET_BIGINT (&out_value[out_value_idx++]);
                ha_apply_info->append_lsa.offset =
                    DB_GET_INTEGER (&out_value[out_value_idx++]);

                /* eof_lsa */
                ha_apply_info->eof_lsa.pageid =
                    DB_GET_BIGINT (&out_value[out_value_idx++]);
                ha_apply_info->eof_lsa.offset =
                    DB_GET_INTEGER (&out_value[out_value_idx++]);

                /* final_lsa */
                if (DB_IS_NULL (&out_value[out_value_idx]) || 
                    DB_IS_NULL (&out_value[out_value_idx + 1]))
                {
                    LSA_SET_NULL (&ha_apply_info->final_lsa);
                    out_value_idx += 2;
                }
                else
                {
                    ha_apply_info->final_lsa.pageid =
                        DB_GET_BIGINT (&out_value[out_value_idx++]);
                    ha_apply_info->final_lsa.offset =
                        DB_GET_INTEGER (&out_value[out_value_idx++]);
                }

                /* required_lsa */
                if (DB_IS_NULL (&out_value[out_value_idx]) || 
                    DB_IS_NULL (&out_value[out_value_idx + 1]))
                {
                    LSA_SET_NULL (&ha_apply_info->required_lsa);
                    out_value_idx += 2;
                }
                else
                {
                    ha_apply_info->required_lsa.pageid =
                        DB_GET_BIGINT (&out_value[out_value_idx++]);
                    ha_apply_info->required_lsa.offset =
                        DB_GET_INTEGER (&out_value[out_value_idx++]);
                }

                assert_release (out_value_idx == CTCL_OUT_VALUE_COUNT);

                for (i = 0; i < CTCL_OUT_VALUE_COUNT; i++)
                {
                    db_value_clear (&out_value[i]);
                }
                break;

            case DB_CURSOR_END:
            case DB_CURSOR_ERROR:
            default:
                result = CTC_FAILURE;
                break;
        }
    }
    else
    {
        result = CTC_FAILURE;
    }

    db_query_end (query_result);

    for (i = 0; i < in_value_idx; i++)
    {
        db_value_clear (&in_value[i]);
    }

    return result;

#undef CTCL_IN_VALUE_COUNT
#undef CTCL_OUT_VALUE_COUNT
}

static void ctcl_thr_args_init (CTCL_CONF_ITEMS *conf_items, CTCL_ARGS *args)
{
    assert (conf_items != NULL);
    assert (args != NULL);

    args->max_mem_size = conf_items->max_mem_size;

    memset (args->database_name, 0, CTCL_NAME_MAX);
    memset (args->log_path, 0, CTCL_LOG_PATH_MAX);
    memset (args->local_db_name, 0, CTCL_NAME_MAX);

    strncpy (args->database_name, 
             conf_items->db_name, 
             strlen (conf_items->db_name));

    strncpy (args->log_path, 
             conf_items->log_path, 
             strlen (conf_items->log_path));

    strncpy (args->local_db_name, 
             conf_items->db_name, 
             strlen (conf_items->db_name));

    return;
}


static void ctcl_info_init (const char *log_path, const int max_mem_size)
{
    memset (&ctcl_Mgr.log_info, 0, sizeof (ctcl_Mgr.log_info));

    strncpy (ctcl_Mgr.log_info.log_path, log_path, CTCL_LOG_PATH_MAX - 1);

    ctcl_Mgr.log_info.act_log.db_iopagesize = CTCL_DEFAULT_CACHE_BUFFER_SIZE;
    ctcl_Mgr.log_info.act_log.db_logpagesize = CTCL_DEFAULT_LOG_PAGE_SIZE;
    ctcl_Mgr.log_info.act_log.log_vdes = CTCL_NULL_VOLDES;

    CTCL_LSA_SET_NULL (&ctcl_Mgr.log_info.final_lsa);
    CTCL_LSA_SET_NULL (&ctcl_Mgr.log_info.committed_lsa);

    ctcl_Mgr.log_info.trans_log_list = NULL;

    ctcl_Mgr.log_info.trans_cnt = 0;
    ctcl_Mgr.log_info.cur_trans = 0;

    ctcl_Mgr.log_info.commit_head = NULL;
    ctcl_Mgr.log_info.commit_tail = NULL;

    ctcl_Mgr.log_info.log_data = NULL;
    ctcl_Mgr.log_info.rec_type = NULL;
    ctcl_Mgr.log_info.undo_unzip_ptr = NULL;
    ctcl_Mgr.log_info.redo_unzip_ptr = NULL;

    ctcl_Mgr.log_info.apply_state = 0;
    ctcl_Mgr.log_info.max_mem_size = max_mem_size;
    ctcl_Mgr.log_info.cache_buffer_size = CTCL_DEFAULT_CACHE_BUFFER_SIZE;

    CTCL_LSA_SET_NULL (&ctcl_Mgr.log_info.append_lsa);
    CTCL_LSA_SET_NULL (&ctcl_Mgr.log_info.eof_lsa);
    CTCL_LSA_SET_NULL (&ctcl_Mgr.log_info.required_lsa);

    ctcl_Mgr.log_info.commit_counter = 0;

    return;
}


/*
 * ctcl_init_cache_pb() - initialize the cache page buffer area
 *   return: the allocated pointer to a cache page buffer
 *
 * Note:
 */
static CTCL_CACHE_PB *ctcl_init_cache_pb (void)
{
    CTCL_CACHE_PB *cache_pb;

    cache_pb = (CTCL_CACHE_PB *)malloc (sizeof (CTCL_CACHE_PB));

    if (cache_pb == NULL)
    {
        fprintf (stdout, "\n ERROR: malloc failed in ctcl_init_cache_pb () \n\t");
        fflush (stdout);

        return NULL;
    }

    cache_pb->hash_table = NULL;
    cache_pb->log_buffer = NULL;
    cache_pb->num_buffers = 0;
    cache_pb->buffer_area = NULL;

    return (cache_pb);
}


extern void ctcl_finalize(void)
{
    ctcl_stop_log_analyzer ();

    ctcl_Mgr.status = CTCL_MGR_STATUS_STOPPED;
    ctcl_Mgr.cur_job_cnt = 0;
}


extern int ctcl_mgr_get_status_nolock (void)
{
    return ctcl_Mgr.status;
}


extern int ctcl_mgr_set_first_tid (void)
{
    int result; 

    CTC_COND_EXCEPTION (ctcl_mgr_lock (), err_lock_failed_label);

    CTC_COND_EXCEPTION (ctcl_Mgr.status != CTCL_MGR_STATUS_PROCESSING,
                        err_ctcl_mgr_not_ready_label);

    if (ctcl_Mgr.first_tid == CTCL_TRAN_NULL_ID)
    {
        ctcl_Mgr.first_tid = ctcl_Mgr.last_tid + 1;
        ctcl_Mgr.cur_job_cnt++;
    }
    else
    {
        if (ctcl_Mgr.cur_job_cnt > 0)
        {
            /* current processing job already exists */
        }
        else
        {
            ctcl_Mgr.first_tid = CTCL_TRAN_NULL_ID;
        }
    }

    CTC_COND_EXCEPTION (ctcl_mgr_unlock (), err_unlock_failed_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_lock_failed_label)
    {
        result = CTC_ERR_LOCK_FAILED;
    }
    CTC_EXCEPTION (err_ctcl_mgr_not_ready_label)
    {
        /* DEBUG for thread start timing */
        printf ("err_ctcl_mgr_not_ready_label\n");
        result = CTC_ERR_NOT_READY_FAILED;
    }
    CTC_EXCEPTION (err_unlock_failed_label)
    {
        result = CTC_ERR_UNLOCK_FAILED;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcl_mgr_get_first_tid_nolock (void)
{
    return ctcl_Mgr.first_tid;
}


extern int ctcl_mgr_dec_cur_job_cnt (void)
{
    int result; 

    CTC_TEST_EXCEPTION (ctcl_mgr_lock (), err_lock_failed_label);

    if (ctcl_Mgr.cur_job_cnt > 0)
    {
        ctcl_Mgr.cur_job_cnt--;

        if (ctcl_Mgr.cur_job_cnt == 0)
        {
            ctcl_Mgr.first_tid = CTCL_TRAN_NULL_ID;
        }
        else
        {
            /* current processing job exists, so maintain first_tid */
        }
    }
    else
    {
        /* critical system error occurred, but ignore */
    }

    CTC_TEST_EXCEPTION (ctcl_mgr_unlock (), err_unlock_failed_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_lock_failed_label)
    {
        result = CTC_ERR_LOCK_FAILED;
    }
    CTC_EXCEPTION (err_unlock_failed_label)
    {
        result = CTC_ERR_UNLOCK_FAILED;
    }
    EXCEPTION_END;

    return result;
}

extern int ctcl_mgr_get_last_tid_nolock (void)
{
    return ctcl_Mgr.last_tid;
}

extern int ctcl_mgr_get_cur_trans_index (void)
{
    return ctcl_Mgr.log_info.cur_trans;
}

extern int ctcl_mgr_get_cur_job_cnt (void)
{
    return ctcl_Mgr.cur_job_cnt;
}


extern int ctcl_mgr_inc_cur_job_cnt (void)
{
    int result;

    CTC_TEST_EXCEPTION (ctcl_mgr_lock (), err_lock_failed_label);

    ctcl_Mgr.cur_job_cnt++;

    CTC_TEST_EXCEPTION (ctcl_mgr_unlock (), err_unlock_failed_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_lock_failed_label)
    {
        result = CTC_ERR_LOCK_FAILED;
    }
    CTC_EXCEPTION (err_unlock_failed_label)
    {
        result = CTC_ERR_UNLOCK_FAILED;
    }
    EXCEPTION_END;

    return result;
}


extern CTCL_TRANS_LOG_LIST **ctcl_mgr_get_trans_log_list (void)
{
    return ctcl_Mgr.log_info.trans_log_list;
}


/*
 * Description : modified from la_log_phypageid()
 *               get the physical page id from the logical pageid
 *
 */
static CTCL_LOG_PHY_PAGEID ctcl_get_log_phypageid (CTCL_LOG_PAGEID lpageid)
{
    CTCL_LOG_PAGEID tmp_pageid;
    CTCL_LOG_PHY_PAGEID phy_pageid;

    if (lpageid == CTCL_LOGPB_HEADER_PAGE_ID)
    {
        phy_pageid = 0;
    }
    else
    {
        tmp_pageid = lpageid - ctcl_Mgr.log_info.act_log.log_hdr->fpageid;

        if (tmp_pageid >= ctcl_Mgr.log_info.act_log.log_hdr->npages)
        {
            tmp_pageid %= ctcl_Mgr.log_info.act_log.log_hdr->npages;
        }
        else if (tmp_pageid < 0)
        {
            tmp_pageid = ctcl_Mgr.log_info.act_log.log_hdr->npages -
                ((-tmp_pageid) % ctcl_Mgr.log_info.act_log.log_hdr->npages);
        }

        tmp_pageid++;

        if (tmp_pageid > ctcl_Mgr.log_info.act_log.log_hdr->npages)
        {
            tmp_pageid %= ctcl_Mgr.log_info.act_log.log_hdr->npages;
        }

        assert (tmp_pageid <= CTCL_PAGE_ID_MAX);
        phy_pageid = (CTCL_LOG_PHY_PAGEID) tmp_pageid;
    }

    return phy_pageid;
}


static int ctcl_read_log_page_from_disk (char *vname, 
                                         int vdes, 
                                         void *io_pgptr, 
                                         LOG_PHY_PAGEID pageid, 
                                         int pagesize)
{
    return ctcl_read_log_page_from_disk_retry (vname, 
                                               vdes, 
                                               io_pgptr, 
                                               pageid, 
                                               pagesize, 
                                               -1);
}


/*
 * Description : read a page from the disk with max retries
 *
 *     vname(in): the volume name of the target file
 *     vdes(in): the volume descriptor of the target file
 *     io_pgptr(out): start pointer to be read
 *     pageid(in): page id to read
 *     pagesize(in): page size to wrea
 *     retries(in): read retry count
 *
 * Note:
 *     reads a predefined size of page from the disk
 */
static int ctcl_read_log_page_from_disk_retry (char *vname, 
                                               int vdes, 
                                               void *io_pgptr, 
                                               LOG_PHY_PAGEID pageid, 
                                               int pagesize, 
                                               int retry)
{
    int result;
    int nbytes;
    int remain_bytes = pagesize;
    off64_t offset = ((off64_t) pagesize) * ((off64_t) pageid);
    char *current_ptr = (char *)io_pgptr;

    CTC_COND_EXCEPTION (lseek64 (vdes, offset, SEEK_SET) == -1,
                        err_lseek_failed_label);

    while (remain_bytes > 0 && retry != 0)
    {
        retry = (retry > 0) ? retry - 1 : retry;

        nbytes = read (vdes, current_ptr, remain_bytes);

        if (nbytes == 0)
        {
            result = CTC_ERR_BAD_PAGE_FAILED;
            usleep (100 * 1000);
            continue;
        }
        else if (nbytes < 0)
        {
            CTC_COND_EXCEPTION (errno != EINTR, err_read_page_failed_label);
            continue;
        }
        else
        {
            remain_bytes -= nbytes;
            current_ptr += nbytes;
        }
    }

    CTC_COND_EXCEPTION (remain_bytes > 0, err_bad_page_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_lseek_failed_label)
    {
        result = CTC_FAILURE;
    }
    CTC_EXCEPTION (err_read_page_failed_label)
    {
        result = CTC_ERR_READ_FROM_DISK_FAILED;
    }
    CTC_EXCEPTION (err_bad_page_label)
    {
        if (retry <= 0)
        {
            result = CTC_ERR_BAD_PAGE_FAILED;
        }
        else
        {
            result = CTC_FAILURE;
        }
    }
    EXCEPTION_END;

    return result;
}


static int ctcl_log_fetch (CTCL_LOG_PAGEID pageid, 
                           CTCL_CACHE_BUFFER *cache_buffer)
{
    int result;
    LOG_PHY_PAGEID phy_pageid = NULL_PAGEID;
    int retry = 5;

    assert (cache_buffer);

    /* get the physical page id */
    phy_pageid = ctcl_get_log_phypageid (pageid);

    if (ctcl_Mgr.log_info.act_log.log_hdr->append_lsa.pageid < pageid)
    {
        /* check it again */
        result = ctcl_fetch_log_hdr (&ctcl_Mgr.log_info.act_log);
        CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                            err_fetch_log_header_failed_label);

        /* check it again */
        CTC_COND_EXCEPTION (ctcl_Mgr.log_info.act_log.log_hdr->append_lsa.pageid < pageid,
                            err_log_not_exist_in_archive_label);
    }

    while (retry > 0)
    {
        retry--;
        /* read from the active log file */
        result = ctcl_read_log_page_from_disk (ctcl_Mgr.log_info.act_log.path, 
                                               ctcl_Mgr.log_info.act_log.log_vdes, 
                                               &cache_buffer->logpage, 
                                               phy_pageid, 
                                               ctcl_Mgr.log_info.act_log.db_logpagesize);

        CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                            err_read_log_page_from_disk_failed_label);

        cache_buffer->in_archive = CTC_FALSE;

        if (cache_buffer->logpage.hdr.logical_pageid == pageid)
        {
            break;
        }

        usleep (100 * 1000);

        result = ctcl_fetch_log_hdr (&ctcl_Mgr.log_info.act_log);

        CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                            err_fetch_log_header_failed_label);
    }

    /*
    CTC_COND_EXCEPTION (retry <= 0 || 
                        ctcl_Mgr.log_info.act_log.log_hdr->append_lsa.pageid < pageid,
                        err_log_not_exist_in_archive_label);
                        */

    cache_buffer->pageid = pageid;
    cache_buffer->phy_pageid = phy_pageid;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_fetch_log_header_failed_label)
    {
        /* error info set from sub-function */
    }
    CTC_EXCEPTION (err_log_not_exist_in_archive_label)
    {
        /* log not exist in archive */
        result = CTC_ERR_LOG_NOT_EXIST_FAILED;
    }
    CTC_EXCEPTION (err_read_log_page_from_disk_failed_label)
    {
        /* log not exist in archive */
        result = CTC_ERR_READ_FROM_DISK_FAILED;
    }
    EXCEPTION_END;

    return result;
}

/*
 * Description : expand cache log buffer
 *   return: CTC_SUCCESS or ER_FAILED
 *   cache_pb : cache page buffer pointer
 *   slb_cnt : the # of cache log buffers per cache page buffer
 *   slb_size : size of CACHE_LOG_BUFFER
 *
 * Note:
 *         : Expand the cache log buffer pool with the given number of buffers.
 *         : If a zero or a negative value is given, the function expands
 *           the cache buffer pool with a default porcentage of the currently
 *           size.
 */
static int ctcl_expand_cache_log_buffer (CTCL_CACHE_PB *cache_pb, 
                                         int slb_cnt, 
                                         int slb_size)
{
    int i; 
    int result;
    int size;
    int bufid;
    int total_buffers;
    CTCL_CACHE_BUFFER_AREA *area = NULL;
    CTCL_CACHE_BUFFER **slb_log_buffer;

    assert (slb_cnt > 0);
    assert (slb_size > 0);

    size = ((slb_cnt * slb_size) + sizeof (CTCL_CACHE_BUFFER_AREA));

    area = (CTCL_CACHE_BUFFER_AREA *)malloc (size);
    CTC_COND_EXCEPTION (area == NULL, err_alloc_failed_label);

    memset (area, 0, size);

    total_buffers = cache_pb->num_buffers + slb_cnt;
    slb_log_buffer = realloc (cache_pb->log_buffer,
                              total_buffers * sizeof (CTCL_CACHE_BUFFER *));
    CTC_COND_EXCEPTION (slb_log_buffer == NULL, err_alloc_failed_label);

    area->buffer_area =
        ((CTCL_CACHE_BUFFER *) ((char *) area + sizeof (CTCL_CACHE_BUFFER_AREA)));
    area->next = cache_pb->buffer_area;

    for (i = 0, bufid = cache_pb->num_buffers; i < slb_cnt; i++, bufid++)
    {
        slb_log_buffer[bufid] =
            (CTCL_CACHE_BUFFER *) ((char *) area->buffer_area + slb_size * i);
    }

    cache_pb->log_buffer = slb_log_buffer;
    cache_pb->buffer_area = area;
    cache_pb->num_buffers = total_buffers;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_alloc_failed_label)
    {
        result = CTC_ERR_ALLOC_FAILED;
    }
    EXCEPTION_END;

    if (area)
    {
        free (area);
        area = NULL;
    }

    return result;
}


static CTCL_CACHE_BUFFER *ctcl_cache_buffer_replace (CTCL_CACHE_PB *cache_pb, 
                                                     CTCL_LOG_PAGEID pageid, 
                                                     int io_pagesize, 
                                                     int buffer_size)
{
    int i;
    int result;
    int found = -1;
    int num_recently_free;
    static unsigned int last = 0;
    CTCL_CACHE_BUFFER *cache_buffer = NULL;

    while (found < 0)
    {
        num_recently_free = 0;

        for (i = 0; i < cache_pb->num_buffers; i++)
        {
            last = ((last + 1) % cache_pb->num_buffers);
            cache_buffer = cache_pb->log_buffer[last];

            if (cache_buffer->fix_count == 0)
            {
                if (cache_buffer->recently_free == CTC_TRUE)
                {
                    cache_buffer->recently_free = CTC_FALSE;
                    num_recently_free++;
                }
                else
                {
                    found = last;
                    break;
                }
            }
        }

        if (found >= 0)
        {
            if (cache_buffer->pageid != 0)
            {
                (void)mht_rem (cache_pb->hash_table, 
                               &cache_buffer->pageid, 
                               NULL, 
                               NULL);
            }

            cache_buffer->fix_count = 0;

            CTC_TEST_EXCEPTION (ctcl_log_fetch (pageid, cache_buffer), 
                                err_log_fetch_failed_label);

            break;
        }

        if (num_recently_free > 0)
        {
            continue;
        }

        CTC_TEST_EXCEPTION (ctcl_expand_cache_log_buffer (cache_pb, 
                                                          buffer_size, 
                                                          SIZEOF_CTCL_CACHE_LOG_BUFFER (io_pagesize)),
                            err_expand_cache_log_buffer_failed_label);
    }

    return cache_buffer;

    CTC_EXCEPTION (err_log_fetch_failed_label)
    {
        cache_buffer->pageid = 0;
    }
    CTC_EXCEPTION (err_expand_cache_log_buffer_failed_label)
    {
    }
    EXCEPTION_END;

    return NULL;
}


static CTCL_CACHE_BUFFER *ctcl_get_page_buffer (CTCL_LOG_PAGEID pageid)
{
    CTCL_CACHE_PB *cache_pb = ctcl_Mgr.log_info.cache_pb;
    CTCL_CACHE_BUFFER *cache_buffer = NULL;

    /* find the target page in the cache buffer */
    cache_buffer = (CTCL_CACHE_BUFFER *)mht_get (cache_pb->hash_table, 
                                                 (void *)&pageid);

    if (cache_buffer == NULL)
    {
        cache_buffer = ctcl_cache_buffer_replace (cache_pb, 
                                                  pageid, 
                                                  ctcl_Mgr.log_info.act_log.db_logpagesize, 
                                                  ctcl_Mgr.log_info.cache_buffer_size);

        if (cache_buffer == NULL
            || cache_buffer->logpage.hdr.logical_pageid != pageid)
        {
            return NULL;
        }

        (void) mht_rem (cache_pb->hash_table, &cache_buffer->pageid,
                        NULL, NULL);

        if (mht_put (cache_pb->hash_table, &cache_buffer->pageid, cache_buffer)
            == NULL)
        {
            return NULL;
        }
    }
    else
    {
        if (cache_buffer->logpage.hdr.logical_pageid != pageid)
        {
            (void) mht_rem (cache_pb->hash_table, &cache_buffer->pageid,
                            NULL, NULL);
            return NULL;
        }
    }

    cache_buffer->fix_count++;
    return cache_buffer;
}


static CTCL_LOG_PAGE *ctcl_get_page (CTCL_LOG_PAGEID pageid)
{
    CTCL_CACHE_BUFFER *cache_buffer = NULL;

    assert (pageid != CTCL_PAGE_NULL_ID);

    if (pageid != CTCL_PAGE_NULL_ID)
    {
        while (cache_buffer == NULL)
        {
            /* cache buffer must exist */
            cache_buffer = ctcl_get_page_buffer (pageid);
        }
    }
    else
    {
        return NULL;
    }

    return &cache_buffer->logpage;
}

/*
 * Description : decrease the fix_count of the target buffer
 *
 */
static void ctcl_release_page_buffer (CTCL_LOG_PAGEID pageid)
{
    CTCL_CACHE_PB *cache_pb = ctcl_Mgr.log_info.cache_pb;
    CTCL_CACHE_BUFFER *cache_buffer = NULL;

    cache_buffer = (CTCL_CACHE_BUFFER *)mht_get (cache_pb->hash_table, 
                                                 (void *)&pageid);
    if (cache_buffer != NULL)
    {
        if ((--cache_buffer->fix_count) <= 0)
        {
            cache_buffer->fix_count = 0;
        }

        cache_buffer->recently_free = CTC_TRUE;
    }
}


/*
 * Description : release all page buffers
 *
 */
static void ctcl_release_all_page_buffers (CTCL_LOG_PAGEID except_pageid)
{
    int i;
    CTCL_CACHE_PB *cache_pb = ctcl_Mgr.log_info.cache_pb;
    CTCL_CACHE_BUFFER *cache_buffer = NULL;

    /* find unfix or unused buffer */
    for (i = 0; i < cache_pb->num_buffers; i++)
    {
        cache_buffer = cache_pb->log_buffer[i];

        if (cache_buffer->pageid == except_pageid)
        {
            continue;
        }

        if (cache_buffer->fix_count > 0)
        {
            cache_buffer->fix_count = 0;
            cache_buffer->recently_free = CTC_TRUE;
        }
    }
}

/*
 * Description : decrease the fix_count and drop the target buffer from cache
 *
 */
static void ctcl_decache_page_buffer (CTCL_CACHE_BUFFER * cache_buffer)
{
    CTCL_CACHE_PB *cache_pb = ctcl_Mgr.log_info.cache_pb;

    if (cache_buffer == NULL)
    {
        return;
    }

    if (cache_buffer->pageid != 0)
    {
        (void)mht_rem (cache_pb->hash_table, &cache_buffer->pageid, NULL, NULL);
    }

    cache_buffer->fix_count = 0;
    cache_buffer->recently_free = CTC_FALSE;
    cache_buffer->pageid = 0;
}


static void ctcl_decache_page_buffer_range (CTCL_LOG_PAGEID from, 
                                            CTCL_LOG_PAGEID to)
{
    int i;

    CTCL_CACHE_PB *cache_pb = ctcl_Mgr.log_info.cache_pb;
    CTCL_CACHE_BUFFER *cache_buffer = NULL;

    for (i = 0; i < cache_pb->num_buffers; i++)
    {
        cache_buffer = cache_pb->log_buffer[i];

        if ((cache_buffer->pageid == NULL_PAGEID) || 
            (cache_buffer->pageid == 0)           || 
            (cache_buffer->pageid < from)         || 
            (cache_buffer->pageid > to))
        {
            continue;
        }

        (void)mht_rem (cache_pb->hash_table, 
                       &cache_buffer->pageid, 
                       NULL, 
                       NULL);

        cache_buffer->fix_count = 0;
        cache_buffer->recently_free = CTC_FALSE;
        cache_buffer->pageid = 0;
    }

    return;
}


static void ctcl_find_lowest_required_lsa (CTCL_LOG_LSA *required_lsa)
{
    int i;
    CTCL_LOG_LSA lowest_lsa;

    CTCL_LSA_SET_NULL (&lowest_lsa);

    for (i = 0; i < ctcl_Mgr.log_info.cur_trans; i++)
    {
        if (ctcl_Mgr.log_info.trans_log_list[i]->tid <= 0)
        {
            continue;
        }

        if (CTCL_LSA_ISNULL (&lowest_lsa) ||
            CTCL_LSA_GT (&lowest_lsa, &ctcl_Mgr.log_info.trans_log_list[i]->start_lsa))
        {
            CTCL_LSA_COPY (&lowest_lsa, &ctcl_Mgr.log_info.trans_log_list[i]->start_lsa);
        }
    }

    if (CTCL_LSA_ISNULL (&lowest_lsa))
    {
        CTCL_LSA_COPY (required_lsa, &ctcl_Mgr.log_info.final_lsa);
    }
    else
    {
        CTCL_LSA_COPY (required_lsa, &lowest_lsa);
    }

    return;
}

/*
 * Description : initialize the cache log buffer area of cache page buffer
 *
 *   cache_pb : cache page buffer pointer
 *   slb_cnt : the # of cache log buffers per cache page buffer
 *   slb_size : size of CACHE_LOG_BUFFER
 *
 * Note:
 *         : allocate the cache page buffer area
 *         : the size of page buffer area is determined after reading the
 *           log header, so we split the "initialize" and "allocate" phase.
 */
static int ctcl_init_cache_log_buffer (CTCL_CACHE_PB *cache_pb, 
                                       int slb_cnt, 
                                       int slb_size)
{
    int result;

    result = ctcl_expand_cache_log_buffer (cache_pb, slb_cnt, slb_size);

    CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                        err_expand_cache_log_buffer_failed_label);

    cache_pb->hash_table = mht_create ("log applier cache log buffer hash table", 
                                       cache_pb->num_buffers * 8, 
                                       mht_logpageidhash, 
                                       mht_compare_logpageids_are_equal);

    CTC_COND_EXCEPTION (cache_pb->hash_table == NULL, 
                        err_hash_table_create_failed_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_expand_cache_log_buffer_failed_label)
    {
        /* error info set from sub-function */
    }
    CTC_EXCEPTION (err_hash_table_create_failed_label)
    {
        result = CTC_ERR_ALLOC_FAILED;
    }
    EXCEPTION_END;

    return result;
}

    
static int ctcl_fetch_log_hdr (CTCL_ACT_LOG *act_log)
{
    int result;

    CTC_TEST_EXCEPTION (ctcl_read_log_page_from_disk (act_log->path, 
                                                      act_log->log_vdes, 
                                                      (void *)act_log->hdr_page, 
                                                      0, 
                                                      act_log->db_logpagesize),
                        err_read_from_disk_failed_label);

    act_log->log_hdr = (struct log_header *)(act_log->hdr_page->area);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_read_from_disk_failed_label)
    {
        result = CTC_ERR_READ_FROM_DISK_FAILED;
    }
    EXCEPTION_END;

    return result;
}


static int ctcl_find_log_pagesize (CTCL_ACT_LOG *act_log, 
                                   const char *logpath, 
                                   const char *dbname)
{
    int result;

    /* set active log file full path */
    sprintf (act_log->path, "%s%s%s%s", 
             logpath, 
             CTC_PATH_SEPARATOR (logpath), 
             dbname, 
             CTCL_ACTIVE_LOG_FILE_SUFFIX);

    /* phase 1 : open active log file on 'read only' */
    do
    {
        act_log->log_vdes = fileio_open (act_log->path, O_RDONLY, 0);

        if (act_log->log_vdes == CTCL_NULL_VOLDES)
        {
            /* active log file not exist */ 
            result = CTC_ERR_FILE_NOT_EXIST_FAILED;
            CTCL_SLEEP (0, 200 * 1000);
        }
        else
        {
            result = CTC_SUCCESS;
            break;
        }
    }
    while (ctcl_Mgr.need_stop_analyzer == CTC_FALSE);

    CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_file_open_failed_label);

    act_log->hdr_page = (CTCL_LOG_PAGE *)malloc (CTCL_DEFAULT_LOG_PAGE_SIZE);

    CTC_COND_EXCEPTION (act_log->hdr_page == NULL, err_alloc_failed_label);

    /* phase2 : read log header from active log file */
    do
    {
        result = ctcl_read_log_page_from_disk (act_log->path, 
                                               act_log->log_vdes, 
                                               (char *)act_log->hdr_page, 
                                               0, 
                                               CTCL_DEFAULT_LOG_PAGE_SIZE);

        CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                            err_read_log_page_failed_label);

        act_log->log_hdr = (struct log_header *)act_log->hdr_page->area;

        /* log header validation */
        if (strncmp (act_log->log_hdr->magic,
                     CTCL_CUBRID_MAGIC_LOG_ACTIVE, 
                     CTCL_CUBRID_MAGIC_MAX_LENGTH) != 0)
        {
            CTCL_SLEEP (0, 10 * 1000);
            continue;
        }

        /* active log header is corrupted. */
        CTC_COND_EXCEPTION (act_log->log_hdr->prefix_name[0] != '\0' &&
                            strncmp (act_log->log_hdr->prefix_name, 
                                     dbname, 
                                     strlen (dbname)) != 0, 
                            err_log_header_corrupted_label);
            
        result = CTC_SUCCESS;
        break;
    }
    while (ctcl_Mgr.need_stop_analyzer == CTC_FALSE);

    CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_read_file_failed_label);

    /* phase 3 : set size to act_log of log_info from log header */
    act_log->db_iopagesize = act_log->log_hdr->db_iopagesize;
    act_log->db_logpagesize = act_log->log_hdr->db_logpagesize;

    /* page size validation */
    CTC_COND_EXCEPTION (act_log->db_logpagesize < CTCL_IO_MIN_PAGE_SIZE || 
                        act_log->db_logpagesize > CTCL_IO_MAX_PAGE_SIZE,
                        err_log_page_corrupted_label);

    if (act_log->db_logpagesize > CTCL_DEFAULT_LOG_PAGE_SIZE)
    {
        act_log->hdr_page = (CTCL_LOG_PAGE *)realloc (act_log->hdr_page, 
                                                      act_log->db_logpagesize);

        act_log->log_hdr = (struct log_header *)act_log->hdr_page->area;
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_file_open_failed_label)
    {
        /* error code already set */
    }
    CTC_EXCEPTION (err_alloc_failed_label)
    {
        result = CTC_ERR_ALLOC_FAILED;
    }
    CTC_EXCEPTION (err_read_log_page_failed_label)
    {
        /* error code already set */
    }
    CTC_EXCEPTION (err_read_file_failed_label)
    {
        /* error code already set */
    }
    CTC_EXCEPTION (err_log_page_corrupted_label)
    {
        result = CTC_ERR_PAGE_CORRUPTED_FAILED;
    }
    CTC_EXCEPTION (err_log_header_corrupted_label)
    {
        ctcl_Mgr.need_stop_analyzer = CTC_TRUE;
        result = CTC_ERR_PAGE_CORRUPTED_FAILED;
    }
    CTC_EXCEPTION (err_db_charset_not_matched_label)
    {
        /* ER_LOC_INIT */
        ctcl_Mgr.need_stop_analyzer = CTC_TRUE;
        result = CTC_FAILURE;
    }
    EXCEPTION_END;

    return result;
}

static int ctcl_info_pre_alloc (void)
{
    int result;
    int stage = 0;

    CTCL_LSA_COPY (&ctcl_Mgr.log_info.final_lsa, 
                   &ctcl_Mgr.log_info.committed_lsa);

    if (ctcl_Mgr.log_info.log_data == NULL)
    {
        ctcl_Mgr.log_info.log_data = 
            (char *)malloc (ctcl_Mgr.log_info.act_log.db_iopagesize);

        CTC_COND_EXCEPTION (ctcl_Mgr.log_info.log_data == NULL,
                            err_alloc_failed_label);
        stage = 1;
    }

    if (ctcl_Mgr.log_info.rec_type == NULL)
    {
        ctcl_Mgr.log_info.rec_type = (char *)malloc (sizeof (INT_16));

        CTC_COND_EXCEPTION (ctcl_Mgr.log_info.rec_type == NULL,
                            err_alloc_failed_label);
        stage = 2;
    }

    if (ctcl_Mgr.log_info.undo_unzip_ptr == NULL)
    {
        ctcl_Mgr.log_info.undo_unzip_ptr = 
            log_zip_alloc (ctcl_Mgr.log_info.act_log.db_iopagesize, CTC_FALSE);

        CTC_COND_EXCEPTION (ctcl_Mgr.log_info.undo_unzip_ptr == NULL,
                            err_alloc_failed_label);
        stage = 3;
    }

    if (ctcl_Mgr.log_info.redo_unzip_ptr == NULL)
    {
        ctcl_Mgr.log_info.redo_unzip_ptr = 
            log_zip_alloc (ctcl_Mgr.log_info.act_log.db_iopagesize, CTC_FALSE);

        CTC_COND_EXCEPTION (ctcl_Mgr.log_info.redo_unzip_ptr == NULL,
                            err_alloc_failed_label);
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_alloc_failed_label)
    {
        switch (stage)
        {
            case 3: log_zip_free (ctcl_Mgr.log_info.undo_unzip_ptr);
            case 2: free (ctcl_Mgr.log_info.rec_type);
            case 1: free (ctcl_Mgr.log_info.log_data);
                break;
        }

        result = CTC_ERR_ALLOC_FAILED;
    }
    EXCEPTION_END;

    return result;
}

/*
 * Description : check where the page exists
 * 
 */
static int ctcl_check_page_exist (CTCL_LOG_PAGEID pageid)
{
    int log_exist = CTCL_PAGE_NOT_EXIST;
    CTCL_CACHE_BUFFER *page_buffer;

    page_buffer = ctcl_get_page_buffer (pageid);

    if (page_buffer != NULL)
    {
        if (page_buffer->pageid == pageid && 
            page_buffer->logpage.hdr.logical_pageid == pageid && 
            page_buffer->logpage.hdr.offset > NULL_OFFSET)
        {
            /* valid page */
            if (page_buffer->in_archive != CTC_TRUE)
            {
                log_exist = CTCL_PAGE_EXST_IN_ACTIVE_LOG;
            }
            else
            {
                log_exist = CTCL_PAGE_EXST_IN_ARCHIVE_LOG;
            }

            ctcl_release_page_buffer (pageid);
        }
        else
        {
            /* invalid page */
            ctcl_decache_page_buffer (page_buffer);
        }
    }

    return log_exist;
}

/*
 * Description : modified from la_init_repl_lists() 
 *               initialize trans_log_list of log_info
 *
 */
static int ctcl_init_trans_log_list (BOOL is_need_realloc)
{
    int i;
    int result;
    int alloced_trans = 0;
    int cur_trans_cnt = 0;

    if (is_need_realloc == CTC_FALSE)
    {
        ctcl_Mgr.log_info.trans_log_list = malloc (sizeof (CTCL_TRANS_LOG_LIST *) * 
                                                   CTCL_TRANS_LOG_LIST_COUNT);

        CTC_COND_EXCEPTION (ctcl_Mgr.log_info.trans_log_list == NULL, 
                            err_alloc_failed_label);

        ctcl_Mgr.log_info.trans_cnt = CTCL_TRANS_LOG_LIST_COUNT;
        ctcl_Mgr.log_info.cur_trans = 0;
    
    }
    else
    {
        ctcl_Mgr.log_info.trans_log_list = realloc (ctcl_Mgr.log_info.trans_log_list, 
                                                    (sizeof (CTCL_TRANS_LOG_LIST *) * 
                                                     (CTCL_TRANS_LOG_LIST_COUNT + 
                                                      ctcl_Mgr.log_info.trans_cnt)));

        CTC_COND_EXCEPTION (ctcl_Mgr.log_info.trans_log_list == NULL, 
                            err_alloc_failed_label);

        cur_trans_cnt = ctcl_Mgr.log_info.trans_cnt;
        ctcl_Mgr.log_info.trans_cnt += CTCL_TRANS_LOG_LIST_COUNT;
    }

    for (i = cur_trans_cnt; i < ctcl_Mgr.log_info.trans_cnt; i++)
    {
        ctcl_Mgr.log_info.trans_log_list[i] = malloc (sizeof (CTCL_TRANS_LOG_LIST));

        CTC_COND_EXCEPTION (ctcl_Mgr.log_info.trans_log_list[i] == NULL, 
                            err_alloc_failed_label);

        ctcl_Mgr.log_info.trans_log_list[i]->tid = 0;
        ctcl_Mgr.log_info.trans_log_list[i]->item_num = 0;
        ctcl_Mgr.log_info.trans_log_list[i]->ref_cnt = 0;
        ctcl_Mgr.log_info.trans_log_list[i]->long_tx_flag = CTC_FALSE;
        CTCL_LSA_SET_NULL (&ctcl_Mgr.log_info.trans_log_list[i]->start_lsa);
        CTCL_LSA_SET_NULL (&ctcl_Mgr.log_info.trans_log_list[i]->last_lsa);
        ctcl_Mgr.log_info.trans_log_list[i]->head = NULL;
        ctcl_Mgr.log_info.trans_log_list[i]->tail = NULL;

        alloced_trans++;
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_alloc_failed_label)
    {
        if (ctcl_Mgr.log_info.trans_log_list)
        {
            for (i = 0; i < alloced_trans; i++)
            {
                free (ctcl_Mgr.log_info.trans_log_list[i]);
            }

            free (ctcl_Mgr.log_info.trans_log_list);
        }

        result = CTC_ERR_ALLOC_FAILED;
    }
    EXCEPTION_END;

    return result;
}


static BOOL ctcl_is_trans_log_list_empty (void)
{
    int i;

    for (i = 0; i < ctcl_Mgr.log_info.cur_trans; i++)
    {
        if (ctcl_Mgr.log_info.trans_log_list[i]->item_num > 0)
        {
            return CTC_FALSE;
        }
    }

    return CTC_TRUE;
}

/*
 * Description : return transaction list pointer for transaction id
 *
 */
static CTCL_TRANS_LOG_LIST *ctcl_find_trans_log_list (int tid)
{
    int i;

    for (i = 0; i < ctcl_Mgr.log_info.cur_trans; i++)
    {
        if (ctcl_Mgr.log_info.trans_log_list[i]->tid == tid)
        {
            return ctcl_Mgr.log_info.trans_log_list[i];
        }
    }

    return NULL;
}


/*
 * Description : modified from la_add_apply_list()
 *
 */
static CTCL_TRANS_LOG_LIST *ctcl_get_trans_log_list_set_tid (int tid)
{
    int i;
    int free_index = -1;
    CTCL_TRANS_LOG_LIST *trans_log_list = NULL;

    trans_log_list = ctcl_find_trans_log_list (tid);

    if (trans_log_list == NULL)
    {
        for (i = 0; i < ctcl_Mgr.log_info.cur_trans; i++)
        {
            if (ctcl_Mgr.log_info.trans_log_list[i]->tid == 0)
            {
                free_index = i;
                break;
            }
        }

        if (free_index < 0)
        {
            if (ctcl_Mgr.log_info.cur_trans == ctcl_Mgr.log_info.trans_cnt)
            {
                /* array is full --> realloc */
                if (ctcl_init_trans_log_list (CTC_TRUE) == CTC_SUCCESS)
                {
                    ctcl_Mgr.log_info.trans_log_list[ctcl_Mgr.log_info.cur_trans]->tid = tid;
                    ctcl_Mgr.log_info.cur_trans++;

                    trans_log_list = ctcl_Mgr.log_info.trans_log_list[ctcl_Mgr.log_info.cur_trans - 1];
                }
                else
                {
                    /* can not get any empty transaction log list */
                    trans_log_list = NULL;
                }
            }
            else
            {
                ctcl_Mgr.log_info.trans_log_list[ctcl_Mgr.log_info.cur_trans]->tid = tid;
                ctcl_Mgr.log_info.cur_trans++;

                trans_log_list = ctcl_Mgr.log_info.trans_log_list[ctcl_Mgr.log_info.cur_trans - 1];
            }
        }
        else
        {
            ctcl_Mgr.log_info.trans_log_list[free_index]->tid = tid;

            trans_log_list = ctcl_Mgr.log_info.trans_log_list[free_index];
        }

    }
    else
    {
        /* found list */
    }
        
    return trans_log_list;
}


/*
 * Description : modified from la_log_copy_fromlog()
 *               copy a portion of the log
 *   
 *   rec_type(out)
 *   area: Area where the portion of the log is copied.
 *               (Set as a side effect)
 *   length: the length to copy (type change PGLENGTH -> int)
 *   log_pageid: log page identifier of the log data to copy
 *               (May be set as a side effect)
 *   log_offset: log offset within the log page of the log data to copy
 *               (May be set as a side effect)
 *   log_pgptr: the buffer containing the log page
 *               (May be set as a side effect)
 *
 * Note:
 *   Copy "length" bytes of the log starting at log_pageid,
 *   log_offset onto the given area.
 *
 *   area is set as a side effect.
 *   log_pageid, log_offset, and log_pgptr are set as a side effect.
 */
static void ctcl_log_copy_fromlog (char *rec_type, 
                                   char *area, 
                                   int length, 
                                   CTCL_LOG_PAGEID log_pageid, 
                                   CTCL_PAGE_LENGTH log_offset, 
                                   CTCL_LOG_PAGE *log_pg)
{
    int result;
    int t_length;			/* target length  */
    int copy_length;
    int rec_length = (int)sizeof (CTCL_PAGE_LENGTH);
    int area_offset = 0;		/* The area offset */
    CTCL_LOG_PAGE *pg;

    pg = log_pg;

    while (rec_type != NULL && rec_length > 0)
    {
        CTCL_LOG_READ_ADVANCE (result, 0, log_offset, log_pageid, pg);

        if (pg == NULL)
        {
            break;
        }

        if ((log_offset + rec_length) <= CTCL_LOGAREA_SIZE)
        {
            copy_length = rec_length;
        }
        else
        {
            copy_length = CTCL_LOGAREA_SIZE - log_offset;
        }

        memcpy (rec_type + area_offset, 
                (char *)(pg)->area + log_offset, 
                copy_length);

        rec_length -= copy_length;
        area_offset += copy_length;
        log_offset += copy_length;
        length = length - sizeof (CTCL_PAGE_LENGTH);
    }

    area_offset = 0;
    t_length = length;

    /* The log data is not contiguous */
    while (t_length > 0)
    {
        CTCL_LOG_READ_ADVANCE (result, 0, log_offset, log_pageid, pg);

        if (pg == NULL)
        {
            break;
        }

        if ((log_offset + t_length) <= CTCL_LOGAREA_SIZE)
        {
            copy_length = t_length;
        }
        else
        {
            copy_length = CTCL_LOGAREA_SIZE - log_offset;
        }

        memcpy (area + area_offset, 
                (char *)(pg)->area + log_offset, 
                copy_length);

        t_length -= copy_length;
        area_offset += copy_length;
        log_offset += copy_length;
    }

    return;
}


static CTCL_ITEM *ctcl_new_item (CTCL_LOG_LSA *lsa, CTCL_LOG_LSA *target_lsa)
{
    CTCL_ITEM *item;

    item = malloc (sizeof (CTCL_ITEM));

    if (item == NULL)
    {
        return NULL;
    }

    item->db_user = NULL;
    item->table_name = NULL;
    item->log_type = -1;
    item->stmt_type = -1;
    CTCL_LSA_COPY (&item->lsa, lsa);
    CTCL_LSA_COPY (&item->target_lsa, target_lsa);

    item->next = NULL;
    item->prev = NULL;

    return item;
}


static void ctcl_add_log_item_list (CTCL_TRANS_LOG_LIST *trans_log_list, 
                                    CTCL_ITEM *item)
{
    assert (trans_log_list != NULL);
    assert (item != NULL);

    item->next = NULL;
    item->prev = trans_log_list->tail;

    if (trans_log_list->tail)
    {
        trans_log_list->tail->next = item;
    }
    else
    {
        trans_log_list->head = item;
    }

    trans_log_list->tail = item;
    trans_log_list->item_num++;

    return;
}



static CTCL_ITEM *ctcl_make_item (CTCL_LOG_PAGE *log_pg, 
                                  int log_type, 
                                  int tid, 
                                  CTCL_LOG_LSA *lsa)
{
    int result = CTC_SUCCESS;
    int length;	
    char *ptr;
    char *str_value;
    char *area;
    CTCL_LOG_PAGEID pageid;
    CTCL_ITEM *item = NULL;
    CTCL_LOG_PAGE *trans_log_pg;
    CTCL_LOG_REPLICATION *repl_log;
    CTCL_PAGE_LENGTH offset;

    trans_log_pg = log_pg;
    pageid = lsa->pageid;
    offset = sizeof (CTCL_LOG_RECORD_HEADER) + lsa->offset;
    length = sizeof (CTCL_LOG_REPLICATION);


//    CTCL_LOG_READ_ALIGN (result, offset, pageid, trans_log_pg);
    /* DEBUG */
    (offset) = CTCL_ALIGN((offset), sizeof(double));                

    while ((offset) >= CTCL_LOGAREA_SIZE) 
    {                     
        if (((trans_log_pg) = ctcl_get_page(++(pageid))) == NULL) 
        { 
            result = CTC_ERR_READ_FROM_DISK_FAILED;                 
        }                                                           

        (offset) -= CTCL_LOGAREA_SIZE;                              
        (offset) = CTCL_ALIGN((offset), sizeof(double));
    }       

    if (result != CTC_SUCCESS)
    {
        return NULL;
    }

    CTCL_LOG_READ_ADVANCE (result, length, offset, pageid, trans_log_pg);

    if (result != CTC_SUCCESS)
    {
        return NULL;
    }

    repl_log = (CTCL_LOG_REPLICATION *)((char *) trans_log_pg->area + offset);

    offset += length;
    length = repl_log->length;

    CTCL_LOG_READ_ALIGN (result, offset, pageid, trans_log_pg);

    if (result != CTC_SUCCESS)
    {
        return NULL;
    }

    area = (char *)malloc (length);

    if (area == NULL)
    {
        return NULL;
    }

    (void)ctcl_log_copy_fromlog (NULL, 
                                 area, 
                                 length, 
                                 pageid, 
                                 offset, 
                                 trans_log_pg);

    item = ctcl_new_item (lsa, &repl_log->lsa);

    if (item == NULL)
    {
        goto error_return;
    }

    switch (log_type)
    {
        case CTCL_LOG_REPLICATION_DATA:

            ptr = or_unpack_string (area, &item->table_name);
            ptr = or_unpack_mem_value (ptr, &item->key);

            switch (repl_log->rcvindex)
            {
                case RVREPL_DATA_INSERT:
                    item->stmt_type = CTCL_STMT_TYPE_INSERT;
                    ctcl_process_insert_log (item);
                    break;

                case RVREPL_DATA_UPDATE_START:
                case RVREPL_DATA_UPDATE_END:
                case RVREPL_DATA_UPDATE:
                    item->stmt_type = CTCL_STMT_TYPE_UPDATE;
                    ctcl_process_update_log (item);
                    break;

                case RVREPL_DATA_DELETE:
                    item->stmt_type = CTCL_STMT_TYPE_DELETE;
                    ctcl_process_delete_log (item);
                    break;

                default:
                    /* DEBUG */
                    printf ("DATA another stmt type entered: LOG_RCVINDEX number = %d\n",
                            repl_log->rcvindex);
                    break;
            }

            /* DEBUG */
            printf ("item->db_user = %s\n \
                    item->table_name = %s\n \
                    item->log_type = %d\n \
                    item->stmt_type = %d\n \
                    item->key = %ld\n", 
                    item->db_user, 
                    item->table_name,
                    item->log_type,
                    item->stmt_type,
                    item->key);

            break;

        case CTCL_LOG_REPLICATION_SCHEMA:

            ptr = or_unpack_int (area, &item->stmt_type);
            /*
            ptr = or_unpack_string (ptr, &item->table_name);
            ptr = or_unpack_string (ptr, &str_value);
            db_make_string (&item->key, str_value);
            item->key.need_clear = CTC_TRUE;
            ptr = or_unpack_string (ptr, &item->db_user);
            */

                    
            printf ("SCHEMA another stmt type entered: LOG_RCVINDEX number = %d\n", 
                    repl_log->rcvindex);

            /* DEBUG */
            printf ("item->db_user = %s\n \
                    item->table_name = %s\n \
                    item->log_type = %d\n \
                    item->stmt_type = %d\n \
                    item->key = %ld\n", 
                    item->db_user, 
                    item->table_name,
                    item->log_type,
                    item->stmt_type,
                    item->key);

            break;

        default:
            /* unknown log type */
            goto error_return;
    }

    item->log_type = log_type;

    if (area)
    {
        free (area);
        area = NULL;
    }

    return item;

error_return:
    if (area)
    {
        free (area);
        area = NULL;
    }

    if (item)
    {
        if (item->table_name != NULL)
        {
            db_private_free_and_init (NULL, item->table_name);
            pr_clear_value (&item->key);
        }

        if (item->db_user != NULL)
        {
            db_private_free_and_init (NULL, item->db_user);
        }

        free (item);
        item = NULL;
    }

    return NULL;
}


static int ctcl_process_insert_log (CTCL_ITEM *item)
{
    BOOL ovfyn = CTC_FALSE;
    int result = CTC_SUCCESS;
    int au_save;
    unsigned int rcvindex;
    DB_OBJECT *class_obj;
    DB_OBJECT *new_object = NULL;
    MOBJ mclass;
    CTCL_LOG_PAGE *pgptr;
    RECDES recdes;
    DB_OTMPL *inst_tp = NULL;
    CTCL_LOG_PAGEID old_pageid = -1;

    /* get the target log page */
    old_pageid = item->target_lsa.pageid;
    pgptr = ctcl_get_page (old_pageid);

    CTC_COND_EXCEPTION (pgptr == NULL, err_null_pg_label);

    /* retrieve the target record description */
    result = ctcl_get_recdes (&item->target_lsa, 
                             pgptr, 
                             NULL, 
                             &recdes, 
                             &rcvindex, 
                             ctcl_Mgr.log_info.log_data, 
                             ctcl_Mgr.log_info.rec_type, 
                             &ovfyn);

    CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_get_recdes_failed_label);

    CTC_COND_EXCEPTION (recdes.type == REC_ASSIGN_ADDRESS || 
                        recdes.type == REC_RELOCATION,
                        err_invalid_rectype_label);

    CTC_COND_EXCEPTION (rcvindex != RVHF_INSERT,
                        err_invalid_rcvindex_label);

    class_obj = db_find_class (item->table_name);
    CTC_COND_EXCEPTION (class_obj == NULL, err_invalid_table_label);

    mclass = locator_fetch_class (class_obj, DB_FETCH_CLREAD_INSTREAD);
    CTC_COND_EXCEPTION (mclass == NULL, err_invalid_table_label);

//    AU_SAVE_AND_DISABLE (au_save);

    /* get template */
    inst_tp = dbt_create_object_internal (class_obj);
    CTC_COND_EXCEPTION (inst_tp == NULL, err_invalid_table_label);

    /* make object using the record rescription */
    result = ctcl_disk_to_obj (mclass, &recdes, inst_tp, item);
    CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_invalid_table_label);

    /* finish object */
//    new_object = dbt_finish_object_and_decache_when_failure (inst_tp);
//    CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_invalid_table_label);

//    AU_RESTORE (au_save);

    if (ovfyn)
    {
        if (recdes.data)
        {
            free (recdes.data);
            recdes.data = NULL;
        }
    }

    if (inst_tp)
    {
        dbt_abort_object (inst_tp);
    }

    if (new_object)
    {
        ws_release_user_instance (new_object);
    }

    new_object = NULL;

    ctcl_release_page_buffer (old_pageid);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_pg_label)
    {
        result = CTC_ERR_BAD_PAGE_FAILED;
    }
    CTC_EXCEPTION (err_get_recdes_failed_label)
    {
        ctcl_release_page_buffer (old_pageid);
        result = CTC_ERR_BAD_PAGE_FAILED;
    }
    CTC_EXCEPTION (err_invalid_rectype_label)
    {
        /* DEBUG */
        printf ("apply_update : rectype.type = %d\n", recdes.type);
        ctcl_release_page_buffer (old_pageid);
        result = CTC_ERR_INVALID_TYPE_FAILED;
    }
    CTC_EXCEPTION (err_invalid_rcvindex_label)
    {
        /* DEBUG */
        printf ("apply_update : rcvindex = %d\n", rcvindex);
        ctcl_release_page_buffer (old_pageid);
        result = CTC_ERR_INVALID_TYPE_FAILED;
    }
    CTC_EXCEPTION (err_invalid_table_label)
    {
        if (ovfyn)
        {
            if (recdes.data)
            {
                free (recdes.data);
                recdes.data = NULL;
            }
        }

        if (new_object)
        {
            ws_release_user_instance (new_object);
            ws_decache (new_object);
            new_object = NULL;
        }

        if (inst_tp)
        {
            dbt_abort_object (inst_tp);
        }

        if (result == ER_NET_CANT_CONNECT_SERVER || 
            result == ER_OBJ_NO_CONNECT)
        {
            result = ER_NET_CANT_CONNECT_SERVER;
        }

        ctcl_release_page_buffer (old_pageid);
    }
    EXCEPTION_END;

    return result;
}


static int ctcl_process_delete_log (CTCL_ITEM *item)
{
    int result;
    int con_name_len;
    MOBJ mclass;
    DB_OBJECT *class_obj;
    DB_OTMPL *inst_tp = NULL;
    SM_CLASS *class_;
    SM_CLASS_CONSTRAINT *cons;
    DB_TYPE value_type;
    MOP mop;

    class_obj = db_find_class (item->table_name);
    CTC_COND_EXCEPTION (class_obj == NULL, err_invalid_table_label);

    mclass = locator_fetch_class (class_obj, DB_FETCH_CLREAD_INSTREAD);
    CTC_COND_EXCEPTION (mclass == NULL, err_invalid_table_label);

    result = au_fetch_class (class_obj, &class_, AU_FETCH_READ, AU_SELECT);
    CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_fetch_class_failed_label);

    cons = classobj_find_class_primary_key (class_);
    CTC_COND_EXCEPTION (cons == NULL, err_find_pk_failed_label);

    value_type = DB_VALUE_TYPE (&item->key);
    CTC_COND_EXCEPTION (value_type == DB_TYPE_NULL, err_invalid_type_label);

    ctcl_item_delete_log_info_init (item);

    con_name_len = strlen (cons->attributes[0]->header.name);

    memcpy (item->delete_log_info.key_col.name, 
            cons->attributes[0]->header.name,
            con_name_len);

    item->delete_log_info.key_col.type = value_type;

    switch (value_type)
    {
        case DB_TYPE_INTEGER:
            item->delete_log_info.key_col.val_len = sizeof (int);
            item->delete_log_info.key_col.val = malloc (sizeof (int));
            *(int *)(item->delete_log_info.key_col.val) = item->key.data.i;
            break;

        case DB_TYPE_CHAR:
        case DB_TYPE_VARCHAR:
            item->delete_log_info.key_col.val_len = 
                strlen (item->key.data.ch.medium.buf);
            item->delete_log_info.key_col.val = 
                malloc (item->delete_log_info.key_col.val_len);
            memcpy (item->delete_log_info.key_col.val,
                    item->key.data.ch.medium.buf,
                    item->delete_log_info.key_col.val_len);
            break;

        default:
            break;
    }

    /* >>> DEBUG */
    if (item->delete_log_info.key_col.val_len != 0)
    {
        printf ("key_col.name = %s\n \
                key_col.type = %d\n \
                key_col.val_len = %d\n",
                item->delete_log_info.key_col.name,
                item->delete_log_info.key_col.type,
                item->delete_log_info.key_col.val_len);

        if (item->delete_log_info.key_col.type == DB_TYPE_INTEGER)
        {
            printf ("key_col.val = %d\n", *(int *)(item->delete_log_info.key_col.val));
        }
        else
        {
            printf ("key_col.val = %s\n", (char *)(item->delete_log_info.key_col.val));
        }
    }
    /* <<< DEBUG */
/*
    inst_tp = dbt_edit_object (object);
    CTC_COND_EXCEPTION (inst_tp == NULL, err_invalid_table_label);

    result = ctcl_disk_to_obj (mclass, &recdes, inst_tp, item);
    CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_invalid_table_label);
*/
    return CTC_SUCCESS;

    CTC_EXCEPTION (err_invalid_table_label)
    {
        result = CTC_FAILURE;
    }
    CTC_EXCEPTION (err_fetch_class_failed_label)
    {
        /* error info set from sub-function */
        /* DEBUG */
        printf ("err_fetch_class_failed_label\n");
    }
    CTC_EXCEPTION (err_find_pk_failed_label)
    {
        /* DEBUG */
        printf ("err_find_pk_failed_label\n");
        result = CTC_FAILURE;
    }
    CTC_EXCEPTION (err_invalid_type_label)
    {
        /* DEBUG */
        printf ("err_invalid_type_label\n");
        result = CTC_FAILURE;
    }
    CTC_EXCEPTION (err_invalid_key_value_label)
    {
        /* DEBUG */
        printf ("err_invalid_key_value_label\n");
        result = CTC_FAILURE;
    }
    EXCEPTION_END;

    return result;
}


static int ctcl_process_update_log (CTCL_ITEM *item)
{
    BOOL ovfyn = CTC_FALSE;
    int result = CTC_SUCCESS;
    int au_save;
    unsigned int rcvindex;
    char buf[256];
    DB_OBJECT *class_obj;
    DB_OBJECT *object = NULL;
    DB_OBJECT *new_object = NULL;
    MOBJ mclass;
    CTCL_LOG_PAGE *pgptr;
    RECDES recdes;
    DB_OTMPL *inst_tp = NULL;
    CTCL_LOG_PAGEID old_pageid = -1;

    /* get the target log page */
    old_pageid = item->target_lsa.pageid;
    pgptr = ctcl_get_page (old_pageid);

    CTC_COND_EXCEPTION (pgptr == NULL, err_null_pg_label);

    /* retrieve the target record description */
    result = ctcl_get_recdes (&item->target_lsa, 
                             pgptr, 
                             NULL, 
                             &recdes, 
                             &rcvindex, 
                             ctcl_Mgr.log_info.log_data, 
                             ctcl_Mgr.log_info.rec_type, 
                             &ovfyn);

    CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_get_recdes_failed_label);

    CTC_COND_EXCEPTION (recdes.type == REC_ASSIGN_ADDRESS || 
                        recdes.type == REC_RELOCATION,
                        err_invalid_rectype_label);

    CTC_COND_EXCEPTION (rcvindex != RVHF_UPDATE && 
                        rcvindex != RVOVF_CHANGE_LINK,
                        err_invalid_rcvindex_label);

    /* get MOBJ */
    class_obj = db_find_class (item->table_name);
    CTC_COND_EXCEPTION (class_obj == NULL, err_invalid_table_label);

    /* check existence */
    object = obj_repl_find_object_by_pkey (class_obj, &item->key,
                                           AU_FETCH_UPDATE);
    CTC_COND_EXCEPTION (object == NULL, err_invalid_table_label);

    /* get class info */
    mclass = locator_fetch_class (class_obj, DB_FETCH_CLREAD_INSTREAD);
    CTC_COND_EXCEPTION (mclass == NULL, err_invalid_table_label);

//    AU_SAVE_AND_DISABLE (au_save);

    /* get template */
    inst_tp = dbt_edit_object (object);
    CTC_COND_EXCEPTION (inst_tp == NULL, err_invalid_table_label);

    /* make object using the record rescription */
    result = ctcl_disk_to_obj (mclass, &recdes, inst_tp, item);
    CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_invalid_table_label);

    /* finish object */
    new_object = dbt_finish_object_and_decache_when_failure (inst_tp);
    CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_invalid_table_label);

//    AU_RESTORE (au_save);

    if (ovfyn)
    {
        if (recdes.data)
        {
            free (recdes.data);
            recdes.data = NULL;
        }
    }

    if (inst_tp)
    {
        dbt_abort_object (inst_tp);
    }

    assert (new_object == object);

    if (new_object)
    {
        ws_release_user_instance (new_object);
    }

    object = new_object = NULL;

    ctcl_release_page_buffer (old_pageid);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_pg_label)
    {
        result = CTC_ERR_BAD_PAGE_FAILED;
    }
    CTC_EXCEPTION (err_get_recdes_failed_label)
    {
        ctcl_release_page_buffer (old_pageid);
        result = CTC_ERR_BAD_PAGE_FAILED;
    }
    CTC_EXCEPTION (err_invalid_rectype_label)
    {
        /* DEBUG */
        printf ("apply_update : rectype.type = %d\n", recdes.type);
        ctcl_release_page_buffer (old_pageid);
        result = CTC_ERR_INVALID_TYPE_FAILED;
    }
    CTC_EXCEPTION (err_invalid_rcvindex_label)
    {
        /* DEBUG */
        printf ("apply_update : rcvindex = %d\n", rcvindex);
        ctcl_release_page_buffer (old_pageid);
        result = CTC_ERR_INVALID_TYPE_FAILED;
    }
    CTC_EXCEPTION (err_invalid_table_label)
    {
        if (ovfyn)
        {
            if (recdes.data)
            {
                free (recdes.data);
                recdes.data = NULL;
            }
        }

        assert (new_object == NULL || new_object == object);

        if (object)
        {
            ws_release_user_instance (object);
            ws_decache (object);
            object = new_object = NULL;
        }

        if (inst_tp)
        {
            dbt_abort_object (inst_tp);
        }

        if (new_object == NULL)
        {
        //    AU_RESTORE (au_save);
        }

        if (result == ER_NET_CANT_CONNECT_SERVER || 
            result == ER_OBJ_NO_CONNECT)
        {
            result = ER_NET_CANT_CONNECT_SERVER;
        }

        ctcl_release_page_buffer (old_pageid);
    }
    EXCEPTION_END;

    return result;
}


static int ctcl_disk_to_obj (MOBJ classobj, 
                             RECDES *record, 
                             DB_OTMPL *def, 
                             CTCL_ITEM *item)
{
    OR_BUF orep, *buf;
    int repid, status;
    SM_CLASS *sm_class;
    unsigned int repid_bits;
    int bound_bit_flag;
    int rc = CTC_SUCCESS;
    int error = CTC_SUCCESS;
    int offset_size;
    DB_VALUE *key = &item->key;

    buf = &orep;
    or_init (buf, record->data, record->length);
    buf->error_abort = 1;

    status = setjmp (buf->env);

    if (status == 0)
    {
        sm_class = (SM_CLASS *)classobj;

        offset_size = OR_GET_OFFSET_SIZE (buf->ptr);

        repid_bits = or_get_int (buf, &rc);

        (void)or_get_int (buf, &rc);

        repid = repid_bits & ~OR_BOUND_BIT_FLAG & ~OR_OFFSET_SIZE_FLAG;

        bound_bit_flag = repid_bits & OR_BOUND_BIT_FLAG;

        if (item->stmt_type == CTCL_STMT_TYPE_UPDATE)
        {
            error = ctcl_get_update_current (buf, 
                                             sm_class, 
                                             bound_bit_flag, 
                                             def, 
                                             item, 
                                             offset_size);
        }
        else if (item->stmt_type == CTCL_STMT_TYPE_INSERT)
        {
            error = ctcl_get_insert_current (buf, 
                                             sm_class, 
                                             bound_bit_flag, 
                                             def, 
                                             item, 
                                             offset_size);
        }
        else
        {
            /* DELETE come in?? */
        }
    }
    else
    {
        error = ER_GENERIC_ERROR;
    }

    return error;
}


static void ctcl_item_delete_log_info_init (CTCL_ITEM *item)
{
    memset (item->delete_log_info.key_col.name, 0, CTCL_NAME_MAX);
}


static void ctcl_item_insert_log_info_init (CTCL_ITEM *item)
{
    item->insert_log_info.set_col_cnt = 0;
    CTCG_LIST_INIT (&(item->insert_log_info.set_col_list));
}


static void ctcl_item_update_log_info_init (CTCL_ITEM *item)
{
    memset (item->update_log_info.key_col.name, 0, CTCL_NAME_MAX);
    item->update_log_info.set_col_cnt = 0;

    CTCG_LIST_INIT (&(item->update_log_info.set_col_list));
}


static int ctcl_get_update_current (OR_BUF *buf, 
                                    SM_CLASS *sm_class, 
                                    int bound_bit_flag, 
                                    DB_OTMPL *def, 
                                    CTCL_ITEM *item, 
                                    int offset_size)
{
    int error = CTC_SUCCESS;
    int rc = CTC_SUCCESS;
    int *vars = NULL;
    int i, j, offset, offset2, pad;
    int col_name_len;
    int key_att_id = 0;
    char *bits, *start, *v_start;
    SM_ATTRIBUTE *att;
    DB_VALUE value;
    CTCL_COLUMN *set_col = NULL;
    CTCL_COLUMN *test_col = NULL;
    CTCG_LIST_NODE *itr;

    if (sm_class->variable_count)
    {
        vars = (int *)malloc (DB_SIZEOF (int) * sm_class->variable_count);

        if (vars == NULL)
        {
            return ER_OUT_OF_VIRTUAL_MEMORY;
        }

        offset = or_get_offset_internal (buf, &rc, offset_size);

        for (i = 0; i < sm_class->variable_count; i++)
        {
            offset2 = or_get_offset_internal (buf, &rc, offset_size);
            vars[i] = offset2 - offset;
            offset = offset2;
        }

        buf->ptr = PTR_ALIGN (buf->ptr, sizeof(int));
    }

    bits = NULL;

    if (bound_bit_flag)
    {
        bits = (char *)buf->ptr + sm_class->fixed_size;
    }

    att = sm_class->attributes;
    start = buf->ptr;

    /* initialize update_log_info */
    ctcl_item_update_log_info_init (item);

    /* find key attribute */
    for (i = 0; 
         i < sm_class->att_count; 
         i++, att = (SM_ATTRIBUTE *)att->header.next)
    {
        if (att->constraints != NULL)
        {
            if (att->constraints->type == SM_CONSTRAINT_PRIMARY_KEY)
            {
                key_att_id = att->id;
            }
        }
        else
        {
            /* key not exist, critical problem, but ignore */
        }
    }

    att = sm_class->attributes;

    /* process the fixed length column */
    for (i = 0; 
         i < sm_class->fixed_count; 
         i++, att = (SM_ATTRIBUTE *)att->header.next)
    {
        if (bits != NULL && !OR_GET_BOUND_BIT (bits, i))
        {
            /* its a NULL value, skip it */
            db_make_null (&value);
            or_advance (buf, tp_domain_disk_size (att->domain));
        }
        else
        {
            /* read the disk value into the db_value */
            (*(att->type->data_readval))(buf, &value, att->domain, 
                                         -1, true, NULL, 0);

            /* key column info setting */
            if (att->id == key_att_id)
            {
                /* 1. column name */
                col_name_len = strlen (att->header.name);
                memcpy (item->update_log_info.key_col.name,
                        att->header.name,
                        col_name_len);

                /* 2. column type */
                item->update_log_info.key_col.type = att->domain->type->id;

                /* 3. column value */
                switch (att->type->id)
                {
                    case DB_TYPE_INTEGER:
                        item->update_log_info.key_col.val_len = sizeof(int);
                        item->update_log_info.key_col.val = malloc (sizeof(int));
                        *(int *)(item->update_log_info.key_col.val) = value.data.i;
                        break;

                    case DB_TYPE_CHAR:
                    case DB_TYPE_VARCHAR:
                        item->update_log_info.key_col.val_len = 
                            strlen (value.data.ch.medium.buf);
                        item->update_log_info.key_col.val =
                            malloc (item->update_log_info.key_col.val_len);
                        memcpy (item->update_log_info.key_col.val,
                                value.data.ch.medium.buf,
                                item->update_log_info.key_col.val_len);
                        break;

                    default:
                        break;
                }
            }
            /* set column info setting */
            else
            {
                set_col = (CTCL_COLUMN *)malloc (sizeof (CTCL_COLUMN));
                memset (set_col->name, 0, CTCL_NAME_MAX);

                CTCG_LIST_INIT_OBJ (&set_col->node, set_col);

                /* 1. column name */
                col_name_len = strlen (att->header.name);
                memcpy (set_col->name, att->header.name, col_name_len);

                /* 2. column type */
                set_col->type = att->domain->type->id;

                /* 3. column value */
                switch (set_col->type)
                {
                    case DB_TYPE_INTEGER:
                        set_col->val_len = sizeof(int);
                        set_col->val = malloc (set_col->val_len);
                        *(int *)(set_col->val) = value.data.i;
                        break;

                    case DB_TYPE_CHAR:
                    case DB_TYPE_VARCHAR:
                        set_col->val_len = strlen (value.data.ch.medium.buf);
                        set_col->val = malloc (set_col->val_len);
                        memcpy (set_col->val, 
                                value.data.ch.medium.buf, 
                                set_col->val_len);
                        break;

                    default:
                        break;
                }

                CTCG_LIST_ADD_LAST (&(item->update_log_info.set_col_list), 
                                    &set_col->node);
            }
        }

        /* skip cache object attribute for foreign key */
        if (att->is_fk_cache_attr)
        {
            continue;
        }

        /* update the column */
        error = dbt_put_internal (def, att->header.name, &value);
        pr_clear_value (&value);

        if (error != CTC_SUCCESS)
        {
            if (vars != NULL)
            {
                free (vars);
                vars = NULL;
            }

            return error;
        }
    }

    /* round up to a to the end of the fixed block */
    pad = (int) (buf->ptr - start);

    if (pad < sm_class->fixed_size)
    {
        or_advance (buf, sm_class->fixed_size - pad);
    }

    /* skip over the bound bits */
    if (bound_bit_flag)
    {
        or_advance (buf, OR_BOUND_BIT_BYTES (sm_class->fixed_count));
    }

    /* process variable length column */
    v_start = buf->ptr;

    for (i = sm_class->fixed_count, j = 0;
         i < sm_class->att_count && j < sm_class->variable_count;
         i++, j++, att = (SM_ATTRIBUTE *)att->header.next)
    {
        (*(att->type->data_readval))(buf, &value, att->domain, 
                                     vars[j], true, NULL, 0);
        v_start += vars[j];
        buf->ptr = v_start;

        set_col = (CTCL_COLUMN *)malloc (sizeof (CTCL_COLUMN));
        memset (set_col->name, 0, CTCL_NAME_MAX);

        CTCG_LIST_INIT_OBJ (&set_col->node, set_col);

        /* 1. column name */
        col_name_len = strlen (att->header.name);
        memcpy (set_col->name, att->header.name, col_name_len);

        /* 2. column type */
        set_col->type = att->domain->type->id;

        /* 3. column value */
        switch (set_col->type)
        {
            case DB_TYPE_INTEGER:
                set_col->val_len = sizeof(int);
                set_col->val = malloc (set_col->val_len);
                *(int *)(set_col->val) = value.data.i;
                break;

            case DB_TYPE_CHAR:
            case DB_TYPE_VARCHAR:
                set_col->val_len = strlen (value.data.ch.medium.buf);
                set_col->val = malloc (set_col->val_len);
                memcpy (set_col->val, 
                        value.data.ch.medium.buf, 
                        set_col->val_len);
                break;

            default:
                break;
        }

        CTCG_LIST_ADD_LAST (&(item->update_log_info.set_col_list), 
                            &set_col->node);

        /* update the column */
        error = dbt_put_internal (def, att->header.name, &value);
        pr_clear_value (&value);

        if (error != CTC_SUCCESS)
        {
            if (vars != NULL)
            {
                free (vars);
                vars = NULL;
            }

            return error;
        }
    }

    /* >>> DEBUG */
    if (item->update_log_info.key_col.val_len != 0)
    {
        printf ("key_col.name = %s\n \
                key_col.type = %d\n \
                key_col.val_len = %d\n",
                item->update_log_info.key_col.name,
                item->update_log_info.key_col.type,
                item->update_log_info.key_col.val_len);

        if (item->update_log_info.key_col.type == DB_TYPE_INTEGER)
        {
            printf ("key_col.val = %d\n", *(int *)(item->update_log_info.key_col.val));
        }
        else
        {
            printf ("key_col.val = %s\n", (char *)(item->update_log_info.key_col.val));
        }
    }

    CTCG_LIST_ITERATE (&(item->update_log_info.set_col_list), itr)
    {
        test_col = (CTCL_COLUMN *)itr->obj;

        if (test_col != NULL)
        {
            printf ("col_name = %s\n \
                    col_type = %d\n \
                    col_val_len = %d\n", 
                    test_col->name,
                    test_col->type,
                    test_col->val_len);
        }

        if (test_col->type == DB_TYPE_INTEGER)
        {
            printf ("col_val = %d\n", *(int *)(test_col->val));
        }
        else
        {
            printf ("col_val = %s\n", (char *)(test_col->val));
        }
    }
    /* <<< DEBUG */

    if (vars != NULL)
    {
        free (vars);
        vars = NULL;
    }

    return error;
}


static int ctcl_get_insert_current (OR_BUF *buf, 
                                    SM_CLASS *sm_class, 
                                    int bound_bit_flag, 
                                    DB_OTMPL *def, 
                                    CTCL_ITEM *item, 
                                    int offset_size)
{
    int error = CTC_SUCCESS;
    int rc = CTC_SUCCESS;
    int *vars = NULL;
    int i, j, offset, offset2, pad;
    int col_name_len;
    char *bits, *start, *v_start;
    SM_ATTRIBUTE *att;
    DB_VALUE value;
    CTCL_COLUMN *set_col = NULL;
    CTCL_COLUMN *test_col = NULL;
    CTCG_LIST_NODE *itr;

    if (sm_class->variable_count)
    {
        vars = (int *)malloc (DB_SIZEOF (int) * sm_class->variable_count);

        if (vars == NULL)
        {
            return ER_OUT_OF_VIRTUAL_MEMORY;
        }

        offset = or_get_offset_internal (buf, &rc, offset_size);

        for (i = 0; i < sm_class->variable_count; i++)
        {
            offset2 = or_get_offset_internal (buf, &rc, offset_size);
            vars[i] = offset2 - offset;
            offset = offset2;
        }

        buf->ptr = PTR_ALIGN (buf->ptr, sizeof(int));
    }

    bits = NULL;

    if (bound_bit_flag)
    {
        bits = (char *)buf->ptr + sm_class->fixed_size;
    }

    att = sm_class->attributes;
    start = buf->ptr;

    /* initialize insert_log_info */
    ctcl_item_insert_log_info_init (item);

    /* process the fixed length column */
    for (i = 0; 
         i < sm_class->fixed_count; 
         i++, att = (SM_ATTRIBUTE *)att->header.next)
    {
        if (bits != NULL && !OR_GET_BOUND_BIT (bits, i))
        {
            /* its a NULL value, skip it */
            db_make_null (&value);
            or_advance (buf, tp_domain_disk_size (att->domain));
        }
        else
        {
            /* read the disk value into the db_value */
            (*(att->type->data_readval))(buf, &value, att->domain, 
                                         -1, true, NULL, 0);

            set_col = (CTCL_COLUMN *)malloc (sizeof (CTCL_COLUMN));
            memset (set_col->name, 0, CTCL_NAME_MAX);

            CTCG_LIST_INIT_OBJ (&set_col->node, set_col);

            /* 1. column name */
            col_name_len = strlen (att->header.name);
            memcpy (set_col->name, att->header.name, col_name_len);

            /* 2. column type */
            set_col->type = att->domain->type->id;

            /* 3. column value */
            switch (set_col->type)
            {
                case DB_TYPE_INTEGER:
                    set_col->val_len = sizeof(int);
                    set_col->val = malloc (set_col->val_len);
                    *(int *)(set_col->val) = value.data.i;
                    break;

                case DB_TYPE_CHAR:
                case DB_TYPE_VARCHAR:
                    set_col->val_len = strlen (value.data.ch.medium.buf);
                    set_col->val = malloc (set_col->val_len);
                    memcpy (set_col->val, 
                            value.data.ch.medium.buf, 
                            set_col->val_len);
                    break;

                default:
                    break;
            }

            CTCG_LIST_ADD_LAST (&(item->insert_log_info.set_col_list), 
                                &set_col->node);

            item->insert_log_info.set_col_cnt++;
        }

        /* skip cache object attribute for foreign key */
        if (att->is_fk_cache_attr)
        {
            continue;
        }

//        error = dbt_put_internal (def, att->header.name, &value);
        pr_clear_value (&value);

        if (error != CTC_SUCCESS)
        {
            if (vars != NULL)
            {
                free (vars);
                vars = NULL;
            }

            return error;
        }
    }

    /* round up to a to the end of the fixed block */
    pad = (int) (buf->ptr - start);

    if (pad < sm_class->fixed_size)
    {
        or_advance (buf, sm_class->fixed_size - pad);
    }

    /* skip over the bound bits */
    if (bound_bit_flag)
    {
        or_advance (buf, OR_BOUND_BIT_BYTES (sm_class->fixed_count));
    }

    /* process variable length column */
    v_start = buf->ptr;

    for (i = sm_class->fixed_count, j = 0;
         i < sm_class->att_count && j < sm_class->variable_count;
         i++, j++, att = (SM_ATTRIBUTE *)att->header.next)
    {
        (*(att->type->data_readval))(buf, &value, att->domain, 
                                     vars[j], true, NULL, 0);
        v_start += vars[j];
        buf->ptr = v_start;

        set_col = (CTCL_COLUMN *)malloc (sizeof (CTCL_COLUMN));
        memset (set_col->name, 0, CTCL_NAME_MAX);

        CTCG_LIST_INIT_OBJ (&set_col->node, set_col);

        /* 1. column name */
        col_name_len = strlen (att->header.name);
        memcpy (set_col->name, att->header.name, col_name_len);

        /* 2. column type */
        set_col->type = att->domain->type->id;

        /* 3. column value */
        switch (set_col->type)
        {
            case DB_TYPE_INTEGER:
                set_col->val_len = sizeof(int);
                set_col->val = malloc (set_col->val_len);
                *(int *)(set_col->val) = value.data.i;
                break;

            case DB_TYPE_CHAR:
            case DB_TYPE_VARCHAR:
                set_col->val_len = strlen (value.data.ch.medium.buf);
                set_col->val = malloc (set_col->val_len);
                memcpy (set_col->val, 
                        value.data.ch.medium.buf, 
                        set_col->val_len);
                break;

            default:
                break;
        }

        CTCG_LIST_ADD_LAST (&(item->insert_log_info.set_col_list), 
                            &set_col->node);
    
        item->insert_log_info.set_col_cnt++;

        /* update the column */
//        error = dbt_put_internal (def, att->header.name, &value);
        pr_clear_value (&value);

        if (error != CTC_SUCCESS)
        {
            if (vars != NULL)
            {
                free (vars);
                vars = NULL;
            }

            return error;
        }
    }

    /* >>> DEBUG */
    CTCG_LIST_ITERATE (&(item->insert_log_info.set_col_list), itr)
    {
        test_col = (CTCL_COLUMN *)itr->obj;

        if (test_col != NULL)
        {
            printf ("col_name = %s\n \
                    col_type = %d\n \
                    col_val_len = %d\n", 
                    test_col->name,
                    test_col->type,
                    test_col->val_len);
        }

        if (test_col->type == DB_TYPE_INTEGER)
        {
            printf ("col_val = %d\n", *(int *)(test_col->val));
        }
        else
        {
            printf ("col_val = %s\n", (char *)(test_col->val));
        }
    }
    /* <<< DEBUG */

    if (vars != NULL)
    {
        free (vars);
        vars = NULL;
    }

    return error;
}


static void ctcl_unlink_log_item (CTCL_TRANS_LOG_LIST *trans_log_list, 
                                  CTCL_ITEM *item)
{
    assert (trans_log_list != NULL);
    assert (item != NULL);

    /* Long transaction case, replication item does not make link */
    if ((item->prev == NULL && trans_log_list->head != item) || 
        (item->next == NULL && trans_log_list->tail != item))
    {
        return;
    }

    if (item->next)
    {
        item->next->prev = item->prev;
    }
    else
    {
        trans_log_list->tail = item->prev;
    }

    if (item->prev)
    {
        item->prev->next = item->next;
    }
    else
    {
        trans_log_list->head = item->next;
    }

    if ((--trans_log_list->item_num) < 0)
    {
        trans_log_list->item_num = 0;
    }

    return;
}


static void ctcl_free_log_item (CTCL_TRANS_LOG_LIST *trans_log_list, 
                                CTCL_ITEM *item)
{
    assert (trans_log_list != NULL);
    assert (item != NULL);

    ctcl_unlink_log_item (trans_log_list, item);

    if (item->table_name != NULL)
    {
        free (item->table_name);
        pr_clear_value (&item->key);
    }

    if (item->db_user != NULL)
    {
        free (item->db_user);
    }

    free (item);    
    item = NULL;

    return;
}


static void ctcl_free_all_log_items_except_head (CTCL_TRANS_LOG_LIST *trans_log_list)
{
    CTCL_ITEM *item, *next_item;

    assert (trans_log_list != NULL);

    if (trans_log_list->head)
    {
        item = trans_log_list->head->next;
    }
    else
    {
        return;
    }

    for (; item; item = next_item)
    {
        next_item = item->next;

        ctcl_free_log_item (trans_log_list, item);
        item = NULL;
    }

    return;
}


static void ctcl_free_all_log_items (CTCL_TRANS_LOG_LIST *trans_log_list)
{
    assert (trans_log_list != NULL);

    ctcl_free_all_log_items_except_head (trans_log_list);

    if (trans_log_list->head)
    {
        ctcl_free_log_item (trans_log_list, trans_log_list->head);
    }

    trans_log_list->item_num = 0;
    trans_log_list->long_tx_flag = CTC_FALSE;
    trans_log_list->head = NULL;
    trans_log_list->tail = NULL;

    return;
}


static void ctcl_clear_trans_log_list (CTCL_TRANS_LOG_LIST *trans_log_list)
{
    if (trans_log_list != NULL)
    {
        ctcl_free_all_log_items (trans_log_list);

        CTCL_LSA_SET_NULL (&trans_log_list->start_lsa);
        CTCL_LSA_SET_NULL (&trans_log_list->last_lsa);
        trans_log_list->tid = 0;
    }
    else
    {
        /* this transaction log list is empty, so do nothing */
    }

    return;
}

/*
 * Description : insert log item into trans_log_list
 *
 */
static int ctcl_insert_log_item (CTCL_LOG_PAGE *log_pg, 
                                 int log_type, 
                                 int tid, 
                                 CTCL_LOG_LSA *lsa)
{
    int result;
    CTCL_TRANS_LOG_LIST *trans_log_list;
    CTCL_ITEM *item = NULL;

    trans_log_list = ctcl_find_trans_log_list (tid);

    if (trans_log_list != NULL)
    {
        if (trans_log_list->long_tx_flag == CTC_FALSE)
        {
            if (trans_log_list->item_num >= CTCL_LOG_ITEM_MAX)
            {
                ctcl_free_all_log_items_except_head (trans_log_list);

                trans_log_list->long_tx_flag = CTC_TRUE;
                CTCL_LSA_COPY (&trans_log_list->last_lsa, lsa);
            }
            else
            {
                item = ctcl_make_item (log_pg, log_type, tid, lsa);
                CTC_COND_EXCEPTION (item == NULL, err_alloc_failed_label);

                ctcl_add_log_item_list (trans_log_list, item);
            }
        }
        else
        {
            /* TODO: long transaction */
            CTCL_LSA_COPY (&trans_log_list->last_lsa, lsa);
        }
    }
    else
    {
        /* can not find transaction log list, but SUCCESS */
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_alloc_failed_label)
    {
        result = CTC_ERR_ALLOC_FAILED;
    }
    EXCEPTION_END;

    return result;
}


/*
 * Description : add unlock_commit log to the commit list
 *
 * Note:
 *     APPLY thread traverses the transaction log pages, and finds out the
 *     REPLICATION LOG record. If it meets the REPLICATION LOG record,
 *     it adds that record to the apply list for later use.
 *     When the APPLY thread meets the LOG COMMIT record, it applies the
 *     inserted REPLICAION LOG records into the slave.
 *     The APPLY thread applies transaction  not in regular sequence of
 *     LOG_COMMIT record, but in sequence of  LOG_UNLOCK_COMMIT record.
 *     When the APPLY thread meet the LOG_UNLOCK_COMMIT record, It doesn't
 *     apply  REPLICATION LOC record to the slave and insert REPLICATION LOC
 *     record into commit list.
 */
static int ctcl_add_unlock_commit_log (int tid, CTCL_LOG_LSA *lsa)
{
    int result;
    CTCL_COMMIT *commit;

    commit = malloc (sizeof (CTCL_COMMIT));

    CTC_COND_EXCEPTION (commit == NULL, err_alloc_failed_label);

    commit->prev = NULL;
    commit->next = NULL;
    commit->type = CTCL_LOG_UNLOCK_COMMIT;
    CTCL_LSA_COPY (&commit->log_lsa, lsa);
    commit->tranid = tid;

    if (ctcl_Mgr.log_info.commit_head == NULL && 
        ctcl_Mgr.log_info.commit_tail == NULL)
    {
        ctcl_Mgr.log_info.commit_head = commit;
        ctcl_Mgr.log_info.commit_tail = commit;
    }
    else
    {
        commit->prev = ctcl_Mgr.log_info.commit_tail;
        ctcl_Mgr.log_info.commit_tail->next = commit;
        ctcl_Mgr.log_info.commit_tail = commit;
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_alloc_failed_label)
    {
        result = CTC_ERR_ALLOC_FAILED;
    }
    EXCEPTION_END;

    return result;
}


static int ctcl_add_abort_log (int tid, CTCL_LOG_LSA *lsa)
{
    int result;
    CTCL_COMMIT *commit;

    result = ctcl_add_unlock_commit_log (tid, lsa);
    CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                        err_add_unlock_commit_log_failed_label);

    commit = ctcl_Mgr.log_info.commit_tail;	/* last commit log */
    commit->type = CTCL_LOG_ABORT;
    commit->log_record_time = 0;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_add_unlock_commit_log_failed_label)
    {
        /* error info set from sub-function */
    }
    EXCEPTION_END;

    return result;
}

/*
 * Description: retrieve the timestamp of end of transaction
 *
 */
static time_t ctcl_retrieve_eot_time (CTCL_LOG_PAGE *pgptr, CTCL_LOG_LSA *lsa)
{
    int result;
    CTCL_LOG_PAGEID pageid;
    CTCL_PAGE_LENGTH offset;
    CTCL_LOG_DONETIME *donetime;
    CTCL_LOG_PAGE *pg;

    pageid = lsa->pageid;
    offset = sizeof (LOG_RECORD_HEADER) + lsa->offset;

    pg = pgptr;

    CTCL_LOG_READ_ALIGN (result, offset, pageid, pg);

    if (result != CTC_SUCCESS)
    {
        /* cannot get eot time */
        return 0;
    }

    CTCL_LOG_READ_ADVANCE (result, SSIZEOF (*donetime), offset, pageid, pg);

    if (result != CTC_SUCCESS)
    {
        /* cannot get eot time */
        return 0;
    }

    donetime = (CTCL_LOG_DONETIME *)((char *)pg->area + offset);

    return donetime->at_time;
}


/*
 * Description : update the unlock_commit log to the commit list
 *               returns commit list count
 *
 *   tid : the target transaction id
 *   type : the target log record type (LOG_COMMIT_TOPOPE | LOG_COMMIT)
 *   lsa : the target LSA of the log
 *
 */
static int ctcl_set_commit_log (int tid, 
                                int type, 
                                CTCL_LOG_LSA *lsa, 
                                time_t rec_time)
{
    int cnt = 0;
    CTCL_COMMIT *commit;

    commit = ctcl_Mgr.log_info.commit_tail;

    while (commit)
    {
        if (commit->tranid == tid)
        {
            commit->type = type;
            commit->log_record_time = rec_time;
            cnt++;
            break;
        }

        commit = commit->prev;
    }

    return cnt;
}


static char *ctcl_get_zipped_data (char *undo_data, 
                                   int undo_length, 
                                   BOOL is_diff, 
                                   BOOL is_undo_zip, 
                                   BOOL is_overflow, 
                                   char **rec_type, 
                                   char **data, 
                                   int *length)
{
    int temp_length = 0;
    int redo_length = 0;
    int rec_len = 0;

    LOG_ZIP *undo_unzip_data = NULL;
    LOG_ZIP *redo_unzip_data = NULL;

    undo_unzip_data = ctcl_Mgr.log_info.undo_unzip_ptr;
    redo_unzip_data = ctcl_Mgr.log_info.redo_unzip_ptr;

    if (is_diff)
    {
        if (is_undo_zip)
        {
            undo_length = undo_unzip_data->data_length;
            redo_length = redo_unzip_data->data_length;

            (void)log_diff (undo_length, undo_unzip_data->log_data, 
                            redo_length, redo_unzip_data->log_data);
        }
        else
        {
            redo_length = redo_unzip_data->data_length;

            (void) log_diff (undo_length, undo_data, 
                             redo_length, redo_unzip_data->log_data);
        }
    }
    else
    {
        redo_length = redo_unzip_data->data_length;
    }

    if (rec_type)
    {
        rec_len = sizeof (INT_16);
        *length = redo_length - rec_len;
    }
    else
    {
        *length = redo_length;
    }

    if (is_overflow)
    {
        if (*data)
        {
            free (*data);
            *data = NULL;
        }

        *data = malloc (*length);

        if (*data == NULL)
        {
            //er_set (ER_ERROR_SEVERITY, ARG_FILE_LINE, 
              //      ER_OUT_OF_VIRTUAL_MEMORY, 1, *length);

            *length = 0;
            return NULL;
        }
    }

    if (rec_type)
    {
        memcpy (*rec_type, 
                (ctcl_Mgr.log_info.redo_unzip_ptr)->log_data, 
                rec_len);

        memcpy (*data, 
                (ctcl_Mgr.log_info.redo_unzip_ptr)->log_data + rec_len, 
                *length);
    }
    else
    {
        memcpy (*data, 
                (ctcl_Mgr.log_info.redo_unzip_ptr)->log_data, 
                redo_length);
    }

    return *data;
}


/*
 * Description : modified from la_get_undoredo_diff()
 *               get undo/redo diff data
 *
 *   return: next log page pointer
 */
static int ctcl_get_undoredo_diff (CTCL_LOG_PAGE **pgptr, 
                                   CTCL_LOG_PAGEID *pageid, 
                                   CTCL_PAGE_LENGTH *offset, 
                                   BOOL *is_undo_zip, 
                                   char **undo_data, 
                                   int *undo_length)
{
    int result;
    LOG_ZIP *undo_unzip_data = NULL;
    CTCL_LOG_PAGE *temp_pg;
    CTCL_LOG_PAGEID temp_pageid;
    CTCL_PAGE_LENGTH temp_offset;

    undo_unzip_data = ctcl_Mgr.log_info.undo_unzip_ptr;

    temp_pg = *pgptr;
    temp_pageid = *pageid;
    temp_offset = *offset;

    if (ZIP_CHECK (*undo_length))
    {				/* Undo data is Zip Check */
        *is_undo_zip = CTC_TRUE;
        *undo_length = GET_ZIP_LEN (*undo_length);
    }

    *undo_data = (char *)malloc (*undo_length);

    CTC_COND_EXCEPTION (*undo_data == NULL, err_alloc_failed_label);

    /* get undo data for XOR process */
    ctcl_log_copy_fromlog (NULL, 
                           *undo_data, 
                           *undo_length, 
                           *pageid, 
                           *offset, 
                           *pgptr);

    if (*is_undo_zip && *undo_length > 0)
    {
        if (!log_unzip (undo_unzip_data, *undo_length, *undo_data))
        {
            free (*undo_data);
            *undo_data = NULL;

            return ER_IO_LZO_DECOMPRESS_FAIL;
        }
    }

    CTCL_LOG_READ_ADD_ALIGN (result, *undo_length, temp_offset, temp_pageid, temp_pg);

    *pgptr = temp_pg;
    *pageid = temp_pageid;
    *offset = temp_offset;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_alloc_failed_label)
    {
        result = CTC_ERR_ALLOC_FAILED;
    }
    EXCEPTION_END;

    return result;
}

/*
 * la_get_log_data() - get the data area of log record
 *   return: error code
 *   lrec (in) : target log record
 *   lsa (in) : the LSA of the target log record
 *   pgptr (in) : the start log page pointer
 *   match_rcvindex (in) : index
 *   rcvindex : recovery index to be returned
 *   logs : the specialized log info
 *   old_type : the type of old RECDES
 *   old_data : the old log data
 *   old_length : the length of old data
 *   rec_type : the type of RECDES
 *   data : the log data
 *   d_length : the length of data
 *
 * Note: get the data area, and rcvindex, length of data for the
 *              given log record
 */
static int ctcl_get_log_data (CTCL_LOG_RECORD_HEADER *lrec, 
                              CTCL_LOG_LSA *lsa, 
                              CTCL_LOG_PAGE *pgptr, 
                              unsigned int match_rcvindex, 
                              unsigned int *rcvindex, 
                              void **logs, 
                              INT_16 *old_type, 
                              char **old_data, 
                              int *old_length, 
                              char **rec_type, 
                              char **data, 
                              int *d_length)
{
    BOOL is_overflow = CTC_FALSE;
    BOOL is_diff = CTC_FALSE;
    BOOL is_undo_zip = CTC_FALSE;
    int length;	
    int error = CTC_SUCCESS;
    int rec_len = 0;
    int zip_len = 0;
    int undo_length = 0;
    int redo_length = 0;
    int temp_length = 0;
    char *undo_data = NULL;
    CTCL_LOG_PAGEID pageid;
    CTCL_PAGE_LENGTH offset;
    CTCL_LOG_PAGE *pg;
    struct log_undoredo *undoredo;
    struct log_undo *undo;
    struct log_redo *redo;

    if (old_data)
    {
        *old_type = 0;
        *old_data = NULL;
        *old_length = 0;
    }

    pg = pgptr;

    offset = sizeof (LOG_RECORD_HEADER) + lsa->offset;
    pageid = lsa->pageid;

    CTCL_LOG_READ_ALIGN (error, offset, pageid, pg);

    if (error != CTC_SUCCESS)
    {
        return error;
    }

    switch (lrec->type)
    {
        case CTCL_LOG_UNDOREDO_DATA:
        case CTCL_LOG_DIFF_UNDOREDO_DATA:

            is_diff = (lrec->type == CTCL_LOG_DIFF_UNDOREDO_DATA) ? CTC_TRUE : CTC_FALSE;

            length = sizeof (struct log_undoredo);
            CTCL_LOG_READ_ADVANCE (error, length, offset, pageid, pg);

            if (error == CTC_SUCCESS)
            {
                undoredo = (struct log_undoredo *)((char *) pg->area + offset);

                undo_length = undoredo->ulength;	/* undo log length */
                temp_length = undoredo->rlength;	/* for the replication, we just need
                                                         * the redo data */
                length = GET_ZIP_LEN (undoredo->rlength);

                if (match_rcvindex == 0 || 
                    undoredo->data.rcvindex == match_rcvindex)
                {
                    if (rcvindex)
                    {
                        *rcvindex = undoredo->data.rcvindex;
                    }

                    if (logs)
                    {
                        *logs = (void *) undoredo;
                    }
                }
                else if (logs)
                {
                    *logs = (void *)NULL;
                }

                CTCL_LOG_READ_ADD_ALIGN (error, sizeof (*undoredo), offset, pageid, pg);

                if (error == CTC_SUCCESS)
                {
                    if (is_diff || old_data)
                    {		/* XOR Redo Data */
                        error = ctcl_get_undoredo_diff (&pg, 
                                                        &pageid, 
                                                        &offset, 
                                                        &is_undo_zip, 
                                                        &undo_data, 
                                                        &undo_length);

                        if (error != CTC_SUCCESS)
                        {
                            if (undo_data != NULL)
                            {
                                free (undo_data);
                                undo_data = NULL;
                            }

                            return error;
                        }
                    }
                    else
                    {
                        CTCL_LOG_READ_ADD_ALIGN (error, GET_ZIP_LEN (undo_length),
                                               offset, pageid, pg);
                    }
                }
            }

            break;

        case CTCL_LOG_UNDO_DATA:

            length = sizeof (struct log_undo);
            CTCL_LOG_READ_ADVANCE (error, length, offset, pageid, pg);

            if (error == CTC_SUCCESS)
            {
                undo = (struct log_undo *) ((char *) pg->area + offset);
                temp_length = undo->length;
                length = (int) GET_ZIP_LEN (undo->length);

                if (match_rcvindex == 0 || undo->data.rcvindex == match_rcvindex)
                {
                    if (logs)
                    {
                        *logs = (void *) undo;
                    }
                    if (rcvindex)
                    {
                        *rcvindex = undo->data.rcvindex;
                    }
                }
                else if (logs)
                {
                    *logs = (void *) NULL;
                }

                CTCL_LOG_READ_ADD_ALIGN (error, sizeof (*undo), offset, pageid, pg);
            }
            break;

        case LOG_REDO_DATA:

            length = sizeof (struct log_redo);
            CTCL_LOG_READ_ADVANCE (error, length, offset, pageid, pg);

            if (error == CTC_SUCCESS)
            {
                redo = (struct log_redo *) ((char *) pg->area + offset);
                temp_length = redo->length;
                length = GET_ZIP_LEN (redo->length);

                if (match_rcvindex == 0 || redo->data.rcvindex == match_rcvindex)
                {
                    if (logs)
                    {
                        *logs = (void *) redo;
                    }
                    if (rcvindex)
                    {
                        *rcvindex = redo->data.rcvindex;
                    }
                }
                else if (logs)
                {
                    *logs = (void *) NULL;
                }

                CTCL_LOG_READ_ADD_ALIGN (error, sizeof (*redo), offset, pageid, pg);
            }
            break;

        default:
            if (logs)
            {
                *logs = NULL;
            }

            return error;
    }

    if (error != CTC_SUCCESS)
    {
        if (undo_data != NULL)
        {
            free (undo_data);
            undo_data = NULL;
        }

        return error;
    }

    if (*data == NULL)
    {
        /* general cases, use the pre-allocated buffer */
        *data = malloc (length);
        is_overflow = CTC_TRUE;

        if (*data == NULL)
        {
            *d_length = 0;
            if (undo_data != NULL)
            {
                free (undo_data);
                undo_data = NULL;
            }

            return ER_OUT_OF_VIRTUAL_MEMORY;
        }
    }

    if (ZIP_CHECK (temp_length))
    {
        zip_len = GET_ZIP_LEN (temp_length);

        /* Get Zip Data */
        ctcl_log_copy_fromlog (NULL, *data, zip_len, pageid, offset, pg);

        if (zip_len != 0)
        {
            if (!log_unzip (ctcl_Mgr.log_info.redo_unzip_ptr, zip_len, *data))
            {
                if (undo_data != NULL)
                {
                    free (undo_data);
                    undo_data = NULL;
                }

                return ER_IO_LZO_DECOMPRESS_FAIL;
            }
        }

        *data = ctcl_get_zipped_data (undo_data, 
                                    undo_length, 
                                    is_diff, 
                                    is_undo_zip, 
                                    is_overflow, 
                                    rec_type, 
                                    data, 
                                    &length);

        if (*data == NULL)
        {
            //error = er_errid ();
        }
    }
    else
    {
        /* Get Redo Data */
        ctcl_log_copy_fromlog (rec_type ? *rec_type : NULL, 
                               *data, 
                               length, 
                               pageid, 
                               offset, 
                               pg);
    }

    *d_length = length;

    if (old_data && error == CTC_SUCCESS)
    {
        rec_len = sizeof (INT_16);

        if (is_undo_zip)
        {
            *old_length = (ctcl_Mgr.log_info.undo_unzip_ptr)->data_length - rec_len;
            *old_data = (char *)malloc (*old_length);

            memcpy (old_type, (ctcl_Mgr.log_info.undo_unzip_ptr)->log_data, rec_len);
            memcpy (*old_data, (ctcl_Mgr.log_info.undo_unzip_ptr)->log_data + rec_len,
                    *old_length);
        }
        else
        {
            if (undo_data)
            {
                *old_length = undo_length - rec_len;
                *old_data = (char *)malloc (*old_length);

                memcpy (old_type, undo_data, rec_len);
                memcpy (*old_data, undo_data + rec_len, *old_length);
            }
        }
    }

    if (undo_data != NULL)
    {
        free (undo_data);
        undo_data = NULL;
    }

    return error;
}

/*
 * Description : modified from la_get_overflow_update_recdes()
 *               prepare the overflow page update
 *
 */
static int ctcl_get_overflow_recdes (CTCL_LOG_RECORD_HEADER *log_record, 
                                     void *logs, 
                                     char **area, 
                                     int *length, 
                                     unsigned int rcvindex)
{
    BOOL first = CTC_TRUE;
    int copyed_len;
    int area_len;
    int area_offset;
    int error = CTC_SUCCESS;
    CTCL_LOG_LSA current_lsa;
    CTCL_LOG_PAGE *current_log_page;
    CTCL_LOG_RECORD_HEADER *current_log_record;
    CTCL_OVF_PAGE_LIST *ovf_list_head = NULL;
    CTCL_OVF_PAGE_LIST *ovf_list_tail = NULL;
    CTCL_OVF_PAGE_LIST *ovf_list_data = NULL;
    struct log_redo *redo_log;
    void *log_info;
    VPID *temp_vpid;
    VPID prev_vpid;

    CTCL_LSA_COPY (&current_lsa, &log_record->prev_tranlsa);
    prev_vpid.pageid = ((struct log_undoredo *) logs)->data.pageid;
    prev_vpid.volid = ((struct log_undoredo *) logs)->data.volid;

    while (!CTCL_LSA_ISNULL (&current_lsa))
    {
        current_log_page = ctcl_get_page (current_lsa.pageid);
        current_log_record = CTCL_GET_LOG_RECORD_HEADER (current_log_page, 
                                                         &current_lsa);

        if (current_log_record->trid != log_record->trid || 
            current_log_record->type == CTCL_LOG_DUMMY_OVF_RECORD)
        {
            ctcl_release_page_buffer (current_lsa.pageid);
            break;
        }
        else if (current_log_record->type == CTCL_LOG_REDO_DATA)
        {
            /* process only LOG_REDO_DATA */

            ovf_list_data = 
                (CTCL_OVF_PAGE_LIST *)malloc (sizeof (CTCL_OVF_PAGE_LIST));

            if (ovf_list_data == NULL)
            {
                /* malloc failed */
                while (ovf_list_head)
                {
                    ovf_list_data = ovf_list_head;
                    ovf_list_head = ovf_list_head->next;

                    if (ovf_list_data)
                    {
                        if (ovf_list_data->data)
                        {
                            free (ovf_list_data->data);
                            ovf_list_data->data = NULL;
                        }

                        free (ovf_list_data);
                        ovf_list_data = NULL;
                    }
                }

                ctcl_release_page_buffer (current_lsa.pageid);

               // er_set (ER_ERROR_SEVERITY, ARG_FILE_LINE,
                 //       ER_OUT_OF_VIRTUAL_MEMORY, 1,
                   //     sizeof (CTCL_OVF_PAGE_LIST));

                return ER_OUT_OF_VIRTUAL_MEMORY;
            }

            memset (ovf_list_data, 0, sizeof (CTCL_OVF_PAGE_LIST));

            error = ctcl_get_log_data (current_log_record, 
                                       &current_lsa, 
                                       current_log_page, 
                                       rcvindex, 
                                       NULL, 
                                       &log_info, 
                                       NULL, 
                                       NULL, 
                                       NULL, 
                                       NULL,
                                       &ovf_list_data->data, 
                                       &ovf_list_data->length);

            if (error == CTC_SUCCESS && log_info && ovf_list_data->data)
            {
                /* add to linked-list */
                if (ovf_list_head == NULL)
                {
                    ovf_list_head = ovf_list_tail = ovf_list_data;
                }
                else
                {
                    ovf_list_data->next = ovf_list_head;
                    ovf_list_head = ovf_list_data;
                }

                *length += ovf_list_data->length;
            }
            else
            {
                if (ovf_list_data->data != NULL)
                {
                    free (ovf_list_data->data);
                    ovf_list_data->data = NULL;
                }

                free (ovf_list_data);
            }
        }

        ctcl_release_page_buffer (current_lsa.pageid);
        CTCL_LSA_COPY (&current_lsa, &current_log_record->prev_tranlsa);
    }

    *area = malloc (*length);

    if (*area == NULL)
    {
        /* malloc failed: clear linked-list */
        while (ovf_list_head)
        {
            ovf_list_data = ovf_list_head;
            ovf_list_head = ovf_list_head->next;

            if (ovf_list_data)
            {
                if (ovf_list_data->data)
                {
                    free (ovf_list_data->data);
                    ovf_list_data->data = NULL;
                }

                free (ovf_list_data);
                ovf_list_data = NULL;
            }
        }

       // er_set (ER_ERROR_SEVERITY, ARG_FILE_LINE, 
         //       ER_OUT_OF_VIRTUAL_MEMORY, 1, *length);
        return ER_OUT_OF_VIRTUAL_MEMORY;
    }

    /* make record description */
    copyed_len = 0;

    while (ovf_list_head)
    {
        ovf_list_data = ovf_list_head;
        ovf_list_head = ovf_list_head->next;

        if (first)
        {
            area_offset = offsetof (CTCL_OVF_FIRST_PART, data);
            first = CTC_FALSE;
        }
        else
        {
            area_offset = offsetof (CTCL_OVF_REST_PARTS, data);
        }

        area_len = ovf_list_data->length - area_offset;

        memcpy (*area + copyed_len, 
                ovf_list_data->data + area_offset, 
                area_len);

        copyed_len += area_len;

        if (ovf_list_data)
        {
            if (ovf_list_data->data)
            {
                free (ovf_list_data->data);
                ovf_list_data->data = NULL;
            }

            free (ovf_list_data);
            ovf_list_data = NULL;
        }
    }

    return error;
}

/*
 * la_get_next_update_log() - get the right update log
 *   return: CTC_SUCCESS or error code
 *   prev_lrec(in):  prev log record
 *   pgptr(in):  the start log page pointer
 *   logs(out) : the specialized log info
 *   rec_type(out) : the type of RECDES
 *   data(out) : the log data
 *   d_length(out): the length of data
 *
 * Note:
 *      When the applier meets the REC_ASSIGN_ADDRESS or REC_RELOCATION
 *      record, it should fetch the real UPDATE log record to be processed.
 */
static int ctcl_get_next_update_log (CTCL_LOG_RECORD_HEADER *prev_lrec, 
                                     CTCL_LOG_PAGE *pgptr, 
                                     void **logs, 
                                     char **rec_type, 
                                     char **data, 
                                     int *d_length)
{
    BOOL is_diff = CTC_FALSE;
    BOOL is_undo_zip = CTC_FALSE;
    int length;	
    int zip_len = 0;
    int rec_len = 0;
    int temp_length = 0;
    int undo_length = 0;
    int redo_length = 0;
    int error = CTC_SUCCESS;
    char *undo_data = NULL;
    CTCL_LOG_PAGE *pg;
    CTCL_LOG_LSA lsa;
    CTCL_PAGE_LENGTH offset;
    CTCL_LOG_PAGEID pageid;
    CTCL_LOG_RECORD_HEADER *lrec;
    struct log_undoredo *undoredo;
    struct log_undoredo *prev_log;
    LOG_ZIP *redo_unzip_data = NULL;


    pg = pgptr;
    CTCL_LSA_COPY (&lsa, &prev_lrec->forw_lsa);
    prev_log = *(struct log_undoredo **) logs;

    redo_unzip_data = ctcl_Mgr.log_info.redo_unzip_ptr;

    while (CTC_TRUE)
    {
        while (pg && pg->hdr.logical_pageid == lsa.pageid)
        {
            lrec = CTCL_GET_LOG_RECORD_HEADER (pg, &lsa);

            if (lrec->trid == prev_lrec->trid && 
                (lrec->type == CTCL_LOG_UNDOREDO_DATA || 
                 lrec->type == CTCL_LOG_DIFF_UNDOREDO_DATA))
            {
                is_diff = (lrec->type == 
                           CTCL_LOG_DIFF_UNDOREDO_DATA) ? CTC_TRUE : CTC_FALSE;

                offset = sizeof (CTCL_LOG_RECORD_HEADER) + lsa.offset;
                pageid = lsa.pageid;
                CTCL_LOG_READ_ALIGN (error, offset, pageid, pg);
                length = sizeof (struct log_undoredo);
                CTCL_LOG_READ_ADVANCE (error, length, offset, pageid, pg);

                if (error == CTC_SUCCESS)
                {
                    undoredo = (struct log_undoredo *)((char *) pg->area + offset);
                    undo_length = undoredo->ulength;
                    temp_length = undoredo->rlength;
                    length = GET_ZIP_LEN (undoredo->rlength);

                    if (undoredo->data.rcvindex == RVHF_UPDATE         &&
                        undoredo->data.pageid == prev_log->data.pageid &&
                        undoredo->data.offset == prev_log->data.offset &&
                        undoredo->data.volid == prev_log->data.volid)
                    {
                        CTCL_LOG_READ_ADD_ALIGN (error, sizeof (*undoredo), 
                                                 offset, pageid, pg);

                        if (is_diff)
                        {
                            error = ctcl_get_undoredo_diff (&pg, 
                                                            &pageid, 
                                                            &offset, 
                                                            &is_undo_zip, 
                                                            &undo_data, 
                                                            &undo_length);

                            if (error != CTC_SUCCESS)
                            {
                                if (undo_data != NULL)
                                {
                                    free (undo_data);
                                    undo_data = NULL;
                                }

                                return error;
                            }
                        }
                        else
                        {
                            CTCL_LOG_READ_ADD_ALIGN (error, 
                                                     GET_ZIP_LEN (undo_length), 
                                                     offset, pageid, pg);
                        }

                        if (ZIP_CHECK (temp_length))
                        {
                            zip_len = GET_ZIP_LEN (temp_length);

                            ctcl_log_copy_fromlog (NULL, 
                                                   *data, 
                                                   zip_len, 
                                                   pageid, 
                                                   offset, 
                                                   pg);

                            if (zip_len != 0)
                            {
                                if (!log_unzip (redo_unzip_data, zip_len, *data))
                                {
                                    if (undo_data != NULL)
                                    {
                                        free (undo_data);
                                        undo_data = NULL;
                                    }

                                    //er_set (ER_ERROR_SEVERITY, ARG_FILE_LINE,
                                      //      ER_IO_LZO_DECOMPRESS_FAIL, 0);

                                    return ER_IO_LZO_DECOMPRESS_FAIL;
                                }
                            }

                            *data = ctcl_get_zipped_data (undo_data, 
                                                          undo_length, 
                                                          is_diff, 
                                                          is_undo_zip, 
                                                          0, 
                                                          rec_type, 
                                                          data, 
                                                          &length);

                            if (*data == NULL)
                            {
                                //error = er_errid ();
                            }
                        }
                        else
                        {
                            ctcl_log_copy_fromlog (rec_type ? *rec_type : NULL, 
                                                   *data, 
                                                   length, 
                                                   pageid, 
                                                   offset, 
                                                   pg);
                        }

                        *d_length = length;

                        if (undo_data != NULL)
                        {
                            free (undo_data);
                            undo_data = NULL;
                        }

                        return error;
                    }
                }
            }
            else if (lrec->trid == prev_lrec->trid && 
                     (lrec->type == CTCL_LOG_COMMIT || 
                      lrec->type == CTCL_LOG_ABORT))
            {
                return ER_GENERIC_ERROR;
            }

            CTCL_LSA_COPY (&lsa, (CTCL_LOG_LSA *)&lrec->forw_lsa);
        }

        pg = ctcl_get_page (lsa.pageid);
    }

    return error;
}


static int ctcl_get_relocation_recdes (CTCL_LOG_RECORD_HEADER *lrec, 
                                       CTCL_LOG_PAGE *pgptr, 
                                       unsigned int match_rcvindex, 
                                       void **logs, 
                                       char **rec_type, 
                                       char **data, 
                                       int *d_length)
{
    CTCL_LOG_RECORD_HEADER *tmp_lrec;
    unsigned int rcvindex;
    CTCL_LOG_PAGE *pg = pgptr;
    CTCL_LOG_LSA lsa;
    int error = CTC_SUCCESS;

    CTCL_LSA_COPY (&lsa, (CTCL_LOG_LSA *)&lrec->prev_tranlsa);

    if (!CTCL_LSA_ISNULL (&lsa))
    {
        pg = ctcl_get_page (lsa.pageid);
        tmp_lrec = CTCL_GET_LOG_RECORD_HEADER (pg, &lsa);

        if (tmp_lrec->trid != lrec->trid)
        {
            error = ER_LOG_PAGE_CORRUPTED;
        }
        else
        {
            error = ctcl_get_log_data (tmp_lrec, 
                                     &lsa, 
                                     pg, 
                                     RVHF_INSERT, 
                                     &rcvindex, 
                                     logs, 
                                     NULL, 
                                     NULL, 
                                     NULL, 
                                     rec_type, 
                                     data, 
                                     d_length);
        }

        ctcl_release_page_buffer (lsa.pageid);
    }
    else
    {
        error = ER_LOG_PAGE_CORRUPTED;
    }

    return error;
}

/*
 * Description : modified from la_get_recdes () 
 *               retrieves record description for the given lsa 
 *               from the log file
 *
 *    pgptr : pointer to the target log page
 *    old_recdes : old record description (output)
 *    recdes : record description (output)
 *    rcvindex : recovery index (output)
 *    log_data : log data area
 *    is_overflow : CTC_TRUE if the log data is in overflow page
 *
 */
static int ctcl_get_recdes (CTCL_LOG_LSA *lsa, 
                            CTCL_LOG_PAGE *pgptr, 
                            RECDES *old_recdes, 
                            RECDES *recdes, 
                            unsigned int *rcvindex, 
                            char *log_data, 
                            char *rec_type, 
                            BOOL *is_overflow)
{
    int result;
    int length = 0;
    int old_length = 0;
    char *old_log_data = NULL;
    char *area = NULL;
    void *logs = NULL;
    INT_16 old_type;
    CTCL_LOG_RECORD_HEADER *lrec;
    CTCL_LOG_PAGE *pg;

    pg = pgptr;
    lrec = CTCL_GET_LOG_RECORD_HEADER (pg, lsa);

    if (old_recdes)
    {
        result = ctcl_get_log_data (lrec, lsa, pg, 0, rcvindex,
                                 &logs, &old_type, &old_log_data, &old_length,
                                 &rec_type, &log_data, &length);
    }
    else
    {
        result = ctcl_get_log_data (lrec, lsa, pg, 0, rcvindex,
                                 &logs, NULL, NULL, NULL,
                                 &rec_type, &log_data, &length);
    }

    CTC_COND_EXCEPTION (result != CTC_SUCCESS || logs == NULL,
                        err_get_log_data_failed_label);

    recdes->type = *(INT16 *)(rec_type);
    recdes->data = log_data;
    recdes->area_size = recdes->length = length;

    if (old_recdes)
    {
        old_recdes->type = old_type;
        old_recdes->data = old_log_data;
        old_recdes->area_size = old_recdes->length = old_length;
    }

    /* Now.. we have to process overflow pages */
    length = 0;

    if (*rcvindex == RVOVF_CHANGE_LINK)
    {
        /* if overflow page update */
        result = ctcl_get_overflow_recdes (lrec, 
                                           logs, 
                                           &area, 
                                           &length, 
                                           RVOVF_PAGE_UPDATE);

        recdes->type = REC_BIGONE;
    }
    else if (recdes->type == REC_BIGONE)
    {
        /* if overflow page insert */
        result = ctcl_get_overflow_recdes (lrec, 
                                           logs, 
                                           &area, 
                                           &length, 
                                           RVOVF_NEWPAGE_INSERT);
    }
    else if (*rcvindex == RVHF_INSERT && recdes->type == REC_ASSIGN_ADDRESS)
    {
        result = ctcl_get_next_update_log (lrec, 
                                           pg, 
                                           &logs, 
                                           &rec_type, 
                                           &log_data, 
                                           &length);

        CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                            err_get_next_update_log_failed_label);

        recdes->type = *(INT16 *)(rec_type);

        if (recdes->type == REC_BIGONE)
        {
            result = ctcl_get_overflow_recdes (lrec, 
                                               logs, 
                                               &area, 
                                               &length, 
                                               RVOVF_NEWPAGE_INSERT);
        }
        else
        {
            recdes->data = log_data;
            recdes->area_size = recdes->length = length;
            return result;
        }
    }
    else if (*rcvindex == RVHF_UPDATE && recdes->type == REC_RELOCATION)
    {
        result = ctcl_get_relocation_recdes (lrec, 
                                             pg, 
                                             0, 
                                             &logs, 
                                             &rec_type, 
                                             &log_data, 
                                             &length);

        if (result == CTC_SUCCESS)
        {
            recdes->type = *(INT16 *) (rec_type);
            recdes->data = log_data;
            recdes->area_size = recdes->length = length;
        }

        return result;
    }
    else
    {
        return result;
    }

    CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_final_check_label);

    recdes->data = (char *)(area);
    recdes->area_size = recdes->length = length;
    *is_overflow = CTC_TRUE;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_get_log_data_failed_label)
    {
        /* error info set from sub-function */
    }
    CTC_EXCEPTION (err_get_next_update_log_failed_label)
    {
        /* error info set from sub-function */
    }
    CTC_EXCEPTION (err_final_check_label)
    {
        /* error info set from sub-function */
        if (area != NULL)
        {
            free (area);
            area = NULL;
        }
    }
    EXCEPTION_END;

    return result;
}


/*
 * la_apply_commit_list() - apply the log to the target slave
 *   return: CTC_SUCCESS or error code
 *   lsa   : the target LSA of the log
 *   final_pageid : the final pageid
 *
 * Note:
 *    This function is called when the APPLY thread meets the LOG_COMMIT
 *    record.
 */
static int ctcl_apply_commit_list (CTCL_LOG_LSA *lsa, 
                                   CTCL_LOG_PAGEID final_pageid)
{
    CTCL_COMMIT *commit;

    CTCL_LSA_SET_NULL (lsa);

    commit = ctcl_Mgr.log_info.commit_head;

    if (commit != NULL)
    {
        if (commit->type == CTCL_LOG_COMMIT        || 
            commit->type == CTCL_LOG_COMMIT_TOPOPE || 
            commit->type == CTCL_LOG_ABORT)
        {
            CTCL_LSA_COPY (lsa, &commit->log_lsa);

            if (commit->type == CTCL_LOG_COMMIT)
            {
                ctcl_Mgr.log_info.log_record_time = commit->log_record_time;
            }

            if (commit->next != NULL)
            {
                commit->next->prev = NULL;
            }

            ctcl_Mgr.log_info.commit_head = commit->next;

            if (ctcl_Mgr.log_info.commit_head == NULL)
            {
                ctcl_Mgr.log_info.commit_tail = NULL;
            }

            if (commit)
            {
                free (commit);
                commit = NULL;
            }
        }
        else
        {
            /* log type is not COMMIT */
        }
    }
    else
    {
        /* nothing to do */
    }

    return CTC_SUCCESS;
}

/*
 * la_free_repl_items_by_tranid() - clear replication item using tranid
 *   return: none
 *   tranid: transaction id
 *
 * Note:
 *       clear the applied list area after processing ..
 *       When we meet the LOG_ABORT_TOPOPE or LOG_ABORT record,
 *       we have to clear the replication items of the target transaction.
 *       In case of LOG_ABORT_TOPOPE, the apply list should be preserved
 *       for the later use (so call la_clear_applied_info() using
 *       CTC_FALSE as the second argument).
 */
static void ctcl_free_log_items_by_tranid (int tid)
{
    CTCL_COMMIT *commit, *commit_next;
    CTCL_TRANS_LOG_LIST *trans_log_list;

    trans_log_list = ctcl_find_trans_log_list (tid);

    if (trans_log_list)
    {
        ctcl_clear_trans_log_list (trans_log_list);
    }

    for (commit = ctcl_Mgr.log_info.commit_head; commit; commit = commit_next)
    {
        commit_next = commit->next;

        if (commit->tranid == tid)
        {
            if (commit->next)
            {
                commit->next->prev = commit->prev;
            }
            else
            {
                ctcl_Mgr.log_info.commit_tail = commit->prev;
            }

            if (commit->prev)
            {
                commit->prev->next = commit->next;
            }
            else
            {
                ctcl_Mgr.log_info.commit_head = commit->next;
            }

            commit->next = NULL;
            commit->prev = NULL;

            free (commit);
            commit = NULL;
        }
    }

    if (ctcl_Mgr.log_info.commit_head == NULL)
    {
        ctcl_Mgr.log_info.commit_tail = NULL;
    }

    return;
}


static CTCL_ITEM *ctcl_get_next_log_item (CTCL_ITEM *item, 
                                          BOOL is_long_trans, 
                                          CTCL_LOG_LSA *last_lsa)
{
    if (is_long_trans)
    {
        return ctcl_get_next_log_item_from_log (item, last_lsa);
    }
    else
    {
        return ctcl_get_next_log_item_from_list (item);
    }
}


static CTCL_ITEM *ctcl_get_next_log_item_from_list (CTCL_ITEM *item)
{
    return (item->next);
}


static CTCL_ITEM *ctcl_get_next_log_item_from_log (CTCL_ITEM *item, 
                                                   CTCL_LOG_LSA *last_lsa)
{
    CTCL_LOG_LSA prev_repl_lsa;
    CTCL_LOG_LSA curr_lsa;
    CTCL_LOG_PAGE *curr_log_page;
    CTCL_LOG_RECORD_HEADER *prev_repl_log_record = NULL;
    CTCL_LOG_RECORD_HEADER *curr_log_record;
    CTCL_ITEM *next_item = NULL;

    CTCL_LSA_COPY (&prev_repl_lsa, &item->lsa);
    CTCL_LSA_COPY (&curr_lsa, &item->lsa);

    while (!CTCL_LSA_ISNULL (&curr_lsa))
    {
        curr_log_page = ctcl_get_page (curr_lsa.pageid);
        curr_log_record = CTCL_GET_LOG_RECORD_HEADER (curr_log_page, &curr_lsa);

        if (prev_repl_log_record == NULL)
        {
            prev_repl_log_record =
                (CTCL_LOG_RECORD_HEADER *)malloc (sizeof (CTCL_LOG_RECORD_HEADER));

            if (prev_repl_log_record == NULL)
            {
                return NULL;
            }

            memcpy (prev_repl_log_record, 
                    curr_log_record,
                    sizeof (LOG_RECORD_HEADER));
        }

        if (!CTCL_LSA_EQ (&curr_lsa, &prev_repl_lsa) && 
            prev_repl_log_record->trid == curr_log_record->trid)
        {
            if (CTCL_LSA_GT (&curr_lsa, last_lsa)        || 
                curr_log_record->type == CTCL_LOG_COMMIT || 
                curr_log_record->type == CTCL_LOG_ABORT  || 
                CTCL_LSA_GE (&curr_lsa, (CTCL_LOG_LSA *)&ctcl_Mgr.log_info.act_log.log_hdr->eof_lsa))
            {
                break;
            }

            if (curr_log_record->type == CTCL_LOG_REPLICATION_DATA || 
                curr_log_record->type == CTCL_LOG_REPLICATION_SCHEMA)
            {
                next_item = ctcl_make_item (curr_log_page, 
                                            curr_log_record->type, 
                                            curr_log_record->trid, 
                                            &curr_lsa);

                assert (next_item);

                break;
            }

        }
        else
        {
            /* nothing to do */
        }

        ctcl_release_page_buffer (curr_lsa.pageid);
        CTCL_LSA_COPY (&curr_lsa, &curr_log_record->forw_lsa);
    }

    if (prev_repl_log_record)
    {
        free (prev_repl_log_record);
        prev_repl_log_record = NULL;
    }

    return next_item;
}


static int ctcl_log_record_process (CTCL_LOG_RECORD_HEADER *lrec, 
                                    CTCL_LOG_LSA *final, 
                                    CTCL_LOG_PAGE *pg_ptr)
{
    CTCL_TRANS_LOG_LIST *apply = NULL;
    int result;
    CTCL_LOG_LSA lsa_apply;
    CTCL_LOG_LSA required_lsa;
    CTCL_LOG_PAGEID final_pageid;
    int commit_list_count;
    struct log_ha_server_state *ha_server_state;
    char buffer[256];

    if (lrec->trid == CTCL_TRAN_NULL_ID          || 
        CTCL_LSA_GT (&lrec->prev_tranlsa, final) || 
        CTCL_LSA_GT (&lrec->back_lsa, final))
    {
        CTC_COND_EXCEPTION (lrec->type != CTCL_LOG_END_OF_LOG &&
                            lrec->type != CTCL_LOG_DUMMY_FILLPAGE_FORARCHIVE,
                            err_log_page_corrupted_label);
    }

    if (lrec->type != CTCL_LOG_END_OF_LOG            && 
        lrec->type != CTCL_LOG_DUMMY_HA_SERVER_STATE && 
        lrec->trid != LOG_SYSTEM_TRANID              && 
        CTCL_LSA_ISNULL (&lrec->prev_tranlsa))
    {
        apply = ctcl_get_trans_log_list_set_tid (lrec->trid);

        CTC_COND_EXCEPTION (apply == NULL, 
                            err_add_trans_log_list_failed_label);

        if (CTCL_LSA_ISNULL (&apply->start_lsa))
        {
            CTCL_LSA_COPY (&apply->start_lsa, final);
        }
    }

    ctcl_Mgr.log_info.is_end_of_record = CTC_FALSE;

    switch (lrec->type)
    {
        case CTCL_LOG_DUMMY_FILLPAGE_FORARCHIVE:

            final->pageid++;
            final->offset = 0;
            break;

        case CTCL_LOG_END_OF_LOG:

            if (ctcl_check_page_exist (final->pageid + 1) && 
                ctcl_check_page_exist (final->pageid) == CTCL_PAGE_EXST_IN_ARCHIVE_LOG)
            {
                final->pageid++;
                final->offset = 0;
            }
            else
            {
                ctcl_Mgr.log_info.is_end_of_record = CTC_TRUE;
            }

            break;

        case CTCL_LOG_REPLICATION_DATA:
        case CTCL_LOG_REPLICATION_SCHEMA:

            /* add replication log to target transaction */
            result = ctcl_insert_log_item (pg_ptr, lrec->type, lrec->trid, final);

            CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                err_set_repl_log_failed_label);
            break;

        case CTCL_LOG_UNLOCK_COMMIT:
        case CTCL_LOG_COMMIT_TOPOPE:

            apply = ctcl_get_trans_log_list_set_tid (lrec->trid);
            apply->is_committed = CTC_TRUE;
            apply->ref_cnt = ctcl_mgr_get_cur_job_cnt ();
            /* add the repl_list to the commit_list  */
            result = ctcl_add_unlock_commit_log (lrec->trid, final);
            CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                err_add_unlock_commit_log_failed_label);

            if (lrec->type != CTCL_LOG_COMMIT_TOPOPE)
            {
                break;
            }

        case CTCL_LOG_COMMIT:

            apply = ctcl_get_trans_log_list_set_tid (lrec->trid);
            apply->is_committed = CTC_TRUE;
            apply->ref_cnt = ctcl_mgr_get_cur_job_cnt ();
            /* apply the replication log to the slave */
            if (CTCL_LSA_GT (final, &ctcl_Mgr.log_info.committed_lsa))
            {
                time_t eot_time;

                if (lrec->type == CTCL_LOG_COMMIT_TOPOPE)
                {
                    eot_time = 0;
                }
                else
                {
                    eot_time = ctcl_retrieve_eot_time (pg_ptr, final);
                }

                commit_list_count = ctcl_set_commit_log (lrec->trid, 
                                                         lrec->type, 
                                                         final, 
                                                         eot_time);

                if (commit_list_count <= 0)
                {
                    /* cannot find commit list */
                    ctcl_free_log_items_by_tranid (lrec->trid);
                    break;
                }

                final_pageid = (pg_ptr) ? pg_ptr->hdr.logical_pageid : CTCL_PAGE_NULL_ID;

                do
                {
                    result = ctcl_apply_commit_list (&lsa_apply, final_pageid);

                    if (!CTCL_LSA_ISNULL (&lsa_apply))
                    {
                        CTCL_LSA_COPY (&(ctcl_Mgr.log_info.committed_lsa), &lsa_apply);

                        if (lrec->type == CTCL_LOG_COMMIT)
                        {
                            ctcl_Mgr.log_info.commit_counter++;
                        }

                    }
                }
                while (!CTCL_LSA_ISNULL (&lsa_apply));	/* if lsa_apply is not null then
                                                         * there is the replication log
                                                         * applying to the slave
                                                         */
            }
            else
            {
                ctcl_free_log_items_by_tranid (lrec->trid);
            }
            break;

        case CTCL_LOG_UNLOCK_ABORT:

            apply = ctcl_get_trans_log_list_set_tid (lrec->trid);
            ctcl_clear_trans_log_list (apply);
            break;

        case CTCL_LOG_ABORT:

            result = ctcl_add_abort_log (lrec->trid, final);
            CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                err_add_abort_log_failed_label);

            apply = ctcl_get_trans_log_list_set_tid (lrec->trid);
            ctcl_clear_trans_log_list (apply);

            break;

        case CTCL_LOG_DUMMY_CRASH_RECOVERY:

            CTCL_LSA_COPY (final, &lrec->forw_lsa);
            break;

        case CTCL_LOG_END_CHKPT:
            break;

        case CTCL_LOG_DUMMY_HA_SERVER_STATE:
            break;

        default:
            break;
    }

    CTC_COND_EXCEPTION (lrec->forw_lsa.pageid == -1 || 
                        lrec->type <= CTCL_LOG_SMALLER_LOGREC_TYPE || 
                        lrec->type >= CTCL_LOG_LARGER_LOGREC_TYPE,
                        err_final_log_page_corrupted_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_log_page_corrupted_label)
    {
        ctcl_Mgr.need_stop_analyzer = CTC_TRUE;
        result = CTC_ERR_PAGE_CORRUPTED_FAILED;
    }
    CTC_EXCEPTION (err_add_trans_log_list_failed_label)
    {
        ctcl_Mgr.need_stop_analyzer = CTC_TRUE;
        result = CTC_FAILURE;
    }
    CTC_EXCEPTION (err_add_unlock_commit_log_failed_label)
    {
        ctcl_Mgr.need_stop_analyzer = CTC_TRUE;
    }
    CTC_EXCEPTION (err_set_repl_log_failed_label)
    {
        ctcl_Mgr.need_stop_analyzer = CTC_TRUE;
    }
    CTC_EXCEPTION (err_add_abort_log_failed_label)
    {
        ctcl_Mgr.need_stop_analyzer = CTC_TRUE;
    }
    CTC_EXCEPTION (err_final_log_page_corrupted_label)
    {
        if (ctcl_check_page_exist (final->pageid) == CTCL_PAGE_EXST_IN_ARCHIVE_LOG)
        {
            final->pageid++;
            final->offset = 0;
        }

        result = CTC_ERR_PAGE_CORRUPTED_FAILED;
    }

    EXCEPTION_END;

    return result;
}


static void ctcl_shutdown (void)
{
    int i;

    /* clean up */
    if (ctcl_Mgr.log_info.act_log.log_vdes != NULL_VOLDES)
    {
        fileio_close (ctcl_Mgr.log_info.act_log.log_vdes);
        ctcl_Mgr.log_info.act_log.log_vdes = NULL_VOLDES;
    }

    if (ctcl_Mgr.log_info.log_data != NULL)
    {
        free (ctcl_Mgr.log_info.log_data);
        ctcl_Mgr.log_info.log_data = NULL;
    }

    if (ctcl_Mgr.log_info.rec_type != NULL)
    {
        free (ctcl_Mgr.log_info.rec_type);
        ctcl_Mgr.log_info.rec_type = NULL;
    }

    if (ctcl_Mgr.log_info.undo_unzip_ptr != NULL)
    {
        log_zip_free (ctcl_Mgr.log_info.undo_unzip_ptr);
        ctcl_Mgr.log_info.undo_unzip_ptr = NULL;
    }

    if (ctcl_Mgr.log_info.redo_unzip_ptr != NULL)
    {
        log_zip_free (ctcl_Mgr.log_info.redo_unzip_ptr);
        ctcl_Mgr.log_info.redo_unzip_ptr = NULL;
    }

    if (ctcl_Mgr.log_info.cache_pb != NULL)
    {
        if (ctcl_Mgr.log_info.cache_pb->buffer_area != NULL)
        {
            free (ctcl_Mgr.log_info.cache_pb->buffer_area);
            ctcl_Mgr.log_info.cache_pb->buffer_area = NULL;
        }

        if (ctcl_Mgr.log_info.cache_pb->log_buffer != NULL)
        {
            free (ctcl_Mgr.log_info.cache_pb->log_buffer);
            ctcl_Mgr.log_info.cache_pb->log_buffer = NULL;
        }

        if (ctcl_Mgr.log_info.cache_pb->hash_table != NULL)
        {
            mht_destroy (ctcl_Mgr.log_info.cache_pb->hash_table);
            ctcl_Mgr.log_info.cache_pb->hash_table = NULL;
        }

        free (ctcl_Mgr.log_info.cache_pb);
        ctcl_Mgr.log_info.cache_pb = NULL;
    }

    if (ctcl_Mgr.log_info.trans_log_list)
    {
        for (i = 0; i < ctcl_Mgr.log_info.trans_cnt; i++)
        {
            if (ctcl_Mgr.log_info.trans_log_list[i] != NULL)
            {
                free (ctcl_Mgr.log_info.trans_log_list[i]);
                ctcl_Mgr.log_info.trans_log_list[i] = NULL;
            }
        }

        free (ctcl_Mgr.log_info.trans_log_list);
        ctcl_Mgr.log_info.trans_log_list = NULL;
    }

    if (ctcl_Mgr.log_info.act_log.hdr_page)
    {
        free (ctcl_Mgr.log_info.act_log.hdr_page);
        ctcl_Mgr.log_info.act_log.hdr_page = NULL;
    }
}


static int ctcl_start_log_analyzer (CTCL_ARGS *ctcl_args)
{
    BOOL is_analyzer_started = CTC_FALSE;
    int result;
    int thr_ret = 0;
    pthread_t la_thr;
    pthread_t tr_thr;

    result = pthread_create (&la_thr, 
                             NULL, 
                             ctcl_log_analyzer_thr_func, 
                             (void *)ctcl_args);

    CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_create_thread_failed_label); 

    /* register thread id to manager */
    ctcl_Mgr.analyzer_thr = la_thr;

    is_analyzer_started = CTC_TRUE;

    fprintf (stdout, "\n Log analyzer thread created.\n");
    fflush (stdout);

    result = pthread_create (&tr_thr, 
                             NULL, 
                             (void *)ctcl_trans_remover_thr_func, 
                             NULL);

    CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_create_thread_failed_label); 

    /* register thread id to manager */
    ctcl_Mgr.trans_remover_thr = tr_thr;

    fprintf (stdout, " Log remover thread created.\n");
    fflush (stdout);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_create_thread_failed_label)
    {
        /* DEBUG */            
        printf ("result of pthread_create : %d\n", result);

        result = CTC_ERR_INSUFFICIENT_SYS_RESOURCE_FAILED;
    }
    EXCEPTION_END;

    if (is_analyzer_started == CTC_TRUE)
    {
        ctcl_Mgr.need_stop_analyzer = CTC_TRUE;
    }

    return result;
}


static void ctcl_stop_log_analyzer (void)
{
    int retry = 10;

    ctcl_Mgr.need_stop_analyzer = CTC_TRUE;

    while (retry > 0)
    {
        if (ctcl_Mgr.cur_job_cnt > 0)
        {
            ctcl_Mgr.cur_job_cnt = 0;
            retry--;
        }
        else
        {
            break;
        }

        /* wait for releasing ctcl resources */
        sleep (1);
    }
}


static void ctcl_adjust_lsa (CTCL_ACT_LOG *act_log)
{

    CTCL_LSA_COPY (&ctcl_Mgr.log_info.committed_lsa, 
                   (CTCL_LOG_LSA *)&(act_log->log_hdr->eof_lsa));

    CTCL_LSA_COPY (&ctcl_Mgr.log_info.committed_rep_lsa, 
                   (CTCL_LOG_LSA *)&(act_log->log_hdr->eof_lsa));

    CTCL_LSA_COPY (&ctcl_Mgr.log_info.append_lsa, 
                   (CTCL_LOG_LSA *)&(act_log->log_hdr->append_lsa));

    CTCL_LSA_COPY (&ctcl_Mgr.log_info.eof_lsa, 
                   (CTCL_LOG_LSA *)&(act_log->log_hdr->eof_lsa));

    CTCL_LSA_COPY (&ctcl_Mgr.log_info.final_lsa, 
                   (CTCL_LOG_LSA *)&(act_log->log_hdr->eof_lsa));

    CTCL_LSA_COPY (&ctcl_Mgr.log_info.required_lsa, 
                   (CTCL_LOG_LSA *)&(act_log->log_hdr->eof_lsa));
}


static void ctcl_free_long_trans_log_list (CTCL_TRANS_LOG_LIST *list)
{
    CTCL_ITEM *item = NULL;
    CTCL_ITEM *next_item = NULL;

    if (list != NULL)
    {
        if (list->long_trans_log_list != NULL)
        {
            if (list->long_trans_log_list->head != NULL)
            {
                item = list->long_trans_log_list->head->next;
            }
            else
            {
                /* no item */
            }

            for (; item; item = next_item)
            {
                next_item = item->next;

                /* TODO: ctcl_long_trans_log_list_free_item */

                item = NULL;
            }
        }
        else
        {
            /* nothing to do */
        }
    }
    else
    {
        /* nothing to do */
    }
}

/*
 * Description: clean committed transaction log lists which have 
 *              no reference count
 *
 */
static void *ctcl_trans_remover_thr_func (void)
{
    int i;
    CTCL_TRANS_LOG_LIST *list = NULL;

    while (ctcl_Mgr.need_stop_analyzer == CTC_FALSE)
    {
        for (i = 0; i < ctcl_Mgr.log_info.trans_cnt; i++)
        {
            if (ctcl_Mgr.need_stop_analyzer == CTC_TRUE)
            {
                break;
            }

            list = ctcl_Mgr.log_info.trans_log_list[i];

            if (list != NULL)
            {
                if (list->is_committed == CTC_TRUE &&
                    list->ref_cnt == 0)
                {
                    ctcl_free_all_log_items (list);
                    list->tid = CTCL_TRAN_NULL_ID;
                    list->item_num = 0;
                    list->is_committed = CTC_FALSE;
                    CTCL_LSA_SET_NULL (&list->start_lsa);
                    CTCL_LSA_SET_NULL (&list->last_lsa);

                    if (list->long_tx_flag == CTC_TRUE &&
                        list->long_trans_log_list != NULL)
                    {
                        ctcl_free_long_trans_log_list (list);
                        list->long_tx_flag = CTC_FALSE;
                    }
                    else
                    {
                        /* no long transaction */
                    }

                }
                else
                {
                    /* nothing to do */
                }
            }
            else
            {
                continue;
            }
        }

        usleep (100 * 1000);
    }

    fprintf (stdout, " Exit from transaction log remover thread.\n");
    fflush (stdout);

    pthread_exit (0);
}


/*
 * Description: modified from la_apply_log_file()
 *
 */
static void *ctcl_log_analyzer_thr_func (void *ctcl_args)
{
    BOOL clear_owner;
    int i;
    int result;
    int valid_pg_read_cnt = 0;
    int now = 0, last_eof_time = 0;
    struct log_header final_log_hdr;
    CTCL_CACHE_BUFFER *log_buf = NULL;
    CTCL_LOG_PAGE *pg_ptr;
    CTCL_TRANS_LOG_LIST *trans = NULL;
    
    CTCL_LOG_RECORD_HEADER *lrec = NULL;
    
    CTCL_LOG_LSA old_lsa = { -1, -1 };
    CTCL_LOG_LSA prev_final;

    CTCL_ARGS *args = (CTCL_ARGS *)ctcl_args;
    
    ctcl_adjust_lsa (&ctcl_Mgr.log_info.act_log);

    /* start the main loop */
    do
    {
        int retry_count = 0;

        /* get next LSA to be processed */
        CTC_TEST_EXCEPTION (ctcl_info_pre_alloc(), err_alloc_failed_label);
    
        CTC_TEST_EXCEPTION (ctcl_fetch_log_hdr (&ctcl_Mgr.log_info.act_log), 
                            err_fetch_log_header_failed_label);

        CTCL_LSA_COPY (&ctcl_Mgr.log_info.final_lsa, 
                       (CTCL_LOG_LSA *)&ctcl_Mgr.log_info.act_log.log_hdr->eof_lsa);

        CTCL_LSA_COPY (&ctcl_Mgr.log_info.committed_lsa, 
                       &ctcl_Mgr.log_info.final_lsa);

        /* DEBUG */
        printf ("ctcl_Mgr.log_info.final_lsa.pageid = %d\n \
                act_log.log_hdr.append_lsa.pageid = %d\n", 
                ctcl_Mgr.log_info.final_lsa.pageid, 
                ctcl_Mgr.log_info.act_log.log_hdr->append_lsa.pageid);

        /* DEBUG */
        int empty_fetch_cnt = 0;

        /* start loop for apply */
        while (!CTCL_LSA_ISNULL (&ctcl_Mgr.log_info.final_lsa) &&
               ctcl_Mgr.need_stop_analyzer != CTC_TRUE)
        {
            CTC_TEST_EXCEPTION (ctcl_fetch_log_hdr (&ctcl_Mgr.log_info.act_log),
                                err_fetch_log_header_failed_label);

            if (CTCL_LSA_GE (&ctcl_Mgr.log_info.final_lsa, 
                             (CTCL_LOG_LSA *)&ctcl_Mgr.log_info.act_log.log_hdr->append_lsa))
            {
                printf ("ctcl_Mgr.log_info.final_lsa.pageid = %d\n \
                         act_log.log_hdr.append_lsa.pageid = %d\n", 
                         ctcl_Mgr.log_info.final_lsa.pageid, 
                         ctcl_Mgr.log_info.act_log.log_hdr->append_lsa.pageid);
                empty_fetch_cnt++;
                fprintf (stdout, " [A] empty fetch count = %d\n", empty_fetch_cnt);
                fflush (stdout);

                if (ctcl_Mgr.need_stop_analyzer != CTC_TRUE)
                {
                    sleep (30);
                    continue;
                }
                else
                {
                    fprintf (stdout, "[A] Now shutdown ctcl\n");
                    fflush (stdout);

                    break;
                }
            }
            else 
            {
                fprintf (stdout, " [B] empty fetch count = %d\n", empty_fetch_cnt);
                fflush (stdout);

                if (ctcl_check_page_exist (ctcl_Mgr.log_info.final_lsa.pageid) 
                    != CTCL_PAGE_EXST_IN_ACTIVE_LOG)
                {
                    CTCL_LSA_COPY (&ctcl_Mgr.log_info.final_lsa, 
                                   (CTCL_LOG_LSA *)&ctcl_Mgr.log_info.act_log.log_hdr->append_lsa);

                    fprintf (stdout, " page exist in aRchive log.\n");
                    fflush (stdout);
                    continue;
                }
                else
                {
                    fprintf (stdout, "ctcl_Mgr.log_info.final_lsa.pageid = %d\n \ 
                                      act_log.log_hdr.append_lsa.pageid = %d\n", 
                                      ctcl_Mgr.log_info.final_lsa.pageid, 
                                      ctcl_Mgr.log_info.act_log.log_hdr->append_lsa.pageid);

                    fprintf (stdout, " page exist in aCtive log.\n");
                    fflush (stdout);
                }
            }

            /* release all page buffers */
            ctcl_release_all_page_buffers (CTCL_PAGE_NULL_ID);

            /* we should fetch final log page from disk not cache buffer */
            ctcl_decache_page_buffer_range (ctcl_Mgr.log_info.final_lsa.pageid, 
                                            CTCL_LOGPAGEID_MAX);

            /* DEBUG */
            ctcl_Mgr.cur_job_cnt = 1;

            if (ctcl_Mgr.cur_job_cnt == 0)
            {
                continue;
            }

            /* DEBUG */
            if (ctcl_Mgr.log_info.final_lsa.pageid 
                != ctcl_Mgr.log_info.act_log.log_hdr->eof_lsa.pageid)
            {
                printf ("IN_LOOP \n \
                        ctcl_Mgr.log_info.final_lsa.pageid = %d\n \
                        act_log.log_hdr.eof_lsa.pageid = %d\n \
                        act_log.log_hdr.append_lsa.pageid = %d\n", 
                        ctcl_Mgr.log_info.final_lsa.pageid, 
                        ctcl_Mgr.log_info.act_log.log_hdr->eof_lsa.pageid,
                        ctcl_Mgr.log_info.act_log.log_hdr->append_lsa.pageid);
            }

            memset (&final_log_hdr, 0, sizeof (struct log_header));
            memcpy (&final_log_hdr, 
                    ctcl_Mgr.log_info.act_log.log_hdr,
                    sizeof (struct log_header));

            if ((final_log_hdr.eof_lsa.pageid < ctcl_Mgr.log_info.final_lsa.pageid) &&
                (final_log_hdr.eof_lsa.offset < ctcl_Mgr.log_info.final_lsa.offset))
            {
                printf ("THIS_1");
                usleep (100 * 1000);
                continue;
            }

            /* get target page from log */
            log_buf = ctcl_get_page_buffer (ctcl_Mgr.log_info.final_lsa.pageid);

            CTCL_LSA_COPY (&old_lsa, &ctcl_Mgr.log_info.final_lsa);

            if (log_buf == NULL)
            {
                CTC_COND_EXCEPTION (ctcl_Mgr.need_stop_analyzer == CTC_TRUE,
                                    err_page_corrupted_label);

                /* request page is greater then append_lsa.(in log_header) */
                if (final_log_hdr.append_lsa.pageid < 
                    ctcl_Mgr.log_info.final_lsa.pageid)
                {
                    usleep (10 * 1000);
                    continue;
                }

                if (retry_count < CTCL_RETRY_COUNT)
                {
                    retry_count++;

                    usleep (3 * 1000 + (retry_count * 100));
                    continue;
                }
            }
            else
            {
                retry_count = 0;
            }

            /* check it and verify it */
            if (log_buf->logpage.hdr.logical_pageid == ctcl_Mgr.log_info.final_lsa.pageid)
            {
                if (log_buf->logpage.hdr.offset < 0)
                {
                    /* DEBUG */
                    printf ("Did you come in here really??\n");

                    ctcl_decache_page_buffer (log_buf);

                    if (!(ctcl_check_page_exist (ctcl_Mgr.log_info.final_lsa.pageid + 1) &&
                        (ctcl_Mgr.log_info.final_lsa.pageid + 1) <= final_log_hdr.eof_lsa.pageid))
                    {
                        /* if page not exist, skip */
                        if (!ctcl_check_page_exist (ctcl_Mgr.log_info.final_lsa.pageid) &&
                            ctcl_Mgr.log_info.final_lsa.pageid < final_log_hdr.eof_lsa.pageid)
                        {
                            ctcl_Mgr.log_info.final_lsa.pageid++;
                            ctcl_Mgr.log_info.final_lsa.offset = 0;

                            continue;
                        }
                        else
                        {
                            /* page exist */
                        }
                    }

                    /* retry */
                    usleep (10 * 1000);
                    continue;
                }
                else
                {
                    /* valid page */
                    /* DEBUG*/
                    valid_pg_read_cnt++;
                }
            }
            else
            {
                ctcl_decache_page_buffer (log_buf);

                usleep (10 * 1000);
                continue;
            }

            /* log page exist */
            CTCL_LSA_SET_NULL (&prev_final);

            pg_ptr = &(log_buf->logpage);

            /* DEBUG */
            ctcl_Mgr.first_tid = ctcl_Mgr.last_tid + 1;
            printf("valid page read count = %d\n", valid_pg_read_cnt);

            while (ctcl_Mgr.log_info.final_lsa.pageid == log_buf->pageid && 
                   ctcl_Mgr.need_stop_analyzer == CTC_FALSE)
            {
                if ((ctcl_Mgr.log_info.final_lsa.offset == 0) || 
                    (ctcl_Mgr.log_info.final_lsa.offset == CTCL_NULL_OFFSET))
                {
                    ctcl_Mgr.log_info.final_lsa.offset = log_buf->logpage.hdr.offset;
                }

                /* check for end of log */
                if (CTCL_LSA_GT (&ctcl_Mgr.log_info.final_lsa, 
                                 (CTCL_LOG_LSA *)&final_log_hdr.eof_lsa))
                {
                    ctcl_Mgr.log_info.is_end_of_record = CTC_TRUE;
                    ctcl_decache_page_buffer (log_buf);
                    break;
                }
                else if (CTCL_LSA_GT (&ctcl_Mgr.log_info.final_lsa, 
                                      (CTCL_LOG_LSA *)&final_log_hdr.append_lsa))
                {
                    /* DEBUG */
                    printf ("HERE1\n");

                    ctcl_decache_page_buffer (log_buf);
                    break;
                }
                else
                {
                    /* nothing to do */
                }

                lrec = CTCL_GET_LOG_RECORD_HEADER (pg_ptr, 
                                                   &ctcl_Mgr.log_info.final_lsa);
                ctcl_Mgr.read_log_cnt++;

                ctcl_Mgr.last_tid = lrec->trid;

                /* DEBUG */
                ctcl_Mgr.cur_job_cnt = 1;

                if (ctcl_Mgr.cur_job_cnt > 0)
                {
                    trans = ctcl_get_trans_log_list_set_tid (lrec->trid);
                    trans->ref_cnt = ctcl_Mgr.cur_job_cnt;
                }
                else
                {
                    /* set the prev/next record */
                    CTCL_LSA_COPY (&prev_final, &ctcl_Mgr.log_info.final_lsa);
                    CTCL_LSA_COPY (&ctcl_Mgr.log_info.final_lsa, &lrec->forw_lsa);
                    continue;
                }

                if (ctcl_Mgr.first_tid == CTCL_TRAN_NULL_ID)
                {
                    /* set the prev/next record */
                    CTCL_LSA_COPY (&prev_final, &ctcl_Mgr.log_info.final_lsa);
                    CTCL_LSA_COPY (&ctcl_Mgr.log_info.final_lsa, &lrec->forw_lsa);
                    continue;
                }
                else 
                {
                    /* current processing job exists */
                }

                CTC_COND_EXCEPTION (!CTCL_LSA_ISNULL (&prev_final) &&
                                    !CTCL_LSA_EQ (&prev_final, &lrec->back_lsa),
                                    err_page_corrupted_label);

                if (CTCL_LSA_EQ (&ctcl_Mgr.log_info.final_lsa, 
                                 (CTCL_LOG_LSA *)&final_log_hdr.eof_lsa) && 
                    lrec->type != LOG_END_OF_LOG)
                {
                    ctcl_Mgr.log_info.is_end_of_record = CTC_TRUE;
                    ctcl_decache_page_buffer (log_buf);
                    break;
                }

                /*
                if (lrec->trid >= ctcl_Mgr.first_tid)
                {
                    continue;
                }
                */

                /* DEBUG */
//                printf ("record type = %d\n record tid = %d\n", lrec->type, lrec->trid);

                printf ("\nBEFORE PROCESS RECORD: ctcl_Mgr.log_info.final_lsa.pageid = %d\n",
                        ctcl_Mgr.log_info.final_lsa.pageid);
                /* process the log record */
                result = ctcl_log_record_process (lrec, 
                                                  &ctcl_Mgr.log_info.final_lsa, 
                                                  pg_ptr);

                CTC_COND_EXCEPTION (result == CTC_ERR_PAGE_CORRUPTED_FAILED,
                                    err_page_corrupted_label);

                CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                    err_log_record_process_failed_label);

                CTC_COND_EXCEPTION (!CTCL_LSA_ISNULL (&lrec->forw_lsa) && 
                                    CTCL_LSA_GT (&ctcl_Mgr.log_info.final_lsa, &lrec->forw_lsa),
                                    err_page_corrupted_label);

                /* set the prev/next record */
                CTCL_LSA_COPY (&prev_final, &ctcl_Mgr.log_info.final_lsa);
                CTCL_LSA_COPY (&ctcl_Mgr.log_info.final_lsa, &lrec->forw_lsa);
            }

//            if (ctcl_Mgr.log_info.final_lsa.pageid > final_log_hdr.eof_lsa.pageid || 
//                ctcl_Mgr.log_info.final_lsa.pageid > final_log_hdr.append_lsa.pageid || 
//                ctcl_Mgr.log_info.is_end_of_record == CTC_TRUE)
            if (CTCL_LSA_GE (&ctcl_Mgr.log_info.final_lsa, 
                             (CTCL_LOG_LSA *)&final_log_hdr.eof_lsa)    || 
                CTCL_LSA_GE (&ctcl_Mgr.log_info.final_lsa, 
                             (CTCL_LOG_LSA *)&final_log_hdr.append_lsa) || 
                ctcl_Mgr.log_info.is_end_of_record == CTC_TRUE)
            {
                /* DEBUG */
                printf ("HERE2\n");
                /* it should be refetched and release */
                ctcl_decache_page_buffer (log_buf);
            }

            /* there is no something new */
            if (CTCL_LSA_EQ (&old_lsa, &ctcl_Mgr.log_info.final_lsa))
            {
                usleep (100 * 1000);
                continue;
            }
        }
    }
    while (ctcl_Mgr.need_stop_analyzer == CTC_FALSE);

    ctcl_shutdown ();

    fprintf (stdout, "now shutdown ctcl\n");
    fflush (stdout);

    result = CTC_SUCCESS;

    pthread_exit ((void *)&result);

    CTC_EXCEPTION (err_alloc_failed_label)
    {
        ctcl_Mgr.need_stop_analyzer = CTC_TRUE;
        ctcl_shutdown ();
        result = CTC_ERR_ALLOC_FAILED;
    }
    CTC_EXCEPTION (err_fetch_log_header_failed_label)
    {
        ctcl_Mgr.need_stop_analyzer = CTC_TRUE;
        ctcl_shutdown ();
        result = CTC_ERR_READ_FROM_DISK_FAILED;
    }
    CTC_EXCEPTION (err_page_corrupted_label)
    {
        if (ctcl_Mgr.need_stop_analyzer != CTC_TRUE)
        {
            ctcl_decache_page_buffer (log_buf);
        }

        ctcl_Mgr.need_stop_analyzer = CTC_TRUE;
        ctcl_shutdown ();
        result = CTC_ERR_PAGE_CORRUPTED_FAILED;
    }
    CTC_EXCEPTION (err_log_record_process_failed_label)
    {
        ctcl_Mgr.need_stop_analyzer = CTC_TRUE;
        ctcl_shutdown ();
    }
    EXCEPTION_END;

    pthread_exit ((void *)&result);
}


static inline void ctcl_mgr_inc_last_tid(void)
{
    ctcl_Mgr.last_tid++;
}

static inline void ctcl_mgr_dec_last_tid(void)
{
    ctcl_Mgr.last_tid--;
}

static inline void ctcl_trans_log_set_committed (CTCL_TRANS_LOG_LIST *trans_log_list)
{
    trans_log_list->is_committed = true;
}

static inline int ctcl_get_trans_ref_cnt (CTCL_TRANS_LOG_LIST *trans_log_list)
{
    if (trans_log_list != NULL)
    {   
        return trans_log_list->ref_cnt;
    }
}

static inline void ctcl_inc_trans_ref_cnt (CTCL_TRANS_LOG_LIST *trans_log_list)
{
    trans_log_list->ref_cnt++;
}

static inline void ctcl_dec_trans_ref_cnt (CTCL_TRANS_LOG_LIST *trans_log_list)
{
    trans_log_list->ref_cnt--;
}

