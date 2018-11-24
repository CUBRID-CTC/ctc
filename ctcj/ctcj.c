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
 * ctcj.c : ctc job manager implementation
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <string.h>

#include "ctcp.h"
#include "ctcg_conf.h"
#include "ctcg_list.h"
#include "ctcj.h"
#include "ctcl.h"
#include "ctcs_def.h"
#include "ctc_common.h"
#include "ctc_types.h"


/*
static ctcj_make_new_ref_tab_info ();
static ctcj_create_job_tab_info ();
static ctcj_job_find_table ();
static ctcj_job_add_table ();
static ctcj_job_delete_table ();
static ctcj_init_table_info ();
static ctcj_destroy_all_job_info ();

static ctcj_job_queue_enq_item ();
static ctcj_job_queue_deq_item ();
static ctcj_get_job_queue_left_size ();
*/
static CTC_REF_TAB_INFO *ctcj_ref_table_find_table (const char *table_name, 
                                                    const char *user_name);

static void ctcj_job_is_registered_table (CTCJ_JOB_INFO *job, 
                                          const char *table_name, 
                                          const char *user_name, 
                                          BOOL *is_registered);

static int ctcj_compare_tid_func (const void *first, 
                                  const void *second);


static CTCJ_JOB_TAB_INFO *ctcj_job_find_table (CTCJ_JOB_INFO *job, 
                                               char *table_name, 
                                               char *user_name);

/* inline functions */
/*
static inline void ctcj_ref_table_inc_tab_ref_cnt(CTC_REF_TAB_INFO *tab);
static inline void ctcj_ref_table_dec_tab_ref_cnt(CTC_REF_TAB_INFO *tab);
static inline void ctcj_ref_table_inc_tbl_cnt(void);
static inline void ctcj_ref_table_dec_tbl_cnt(void);
static inline void ctcj_job_inc_table_cnt (CTCJ_JOB_INFO *job);
static inline void ctcj_job_dec_table_cnt (CTCJ_JOB_INFO *job);
static inline int ctcj_get_job_queue_left_size (CTCJ_JOB_INFO *job_info);
*/

CTC_JOB_REF_TABLE job_ref_Tbl;

/* ctcj */
extern int ctcj_initialize (void)
{
    int result;
    /* job info initialize */
    pthread_mutex_init (&job_ref_Tbl.job_lock, NULL);

    CTC_TEST_EXCEPTION (ctcj_ref_table_job_lock (), 
                        err_lock_failed_label);

    job_ref_Tbl.total_job_cnt = 0;
    job_ref_Tbl.cur_job_cnt = 0;

    CTCG_LIST_INIT (&job_ref_Tbl.job_info_list);

    CTC_TEST_EXCEPTION (ctcj_ref_table_job_unlock (), 
                        err_unlock_failed_label);

    /* table info initialize */
    pthread_mutex_init (&job_ref_Tbl.job_lock, NULL);

    CTC_TEST_EXCEPTION (ctcj_ref_table_table_lock (), 
                        err_lock_failed_label);

    job_ref_Tbl.total_tbl_cnt = 0;
    CTCG_LIST_INIT (&job_ref_Tbl.table_list);

    CTC_TEST_EXCEPTION (ctcj_ref_table_table_unlock (), 
                        err_unlock_failed_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_lock_failed_label)
    {
        /* EINVAL, EDEADLK or EAGAIN */
        result = CTC_ERR_LOCK_FAILED;
    }
    CTC_EXCEPTION (err_unlock_failed_label)
    {
        result = CTC_ERR_UNLOCK_FAILED;
    }
    EXCEPTION_END;

    return result;
}


extern void ctcj_finalize (void)
{
    int status;
    CTCJ_JOB_INFO *job =  NULL;
    CTC_REF_TAB_INFO *table = NULL;
    CTCG_LIST_NODE *itr;

    /* phase 1: job info */
    if (CTCG_LIST_IS_EMPTY (&job_ref_Tbl.job_info_list) != CTC_TRUE)
    {
        CTCG_LIST_ITERATE (&job_ref_Tbl.job_info_list, itr)
        {
            job = (CTCJ_JOB_INFO *)itr->obj;

            if (job != NULL)
            {
                (void)ctcj_get_job_status (job, &status);

                if (status == CTCJ_JOB_PROCESSING)
                {
                    ctcj_set_job_status (job, CTCJ_JOB_IMMEDIATE_STOPPED);

                    while (status == CTCJ_JOB_PROCESSING)
                    {
                        sleep (1);
                    }
                }
                else
                {
                    /* already stopped */
                }

                /* remove job from list */
                (void)ctcj_ref_table_remove_job (job);

                /* destroy job */
                ctcj_destroy_job_info (job);
            }
            else
            {
                /* until end of list */
            }
        }
    }
    else
    {
        /* empty job info list */
    }

    itr = NULL;

    /* phase 2: table info */
    if (CTCG_LIST_IS_EMPTY (&job_ref_Tbl.table_list) != CTC_TRUE)
    {
        CTCG_LIST_ITERATE (&job_ref_Tbl.table_list, itr)
        {
            table = (CTC_REF_TAB_INFO *)itr->obj;

            if (table != NULL)
            {                  
                CTCG_LIST_REMOVE (&(table->node));
                job_ref_Tbl.total_tbl_cnt--;
//                (void)ctcj_ref_table_remove_table (table);
                free (table);
            }
            else
            {
                continue;
            }
        }
    }
    else
    {
        /* empty table list */
    }

    return;
}


/* reference table */
extern int ctcj_ref_table_job_lock (void)
{
    int result;

    CTC_TEST_EXCEPTION (pthread_mutex_lock (&job_ref_Tbl.job_lock),
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


extern int ctcj_ref_table_job_unlock (void)
{
    int result;

    CTC_TEST_EXCEPTION (pthread_mutex_unlock (&job_ref_Tbl.job_lock),
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


extern int ctcj_ref_table_table_lock (void)
{
    int result;

    CTC_TEST_EXCEPTION (pthread_mutex_lock (&job_ref_Tbl.table_lock),
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


extern int ctcj_ref_table_table_unlock (void)
{
    int result;

    CTC_TEST_EXCEPTION (pthread_mutex_unlock (&job_ref_Tbl.table_lock),
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


extern int ctcj_ref_table_add_job (CTCJ_JOB_INFO *job)
{
    int result;

    assert (job != NULL);

    CTC_TEST_EXCEPTION (ctcj_ref_table_job_lock (),
                        err_lock_failed_label);

    CTCG_LIST_ADD_LAST (&(job_ref_Tbl.job_info_list), &(job->node));

    job_ref_Tbl.total_job_cnt++;

    CTC_TEST_EXCEPTION (ctcj_ref_table_job_unlock (),
                        err_unlock_failed_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_lock_failed_label)
    {
        /* EINVAL, EDEADLK or EAGAIN */
        result = CTC_ERR_LOCK_FAILED;
    }
    CTC_EXCEPTION (err_unlock_failed_label)
    {
        /* EINVAL, EDEADLK or EAGAIN */
        result = CTC_ERR_UNLOCK_FAILED;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcj_ref_table_remove_job (CTCJ_JOB_INFO *job)
{
    int result;
    CTCG_LIST_NODE *itr;
    CTCJ_JOB_INFO *job_info = NULL;

    assert (job != NULL);

    CTC_TEST_EXCEPTION (ctcj_ref_table_job_lock (),
                        err_lock_failed_label);

    /* find job */
    CTCG_LIST_ITERATE (&(job_ref_Tbl.job_info_list), itr)
    {
        job_info = (CTCJ_JOB_INFO *)itr->obj;

        if (job_info != NULL)
        {
            if (job_info->job_desc == job->job_desc)
            {
                CTCG_LIST_REMOVE (&(job->node));
                job_ref_Tbl.total_job_cnt--;
            }
            else
            {
                continue;
            }
        }
        else
        {
            /* until end of list */
        }
    }

    CTC_TEST_EXCEPTION (ctcj_ref_table_job_unlock (),
                        err_unlock_failed_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_lock_failed_label)
    {
        /* EINVAL, EDEADLK or EAGAIN */
        result = CTC_ERR_LOCK_FAILED;
    }
    CTC_EXCEPTION (err_unlock_failed_label)
    {
        /* EINVAL, EDEADLK or EAGAIN */
        result = CTC_ERR_UNLOCK_FAILED;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcj_ref_table_add_table (CTCJ_JOB_TAB_INFO *tab_info)
{
    int result;
    CTCG_LIST_NODE *itr;
    CTC_REF_TAB_INFO *table = NULL;

    CTC_TEST_EXCEPTION (ctcj_ref_table_table_lock (),
                        err_lock_failed_label);

    /* find table */
    CTCG_LIST_ITERATE (&(job_ref_Tbl.table_list), itr)
    {
        table = (CTC_REF_TAB_INFO *)itr->obj;

        if (table != NULL)
        {
            if (strcmp (table->name, tab_info->name) == 0)
            {
                table->ref_cnt++;
            }
            else
            {
                CTCG_LIST_ADD_LAST (&(job_ref_Tbl.table_list), &(table->node));
                job_ref_Tbl.total_tbl_cnt++;
                table->ref_cnt++;
            }
        }
        else
        {
            /* until end of list */
        }
    }

    CTC_TEST_EXCEPTION (ctcj_ref_table_table_unlock (),
                        err_lock_failed_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_lock_failed_label)
    {
        /* EINVAL, EDEADLK or EAGAIN */
        result = CTC_ERR_LOCK_FAILED;
    }
    CTC_EXCEPTION (err_unlock_failed_label)
    {
        /* EINVAL, EDEADLK or EAGAIN */
        result = CTC_ERR_UNLOCK_FAILED;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcj_ref_table_remove_table (CTCJ_JOB_TAB_INFO *tab_info)
{
    int result;
    CTCG_LIST_NODE *itr;
    CTC_REF_TAB_INFO *table = NULL;

    CTC_TEST_EXCEPTION (ctcj_ref_table_table_lock (),
                        err_lock_failed_label);

    /* find table */
    CTCG_LIST_ITERATE (&(job_ref_Tbl.table_list), itr)
    {
        table = (CTC_REF_TAB_INFO *)itr->obj;

        if (table != NULL)
        {
            if (strcmp (table->name, tab_info->name) == 0)
            {
                if (table->ref_cnt > 1)
                {
                    table->ref_cnt--;
                }
                else
                {
                    CTCG_LIST_REMOVE (&(table->node));
                    job_ref_Tbl.total_tbl_cnt--;
                }
            }
            else
            {
                continue;
            }
        }
        else
        {
            /* until end of list */
        }
    }

    CTC_TEST_EXCEPTION (ctcj_ref_table_table_unlock (),
                        err_lock_failed_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_lock_failed_label)
    {
        /* EINVAL, EDEADLK or EAGAIN */
        result = CTC_ERR_LOCK_FAILED;
    }
    CTC_EXCEPTION (err_unlock_failed_label)
    {
        /* EINVAL, EDEADLK or EAGAIN */
        result = CTC_ERR_UNLOCK_FAILED;
    }
    EXCEPTION_END;

    return result;
}


/* job info */
extern int ctcj_make_new_job (CTCJ_JOB_INFO **job_info)
{
    int result;
    CTCJ_JOB_INFO *job = NULL;

    job = (CTCJ_JOB_INFO *)malloc (sizeof (CTCJ_JOB_INFO));
    CTC_COND_EXCEPTION (job == NULL, err_alloc_job_info_failed_label);

    *job_info = job;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_alloc_job_info_failed_label)
    {
        result = CTC_ERR_ALLOC_FAILED;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcj_init_job_info (CTCJ_JOB_INFO *job_info, 
                               unsigned short job_id, 
                               int sgid, 
                               int job_qsize, 
                               int long_tran_qsize)
{
    int result;

    assert (job_info != NULL);

    job_info->job_desc = job_id;
    job_info->session_group_id = sgid;
    job_info->start_tid = 0;
    job_info->table_cnt = 0;

    CTCG_LIST_INIT (&(job_info->table_list));

    job_info->job_qsize = job_qsize; 
    job_info->long_tran_qsize = long_tran_qsize;
    job_info->job_queue = (unsigned long *)malloc (sizeof (unsigned long) *
                                                   job_info->job_qsize);

    CTC_COND_EXCEPTION (job_info->job_queue == NULL, 
                        err_job_queue_alloc_failed_label);

    job_info->status = CTCJ_JOB_NONE;

    job_info->last_processed_tid = 0;
    job_info->enqueued_item_num = 0;
    job_info->dequeued_item_num = 0;
    
    CTCG_LIST_INIT_OBJ (&(job_info->node), job_info);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_job_queue_alloc_failed_label)
    {
        result = CTC_ERR_ALLOC_FAILED;
    }
    EXCEPTION_END;

    return result;
}


extern void ctcj_destroy_job_info (CTCJ_JOB_INFO *job_info)
{
    assert (job_info->status != CTCJ_JOB_PROCESSING);

    if (job_info != NULL)
    {
        free (job_info->job_queue);
        free (job_info);
    }
    else
    {
        /* already destroyed */
    }

    return;
}

/*
extern CTCG_LIST *ctcj_job_get_table_list (CTCJ_JOB_INFO *job_info)
{
}
*/

/* job status */
extern int ctcj_set_job_status (CTCJ_JOB_INFO *job_info, int status)
{
    int result;

    assert (job_info != NULL);

    CTC_COND_EXCEPTION (status < CTCJ_JOB_NONE || 
                        status > CTCJ_JOB_CLOSING,
                        err_invalid_job_status_label);

    job_info->status = status;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_invalid_job_status_label)
    {
        result = CTC_ERR_INVALID_JOB_STATUS_FAILED;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcj_get_job_status (CTCJ_JOB_INFO *job_info, int *status)
{
    int result;

    assert (job_info != NULL);
    assert (status != NULL);

    CTC_COND_EXCEPTION (job_info->job_desc < 1 ||
                        job_info->job_desc > 9,
                        err_invalid_job_label);

    *status = job_info->status; 

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_invalid_job_label)
    {
        result = CTC_ERR_INVALID_JOB_FAILED;
    }
    EXCEPTION_END;

    return result;
}



/* register/unregister table */
static void ctcj_job_is_registered_table (CTCJ_JOB_INFO *job, 
                                          const char *table_name, 
                                          const char *user_name, 
                                          BOOL *is_registered)
{
    BOOL is_exist = CTC_FALSE;
    CTCJ_JOB_TAB_INFO *table = NULL;
    CTCG_LIST_NODE *itr;

    assert (job != NULL);

    if (CTCG_LIST_IS_EMPTY (&(job->table_list)) != CTC_TRUE)
    {
        CTCG_LIST_ITERATE (&(job->table_list), itr)
        {
            table = (CTCJ_JOB_TAB_INFO *)itr->obj;

            if (table != NULL)
            {
                if (strcmp (table->name, table_name) == 0)
                {
                    is_exist = CTC_TRUE;
                }
                else
                {
                    continue;
                }
            }
            else
            {
                /* until end of list */
            }
        }
    }

    *is_registered = is_exist;

    return;
}


extern int ctcj_job_register_table (CTCJ_JOB_INFO *job, 
                                    const char *table_name, 
                                    const char *user_name)
{
    BOOL is_exist;
    int stage = 0;
    int result;
    int table_name_len;
    int user_name_len;
    CTCJ_JOB_TAB_INFO *table = NULL;

    assert (job != NULL);

    CTC_COND_EXCEPTION (table_name == NULL, err_invalid_table_name_label);
    table_name_len = strlen (table_name);
    CTC_COND_EXCEPTION (table_name_len == 0, err_invalid_table_name_label);

    CTC_COND_EXCEPTION (user_name == NULL, err_invalid_user_name_label);
    user_name_len = strlen (user_name);
    CTC_COND_EXCEPTION (user_name_len == 0, err_invalid_user_name_label);

    ctcj_job_is_registered_table (job, table_name, user_name, &is_exist);

    CTC_COND_EXCEPTION (is_exist == CTC_TRUE, err_already_exist_label);
    
    /* make new table_info */
    table = (CTCJ_JOB_TAB_INFO *)malloc (sizeof (CTCJ_JOB_TAB_INFO));
    CTC_COND_EXCEPTION (table == NULL, err_alloc_failed_label);
    stage = 1;

    memset (table, 0, sizeof (*table));

    /* init table_info with name */
    strncpy (table->name, table_name, table_name_len);
    strncpy (table->user, user_name, user_name_len);

    CTCG_LIST_INIT_OBJ (&(table->node), table);
        
    /* add table into list */
    CTCG_LIST_ADD_LAST (&(job->table_list), &(table->node));
    stage = 2;

    /* add table to job reference table */
    result = ctcj_ref_table_add_table (table);

    CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                        err_ref_table_add_table_failed_label);

    job->status = CTCJ_JOB_READY;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_invalid_table_name_label)
    {
        result = CTC_ERR_INVALID_TABLE_NAME_FAILED;
    }
    CTC_EXCEPTION (err_invalid_user_name_label)
    {
        result = CTC_ERR_INVALID_USER_NAME_FAILED;
    }
    CTC_EXCEPTION (err_already_exist_label)
    {
        result = CTC_ERR_ALREADY_EXIST_TABLE_FAILED;
    }
    CTC_EXCEPTION (err_alloc_failed_label)
    {
        result = CTC_ERR_ALLOC_FAILED;
    }
    CTC_EXCEPTION (err_ref_table_add_table_failed_label)
    {
        /* error info set from sub-function */
    }
    EXCEPTION_END;

    switch (stage)
    {
        case 2:
            CTCG_LIST_REMOVE (&(table->node));
        case 1:
            free (table);
            break;
    }

    return result;
}



extern int ctcj_job_unregister_table (CTCJ_JOB_INFO *job, 
                                      const char *table_name, 
                                      const char *user_name)
{
    BOOL is_exist;
    int result;
    int table_name_len;
    int user_name_len;
    CTCJ_JOB_TAB_INFO *table = NULL;

    assert (job != NULL);

    CTC_COND_EXCEPTION (table_name == NULL, err_invalid_table_name_label);
    table_name_len = strlen (table_name);
    CTC_COND_EXCEPTION (table_name_len == 0, err_invalid_table_name_label);

    CTC_COND_EXCEPTION (user_name == NULL, err_invalid_user_name_label);
    user_name_len = strlen (user_name);
    CTC_COND_EXCEPTION (user_name_len == 0, err_invalid_user_name_label);

    ctcj_job_is_registered_table (job, table_name, user_name, &is_exist);

    CTC_COND_EXCEPTION (is_exist != CTC_TRUE, err_not_exist_label);

    table = ctcj_job_find_table (job, table_name, user_name);

    assert (table != NULL);
        
    /* remove table from list */
    CTCG_LIST_REMOVE (&(table->node));

    /* remove table from job reference table */
    result = ctcj_ref_table_remove_table (table);

    CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                        err_ref_table_remove_table_failed_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_invalid_table_name_label)
    {
        result = CTC_ERR_INVALID_TABLE_NAME_FAILED;
    }
    CTC_EXCEPTION (err_invalid_user_name_label)
    {
        result = CTC_ERR_INVALID_USER_NAME_FAILED;
    }
    CTC_EXCEPTION (err_not_exist_label)
    {
        result = CTC_ERR_NOT_REGISTERED_TABLE_FAILED;
    }
    CTC_EXCEPTION (err_ref_table_remove_table_failed_label)
    {
        /* error info set from sub-function */
    }
    EXCEPTION_END;

    return result;
}


static CTC_REF_TAB_INFO *ctcj_ref_table_find_table (const char *table_name, 
                                                    const char *user_name)
{
    CTC_REF_TAB_INFO *table = NULL;

    return table;
}


static int ctcj_compare_tid_func (const void *first, 
                                  const void *second)
{
    if (((CTCL_TRANS_LOG_LIST *)first)->tid > ((CTCL_TRANS_LOG_LIST *)second)->tid)
    {
        return 1;
    }
    else if (((CTCL_TRANS_LOG_LIST *)first)->tid < ((CTCL_TRANS_LOG_LIST *)second)->tid)
    {
        return -1;
    }
    else
    {
        return 0;
    }
}


/* capture */
extern void *ctcj_capture_thr_func (void *args)
{
    int i, j;
    int result;
    int last_tid;
    int biggest_tid;
    int sorted_trans_cnt;
    int cur_trans_cnt;
    CTCS_JOB_SESSION *job_session = (CTCS_JOB_SESSION *)args;
    CTCJ_JOB_INFO *job = NULL;
    CTCL_TRANS_LOG_LIST *list = NULL;
    CTCL_TRANS_LOG_LIST **trans_list = NULL;
    CTCL_TRANS_LOG_LIST ***trans_log_list = NULL;

    assert (job_session != NULL);

    job = job_session->job;

    last_tid = ctcl_mgr_get_last_tid_nolock ();
    job->last_processed_tid = last_tid;
    job->start_tid = last_tid + 1;
    job->status = CTCJ_JOB_PROCESSING;

    while (job->status == CTCJ_JOB_PROCESSING)
    {
        biggest_tid = 0;
        cur_trans_cnt = ctcl_mgr_get_cur_trans_index ();

        if (cur_trans_cnt > 0)
        {
            trans_list = ctcl_mgr_get_trans_log_list ();

            trans_log_list = (CTCL_TRANS_LOG_LIST ***)malloc (cur_trans_cnt * 
                                                              sizeof (CTCL_TRANS_LOG_LIST *));

            /* get committed transaction log list from ctcl_Mgr */
            for (i = 0, j = 0; i < cur_trans_cnt; i++)
            {
                list = trans_list[i];

                if (list != NULL)
                {
                    if (list->is_committed == CTC_TRUE)
                    {
                        if (list->tid > job->last_processed_tid &&
                            list->ref_cnt > 0)
                        {
                            trans_log_list[j++] = &trans_list[i];

                            if (list->tid > biggest_tid)
                            {
                                biggest_tid = list->tid;
                            }
                        }
                        else
                        {
                            /* already processed transaction */
                        }
                    }
                    else
                    {
                        /* not yet committed transaction */
                    }
                }
                else
                {
                    continue;
                }
            }

            sorted_trans_cnt = j;

            /* update tid infos and decrease ref_cnt of ctcl */
            job->last_processed_tid = biggest_tid;

            if (sorted_trans_cnt > 1)
            {
                /* sort trans_log_list */
                qsort (trans_log_list[0], 
                       sorted_trans_cnt, 
                       sizeof(CTCL_TRANS_LOG_LIST *), 
                       ctcj_compare_tid_func);

                /* send transaction log list */
                result = ctcp_send_captured_data_result (job_session->link,
                                                         job_session->job->job_desc,
                                                         job_session->sgid,
                                                         sorted_trans_cnt,
                                                         (void **)trans_log_list);

                CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                    err_send_capture_result_failed_label);
            }

            /* free trans_log_list */
            free (trans_log_list);
            trans_log_list = NULL;
        }
        else
        {
            usleep (100 * 1000);
            continue;
        }
    }

    pthread_exit ((void *)&result);

    CTC_EXCEPTION (err_send_capture_result_failed_label)
    {
        /* error info set from sub-function */
        if (trans_log_list != NULL)
        {
            free (trans_log_list);
        }
    }
    EXCEPTION_END;

    pthread_exit ((void *)&result);
}


extern void ctcj_stop_capture_immediately (pthread_t job_thr_id, 
                                           CTCJ_JOB_INFO *job)
{
    assert (job != NULL);

    if (job_thr_id > 0)
    {
        if (job->status == CTCJ_JOB_PROCESSING)
        {
            job->status = CTCJ_JOB_IMMEDIATE_STOPPED;
        }
        else
        {
            /* already stopped */
        }
    }
    else
    {
        /* invalid thread id, critical system error but, ignore */
    }

    return;
}


extern void ctcj_stop_capture (pthread_t job_thr_id, CTCJ_JOB_INFO *job)
{
    assert (job != NULL);

    if (job_thr_id > 0)
    {
        if (job->status == CTCJ_JOB_PROCESSING)
        {
            job->status = CTCJ_JOB_STOPPED;
        }
        else
        {
            /* already stopped */
        }
    }
    else
    {
        /* invalid thread id, critical system error but, ignore */
    }

    return;
}



static CTCJ_JOB_TAB_INFO *ctcj_job_find_table (CTCJ_JOB_INFO *job, 
                                               char *table_name, 
                                               char *user_name)
{
    CTCJ_JOB_TAB_INFO *table = NULL;
    CTCG_LIST_NODE *itr;

    if (CTCG_LIST_IS_EMPTY (&(job->table_list)) != CTC_TRUE)
    {
        CTCG_LIST_ITERATE (&(job->table_list), itr)
        {
            table = (CTCJ_JOB_TAB_INFO *)itr->obj;

            if (table != NULL)
            {
                if (strcmp (table->name, table_name) == 0)
                {
                    break;
                }
                else
                {
                    continue;
                }
            }
            else
            {
                /* until end of list */
            }
        }
    }

    return table;
}


/* inline functions */
static inline void ctcj_ref_table_inc_tab_ref_cnt(CTC_REF_TAB_INFO *tab)
{
}

static inline void ctcj_ref_table_dec_tab_ref_cnt(CTC_REF_TAB_INFO *tab)
{
}

static inline void ctcj_ref_table_inc_tbl_cnt(void)
{
}

static inline void ctcj_ref_table_dec_tbl_cnt(void)
{
}

static inline void ctcj_job_inc_table_cnt (CTCJ_JOB_INFO *job)
{
}

static inline void ctcj_job_dec_table_cnt (CTCJ_JOB_INFO *job)
{
}

static inline int ctcj_get_job_queue_left_size (CTCJ_JOB_INFO *job_info)
{
    return 0;
}



