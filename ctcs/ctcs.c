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
 * ctcs.c : ctc session implementation
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include "ctcp.h"
#include "ctc_include.h"
#include "ctc_common.h"
#include "ctcg_conf.h"
#include "ctcg_list.h"
#include "ctcj.h"
#include "ctcs_def.h"
#include "ctcs.h"
#include "ctc_types.h"


static int ctcs_mgr_lock_sg_list(void);
static int ctcs_mgr_unlock_sg_list(void);
static int ctcs_mgr_destroy_session_group (CTCS_SESSION_GROUP *sg);
static int ctcs_mgr_add_session_group (CTCS_SESSION_GROUP *sg);
static int ctcs_mgr_delete_session_group (CTCS_SESSION_GROUP *sg);
static int ctcs_sg_get_empty_job_session_position (CTCS_SESSION_GROUP *sg);

static CTCS_JOB_SESSION *ctcs_sg_get_available_job_session (CTCS_SESSION_GROUP *sg, 
                                                            unsigned short *job_desc);

static int ctcs_init_ctrl_session (CTCS_CTRL_SESSION *ctrl_session, 
                                   CTCN_LINK *link, 
                                   int sgid);

static void *ctcs_ctrl_session_thr_func (void *args);

static int ctcs_job_session_get_job_status (CTCS_JOB_SESSION *job_session, 
                                            int *job_status);

static int ctcs_job_session_register_table (CTCS_JOB_SESSION *job_session, 
                                            char *table_name, 
                                            char *user_name);

static int ctcs_job_session_unregister_table (CTCS_JOB_SESSION *job_session, 
                                              char *table_name, 
                                              char *user_name);

static int ctcs_job_session_set_attr (CTCS_JOB_SESSION *job_session, 
                                      CTCJ_JOB_ATTR *job_attr);

static int ctcs_job_session_stop_capture (CTCS_JOB_SESSION *job_session, 
                                          int stop_cond);

static int ctcs_job_session_init (CTCS_JOB_SESSION *job_session, 
                                  CTCN_LINK *link, 
                                  int sgid, 
                                  unsigned short job_id);

static int ctcs_job_session_final (CTCS_JOB_SESSION *job_session);

static void ctcs_job_session_add_job (CTCS_JOB_SESSION *job_session);

static void ctcs_job_session_clean (CTCS_JOB_SESSION *job_session);

static int ctcs_validate_job_attr (CTCJ_JOB_ATTR *job_attr);

/* inline functions */
static inline int ctcs_mgr_get_sg_max_cnt (void);
static inline void ctcs_mgr_inc_sg_cnt (void);
static inline void ctcs_mgr_dec_sg_cnt (void);

static inline void ctcs_job_session_set_status (CTCS_JOB_SESSION *job_session, 
                                                int status);

static inline int ctcs_job_session_get_status (CTCS_JOB_SESSION *job_session);


CTCS_MGR ctcs_Mgr;


extern int ctcs_initialize (void)
{
    int result;
    int session_group_max = 0;

    result = ctcg_conf_get_item_value (CTCG_CONF_ID_CTC_SESSION_GROUP_MAX, 
                                       CTCG_CONF_ITEM_VAL_SET_INT, 
                                       (void *)&session_group_max);

    CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_get_conf_item_label);

    ctcs_Mgr.sg_max_cnt = session_group_max;
    ctcs_Mgr.sg_cnt = 0;

    CTCG_LIST_INIT (&(ctcs_Mgr.sg_list));

    pthread_mutex_init(&ctcs_Mgr.sg_list_lock, NULL);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_get_conf_item_label)
    {
        /* ERROR: configuration loading */
    }
    EXCEPTION_END;

    return result;
}


extern void ctcs_finalize (void)
{
    CTCS_SESSION_GROUP *sg;
    CTCG_LIST_NODE *itr;

    if (CTCG_LIST_IS_EMPTY (&(ctcs_Mgr.sg_list)))
    {
        /* already clean */
    }
    else
    {
        CTCG_LIST_ITERATE (&(ctcs_Mgr.sg_list), itr)
        {
            sg = (CTCS_SESSION_GROUP *)itr->obj;

            if (sg != NULL)
            {
                sg->ctrl_session.status = CTCS_CTRL_SESSION_CLOSING;
                (void)ctcs_sg_finalize (sg);
            }
            else
            {
                /* end of list */
            }
        }
    }

    return;
}


extern int ctcs_mgr_create_session_group (CTCN_LINK *link, int *sgid)
{
    int id, sg_cnt;
    int result;
    int stage = 0;
    CTCS_SESSION_GROUP *sg = NULL;

    /* alloc session group */
    sg = (CTCS_SESSION_GROUP *)malloc (sizeof (CTCS_SESSION_GROUP));
    CTC_COND_EXCEPTION (sg == NULL, err_alloc_session_group_label);
    stage = 1;

    (void)ctcs_mgr_get_sg_cnt (&sg_cnt);
    sg_cnt++;

    /* session group initialize */
    CTC_TEST_EXCEPTION (ctcs_sg_initialize (sg, link, sg_cnt), 
                        err_sg_initilaize_label);
    stage = 2;

    /* add session group into sg_list */
    CTC_TEST_EXCEPTION (ctcs_mgr_add_session_group (sg),
                        err_add_session_group_label);

    *sgid = sg_cnt;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_alloc_session_group_label)
    {
        result = CTC_ERR_ALLOC_FAILED;
    }
    CTC_EXCEPTION (err_sg_initilaize_label)
    {
        result = CTC_ERR_INIT_FAILED;
    }
    CTC_EXCEPTION (err_add_session_group_label)
    {
        result = CTC_ERR_ADD_LIST_FAILED;
    }
    EXCEPTION_END;

    switch (stage)
    {
        case 2:
            ctcs_mgr_dec_sg_cnt ();
            (void)ctcs_sg_finalize (sg);
        case 1:
            (void)free (sg);
            break;
    }

    return result;
}


extern int ctcs_mgr_destroy_session_group (CTCS_SESSION_GROUP *sg)
{
    int i;
    int result;

    for (i = 0; i < CTCS_JOB_SESSION_COUNT_MAX; i++)
    {
        result = ctcs_job_session_final (&(sg->job_session[i]));

        if (result == CTC_SUCCESS)
        {
            ctcs_mgr_dec_session_count ();
        }
        else
        {
            CTC_COND_EXCEPTION (result != CTC_ERR_JOB_ALREADY_STOPPED &&
                                result != CTC_ERR_JOB_NOT_EXIST_FAILED, 
                                err_job_session_final_label);
        }
    }

    ctcs_mgr_dec_session_count ();

    free (sg);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_job_session_final_label)
    {
        /* error info set from sub-function */
    }
    EXCEPTION_END;

    return result;
}


extern int ctcs_sg_initialize (CTCS_SESSION_GROUP *sg, 
                               CTCN_LINK *link, 
                               int sgid)
{
    int result;

    sg->sgid = sgid;
    sg->added_job_cnt = 0;
    sg->job_sessions_status_flag = JOB_SESSION_POSITION_NULL;

    result = ctcs_init_ctrl_session (&(sg->ctrl_session), link, sg->sgid);
    CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                        err_init_ctrl_session_failed_label);

    CTCG_LIST_INIT_OBJ (&(sg->node), sg);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_init_ctrl_session_failed_label)
    {
        /* error info set from sub-function */
    }
    EXCEPTION_END;

    return result;
}


extern int ctcs_sg_finalize (CTCS_SESSION_GROUP *sg)
{
    int result;

    CTC_TEST_EXCEPTION (ctcs_mgr_delete_session_group (sg),
                        err_delete_session_group_label);    

    result = ctcs_mgr_destroy_session_group (sg);

    CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                        err_destroy_sg_failed_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_delete_session_group_label)
    {
        result = CTC_ERR_DELETE_SESSION_GROUP_FAILED;
    }
    CTC_EXCEPTION (err_destroy_sg_failed_label)
    {
        result = CTC_FAILURE;
    }
    EXCEPTION_END;

    return result;
}


extern CTCS_SESSION_GROUP *ctcs_find_session_group_by_id (int sgid)
{
    CTCG_LIST *itr = NULL;
    CTCS_SESSION_GROUP *sg = NULL; 

    if (CTCG_LIST_IS_EMPTY(&ctcs_Mgr.sg_list) != CTC_TRUE)
    {
        CTCG_LIST_ITERATE (&ctcs_Mgr.sg_list, itr)
        {
            sg = (CTCS_SESSION_GROUP *)itr->obj;
            if (sg->sgid == sgid)
            {
                break;
            }
        }
    }
    else
    {
        /* empty sglist */
    }

    return sg;
}


static int ctcs_init_ctrl_session (CTCS_CTRL_SESSION *ctrl_session, 
                                   CTCN_LINK *link,
                                   int sgid)
{
    int result;
    int thr_ret = 0;
    pthread_t ctrl_thr;
    pthread_attr_t ctrl_thr_attr;

    CTC_COND_EXCEPTION (link == NULL, err_null_link);
    ctrl_session->link = link;
    ctrl_session->status = CTCS_CTRL_SESSION_INIT;
    ctrl_session->sgid = sgid;

    /* ctrl session thread create */
    CTC_TEST_EXCEPTION (pthread_create (&ctrl_thr, 
                                        NULL, 
                                        (void *)ctcs_ctrl_session_thr_func, 
                                        (void *)ctrl_session),
                        err_create_thread_failed_label); 

    /* register thread id to job_session */
    ctrl_session->thread = ctrl_thr;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_link)
    {
        result = CTC_ERR_NULL_LINK_FAILED;
    }
    CTC_EXCEPTION (err_alloc_session_group_label)
    {
        result = CTC_ERR_ALLOC_FAILED;
    }
    CTC_EXCEPTION (err_create_thread_failed_label)
    {
        result = CTC_ERR_INSUFFICIENT_SYS_RESOURCE_FAILED;
    }
    EXCEPTION_END;

    return result;
}


static void *ctcs_ctrl_session_thr_func (void *args)
{
    BOOL is_timeout = CTC_FALSE;
    int i;
    int result = 0;
    CTCS_CTRL_SESSION *ctrl_session = (CTCS_CTRL_SESSION *)args;
    CTCG_LIST_NODE *itr = NULL;

    assert (ctrl_session != NULL);

    while (ctrl_session->status != CTCS_CTRL_SESSION_CLOSING)
    {
        /* DEBUG if (0) */
//        if (0) { sleep (3);
        result = ctcn_link_poll_socket (ctrl_session->link, 
                                        100 * 1000, 
                                        &is_timeout);

        CTC_COND_EXCEPTION (result != CTC_SUCCESS,
                            err_link_poll_socket_failed_label);

        if (is_timeout == CTC_TRUE)
        {
            sleep (1);
            continue;
        }
        else
        {
            result = ctcp_process_protocol (ctrl_session->link,
                                            ctrl_session->sgid);

            CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                err_process_prcl_failed_label);
        }
//        } /* DEBUG if (0) */
    }

    pthread_exit (CTC_SUCCESS);

    CTC_EXCEPTION (err_link_poll_socket_failed_label)
    {
        /* DEBUG */
        fprintf (stderr, 
                 "session group [%d]'s control session link polling failed.\n",
                 ctrl_session->sgid);
        fflush (stderr);

        result = CTC_ERR_NETWORK_FAILED;
    }
    CTC_EXCEPTION (err_process_prcl_failed_label)
    {
        /* TODO: logging protocol errors */
        /* ERROR: protocol error */
    }
    EXCEPTION_END;

    pthread_exit ((void *)&result);
}


static int ctcs_mgr_add_session_group (CTCS_SESSION_GROUP *sg)
{
    int result; 

    CTC_TEST_EXCEPTION (ctcs_mgr_lock_sg_list (),
                        err_mgr_lock_failed_label);

    CTCG_LIST_ADD_LAST (&(ctcs_Mgr.sg_list), &(sg->node));
    ctcs_mgr_inc_sg_cnt ();

    CTC_TEST_EXCEPTION (ctcs_mgr_unlock_sg_list (),
                        err_mgr_unlock_failed_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_mgr_lock_failed_label)
    {
        result = CTC_ERR_LOCK_FAILED;
    }
    CTC_EXCEPTION (err_mgr_unlock_failed_label)
    {
        result = CTC_ERR_UNLOCK_FAILED;
    }
    EXCEPTION_END;

    return result;
}


static int ctcs_mgr_delete_session_group (CTCS_SESSION_GROUP *sg)
{
    int result; 

    CTC_TEST_EXCEPTION (ctcs_mgr_lock_sg_list (),
                        err_mgr_lock_failed_label);

    CTCG_LIST_REMOVE (&(sg->node));
    ctcs_mgr_dec_sg_cnt ();

    CTC_TEST_EXCEPTION (ctcs_mgr_unlock_sg_list (),
                        err_mgr_unlock_failed_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_mgr_lock_failed_label)
    {
        result = CTC_ERR_LOCK_FAILED;
    }
    CTC_EXCEPTION (err_mgr_unlock_failed_label)
    {
        result = CTC_ERR_UNLOCK_FAILED;
    }
    EXCEPTION_END;

    return result;
}


static int ctcs_mgr_lock_sg_list(void)
{
    int result;

    CTC_TEST_EXCEPTION (pthread_mutex_lock (&ctcs_Mgr.sg_list_lock),
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


static int ctcs_mgr_unlock_sg_list(void)
{
    int result;

    CTC_TEST_EXCEPTION (pthread_mutex_unlock (&ctcs_Mgr.sg_list_lock),
                        err_mutex_unlock_failed_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_mutex_unlock_failed_label)
    {
        /* EINVAL, EPERM or EAGAIN */
        result = CTC_ERR_UNLOCK_FAILED;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcs_destroy_all_job_session (CTCS_SESSION_GROUP *sg,
                                         int close_cond)
{
    int i;
    int result;
    int job_status;

    for (i = 0; i < CTC_JOB_SESSION_PER_GROUP; i++) 
    {    
        if (sg->job_session[i].status == CTCS_JOB_SESSION_CONNECTED)
        {
            /* get job status */
            ctcj_get_job_status (sg->job_session[i].job, &job_status);

            if (job_status == CTCJ_JOB_PROCESSING)
            {
                /* stop_capture: IMMEDIATELY */
                ctcj_stop_capture_immediately (1, sg->job_session[i].job);
            }
            else
            {
                /* just transfer status to CTCJ_JOB_CLOSING */
            }

            ctcj_set_job_status (sg->job_session[i].job, CTCJ_JOB_CLOSING);
        }    
        else 
        {
            /* just clean */
        }

        ctcs_job_session_clean (&(sg->job_session[i]));

        ctcs_job_session_set_status (&(sg->job_session[i]), 
                                     CTCS_JOB_SESSION_CLOSING);

        UNSET_JOB_POSITION_FLAG (sg->job_sessions_status_flag, 
                                 GET_JOB_SESSION_POSITION_MASK(i));
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_mgr_lock_failed_label)
    {
        result = CTC_ERR_LOCK_FAILED;
    }
    CTC_EXCEPTION (err_mgr_unlock_failed_label)
    {
        result = CTC_ERR_UNLOCK_FAILED;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcs_destroy_job_session (CTCS_SESSION_GROUP *sg, 
                                     unsigned short job_desc,
                                     int close_cond)
{
    int result;
    int job_status = CTCJ_JOB_NONE;
    CTCS_JOB_SESSION *job_session = NULL;

    job_session = ctcs_sg_find_job_session(sg, job_desc);
    CTC_COND_EXCEPTION (job_session == NULL, err_invalid_job_label);

    /* check job session's status */
    ctcj_get_job_status (job_session->job, &job_status);

    if (job_status == CTCJ_JOB_PROCESSING)
    {
        ctcj_stop_capture_immediately (1, job_session->job);

        while (job_status == CTCJ_JOB_PROCESSING)
        {
            ctcj_get_job_status (job_session->job, &job_status);

            if (job_status == CTCJ_JOB_PROCESSING)
            {
                sleep (1);
            }
            else
            {
                break;
            }
        }
    }
    else
    {
        /* just transfer status to CTCJ_JOB_CLOSING */
    }
        
    ctcj_set_job_status (job_session->job, CTCJ_JOB_CLOSING);

    ctcs_job_session_clean (job_session);

    ctcs_job_session_set_status (job_session, CTCS_JOB_SESSION_CLOSING);
    
    UNSET_JOB_POSITION_FLAG (sg->job_sessions_status_flag, 
                             GET_JOB_SESSION_POSITION_MASK(job_desc));

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_invalid_job_label)
    {
        result = CTC_ERR_INVALID_JOB_FAILED;
    }
    EXCEPTION_END;

    return result;
}


extern CTCS_JOB_SESSION *ctcs_sg_find_job_session (CTCS_SESSION_GROUP *sg,
                                                   unsigned short job_desc)
{
    int job_session_pos = CTCS_INVALID_JOB_SESSION_POSITION;
    CTCS_JOB_SESSION *job_session = NULL;

    job_session_pos = GET_JOB_SESSION_POS_FROM_JOB_DESC(job_desc);

    if (job_session_pos != CTCS_INVALID_JOB_SESSION_POSITION)
    {
        job_session = &(sg->job_session[job_session_pos]);
    }
    else
    {
        /* invalid job descriptor */
    }

    return job_session;
}


extern CTCS_CTRL_SESSION *ctcs_sg_get_ctrl_session (CTCS_SESSION_GROUP *sg)
{
    CTCS_CTRL_SESSION *ctrl_session = NULL;

    if (sg != NULL)
    {
        ctrl_session = &(sg->ctrl_session);
    }
    else
    {
        /* NULL */
    }

    return ctrl_session;
}


extern int ctcs_sg_add_job (CTCS_SESSION_GROUP *sg, 
                            CTCN_LINK *link,
                            unsigned short *job_desc)
{
    int result;
    unsigned short job_id;
    int job_session_pos = CTCS_INVALID_JOB_SESSION_POSITION;
    CTCS_JOB_SESSION *job_session = NULL;

    assert (sg != NULL);

    job_session = ctcs_sg_get_available_job_session (sg, &job_id);
    CTC_COND_EXCEPTION (job_session == NULL, err_no_more_job_available_label);

    CTC_TEST_EXCEPTION (ctcs_job_session_init (job_session, link, sg->sgid, job_id),
                        err_job_session_init_failed_label);

    /* add job to job reference table */
    ctcs_job_session_add_job (job_session);

    *job_desc = job_id;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_no_more_job_available_label)
    {
        result = CTC_ERR_EXCEED_MAX_FAILED;
    }
    CTC_EXCEPTION (err_job_session_init_failed_label)
    {
        ctcs_job_session_final (job_session);
        result = CTC_ERR_INIT_FAILED;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcs_sg_delete_job (CTCS_SESSION_GROUP *sg, unsigned short job_desc)
{
    int result;
    CTCS_JOB_SESSION *job_session = NULL;

    assert (sg != NULL);

    job_session = ctcs_sg_find_job_session (sg, job_desc);
    CTC_COND_EXCEPTION (job_session == NULL, err_job_not_exist_label);

    result = ctcs_job_session_final (job_session);
    CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                        err_job_session_final_failed_label);

    ctcs_mgr_dec_session_count ();

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_job_not_exist_label)
    {
        result = CTC_ERR_JOB_NOT_EXIST_FAILED;
    }
    CTC_EXCEPTION (err_job_session_final_failed_label)
    {
        /* error info set from sub-function */
    }
    EXCEPTION_END;

    return result;
}


static CTCS_JOB_SESSION *ctcs_sg_get_available_job_session (CTCS_SESSION_GROUP *sg, 
                                                            unsigned short *job_desc)
{
    int position;
    int job_id = CTCJ_NULL_JOB_DESCRIPTOR;
    CTCS_JOB_SESSION *job_session;

    position = ctcs_sg_get_empty_job_session_position (sg);

    if (position != CTCS_INVALID_JOB_SESSION_POSITION)
    {
        job_session = &(sg->job_session[position]);
        job_id = GET_JOB_DESC_FROM_JOB_SESSION_POS(position);
    }
    else
    {
        job_session = NULL;
    }

    *job_desc = (unsigned short)job_id;

    return job_session;
}


static int ctcs_sg_get_empty_job_session_position (CTCS_SESSION_GROUP *sg)
{
    int i;
    unsigned short status_flag = sg->job_sessions_status_flag;

    for (i = 0; i < CTCS_JOB_SESSION_COUNT_MAX; i++)
    {
        if (!(status_flag &= GET_JOB_SESSION_POSITION_MASK(i)))
        {
            return i;
        }
    }

    return CTCS_INVALID_JOB_SESSION_POSITION;
}

/*
 * Description: get job status 
 *              call by only ctcp protocol functions directly
 *
 */
extern int ctcs_sg_get_job_status (CTCS_SESSION_GROUP *sg,
                                   unsigned short job_desc,
                                   int *job_status)
{
    int result;
    int status;
    CTCS_JOB_SESSION *job_session = NULL;

    job_session = ctcs_sg_find_job_session (sg, job_desc);

    result = ctcs_job_session_get_job_status (job_session, &status);
    CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_get_job_status_label);

    *job_status = status;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_get_job_status_label)
    {
        /* error info set from sub-function */
    }
    EXCEPTION_END;

    return result;
}


static int ctcs_job_session_get_job_status (CTCS_JOB_SESSION *job_session,
                                            int *job_status)
{
    int result;
    CTCJ_JOB_INFO *job = NULL;

    assert (job_session != NULL);

    job = job_session->job;
    CTC_COND_EXCEPTION (job == NULL, err_job_not_exist_label);

    CTC_COND_EXCEPTION (job->status < CTCJ_JOB_NONE || 
                        job->status > CTCJ_JOB_CLOSING, 
                        err_invalid_job_status_label);

    *job_status = job->status;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_job_not_exist_label)
    {
        result = CTC_ERR_JOB_NOT_EXIST_FAILED;
    }
    CTC_EXCEPTION (err_invalid_job_status_label)
    {
        result = CTC_ERR_INVALID_JOB_STATUS_FAILED;
    }
    EXCEPTION_END;

    return result;
}


static void ctcs_job_session_add_job (CTCS_JOB_SESSION *job_session)
{
    CTCJ_JOB_INFO *job = NULL;

    job = job_session->job;
    ctcj_ref_table_add_job (job);

    job_session->status = CTCS_JOB_SESSION_CONNECTED;

    return;
}


static void ctcs_job_session_remove_job (CTCS_JOB_SESSION *job_session)
{
    CTCJ_JOB_INFO *job = NULL;

    job = job_session->job;
    ctcj_ref_table_remove_job (job);

    job_session->status = CTCS_JOB_SESSION_DISCONNECTED;

    return;
}


static int ctcs_job_session_init (CTCS_JOB_SESSION *job_session, 
                                  CTCN_LINK *link, 
                                  int sgid, 
                                  unsigned short job_id)
{
    int result;
    int job_qsize;
    int long_tran_qsize;
    CTCJ_JOB_INFO *job_info = NULL;

    assert (job_session != NULL);

    if (link != NULL)
    {
        job_session->link = link;
        job_session->sgid = sgid;
            
        result = ctcg_conf_get_item_value (CTCG_CONF_ID_CTC_JOB_QUEUE_SIZE, 
                                           CTCG_CONF_ITEM_VAL_SET_INT, 
                                           (void *)&job_qsize);
        job_session->job_qsize = job_qsize;

        result = ctcg_conf_get_item_value (CTCG_CONF_ID_CTC_LONG_TRAN_QUEUE_SIZE, 
                                           CTCG_CONF_ITEM_VAL_SET_INT, 
                                           (void *)&long_tran_qsize);
        job_session->long_tran_qsize = long_tran_qsize;

        job_session->thread = CTCS_JOB_THREAD_NULL_ID;

        CTC_TEST_EXCEPTION (ctcj_make_new_job (&job_info),
                            err_make_new_job_failed_label);

        CTC_TEST_EXCEPTION (ctcj_init_job_info (job_info, 
                                                job_id,
                                                job_session->sgid,
                                                job_session->job_qsize,
                                                job_session->long_tran_qsize),
                            err_init_job_info_failed_label);

        job_session->job = job_info;

        pthread_mutex_init(&job_session->lock, NULL);
    }
    else
    {
        CTC_COND_EXCEPTION (job_session->link == NULL, err_null_link_label);

        job_session->thread = CTCS_JOB_THREAD_NULL_ID;
    }

    job_session->status = CTCS_JOB_SESSION_OPEN;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_make_new_job_failed_label)
    {
        result = CTC_ERR_ALLOC_FAILED;
    }
    CTC_EXCEPTION (err_init_job_info_failed_label)
    {
        free (job_info);
        result = CTC_ERR_ALLOC_FAILED;
    }
    CTC_EXCEPTION (err_null_link_label)
    {
        /* ERROR: critical error but ignore */
    }
    EXCEPTION_END;

    return result;
}


static void ctcs_job_session_clean (CTCS_JOB_SESSION *job_session)
{
    (void)ctcs_job_session_init (job_session, 
                                 NULL, 
                                 job_session->sgid,
                                 CTCS_NULL_SESSION_ID);

    return;
}


static int ctcs_job_session_final (CTCS_JOB_SESSION *job_session)
{
    int result;
    int job_status;

    assert (job_session != NULL);

    if (job_session->status > CTCS_JOB_SESSION_FREE)
    {
        job_session->status = CTCS_JOB_SESSION_CLOSING;

        result = ctcj_get_job_status (job_session->job, &job_status);
        CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_get_status_label);

        if (job_status == CTCJ_JOB_PROCESSING)
        {
            result = ctcs_job_session_stop_capture (job_session, 
                                                    CTCS_CLOSE_IMMEDIATELY);

            CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                err_stop_capture_failed_label);
        }
        else
        {
            /* already stopped */
        }

        /* remove job */
        (void)ctcj_ref_table_remove_job (job_session->job);

        /* destroy job info */
        ctcj_destroy_job_info (job_session->job);

        job_session->status = CTCS_JOB_SESSION_FREE;
    }
    else
    {
        /* already clean */
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_get_status_label)
    {
        /* error info set from sub-function */
    }
    CTC_EXCEPTION (err_stop_capture_failed_label)
    {
        /* error info set from sub-function */
    }
    EXCEPTION_END;

    return result;
}


extern int ctcs_sg_is_table_registered (CTCS_SESSION_GROUP *sg,
                                        unsigned short job_desc,
                                        char *table_name,
                                        char *user_name,
                                        BOOL *is_exist)
{
    int result;
    CTCS_JOB_SESSION *job_session = NULL;
    CTCG_LIST *table_list = NULL;
    CTCG_LIST_NODE *itr = NULL;
    CTCJ_JOB_TAB_INFO *table_info = NULL;

    assert (sg != NULL);
    assert (job_desc < 10);
    assert (table_name != NULL);

    /* find job session */
    job_session = ctcs_sg_find_job_session(sg, job_desc);
    CTC_COND_EXCEPTION (job_session == NULL, err_invalid_job_label);

    /* get table info list */
//    table_list = ctcj_job_get_table_list (job_session->job);

    table_list = &((job_session->job)->table_list);

    /* find job table info in job_info */
    if (CTCG_LIST_IS_EMPTY(table_list) != CTC_TRUE)
    {
        CTCG_LIST_ITERATE (table_list, itr)
        {
            table_info = (CTCJ_JOB_TAB_INFO *)itr->obj;

            if (table_info != NULL)
            {
                if (strcmp (table_info->name, table_name) == 0)
                {
                    /* found table */
                    *is_exist = CTC_TRUE;
                    break;
                }
                else
                {
                    continue;
                }
            }
            else
            {
                /* end of list */
                *is_exist = CTC_FALSE;
            }
        }
    }
    else
    {
        *is_exist = CTC_FALSE;
        /* empty table_list */
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_invalid_job_label)
    {
        result = CTC_ERR_INVALID_JOB_FAILED;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcs_sg_register_table (CTCS_SESSION_GROUP *sg,
                                   unsigned short job_desc,
                                   char *table_name,
                                   char *user_name)
{
    int result;
    CTCS_JOB_SESSION *job_session = NULL;

    /* find job session */
    job_session = ctcs_sg_find_job_session(sg, job_desc);
    CTC_COND_EXCEPTION (job_session == NULL, err_invalid_job_label);

    result = ctcs_job_session_register_table (job_session, 
                                              table_name,
                                              user_name);
    CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_register_table);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_invalid_job_label)
    {
        result = CTC_ERR_INVALID_JOB_FAILED;
    }
    CTC_EXCEPTION (err_register_table)
    {
        /* error info set from sub-function */
    }
    EXCEPTION_END;

    return result;
}


static int ctcs_job_session_register_table (CTCS_JOB_SESSION *job_session,
                                            char *table_name,
                                            char *user_name)
{
    int result;
    CTCG_LIST *table_list = NULL;
    CTCG_LIST_NODE *itr = NULL;

    CTC_COND_EXCEPTION (table_name == NULL || strlen (table_name) == 0,
                        err_invalid_table_name_label);
   
    CTC_COND_EXCEPTION (user_name == NULL || strlen (user_name) == 0,
                        err_invalid_user_name_label);
   
    result = ctcj_job_register_table (job_session->job, 
                                      table_name, 
                                      user_name);

    CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                        err_job_register_table_label);

    job_session->status = CTCS_JOB_SESSION_JOB_ADDED;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_invalid_table_name_label)
    {
        result = CTC_ERR_INVALID_TABLE_NAME_FAILED;
    }
    CTC_EXCEPTION (err_invalid_user_name_label)
    {
        result = CTC_ERR_INVALID_USER_NAME_FAILED;
    }
    CTC_EXCEPTION (err_job_register_table_label)
    {
        /* error info set from sub-function */
    }
    EXCEPTION_END;

    return result;
}


extern int ctcs_sg_set_job_attr (CTCS_SESSION_GROUP *sg,
                                 unsigned short job_desc,
                                 CTCJ_JOB_ATTR *job_attr)
{
    int result;
    CTCS_JOB_SESSION *job_session = NULL;

    /* find job session */
    job_session = ctcs_sg_find_job_session(sg, job_desc);
    CTC_COND_EXCEPTION (job_session == NULL, err_invalid_job_label);

    /* set attribute value */
    result = ctcs_job_session_set_attr (job_session, job_attr);
    CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_set_attr_failed_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_invalid_job_label)
    {
        result = CTC_ERR_JOB_NOT_EXIST_FAILED;
    }
    CTC_EXCEPTION (err_set_attr_failed_label)
    {
        /* error info set from sub-function */
    }
    EXCEPTION_END;

    return result;
}


static int ctcs_job_session_set_attr (CTCS_JOB_SESSION *job_session, 
                                      CTCJ_JOB_ATTR *job_attr)
{
    int result;

    result = ctcs_validate_job_attr (job_attr);
    CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_invalid_job_attr);

    switch (job_attr->id)
    {
        case CTCJ_JOB_ATTR_ID_JOB_QUEUE_SIZE:
            job_session->job_qsize = job_attr->value;
            break;

        case CTCJ_JOB_ATTR_ID_LONG_TRAN_QUEUE_SIZE:
            job_session->long_tran_qsize = job_attr->value;
            break;

        default:
            break;
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_invalid_job_attr)
    {
        /* error info set from sub-function */
    }
    EXCEPTION_END;

    return result;
}


static int ctcs_validate_job_attr (CTCJ_JOB_ATTR *job_attr)
{
    int result;
    int attr_val = 0;

    CTC_COND_EXCEPTION (job_attr->id < CTCJ_JOB_ATTR_ID_START || 
                        job_attr->id > CTCJ_JOB_ATTR_ID_LAST,
                        err_invalid_job_attr_label);

    switch (job_attr->id)
    {
        case CTCJ_JOB_ATTR_ID_JOB_QUEUE_SIZE:

            /* get attribute min value from conf */
            result = ctcg_conf_get_item_value (CTCG_CONF_ID_CTC_JOB_QUEUE_SIZE, 
                                               CTCG_CONF_ITEM_VAL_MIN, 
                                               (void *)&attr_val);

            CTC_COND_EXCEPTION (job_attr->value < attr_val,
                                err_invalid_attr_val_label);
            break;

        case CTCJ_JOB_ATTR_ID_LONG_TRAN_QUEUE_SIZE:

            /* get attribute max value from conf */
            result = ctcg_conf_get_item_value (CTCG_CONF_ID_CTC_LONG_TRAN_QUEUE_SIZE, 
                                               CTCG_CONF_ITEM_VAL_MAX, 
                                               (void *)&attr_val);

            CTC_COND_EXCEPTION (job_attr->value < attr_val,
                                err_invalid_attr_val_label);
            break;

        default:
            break;
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_invalid_job_attr_label)
    {
        result = CTC_ERR_INVALID_ATTR_FAILED;
    }
    CTC_EXCEPTION (err_invalid_attr_val_label)
    {
        result = CTC_ERR_INVALID_VALUE_FAILED;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcs_sg_unregister_table (CTCS_SESSION_GROUP *sg,
                                     unsigned short job_desc,
                                     char *table_name, 
                                     char *user_name)
{
    int result;
    CTCS_JOB_SESSION *job_session = NULL;

    /* find job session */
    job_session = ctcs_sg_find_job_session(sg, job_desc);
    CTC_COND_EXCEPTION (job_session == NULL, err_invalid_job_label);

    result = ctcs_job_session_unregister_table (job_session, 
                                                table_name, 
                                                user_name);
    CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_unregister_table);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_invalid_job_label)
    {
        result = CTC_ERR_INVALID_JOB_FAILED;
    }
    CTC_EXCEPTION (err_unregister_table)
    {
        /* error info set from sub-function */
    }
    EXCEPTION_END;

    return result;
}


static int ctcs_job_session_unregister_table (CTCS_JOB_SESSION *job_session,
                                              char *table_name,
                                              char *user_name)
{
    int result;
    CTCG_LIST *table_list = NULL;
    CTCG_LIST_NODE *itr = NULL;

    CTC_COND_EXCEPTION (table_name == NULL || strlen(table_name) == 0,
                        err_invalid_table_name_label);
   
    CTC_COND_EXCEPTION (user_name == NULL || strlen (user_name) == 0,
                        err_invalid_user_name_label);
   
    result = ctcj_job_unregister_table (job_session->job, 
                                        table_name,
                                        user_name);

    CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                        err_job_unregister_table_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_invalid_table_name_label)
    {
        result = CTC_ERR_INVALID_TABLE_NAME_FAILED;
    }
    CTC_EXCEPTION (err_invalid_user_name_label)
    {
        result = CTC_ERR_INVALID_USER_NAME_FAILED;
    }
    CTC_EXCEPTION (err_job_unregister_table_label)
    {
        /* error info set from sub-function */
    }
    EXCEPTION_END;

    return result;
}


extern int ctcs_sg_start_capture (CTCS_SESSION_GROUP *sg,
                                  unsigned short job_desc)
{
    int result;
    int status;
    CTCS_JOB_SESSION *job_session = NULL;

    /* find job session */
    job_session = ctcs_sg_find_job_session(sg, job_desc);
    CTC_COND_EXCEPTION (job_session == NULL, err_invalid_job_label);

    /* check job_session's status */
    status = ctcs_job_session_get_status (job_session);
    CTC_COND_EXCEPTION (status != CTCS_JOB_SESSION_JOB_ADDED,
                        err_job_session_already_stopped_label);

    /* start capture */
    result = ctcs_job_session_start_capture (job_session);
    CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                        err_start_capture_failed_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_invalid_job_label)
    {
        result = CTC_ERR_JOB_NOT_EXIST_FAILED;
    }
    CTC_EXCEPTION (err_job_session_already_stopped_label)
    {
        result = CTC_ERR_JOB_ALREADY_STOPPED;
    }
    CTC_EXCEPTION (err_start_capture_failed_label)
    {
        /* error info set from sub-function */
    }
    EXCEPTION_END;

    return result;
}


extern int ctcs_job_session_start_capture (CTCS_JOB_SESSION *job_session)
{
    int result;
    int job_status;
    int thr_ret = 0;
    pthread_t job_thr;
    CTCJ_JOB_INFO *job = NULL;

    assert (job_session != NULL);

    job = job_session->job;

    /* get job status */
    result = ctcj_get_job_status (job, &job_status);
    CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_job_not_exist_label);

    CTC_COND_EXCEPTION (job_status == CTCJ_JOB_PROCESSING,
                        err_job_already_started_label);

    if (job_status == CTCJ_JOB_READY ||
        job_status == CTCJ_JOB_STOPPED ||
        job_status == CTCJ_JOB_IMMEDIATE_STOPPED)
    {
        /* increase current processing job count of ctcl */
        ctcl_mgr_inc_cur_job_cnt ();

        /* create thread */
        CTC_TEST_EXCEPTION (pthread_create (&job_thr, 
                                            NULL, 
                                            ctcj_capture_thr_func, 
                                            (void *)job_session),
                            err_create_thread_failed_label); 

        /* register thread id to job_session */
        job_session->thread = job_thr;
    }
    else
    {
        CTC_COND_EXCEPTION (job_status == CTCJ_JOB_CLOSING ||
                            job_status == CTCJ_JOB_NONE,
                            err_invalid_job_status_label);
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_job_not_exist_label)
    {
        result = CTC_ERR_JOB_NOT_EXIST_FAILED;
    }
    CTC_EXCEPTION (err_job_already_started_label)
    {
        result = CTC_ERR_JOB_ALREADY_STARTED;
    }
    CTC_EXCEPTION (err_create_thread_failed_label)
    {
        ctcl_mgr_dec_cur_job_cnt ();
        result = CTC_ERR_INSUFFICIENT_SYS_RESOURCE_FAILED;
    }
    CTC_EXCEPTION (err_invalid_job_status_label)
    {
        result = CTC_ERR_INVALID_JOB_STATUS_FAILED;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcs_sg_stop_capture (CTCS_SESSION_GROUP *sg,
                                 unsigned short job_desc,
                                 int stop_cond)
{
    int result;
    CTCS_JOB_SESSION *job_session = NULL;
    CTCJ_JOB_INFO *job = NULL;

    /* find job session */
    job_session = ctcs_sg_find_job_session(sg, job_desc);
    CTC_COND_EXCEPTION (job_session == NULL, err_invalid_job_label);

    /* check job_session's status */
    CTC_COND_EXCEPTION (job_session->status > CTCS_JOB_SESSION_DISCONNECTED,
                        err_job_session_already_disconnected_label);

    /* start capture */
    result = ctcs_job_session_stop_capture (job_session, stop_cond);
    CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                        err_stop_capture_failed_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_invalid_job_label)
    {
        result = CTC_ERR_JOB_NOT_EXIST_FAILED;
    }
    CTC_EXCEPTION (err_job_session_already_disconnected_label)
    {
        result = CTC_ERR_JOB_ALREADY_STOPPED;
    }
    CTC_EXCEPTION (err_stop_capture_failed_label)
    {
        /* error info set from sub-function */
    }
    EXCEPTION_END;

    return result;
}


static int ctcs_job_session_stop_capture (CTCS_JOB_SESSION *job_session,
                                          int stop_cond)
{
    int result;
    int job_status;

    assert (job_session != NULL);

    /* get job status */
    result = ctcj_get_job_status (job_session->job, &job_status);
    CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_job_not_exist_label);

    CTC_COND_EXCEPTION (job_status != CTCJ_JOB_PROCESSING,
                        err_job_already_stopped_label);

    if (stop_cond == CTCS_CLOSE_IMMEDIATELY)
    {
        ctcj_stop_capture_immediately (job_session->thread, job_session->job);
    }
    else
    {
        ctcj_stop_capture (job_session->thread, job_session->job);
    }

    ctcl_mgr_dec_cur_job_cnt ();
   
    return CTC_SUCCESS;

    CTC_EXCEPTION (err_job_not_exist_label)
    {
        /* error info set from sub-function */
    }
    CTC_EXCEPTION (err_job_already_stopped_label)
    {
        result = CTC_ERR_JOB_ALREADY_STOPPED;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcs_mgr_get_session_count (int *cnt)
{
    int result;

    CTC_TEST_EXCEPTION (ctcs_mgr_lock_sg_list(), err_lock_failed_label);

    *cnt = ctcs_Mgr.total_session_cnt;

    CTC_TEST_EXCEPTION (ctcs_mgr_unlock_sg_list(), err_unlock_failed_label);

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


extern int ctcs_mgr_inc_session_count (void)
{
    int result;

    CTC_TEST_EXCEPTION (ctcs_mgr_lock_sg_list(), err_lock_failed_label);

    ctcs_Mgr.total_session_cnt++;

    CTC_TEST_EXCEPTION (ctcs_mgr_unlock_sg_list(), err_unlock_failed_label);

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


extern int ctcs_mgr_dec_session_count (void)
{
    int result; 

    CTC_TEST_EXCEPTION (ctcs_mgr_lock_sg_list(), err_lock_failed_label);

    if (ctcs_Mgr.total_session_cnt > 0)
    {
        ctcs_Mgr.total_session_cnt--;
    }

    CTC_TEST_EXCEPTION (ctcs_mgr_unlock_sg_list(), err_unlock_failed_label);

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


extern int ctcs_mgr_total_registered_job_cnt (void)
{
    int job_cnt = 0;
    CTCS_SESSION_GROUP *sg;
    CTCG_LIST_NODE *itr;

    CTCG_LIST_ITERATE (&(ctcs_Mgr.sg_list), itr)
    {
        sg = (CTCS_SESSION_GROUP *)itr->obj;

        if (sg != NULL)
        {
            job_cnt += sg->added_job_cnt;
        }
    }

    return job_cnt;
}


extern int ctcs_mgr_get_sg_cnt (int *sg_cnt)
{
    int result;

    CTC_TEST_EXCEPTION (ctcs_mgr_lock_sg_list(), err_lock_failed_label);

    *sg_cnt = ctcs_Mgr.sg_cnt;

    CTC_TEST_EXCEPTION (ctcs_mgr_unlock_sg_list(), err_unlock_failed_label);

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


/* inline functions */
static inline int ctcs_mgr_get_sg_max_cnt (void)
{
    return ctcs_Mgr.sg_max_cnt;
}

static inline void ctcs_mgr_inc_sg_cnt (void)
{
    ctcs_Mgr.sg_cnt++;
}

static inline void ctcs_mgr_dec_sg_cnt (void)
{
    ctcs_Mgr.sg_cnt--;
}

static inline void ctcs_job_session_set_status (CTCS_JOB_SESSION *job_session, 
                                                int status)
{
    job_session->status = status;
}

static inline int ctcs_job_session_get_status (CTCS_JOB_SESSION *job_session)
{
    return job_session->status;
}



