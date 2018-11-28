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
 * ctcp.c : ctc protocol(CTCP) implementation
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include "ctcp.h"
#include "ctcs.h"
#include "ctcl.h"
#include "ctcm.h"
#include "ctcn_link.h"
#include "ctc_types.h"


static int ctcp_validate_prcl_ver (int ver);
static int ctcp_validate_job_desc (int job_desc);
static int ctcp_validate_op_param (int opid, unsigned char op_param);
static BOOL ctcp_is_recv_protocol (int opid);
static int ctcp_execute_protocol (void *link, CTCP_HEADER *header);


extern void ctcp_initialize (void)
{
    fprintf (stdout, "\n\tCurrent CTC protocol version is %d.%d.%d.%d\n", 
             CTCP_VER_MAJOR, 
             CTCP_VER_MINOR, 
             CTCP_VER_PATCH, 
             CTCP_VER_TAG);

    fflush (stdout);

    return;
}


/* function just for pair with ctcp_initialize */
extern void ctcp_finalize (void)
{
    return;
}


/* protocol header */
extern int ctcp_make_protocol_header (void *inlink, 
                                      unsigned char opid, 
                                      unsigned char result_code,
                                      unsigned short job_desc,
                                      int sgid,
                                      int data_len)
{
    int result;
    int version;
    CTCN_LINK *link;

    assert (inlink != NULL);
    assert (&opid != NULL);

    link = (CTCN_LINK *)inlink;
    /* check operation id is known */
    CTC_TEST_EXCEPTION (ctcp_check_opid_range ((int)opid), 
                        err_invalid_opid_label);

    link->wbuf_pos = 0;

    /* 1. write operation */
    CTC_TEST_EXCEPTION (ctcn_link_write_one_byte_number (link, (void *)&opid),
                        err_ctcn_link_wbuf_overflow_label);

    /* 2. write result code */
    CTC_TEST_EXCEPTION (ctcn_link_write_one_byte_number (link, (void *)&result_code),
                        err_ctcn_link_wbuf_overflow_label);

    /* 3. write job description */
    CTC_TEST_EXCEPTION (ctcn_link_write_two_byte_number (link, (void *)&job_desc),
                        err_ctcn_link_wbuf_overflow_label);

    /* 4. write session group id */
    CTC_TEST_EXCEPTION (ctcn_link_write_four_byte_number (link, (void *)&sgid),
                        err_ctcn_link_wbuf_overflow_label);

    /* 5. write protocol version */
    version = CTCP_VERSION;
    CTC_TEST_EXCEPTION (ctcn_link_write_four_byte_number (link, (void *)&version),
                        err_ctcn_link_wbuf_overflow_label);

    /* 6. write length of data payload */
    CTC_TEST_EXCEPTION (ctcn_link_write_four_byte_number (link, (void *)&data_len),
                        err_ctcn_link_wbuf_overflow_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_invalid_opid_label)
    {
        result = CTC_ERR_INVALID_TYPE_FAILED;
    }
    CTC_EXCEPTION (err_ctcn_link_wbuf_overflow_label)
    {
        result = CTC_ERR_BUFFER_OVERFLOW_FAILED;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcp_analyze_protocol_header (void *inlink, 
                                         unsigned char opid,
                                         CTCP_HEADER *read_header)
{
    int result = CTC_SUCCESS;
    int read_opid = CTCP_UNKNOWN_OPERATION;
    int read_op_param;
    int read_job_desc;
    int read_sgid;
    int read_ver;
    int read_data_len = 0;
    CTCN_LINK *link = (CTCN_LINK *)inlink;

    link->rbuf_pos = 0;

    /* operation id */
    CTC_TEST_EXCEPTION (ctcn_link_read_one_byte_number (link, &read_opid),
                        err_ctcn_link_read_operation_label);

    if ((int)opid == CTCP_UNKNOWN_OPERATION)
    {
        opid = read_opid;
    }

    CTC_TEST_EXCEPTION (ctcp_validate_op_id ((int)opid, read_opid), 
                        err_ctcp_invalid_operation_label);
    read_header->op_id = (unsigned char)read_opid;

    /* operation specific param */
    CTC_TEST_EXCEPTION (ctcn_link_read_one_byte_number (link, &read_op_param),
                        err_ctcn_link_read_param_label);

    CTC_TEST_EXCEPTION (ctcp_validate_op_param (read_opid, read_op_param),
                        err_ctcp_invalid_param_label);

    read_header->op_param = (char)read_op_param;

    /* job descriptor */
    CTC_TEST_EXCEPTION (ctcn_link_read_two_byte_number (link, &read_job_desc),
                        err_ctcn_link_read_job_desc_label);

    if (read_opid == CTCP_DESTROY_JOB_SESSION ||
        read_opid == CTCP_REQUEST_JOB_STATUS  ||
        read_opid == CTCP_REGISTER_TABLE      ||
        read_opid == CTCP_UNREGISTER_TABLE    ||
        read_opid == CTCP_SET_JOB_ATTRIBUTE   ||
        read_opid == CTCP_START_CAPTURE       ||
        read_opid == CTCP_STOP_CAPTURE)
    {
        CTC_TEST_EXCEPTION (ctcp_validate_job_desc (read_job_desc),
                            err_ctcp_invalid_job_desc_label);
    }
    else
    {
        /* padding */
    }

    read_header->job_desc = (unsigned short)read_job_desc;

    /* session group id */
    CTC_TEST_EXCEPTION (ctcn_link_read_four_byte_number (link, &read_sgid),
                        err_ctcn_link_read_sgid_label);

    if (read_opid != CTCP_CREATE_CONTROL_SESSION)
    {
        read_header->session_group_id = read_sgid;
    }
    else
    {
        read_header->session_group_id = CTCS_NULL_SESSION_GROUP_ID;
    }

    /* protocol version */
    CTC_TEST_EXCEPTION (ctcn_link_read_four_byte_number (link, &read_ver),
                        err_ctcn_link_read_prcl_ver_label);
// TEMPORARY DISABLED
    CTC_TEST_EXCEPTION (ctcp_validate_prcl_ver (read_ver),
                        err_ctcp_invalid_prcl_ver_label);

    read_header->protocol_ver = read_ver;

    /* length of data */
    CTC_TEST_EXCEPTION (ctcn_link_read_four_byte_number (link, &read_data_len),
                        err_ctcn_link_read_data_len_label);

    read_header->data_len = read_data_len;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_ctcn_link_read_operation_label)
    {
        result = CTC_ERR_INVALID_TYPE_FAILED;
    }
    CTC_EXCEPTION (err_ctcp_invalid_operation_label)
    {
        result = CTC_ERR_INVALID_VALUE_FAILED;
    }
    CTC_EXCEPTION (err_ctcn_link_read_param_label)
    {
        result = CTC_ERR_INVALID_TYPE_FAILED;
    }
    CTC_EXCEPTION (err_ctcp_invalid_param_label)
    {
        result = CTC_ERR_INVALID_VALUE_FAILED;
    }
    CTC_EXCEPTION (err_ctcn_link_read_job_desc_label)
    {
        result = CTC_ERR_INVALID_TYPE_FAILED;
    }
    CTC_EXCEPTION (err_ctcp_invalid_job_desc_label)
    {
        result = CTC_ERR_INVALID_JOB_FAILED;
    }
    CTC_EXCEPTION (err_ctcn_link_read_sgid_label)
    {
        result = CTC_ERR_INVALID_TYPE_FAILED;
    }
    CTC_EXCEPTION (err_ctcn_link_read_prcl_ver_label)
    {
        result = CTC_ERR_INVALID_TYPE_FAILED;
    }
    CTC_EXCEPTION (err_ctcp_invalid_prcl_ver_label)
    {
        /* ERROR: there is a possibility that a wrong packet injected 
         * critical protocol error but, just ignore the packet */
        result = CTC_ERR_INVALID_VALUE_FAILED;
    }
    CTC_EXCEPTION (err_ctcn_link_read_data_len_label)
    {
        result = CTC_ERR_INVALID_TYPE_FAILED;
    }
    EXCEPTION_END;

    return CTC_FAILURE;
}


static int ctcp_validate_prcl_ver (int ver)
{
    assert (&ver != NULL);

    CTC_COND_EXCEPTION (ver != CTCP_VERSION, err_invalid_prcl_ver_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_invalid_prcl_ver_label)
    {
        /* ERROR: there is a possibility that a wrong packet injected 
         * critical protocol error but, just ignore the packet */
    }
    EXCEPTION_END;

    return CTC_FAILURE;
}


static int ctcp_validate_job_desc (int job_desc)
{
    CTC_COND_EXCEPTION (job_desc <= 0 || 
                        job_desc > CTCJ_JOB_COUNT_PER_GROUP_MAX, 
                        err_invalid_job_desc);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_invalid_job_desc)
    EXCEPTION_END;

    return CTC_FAILURE;
}


static int ctcp_validate_op_param (int opid, unsigned char op_param)
{
    int result = CTC_SUCCESS;
    int op_prm = (int)op_param;

    switch (opid)
    {
        case CTCP_CREATE_CONTROL_SESSION:

            if (op_prm == CTCP_CONNECTION_TYPE_DEFAULT ||
                op_prm == CTCP_CONNECTION_TYPE_CTRL_ONLY)
            {
                result = CTC_SUCCESS;
            }
            else
            {
                result = CTC_FAILURE;
            }

            break;

        case CTCP_SET_JOB_ATTRIBUTE:

            if (op_prm > CTCJ_JOB_ATTR_ID_START &&
                op_prm < CTCJ_JOB_ATTR_ID_LAST)
            {
                result = CTC_SUCCESS;
            }
            else
            {
                result = CTC_FAILURE;
            }

            break;

        case CTCP_STOP_CAPTURE:

            if (op_prm == CTCP_STOP_CAPTURE_COND_IMMEDIATELY ||
                op_prm == CTCP_STOP_CAPTURE_COND_AFTER_TRANS)
            {
                result = CTC_SUCCESS;
            }
            else
            {
                result = CTC_FAILURE;
            }

            break;

        default:

            result = CTC_SUCCESS;
            break;
    }

    return result;
}


extern int ctcp_check_opid_range (int cmp_opid)
{
    if ((cmp_opid > CTCP_OPID_CTRL_MIN && cmp_opid < CTCP_OPID_CTRL_MAX) ||
        (cmp_opid > CTCP_UNKNOWN_OPERATION && cmp_opid < CTCP_OPID_DATA_MAX))
    {
        return CTC_SUCCESS;
    }
    else
    {
        return CTC_FAILURE;
    }
}

static BOOL ctcp_is_recv_protocol (int opid)
{
    BOOL is_recv_protocol = CTC_TRUE;

    if (ctcp_check_opid_range (opid) == CTC_SUCCESS)
    {
        if (opid % CTCP_RESULT_OPID_VALIDATION_FACTOR != 0 &&
            opid != CTCP_START_CAPTURE_RESULT)
        {
            /* valid recv protocol from the view point of ctc server */
        }
        else if (opid == CTCP_START_CAPTURE)
        {
            /* start capture */
        }
        else
        {
            is_recv_protocol = CTC_FALSE;
        }
    }
    else
    {
        is_recv_protocol = CTC_FALSE;
    }

    return is_recv_protocol;
}


extern int ctcp_validate_op_id (int opid, int cmp_opid)
{
    int error; 

    CTC_COND_EXCEPTION (ctcp_is_recv_protocol (cmp_opid) != CTC_TRUE,
                        err_invalid_protocol_label);

    CTC_COND_EXCEPTION (opid != cmp_opid, 
                        err_opid_not_matched_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_invalid_protocol_label)
    {
        /* TODO: ERR_INVALID_PROTOCOL */
    }
    CTC_EXCEPTION (err_opid_not_matched_label)
    {
        /* TODO: ERR_OPID_NOT_MATCHED */
    }
    EXCEPTION_END;

    return CTC_FAILURE;
}

extern char ctcp_header_get_op_id (CTCP_HEADER *header)
{
    return header->op_id;
}

extern char ctcp_header_get_op_param (CTCP_HEADER *header)
{
    return header->op_param;
}

extern unsigned short ctcp_header_get_job_desc (CTCP_HEADER *header)
{
    return header->job_desc;
}

extern int ctcp_header_get_sgid (CTCP_HEADER *header)
{
    return header->session_group_id;
}

extern int ctcp_header_get_data_len (CTCP_HEADER *header)
{
    return header->data_len;
}

/* 
 * ctc protocol operation functions 
 *
 */

/* control session */
extern int ctcp_do_create_ctrl_session (void *inlink, 
                                        CTCP_HEADER *header,
                                        int *sgid,
                                        int *result_code)
{
    int id;
    int result;
    CTCN_LINK *link = (CTCN_LINK *)inlink;

    id = ctcp_header_get_sgid (header);

    result = ctcs_mgr_create_session_group (link, &id);

    CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                        err_create_session_grp_label);

    *sgid = id;
    *result_code = CTCP_RC_SUCCESS;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_create_session_grp_label)
    {
        *result_code = CTCP_RC_FAILED_CREATE_SESSION;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcp_send_create_ctrl_session_result (void *inlink, 
                                                 int result_code, 
                                                 int sgid)
{
    int result;
    unsigned short job_desc = CTCJ_NULL_JOB_DESCRIPTOR;
    CTCN_LINK *link = (CTCN_LINK *)inlink;
    /* link validation */
    CTC_COND_EXCEPTION (link == NULL, err_null_link_label);

    /* process by result code */
    switch (result_code)
    {
        case CTCP_RC_SUCCESS:
        case CTCP_RC_FAILED_CREATE_SESSION:
            break;

        default:
            result_code = CTCP_RC_FAILED;
            break;
    }

    /* make protocol header */
    CTC_TEST_EXCEPTION (ctcp_make_protocol_header (link,
                                                   (unsigned char)CTCP_CREATE_CONTROL_SESSION_RESULT,
                                                   (unsigned char)result_code,
                                                   job_desc,
                                                   sgid,
                                                   0),
                        err_make_protocol_header_label);

    /* send result */
    CTC_TEST_EXCEPTION (ctcn_link_send (link), err_link_send_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_link_label)
    {
        result = CTC_ERR_NULL_LINK_FAILED;
    }
    CTC_EXCEPTION (err_make_protocol_header_label)
    {
        /* maybe.. buffer managing problem occurred something like overflow */
        result = CTC_ERR_BUFFER_OVERFLOW_FAILED;
    }
    CTC_EXCEPTION (err_link_send_label)
    {
        result = CTC_ERR_NETWORK_FAILED;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcp_do_destroy_ctrl_session (int sgid, int *result_code)
{
    int result;
    CTCS_SESSION_GROUP *sg = NULL;

    sg = ctcs_find_session_group_by_id (sgid);

    if (sg != NULL)
    {
        result = ctcs_sg_finalize (sg); 
        CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_sg_finalize_label);

        *result_code = CTCP_RC_SUCCESS;
    }
    else
    {
        *result_code = CTCP_RC_FAILED_INVALID_HANDLE;
    }

    *result_code = CTCP_RC_SUCCESS;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_sg_finalize_label)
    {
        *result_code = CTCP_RC_FAILED_SESSION_CLOSE;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcp_send_destroy_ctrl_session_result (void *inlink, 
                                                  int result_code, 
                                                  int sgid)
{
    int result;
    unsigned short job_desc = CTCJ_NULL_JOB_DESCRIPTOR;
    CTCN_LINK *link = (CTCN_LINK *)inlink;
    /* link validation */
    CTC_COND_EXCEPTION (link == NULL, err_null_link_label);

    /* process by result code */
    switch (result_code)
    {
        case CTCP_RC_SUCCESS:
        case CTCP_RC_FAILED_INVALID_HANDLE:
        case CTCP_RC_FAILED_SESSION_CLOSE:
            break;

        default:
            result_code = CTCP_RC_FAILED;
            break;
    }

    /* make protocol header */
    CTC_TEST_EXCEPTION (ctcp_make_protocol_header (link,
                                                   (unsigned char)CTCP_DESTROY_CONTROL_SESSION_RESULT,
                                                   (unsigned char)result_code,
                                                   job_desc,
                                                   sgid,
                                                   0),
                        err_make_protocol_header_label);

    /* send */
    result = ctcn_link_send (link);

    if (result != CTC_SUCCESS)
    {
        fprintf (stderr, "link send failed in ctcp_process_protocol ()\n");
        fflush (stderr);
    }
    else
    {
        /* send success */
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_link_label)
    {
        result = CTC_ERR_NULL_LINK_FAILED;
    }
    CTC_EXCEPTION (err_make_protocol_header_label)
    {
        /* maybe.. buffer managing problem occurred something like overflow */
        result = CTC_ERR_BUFFER_OVERFLOW_FAILED;
    }
    EXCEPTION_END;

    return result;
}


/* job session */
extern int ctcp_do_create_job_session (void *inlink,
                                       int sgid,
                                       CTCP_HEADER *header,
                                       unsigned short *job_desc,
                                       int *result_code)
{
    int result;
    unsigned short job_id;
    CTCS_SESSION_GROUP *sg = NULL; 
    CTCN_LINK *link = (CTCN_LINK *)inlink;

    sg = ctcs_find_session_group_by_id (sgid);

    if (sg != NULL)
    {
        /* add job session */
        result = ctcs_sg_add_job (sg, link, &job_id);

        switch (result)
        {
            case CTC_SUCCESS:
                ctcs_mgr_inc_session_count ();
                *job_desc = job_id;
                *result_code = CTCP_RC_SUCCESS;
                break;

            case CTC_ERR_EXCEED_MAX_FAILED: 
                *result_code = CTCP_RC_FAILED_NO_MORE_JOB_ALLOWED;
                break;

            default:
                *result_code = CTCP_RC_FAILED;
                CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                    err_add_job_label);
                break;
        }
    }
    else
    {
        *result_code = CTCP_RC_FAILED_INVALID_HANDLE;
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_add_job_label)
    {
        /* program error: error info set from sub-function */
        /* DEBUG */
        fprintf (stdout, 
                 "err_add_job_label in ctcp_do_create_job_session ()\n");
        fflush (stdout);
    }
    EXCEPTION_END;

    return result;
}


extern int ctcp_send_create_job_session_result (void *inlink,
                                                int result_code,
                                                unsigned short job_desc,
                                                int sgid)
{
    int result;
    CTCN_LINK *link = (CTCN_LINK *)inlink;
    /* link validation */
    CTC_COND_EXCEPTION (link == NULL, err_null_link_label);

    /* process by result code */
    switch (result_code)
    {
        case CTCP_RC_SUCCESS:

            CTC_TEST_EXCEPTION (ctcp_validate_job_desc ((int)job_desc),
                                err_job_desc);
            break;

        case CTCP_RC_FAILED_INVALID_HANDLE:
        case CTCP_RC_FAILED_NO_MORE_JOB_ALLOWED:
            break;

        default:
            break;
    }

    /* make protocol header */
    CTC_TEST_EXCEPTION (ctcp_make_protocol_header (link,
                                                   (unsigned char)CTCP_CREATE_JOB_SESSION_RESULT,
                                                   (unsigned char)result_code,
                                                   job_desc,
                                                   sgid,
                                                   0),
                        err_make_protocol_header_label);

    /* send */
    result = ctcn_link_send (link);

    if (result != CTC_SUCCESS)
    {
        fprintf (stderr, "link send failed in ctcp_send_create_job_session_result ()\n");
        fflush (stderr);
    }
    else
    {
        /* send success */
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_link_label)
    {
        result = CTC_ERR_NULL_LINK_FAILED;
    }
    CTC_EXCEPTION (err_job_desc)
    {
        /* ERROR: critical problem, anyway failed */
        result = CTC_FAILURE;
    }
    CTC_EXCEPTION (err_make_protocol_header_label)
    {
        /* maybe.. buffer managing problem occurred something like overflow */
        result = CTC_ERR_BUFFER_OVERFLOW_FAILED;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcp_do_destroy_job_session (void *inlink,
                                        int sgid,
                                        CTCP_HEADER *header,
                                        unsigned short job_desc,
                                        int *result_code)
{
    int result;
    CTCS_SESSION_GROUP *sg = NULL;
    CTCN_LINK *link = (CTCN_LINK *)inlink;

    CTC_COND_EXCEPTION (link == NULL, err_null_link_label);

    sg = ctcs_find_session_group_by_id (sgid);

    if (sg != NULL)
    {
        result = ctcs_sg_delete_job (sg, job_desc);

        switch (result)
        {
            case CTC_SUCCESS:
                *result_code = CTCP_RC_SUCCESS;
                break;

            case CTC_ERR_JOB_NOT_EXIST_FAILED:
                *result_code = CTCP_RC_FAILED_INVALID_JOB;
                break;

            case CTC_ERR_STOP_CAPTURE_FAILED:
            default:
                *result_code = CTCP_RC_FAILED;
                CTC_COND_EXCEPTION (CTC_TRUE, err_destroy_job_session_label);
                break;
        }
    }
    else
    {
        *result_code = CTCP_RC_FAILED_INVALID_HANDLE;
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_link_label)
    {
        result = CTC_ERR_NULL_LINK_FAILED;
    }
    CTC_EXCEPTION (err_destroy_job_session_label)
    {
        /* program error: error info set from sub-function */
        /* DEBUG */
        fprintf (stdout, 
                 "err_destroy_job_session_label in ctcp_do_destroy_job_session () \n");
        fflush (stdout);
    }
    EXCEPTION_END;

    return result;
}


extern int ctcp_send_destroy_job_session_result (void *inlink,
                                                 int result_code,
                                                 unsigned short job_desc,
                                                 int sgid)
{
    int result;
    CTCN_LINK *link = (CTCN_LINK *)inlink;
    /* link validation */
    CTC_COND_EXCEPTION (link == NULL, err_null_link_label);

    /* process by result code */
    switch (result_code)
    {
        case CTCP_RC_SUCCESS:
        case CTCP_RC_FAILED_INVALID_HANDLE:
        case CTCP_RC_FAILED_SESSION_NOT_EXIST:
        case CTCP_RC_FAILED_SESSION_CLOSE:
        case CTCP_RC_FAILED_INVALID_JOB:
            break;

        default:
            result_code = CTCP_RC_FAILED;
            break;
    }

    /* make protocol header */
    CTC_TEST_EXCEPTION (ctcp_make_protocol_header (link,
                                                   (unsigned char)CTCP_DESTROY_JOB_SESSION_RESULT,
                                                   (unsigned char)result_code,
                                                   job_desc,
                                                   sgid,
                                                   0),
                        err_make_protocol_header_label);

    /* send */
    result = ctcn_link_send (link);

    if (result != CTC_SUCCESS)
    {
        fprintf (stderr, "link send failed in ctcp_send_destroy_job_session_result ()\n");
        fflush (stderr);
    }
    else
    {
        /* send success */
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_link_label)
    {
        /* ERROR: critical error, anyway failed */
        result = CTC_ERR_NULL_LINK_FAILED;
    }
    CTC_EXCEPTION (err_make_protocol_header_label)
    {
        /* maybe.. buffer managing problem occurred something like overflow */
        result = CTC_ERR_BUFFER_OVERFLOW_FAILED;
    }
    EXCEPTION_END;

    return result;
}

/* job status */
extern int ctcp_do_request_job_status (void *inlink,
                                       int sgid,
                                       CTCP_HEADER *header,
                                       unsigned short job_desc,
                                       int *status,
                                       int *result_code)
{
    int result;
    int job_status;
    CTCS_SESSION_GROUP *sg = NULL;
    CTCN_LINK *link = (CTCN_LINK *)inlink;

    CTC_COND_EXCEPTION (link == NULL, err_null_link_label);

    sg = ctcs_find_session_group_by_id (sgid);

    if (sg != NULL)
    {
        result = ctcs_sg_get_job_status (sg, job_desc, &job_status);

        switch (result)
        {
            case CTC_SUCCESS:
                *status = job_status;
                *result_code = CTCP_RC_SUCCESS;
                break;

            case CTC_ERR_JOB_NOT_EXIST_FAILED:
                *result_code = CTCP_RC_FAILED_INVALID_JOB;
                break;

            case CTC_ERR_INVALID_JOB_STATUS_FAILED:
                *result_code = CTCP_RC_FAILED_INVALID_JOB_STATUS;
                break;

            default:
                *result_code = CTCP_RC_FAILED;
                CTC_COND_EXCEPTION (CTC_TRUE, 
                                    err_get_job_status_failed_label);
                break;
        }
    }
    else
    {
        *result_code = CTCP_RC_FAILED_INVALID_HANDLE;
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_link_label)
    {
        result = CTC_ERR_NULL_LINK_FAILED;
    }
    CTC_EXCEPTION (err_get_job_status_failed_label)
    {
        /* program error: error info set from sub-function */
        /* DEBUG */
        fprintf (stdout, 
                 "err_get_job_status_failed_label in ctcp_do_request_job_status ()\n");
        fflush (stdout);
    }
    EXCEPTION_END;

    return result;
}


extern int ctcp_send_request_job_status_result (void *inlink,
                                                int result_code,
                                                unsigned short job_desc,
                                                int sgid,
                                                int status)
{
    int result;
    CTCN_LINK *link = (CTCN_LINK *)inlink;
    /* link validation */
    CTC_COND_EXCEPTION (link == NULL, err_null_link_label);

    /* process by result code */
    switch (result_code)
    {
        case CTCP_RC_SUCCESS:

            CTC_TEST_EXCEPTION (ctcp_validate_job_desc ((int)job_desc),
                                err_job_desc);
            break;

        case CTCP_RC_FAILED_INVALID_HANDLE:
        case CTCP_RC_FAILED_INVALID_JOB:
        case CTCP_RC_FAILED_INVALID_JOB_STATUS:
            break;

        default:
            result_code = CTCP_RC_FAILED;
            break;
    }

    /* make protocol header */
    CTC_TEST_EXCEPTION (ctcp_make_protocol_header (link,
                                                   (unsigned char)CTCP_REQUEST_JOB_STATUS_RESULT,
                                                   (unsigned char)result_code,
                                                   job_desc,
                                                   sgid,
                                                   status),
                        err_make_protocol_header_label);

    /* send */
    result = ctcn_link_send (link);

    if (result != CTC_SUCCESS)
    {
        fprintf (stderr, "link send failed in ctcp_send_request_job_status_result ()\n");
        fflush (stderr);
    }
    else
    {
        /* send success */
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_link_label)
    {
        result = CTC_ERR_NULL_LINK_FAILED;
    }
    CTC_EXCEPTION (err_job_desc)
    {
        /* ERROR: critical problem, anyway failed */
        result = CTC_FAILURE;
    }
    CTC_EXCEPTION (err_make_protocol_header_label)
    {
        /* maybe.. buffer managing problem occurred something like overflow */
        result = CTC_ERR_BUFFER_OVERFLOW_FAILED;
    }
    EXCEPTION_END;

    return result;
}


/* server status */
extern int ctcp_do_request_server_status (void *inlink,
                                          int sgid,
                                          CTCP_HEADER *header,
                                          int *status,
                                          int *result_code)
{
    int result;
    int server_status;

    CTCS_SESSION_GROUP *sg = NULL;
    CTCN_LINK *link = (CTCN_LINK *)inlink;

    CTC_COND_EXCEPTION (link == NULL, err_null_link_label);

    /* just check requester is valid user */
    sg = ctcs_find_session_group_by_id (sgid);

    if (sg != NULL)
    {
        ctc_get_server_status (&server_status);

        *status = server_status;    
        *result_code = CTCP_RC_SUCCESS;
    }
    else
    {
        *result_code = CTCP_RC_FAILED_INVALID_HANDLE;
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_link_label)
    {
        result = CTC_ERR_NULL_LINK_FAILED;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcp_send_request_server_status_result (void *inlink,
                                                   int result_code,
                                                   int sgid,
                                                   int status)
{
    int result;
    unsigned short job_desc = CTCJ_NULL_JOB_DESCRIPTOR;

    CTCN_LINK *link = (CTCN_LINK *)inlink;
    /* link validation */
    CTC_COND_EXCEPTION (link == NULL, err_null_link_label);

    /* process by result code */
    switch (result_code)
    {
        case CTCP_RC_SUCCESS:
        case CTCP_RC_FAILED_INVALID_HANDLE:
            break;

        default:
            result_code = CTCP_RC_FAILED;
            break;
    }

    /* make protocol header */
    CTC_TEST_EXCEPTION (ctcp_make_protocol_header (link,
                                                   (unsigned char)CTCP_REQUEST_SERVER_STATUS_RESULT,
                                                   (unsigned char)result_code,
                                                   job_desc,
                                                   sgid,
                                                   status),
                        err_make_protocol_header_label);

    /* send */
    result = ctcn_link_send (link);

    if (result != CTC_SUCCESS)
    {
        fprintf (stderr, "link send failed in ctcp_send_request_server_status_result ()\n");
        fflush (stderr);
    }
    else
    {
        /* send success */
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_link_label)
    {
        result = CTC_ERR_NULL_LINK_FAILED;
    }
    CTC_EXCEPTION (err_make_protocol_header_label)
    {
        /* maybe.. buffer managing problem occurred something like overflow */
        result = CTC_ERR_BUFFER_OVERFLOW_FAILED;
    }
    EXCEPTION_END;

    return result;
}


/* register table */
extern int ctcp_do_register_table (void *inlink,
                                   int sgid,
                                   CTCP_HEADER *header,
                                   unsigned short job_desc,
                                   char *user_name,
                                   char *table_name,
                                   int *result_code)
{
    BOOL is_exist = CTC_FALSE;
    int result;
    CTCS_SESSION_GROUP *sg = NULL;
    CTCN_LINK *link = (CTCN_LINK *)inlink;

    CTC_COND_EXCEPTION (link == NULL, err_null_link_label);

    sg = ctcs_find_session_group_by_id (sgid);

    if (sg != NULL)
    {
        result = ctcs_sg_is_table_registered (sg, 
                                              job_desc, 
                                              table_name, 
                                              user_name,
                                              &is_exist);

        if (result == CTC_ERR_INVALID_JOB_FAILED)
        {
            *result_code = CTCP_RC_FAILED_INVALID_JOB;
        }
        else
        {
            CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                err_check_table_failed_label);
        }

        if (is_exist != CTC_TRUE)
        {
            result = ctcs_sg_register_table (sg, 
                                             job_desc, 
                                             table_name, 
                                             user_name);

            switch (result)
            {
                /* CTCP_RC code setting by result */
                case CTC_SUCCESS:
                    *result_code = CTCP_RC_SUCCESS;
                    break;

                case CTC_ERR_INVALID_USER_NAME_FAILED:
                case CTC_ERR_INVALID_TABLE_NAME_FAILED:
                    *result_code = CTCP_RC_FAILED_INVALID_TABLE_NAME;
                    break;

                case CTC_ERR_JOB_NOT_EXIST_FAILED:
                    *result_code = CTCP_RC_FAILED_INVALID_JOB;
                    break;

                case CTC_ERR_ALLOC_FAILED:
                default:
                    *result_code = CTCP_RC_FAILED;
                    CTC_COND_EXCEPTION (CTC_TRUE, err_register_table_label);
                    break;
            }
        }
        else
        {
            *result_code = CTCP_RC_FAILED_TABLE_ALREADY_EXIST;
        }
    }
    else
    {
        *result_code = CTCP_RC_FAILED_INVALID_HANDLE;
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_link_label)
    {
        result = CTC_ERR_NULL_LINK_FAILED;
    }
    CTC_EXCEPTION (err_check_table_failed_label)
    {
        /* program error: error info set from sub-function */
        /* DEBUG */
        fprintf (stdout, 
                 "err_check_table_failed_label in ctcp_do_register_table ()\n");
        fflush (stdout);
    }
    CTC_EXCEPTION (err_register_table_label)
    {
        /* error info set from sub-function */
    }
    EXCEPTION_END;

    return result;
}


extern int ctcp_send_register_table_result (void *inlink,
                                            int result_code,
                                            unsigned short job_desc,
                                            int sgid)
{
    int result;
    CTCN_LINK *link = (CTCN_LINK *)inlink;
    /* link validation */
    CTC_COND_EXCEPTION (link == NULL, err_null_link_label);

    /* process by result code */
    switch (result_code)
    {
        case CTCP_RC_SUCCESS:

            CTC_TEST_EXCEPTION (ctcp_validate_job_desc ((int)job_desc),
                                err_job_desc);
            break;

        case CTCP_RC_FAILED_INVALID_HANDLE:
        case CTCP_RC_FAILED_TABLE_ALREADY_EXIST:
        case CTCP_RC_FAILED_INVALID_TABLE_NAME:
        case CTCP_RC_FAILED_INVALID_JOB:
            break;

        default:
            result_code = CTCP_RC_FAILED;
            break;
    }

    /* make protocol header */
    CTC_TEST_EXCEPTION (ctcp_make_protocol_header (link,
                                                   (unsigned char)CTCP_REGISTER_TABLE_RESULT,
                                                   (unsigned char)result_code,
                                                   job_desc,
                                                   sgid,
                                                   0),
                        err_make_protocol_header_label);

    /* send */
    result = ctcn_link_send (link);

    if (result != CTC_SUCCESS)
    {
        fprintf (stderr, "link send failed in ctcp_send_register_table_result ()\n");
        fflush (stderr);
    }
    else
    {
        /* send success */
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_link_label)
    {
        result = CTC_ERR_NULL_LINK_FAILED;
    }
    CTC_EXCEPTION (err_job_desc)
    {
        /* ERROR: critical problem, anyway failed */
        result = CTC_FAILURE;
    }
    CTC_EXCEPTION (err_make_protocol_header_label)
    {
        /* maybe.. buffer managing problem occurred something like overflow */
        result = CTC_ERR_BUFFER_OVERFLOW_FAILED;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcp_do_unregister_table (void *inlink,
                                     int sgid,
                                     CTCP_HEADER *header,
                                     unsigned short job_desc,
                                     char *user_name,
                                     char *table_name,
                                     int *result_code)
{
    BOOL is_exist = CTC_FALSE;
    int result;
    CTCS_SESSION_GROUP *sg = NULL;
    CTCN_LINK *link = (CTCN_LINK *)inlink;

    CTC_COND_EXCEPTION (link == NULL, err_null_link_label);

    sg = ctcs_find_session_group_by_id (sgid);

    if (sg != NULL)
    {
        result = ctcs_sg_is_table_registered (sg, 
                                              job_desc, 
                                              table_name, 
                                              user_name,
                                              &is_exist);

        if (result == CTC_ERR_INVALID_JOB_FAILED)
        {
            *result_code = CTCP_RC_FAILED_INVALID_JOB;
        }
        else
        {
            CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                err_check_table_failed_label);
        }

        if (is_exist == CTC_TRUE)
        {
            result = ctcs_sg_unregister_table (sg, 
                                               job_desc, 
                                               table_name, 
                                               user_name);

            switch (result)
            {
                /* CTCP_RC code setting by result */
                case CTC_SUCCESS:
                    *result_code = CTCP_RC_SUCCESS;
                    break;

                case CTC_ERR_INVALID_USER_NAME_FAILED:
                case CTC_ERR_INVALID_TABLE_NAME_FAILED:
                    *result_code = CTCP_RC_FAILED_INVALID_TABLE_NAME;
                    break;

                case CTC_ERR_JOB_NOT_EXIST_FAILED:
                    *result_code = CTCP_RC_FAILED_INVALID_JOB;
                    break;

                default:
                    *result_code = CTCP_RC_FAILED;
                    CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                        err_unregister_table_failed_label); 
                    break;
            }
        }
        else
        {
            *result_code = CTCP_RC_FAILED_UNREGISTERED_TABLE;
        }
    }
    else
    {
        *result_code = CTCP_RC_FAILED_INVALID_HANDLE;
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_link_label)
    {
        result = CTC_ERR_NULL_LINK_FAILED;
    }
    CTC_EXCEPTION (err_check_table_failed_label)
    {
        /* DEBUG */
        fprintf (stdout, 
                 "err_check_table_failed_label in ctcp_do_unregister_table ()\n");
        fflush (stdout);
    }
    CTC_EXCEPTION (err_unregister_table_failed_label)
    {
        /* error info set from sub-function */
    }
    EXCEPTION_END;

    return result;
}


extern int ctcp_send_unregister_table_result (void *inlink,
                                              int result_code,
                                              unsigned short job_desc,
                                              int sgid)
{
    int result;
    CTCN_LINK *link = (CTCN_LINK *)inlink;
    /* link validation */
    CTC_COND_EXCEPTION (link == NULL, err_null_link_label);

    /* process by result code */
    switch (result_code)
    {
        case CTCP_RC_SUCCESS:

            CTC_TEST_EXCEPTION (ctcp_validate_job_desc ((int)job_desc),
                                err_job_desc);
            break;

        case CTCP_RC_FAILED_INVALID_HANDLE:
        case CTCP_RC_FAILED_INVALID_TABLE_NAME:
        case CTCP_RC_FAILED_INVALID_JOB:
        case CTCP_RC_FAILED_UNREGISTERED_TABLE:
            break;

        default:
            result_code = CTCP_RC_FAILED;
            break;
    }

    /* make protocol header */
    CTC_TEST_EXCEPTION (ctcp_make_protocol_header (link,
                                                   (unsigned char)CTCP_UNREGISTER_TABLE_RESULT,
                                                   (unsigned char)result_code,
                                                   job_desc,
                                                   sgid,
                                                   0),
                        err_make_protocol_header_label);

    /* send */
    result = ctcn_link_send (link);

    if (result != CTC_SUCCESS)
    {
        fprintf (stderr, "link send failed in ctcp_send_unregister_table_result ()\n");
        fflush (stderr);
    }
    else
    {
        /* send success */
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_link_label)
    {
        result = CTC_ERR_NULL_LINK_FAILED;
    }
    CTC_EXCEPTION (err_job_desc)
    {
        /* ERROR: critical problem, anyway failed */
        result = CTC_FAILURE;
    }
    CTC_EXCEPTION (err_make_protocol_header_label)
    {
        /* maybe.. buffer managing problem occurred something like overflow */
        result = CTC_ERR_BUFFER_OVERFLOW_FAILED;
    }
    EXCEPTION_END;

    return result;
}


/* set attribute */
extern int ctcp_do_set_job_attribute (void *inlink,
                                      int sgid,
                                      CTCP_HEADER *header,
                                      unsigned short job_desc,
                                      void *job_attr,
                                      int *result_code)
{
    BOOL is_exist = CTC_FALSE;
    int result;
    CTCS_SESSION_GROUP *sg = NULL;
    CTCN_LINK *link = (CTCN_LINK *)inlink;

    assert(job_attr != NULL);

    CTC_COND_EXCEPTION (link == NULL, err_null_link_label);

    sg = ctcs_find_session_group_by_id (sgid);

    if (sg != NULL)
    {
        result = ctcs_sg_set_job_attr (sg, job_desc, (CTCJ_JOB_ATTR *)job_attr);

        switch (result)
        {
            /* CTCP_RC code setting by result */
            case CTC_SUCCESS:
                *result_code = CTCP_RC_SUCCESS;
                break;

            case CTC_ERR_INVALID_ATTR_FAILED:
                *result_code = CTCP_RC_FAILED_JOB_ATTR_NOT_EXIST;
                break;

            case CTC_ERR_INVALID_VALUE_FAILED:
                *result_code = CTCP_RC_FAILED_INVALID_JOB_ATTR_VALUE;
                break;

            case CTC_ERR_JOB_NOT_EXIST_FAILED:
                *result_code = CTCP_RC_FAILED_INVALID_JOB;
                break;

            default:
                *result_code = CTCP_RC_FAILED;
                CTC_TEST_EXCEPTION (result != CTC_SUCCESS, 
                                    err_set_job_attr_label); 
                break;
        }
    }
    else
    {
        *result_code = CTCP_RC_FAILED_INVALID_HANDLE;
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_link_label)
    {
        result = CTC_ERR_NULL_LINK_FAILED;
    }
    CTC_EXCEPTION (err_set_job_attr_label)
    {
        /* DEBUG */
        fprintf (stdout, 
                 "err_set_job_attr_label in ctcp_do_set_job_attribute ()\n");
        fflush (stdout);
    }
    EXCEPTION_END;

    return result;
}


extern int ctcp_send_set_job_attribute_result (void *inlink,
                                               int result_code,
                                               unsigned short job_desc,
                                               int sgid)
{
    int result;
    CTCN_LINK *link = (CTCN_LINK *)inlink;
    /* link validation */
    CTC_COND_EXCEPTION (link == NULL, err_null_link_label);

    /* process by result code */
    switch (result_code)
    {
        case CTCP_RC_SUCCESS:

            CTC_TEST_EXCEPTION (ctcp_validate_job_desc ((int)job_desc),
                                err_job_desc);
            break;

        case CTCP_RC_FAILED_INVALID_HANDLE:
        case CTCP_RC_FAILED_INVALID_JOB:
        case CTCP_RC_FAILED_JOB_ATTR_NOT_EXIST:
        case CTCP_RC_FAILED_INVALID_JOB_ATTR_VALUE:
            break;

        default:
            result_code = CTCP_RC_FAILED;
            break;
    }

    /* make protocol header */
    CTC_TEST_EXCEPTION (ctcp_make_protocol_header (link,
                                                   (unsigned char)CTCP_SET_JOB_ATTRIBUTE_RESULT,
                                                   (unsigned char)result_code,
                                                   job_desc,
                                                   sgid,
                                                   0),
                        err_make_protocol_header_label);

    /* send */
    result = ctcn_link_send (link);

    if (result != CTC_SUCCESS)
    {
        fprintf (stderr, "link send failed in ctcp_send_set_job_attribute_result ()\n");
        fflush (stderr);
    }
    else
    {
        /* send success */
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_link_label)
    {
        result = CTC_ERR_NULL_LINK_FAILED;
    }
    CTC_EXCEPTION (err_job_desc)
    {
        /* ERROR: critical problem, anyway failed */
        result = CTC_FAILURE;
    }
    CTC_EXCEPTION (err_make_protocol_header_label)
    {
        /* maybe.. buffer managing problem occurred something like overflow */
        result = CTC_ERR_BUFFER_OVERFLOW_FAILED;
    }
    EXCEPTION_END;

    return result;
}


/* capture */
extern int ctcp_do_start_capture (void *inlink,
                                  int sgid,
                                  CTCP_HEADER *header,
                                  unsigned short job_desc,
                                  int *result_code)
{
    BOOL is_exist = CTC_FALSE;
    int result;
    CTCS_SESSION_GROUP *sg = NULL;
    CTCN_LINK *link = (CTCN_LINK *)inlink;

    CTC_COND_EXCEPTION (link == NULL, err_null_link_label);

    sg = ctcs_find_session_group_by_id (sgid);

    if (sg != NULL)
    {
        result = ctcs_sg_start_capture (sg, job_desc);

        switch (result)
        {
            /* CTCP_RC code setting by result */
            case CTC_SUCCESS:
                *result_code = CTCP_RC_SUCCESS;
                break;

            case CTC_ERR_INVALID_TABLE_NAME_FAILED:
                *result_code = CTCP_RC_FAILED_INVALID_TABLE_NAME;
                break;

            case CTC_ERR_JOB_NOT_EXIST_FAILED:
                *result_code = CTCP_RC_FAILED_INVALID_JOB;
                break;

            case CTC_ERR_JOB_ALREADY_STARTED:
                *result_code = CTCP_RC_FAILED_JOB_ALREADY_STARTED;
                break;

            case CTC_ERR_INVALID_JOB_STATUS_FAILED:
                *result_code = CTCP_RC_FAILED_INVALID_JOB_STATUS;
                break;

            case CTC_ERR_ALLOC_FAILED:
                *result_code = CTCP_RC_FAILED_INSUFFICIENT_SERVER_RESOURCE;
                break;

            default:
                *result_code = CTCP_RC_FAILED;
                CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                    err_start_capture_failed_label);
                break;
        }
    }
    else
    {
        *result_code = CTCP_RC_FAILED_INVALID_HANDLE;
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_link_label)
    {
        result = CTC_ERR_NULL_LINK_FAILED;
    }
    CTC_EXCEPTION (err_start_capture_failed_label)
    {
        /* DEBUG */
        fprintf (stdout, 
                 "err_start_capture_failed_label in ctcp_do_start_capture ()\n");
        fflush (stdout);
    }
    EXCEPTION_END;

    return result;
}


extern int ctcp_send_start_capture_result (void *inlink,
                                           int result_code,
                                           unsigned short job_desc,
                                           int sgid)
{
    int result;
    CTCN_LINK *link = (CTCN_LINK *)inlink;
    /* link validation */
    CTC_COND_EXCEPTION (link == NULL, err_null_link_label);

    /* process by result code */
    switch (result_code)
    {
        case CTCP_RC_SUCCESS:

            CTC_TEST_EXCEPTION (ctcp_validate_job_desc ((int)job_desc),
                                err_job_desc);
            break;

        case CTCP_RC_FAILED_INVALID_JOB_STATUS:
        case CTCP_RC_FAILED_JOB_ALREADY_STARTED:
        case CTCP_RC_FAILED_INVALID_TABLE_NAME:
        case CTCP_RC_FAILED_INVALID_HANDLE:
        case CTCP_RC_FAILED_INVALID_JOB:
            break;

        default:
            result_code = CTCP_RC_FAILED;
            break;
    }

    /* make protocol header */
    CTC_TEST_EXCEPTION (ctcp_make_protocol_header (link,
                                                   (unsigned char)CTCP_START_CAPTURE_RESULT,
                                                   (unsigned char)result_code,
                                                   job_desc,
                                                   sgid,
                                                   0),
                        err_make_protocol_header_label);

    /* send */
    result = ctcn_link_send (link);

    if (result != CTC_SUCCESS)
    {
        fprintf (stderr, "link send failed in ctcp_send_start_capture_result ()\n");
        fflush (stderr);
    }
    else
    {
        /* send success */
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_link_label)
    {
        result = CTC_ERR_NULL_LINK_FAILED;
    }
    CTC_EXCEPTION (err_job_desc)
    {
        /* ERROR: critical problem, anyway failed */
        result = CTC_FAILURE;
    }
    CTC_EXCEPTION (err_make_protocol_header_label)
    {
        /* maybe.. buffer managing problem occurred something like overflow */
        result = CTC_ERR_BUFFER_OVERFLOW_FAILED;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcp_send_captured_data_result (void *inlink,
                                           unsigned short job_desc,
                                           int sgid,
                                           int trans_cnt,
                                           void **trans_list)
{
    BOOL is_exist = CTC_FALSE;
    BOOL is_ovf = CTC_FALSE;
    int i;
    int result;
    int remained_len;
    int write_data_len;
    int total_data_len;
    int tid;
    int result_code;
    int str_len = 0;
    int attr_num;
    int start_offset;
    int set_col_cnt;
    int remained_item_cnt;
    int read_item_cnt;
    int num_of_item_wbuf_pos;
    int last_processed_tid;
    char *payload; /* TODO:*/
    CTCL_ITEM *log_item = NULL;
    CTCL_ITEM *next_log_item = NULL;
    CTCL_COLUMN *set_col = NULL;
    CTCL_COLUMN *key_col = NULL;
    CTCN_LINK *link = (CTCN_LINK *)inlink;
//    CTCL_TRANS_LOG_LIST ***trans_log_list = (CTCL_TRANS_LOG_LIST ***)trans_list;
    CTCL_TRANS_LOG_LIST *log_item_list;
    CTCS_SESSION_GROUP *sg = NULL;
    CTCS_JOB_SESSION *job_session = NULL;
    CTCG_LIST_NODE *itr;

    /* link validation */
    CTC_COND_EXCEPTION (link == NULL, err_null_link_label);

    sg = ctcs_find_session_group_by_id (sgid);
    CTC_COND_EXCEPTION (sg == NULL, err_invalid_sgid_label);

    job_session = ctcs_sg_find_job_session(sg, job_desc);
//    last_processed_tid = job_session->job->last_processed_tid;

    /* about process by result code:
     * in this case, acceptable result codes are only two
     * and just send the result code generated from job thread
     *
     *  acceptable result codes :
     *      CTCP_RC_SUCCESS 
     *      CTCP_RC_SUCCESS_FRAGMENTED 
     */
    for (i = 0; i < trans_cnt; i++)
    {
        log_item_list = (*(CTCL_TRANS_LOG_LIST **)trans_list[i]);    
        tid = log_item_list->tid;

//        if (tid > last_processed_tid)
//        {
            start_offset = CTCP_HDR_LEN;
            remained_item_cnt = log_item_list->item_num;
            read_item_cnt = 0;
            total_data_len = 0;
            next_log_item = log_item_list->head; 

            write_data_len = 0;

            while (remained_item_cnt > 0 && next_log_item != NULL)
            {
                if (next_log_item->stmt_type < CTCL_STMT_TYPE_INSERT || 
                    next_log_item->stmt_type > CTCL_STMT_TYPE_DELETE)
                {
                    next_log_item = next_log_item->next;
                    remained_item_cnt--;
                    continue;
                }

                ctcn_link_move_wbuf_pos (link, CTCP_HDR_LEN);

                /* 1. transaction id (4 BYTE) */
                if (ctcn_link_write_four_byte_number (link, (void *)&tid) 
                    != CTC_SUCCESS)
                {
                    is_ovf = CTC_TRUE;
                    break;
                }
                else
                {
                    write_data_len += 4;
                }

                /* 2. the number of items (4 BYTE) write later, 
                 *    only increase write_data_len by offset */
                if (ctcn_link_forward_wbuf_pos (link, sizeof (int)) 
                    != CTC_SUCCESS)
                {
                    is_ovf = CTC_TRUE;
                    break;
                }
                else
                {
                    num_of_item_wbuf_pos = CTCN_HDR_LEN + write_data_len;
                    write_data_len += sizeof (int);
                }

                for (read_item_cnt; 
                     read_item_cnt < log_item_list->item_num; 
                     read_item_cnt++)
                {
                    set_col_cnt = 0;
                    log_item = next_log_item;
                    next_log_item = log_item->next;

                    if (log_item->stmt_type < CTCL_STMT_TYPE_INSERT || 
                        log_item->stmt_type > CTCL_STMT_TYPE_DELETE)
                    {
                        remained_item_cnt--;
                        continue;
                    }

                    /* check table_name of log item is registered table */
                    (void)ctcs_sg_is_table_registered (sg, 
                                                       job_desc, 
                                                       log_item->table_name, 
                                                       log_item->db_user, 
                                                       &is_exist);

                    if (is_exist != CTC_TRUE)
                    {
                        /* skip this log item */
                        continue;
                    }

                    /* 3. table_name length (4 BYTE) */
                    str_len = strlen (log_item->table_name);

                    if (ctcn_link_write_four_byte_number (link, (void *)&str_len) 
                        != CTC_SUCCESS)
                    {
                        is_ovf = CTC_TRUE;
                        break;
                    }
                    else
                    {
                        write_data_len += 4;
                    }

                    /* 4. table_name value (VARIABLE_LENGTH) */
                    if (ctcn_link_write (link, log_item->table_name, str_len) 
                        != CTC_SUCCESS)
                    {
                        is_ovf = CTC_TRUE;
                        break;
                    }
                    else
                    {
                        write_data_len += str_len;
                    }

                    /* 5. stmt type (4 BYTE) */
                    if (ctcn_link_write_four_byte_number (link, (void *)&log_item->stmt_type) 
                        != CTC_SUCCESS)
                    {
                        is_ovf = CTC_TRUE;
                        break;
                    }
                    else
                    {
                        write_data_len += 4;
                    }

                    switch (log_item->stmt_type)
                    {
                        case CTCL_STMT_TYPE_INSERT:

                            set_col_cnt = log_item->insert_log_info.set_col_cnt;

                            /* 6. set column count (4 BYTE)*/
                            if (ctcn_link_write_four_byte_number (link, (void *)&set_col_cnt)
                                != CTC_SUCCESS)
                            {
                                is_ovf = CTC_TRUE;
                                break;
                            }
                            else
                            {
                                write_data_len += 4;
                            }

                            /* 7. set column info */
                            CTCG_LIST_ITERATE (&(log_item->insert_log_info.set_col_list), itr)
                            {
                                set_col = (CTCL_COLUMN *)itr->obj;

                                /* set column name length (4 BYTE) */
                                if (ctcn_link_write_four_byte_number 
                                    (link, (void *)&set_col->name_len) != CTC_SUCCESS)
                                {
                                    is_ovf = CTC_TRUE;
                                    break;
                                }
                                else
                                {
                                    write_data_len += 4;
                                }

                                /* set column name (VARIABLE) */
                                if (ctcn_link_write (link, set_col->name, set_col->name_len) 
                                    != CTC_SUCCESS)
                                {
                                    is_ovf = CTC_TRUE;
                                    break;
                                }
                                else
                                {
                                    write_data_len += set_col->name_len;
                                }

                                /* set column type (4 BYTE) */
                                if (ctcn_link_write_four_byte_number 
                                    (link, (void *)&set_col->type) != CTC_SUCCESS)
                                {
                                    is_ovf = CTC_TRUE;
                                    break;
                                }
                                else
                                {
                                    write_data_len += 4;
                                }

                                /* set column value length (4 BYTE) */
                                if (ctcn_link_write_four_byte_number 
                                    (link, (void *)&set_col->val_len) != CTC_SUCCESS)
                                {
                                    is_ovf = CTC_TRUE;
                                    break;
                                }
                                else
                                {
                                    write_data_len += 4;
                                }

                                /* set column value (VARIABLE) */
                                if (ctcn_link_write (link, set_col->val, set_col->val_len) 
                                    != CTC_SUCCESS)
                                {
                                    is_ovf = CTC_TRUE;
                                    break;
                                }
                                else
                                {
                                    write_data_len += set_col->val_len;
                                }
                            }

                            break;

                        case CTCL_STMT_TYPE_UPDATE:

                            key_col = &log_item->update_log_info.key_col;

                            /* 6. key column name length (4 BYTE) */
                            if (ctcn_link_write_four_byte_number 
                                (link, (void *)&key_col->name_len) != CTC_SUCCESS)
                            {
                                is_ovf = CTC_TRUE;
                                break;
                            }
                            else
                            {
                                write_data_len += 4;
                            }

                            /* 7. key column name (VARIABLE) */
                            if (ctcn_link_write (link, key_col->name, key_col->name_len) 
                                != CTC_SUCCESS)
                            {
                                is_ovf = CTC_TRUE;
                                break;
                            }
                            else
                            {
                                write_data_len += key_col->name_len;
                            }

                            /* 8. key column type (4 BYTE) */
                            if (ctcn_link_write_four_byte_number 
                                (link, (void *)&key_col->type) != CTC_SUCCESS)
                            {
                                is_ovf = CTC_TRUE;
                                break;
                            }
                            else
                            {
                                write_data_len += 4;
                            }

                            /* 9. key column value length (4BYTE) */
                            if (ctcn_link_write_four_byte_number 
                                (link, (void *)&key_col->val_len) != CTC_SUCCESS)
                            {
                                is_ovf = CTC_TRUE;
                                break;
                            }
                            else
                            {
                                write_data_len += 4;
                            }

                            /* 10. key column value (VARIABLE) */
                            if (ctcn_link_write (link, key_col->val, key_col->val_len) 
                                != CTC_SUCCESS)
                            {
                                is_ovf = CTC_TRUE;
                                break;
                            }
                            else
                            {
                                write_data_len += key_col->val_len;
                            }

                            set_col_cnt = log_item->update_log_info.set_col_cnt;

                            /* 11. set column count (4 BYTE)*/
                            if (ctcn_link_write_four_byte_number (link, (void *)&set_col_cnt)
                                != CTC_SUCCESS)
                            {
                                is_ovf = CTC_TRUE;
                                break;
                            }
                            else
                            {
                                write_data_len += 4;
                            }

                            /* 12. set column info */
                            CTCG_LIST_ITERATE (&(log_item->update_log_info.set_col_list), itr)
                            {
                                set_col = (CTCL_COLUMN *)itr->obj;

                                /* set column name length (4 BYTE) */
                                if (ctcn_link_write_four_byte_number 
                                    (link, (void *)&set_col->name_len) != CTC_SUCCESS)
                                {
                                    is_ovf = CTC_TRUE;
                                    break;
                                }
                                else
                                {
                                    write_data_len += 4;
                                }

                                /* set column name (VARIABLE) */
                                if (ctcn_link_write (link, set_col->name, set_col->name_len) 
                                    != CTC_SUCCESS)
                                {
                                    is_ovf = CTC_TRUE;
                                    break;
                                }
                                else
                                {
                                    write_data_len += set_col->name_len;
                                }

                                /* set column type (4 BYTE) */
                                if (ctcn_link_write_four_byte_number 
                                    (link, (void *)&set_col->type) != CTC_SUCCESS)
                                {
                                    is_ovf = CTC_TRUE;
                                    break;
                                }
                                else
                                {
                                    write_data_len += 4;
                                }

                                /* set column value length (4 BYTE) */
                                if (ctcn_link_write_four_byte_number 
                                    (link, (void *)&set_col->val_len) != CTC_SUCCESS)
                                {
                                    is_ovf = CTC_TRUE;
                                    break;
                                }
                                else
                                {
                                    write_data_len += 4;
                                }

                                /* set column value (VARIABLE) */
                                if (ctcn_link_write (link, set_col->val, set_col->val_len) 
                                    != CTC_SUCCESS)
                                {
                                    is_ovf = CTC_TRUE;
                                    break;
                                }
                                else
                                {
                                    write_data_len += set_col->val_len;
                                }
                            }

                            break;

                        case CTCL_STMT_TYPE_DELETE:

                            key_col = &log_item->delete_log_info.key_col;

                            /* 6. key column name length (4 BYTE) */
                            if (ctcn_link_write_four_byte_number 
                                (link, (void *)&key_col->name_len) != CTC_SUCCESS)
                            {
                                is_ovf = CTC_TRUE;
                                break;
                            }
                            else
                            {
                                write_data_len += 4;
                            }

                            /* 7. key column name (VARIABLE) */
                            if (ctcn_link_write (link, key_col->name, key_col->name_len) 
                                != CTC_SUCCESS)
                            {
                                is_ovf = CTC_TRUE;
                                break;
                            }
                            else
                            {
                                write_data_len += key_col->name_len;
                            }

                            /* 8. key column type (4 BYTE) */
                            if (ctcn_link_write_four_byte_number 
                                (link, (void *)&key_col->type) != CTC_SUCCESS)
                            {
                                is_ovf = CTC_TRUE;
                                break;
                            }
                            else
                            {
                                write_data_len += 4;
                            }

                            /* 9. key column value length (4BYTE) */
                            if (ctcn_link_write_four_byte_number 
                                (link, (void *)&key_col->val_len) != CTC_SUCCESS)
                            {
                                is_ovf = CTC_TRUE;
                                break;
                            }
                            else
                            {
                                write_data_len += 4;
                            }

                            /* 10. key column value (VARIABLE) */
                            if (ctcn_link_write (link, key_col->val, key_col->val_len) 
                                != CTC_SUCCESS)
                            {
                                is_ovf = CTC_TRUE;
                                break;
                            }
                            else
                            {
                                write_data_len += key_col->val_len;
                            }

                            break;

                        default:
                            break;
                    }

                    if (is_ovf == CTC_TRUE)
                    {
                        break;
                    }
                    else
                    {
                        remained_item_cnt--;
                        continue;
                    }
                }

                /* remained log item count is 0 */
                if (is_ovf != CTC_TRUE)
                {
                    total_data_len += write_data_len;
                }
                else
                {
                    if (total_data_len > 0)
                    {
                        /* adjust remained log item count */
                        /* 1 log record size must less than CTCP_PACKET_DATA_MAX_LEN */
                        read_item_cnt--;

                        CTC_TEST_EXCEPTION (ctcn_link_backward_wbuf_pos (link, write_data_len),
                                            err_write_buf_overflow_label);

                        /* initialize write data length */
                        write_data_len = 0;

                        /* fill 2. the number of item (4BYTE) */
                        ctcn_link_move_wbuf_pos (link, num_of_item_wbuf_pos);

                        (void)ctcn_link_write_four_byte_number (link, (void *)&read_item_cnt);
                        read_item_cnt = 0;

                        /* set result code */
                        result_code = CTCP_RC_SUCCESS_FRAGMENTED;

                        /* make ctcp header */
                        CTC_TEST_EXCEPTION (ctcp_make_protocol_header (link,
                                                                       (unsigned char)CTCP_CAPTURED_DATA_RESULT,
                                                                       (unsigned char)result_code,
                                                                       job_desc,
                                                                       sgid,
                                                                       total_data_len),
                                            err_make_protocol_header_label);

                        /* send packet */
                        CTC_TEST_EXCEPTION (ctcn_link_send (link), err_link_send_label);
                    }
                    else
                    {
                        /* not need to send */
                    }
                }
            }

            if (total_data_len > 0)
            {
                /* fill 2. the number of item (4BYTE) */
                ctcn_link_move_wbuf_pos (link, num_of_item_wbuf_pos);

                fprintf (stdout, "read_item_cnt = %d\n", read_item_cnt);
                fflush (stdout);

                (void)ctcn_link_write_four_byte_number (link, (void *)&read_item_cnt);
                read_item_cnt = 0;

                result_code = CTCP_RC_SUCCESS;

                /* make protocol header */
                CTC_TEST_EXCEPTION (ctcp_make_protocol_header (link,
                                                               (unsigned char)CTCP_CAPTURED_DATA_RESULT,
                                                               (unsigned char)result_code,
                                                               job_desc,
                                                               sgid,
                                                               total_data_len),
                                    err_make_protocol_header_label);

                ctcn_link_move_wbuf_pos (link, CTCP_HDR_LEN + total_data_len);

                /* send */
                CTC_TEST_EXCEPTION (ctcn_link_send (link), err_link_send_label);

        //        last_processed_tid = tid;

                /* transaction end */
                if (log_item_list->ref_cnt > 0)
                {
                    log_item_list->ref_cnt--;
                }
            }
//        }
//        else
//        {
            /* already processed transaction */ 
//        }
    }

    /* set tid to last processed tid */

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_link_label)
    {
        result = CTC_ERR_NULL_LINK_FAILED;
    }
    CTC_EXCEPTION (err_invalid_sgid_label)
    {
        /* ERROR: critical problem, anyway failed */
        result = CTC_ERR_INVALID_VALUE_FAILED;
    }
    CTC_EXCEPTION (err_make_protocol_header_label)
    {
        /* maybe.. buffer managing problem occurred something like overflow */
        result = CTC_ERR_BUFFER_OVERFLOW_FAILED;
    }
    CTC_EXCEPTION (err_write_buf_overflow_label)
    {
        result = CTC_ERR_BUFFER_OVERFLOW_FAILED;
    }
    CTC_EXCEPTION (err_link_send_label)
    {
        result = CTC_ERR_NETWORK_FAILED;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcp_do_stop_capture (void *inlink,
                                 int sgid,
                                 CTCP_HEADER *header,
                                 unsigned short job_desc,
                                 int close_cond,
                                 int *result_code)
{
    BOOL is_exist = CTC_FALSE;
    int result;
    CTCS_SESSION_GROUP *sg = NULL;
    CTCN_LINK *link = (CTCN_LINK *)inlink;

    CTC_COND_EXCEPTION (link == NULL, err_null_link_label);

    sg = ctcs_find_session_group_by_id (sgid);

    if (sg != NULL)
    {
        result = ctcs_sg_stop_capture (sg, job_desc, close_cond);

        switch (result)
        {
            /* CTCP_RC code setting by result */
            case CTC_SUCCESS:
                *result_code = CTCP_RC_SUCCESS;
                break;

            case CTC_ERR_JOB_NOT_EXIST_FAILED:
                *result_code = CTCP_RC_FAILED_INVALID_JOB;
                break;

            case CTC_ERR_JOB_ALREADY_STOPPED:
                *result_code = CTCP_RC_FAILED_JOB_ALREADY_STOPPED;
                break;

            default:
                *result_code = CTCP_RC_FAILED;
                CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                    err_stop_capture_failed_label);
                break;
        }
    }
    else
    {
        *result_code = CTCP_RC_FAILED_INVALID_HANDLE;
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_link_label)
    {
        *result_code = CTCP_RC_FAILED;
        result = CTC_ERR_NULL_LINK_FAILED;
    }
    CTC_EXCEPTION (err_stop_capture_failed_label)
    {
        /* DEBUG */
        fprintf (stdout, 
                 "err_stop_capture_failed_label in ctcp_do_stop_capture ()\n");
        fflush (stdout);
    }
    EXCEPTION_END;

    return result;
}


extern int ctcp_send_stop_capture_result (void *inlink,
                                          int result_code,
                                          unsigned short job_desc,
                                          int sgid)
{
    int result;
    CTCN_LINK *link = (CTCN_LINK *)inlink;
    /* link validation */
    CTC_COND_EXCEPTION (link == NULL, err_null_link_label);

    /* process by result code */
    switch (result_code)
    {
        case CTCP_RC_SUCCESS:

            CTC_TEST_EXCEPTION (ctcp_validate_job_desc ((int)job_desc),
                                err_job_desc);
            break;

        case CTCP_RC_FAILED_INVALID_HANDLE:
        case CTCP_RC_FAILED_INVALID_JOB:
        case CTCP_RC_FAILED_JOB_ALREADY_STOPPED:
            break;

        default:
            result_code = CTCP_RC_FAILED;
            break;
    }

    /* make protocol header */
    CTC_TEST_EXCEPTION (ctcp_make_protocol_header (link,
                                                   (unsigned char)CTCP_STOP_CAPTURE_RESULT,
                                                   (unsigned char)result_code,
                                                   job_desc,
                                                   sgid,
                                                   0),
                        err_make_protocol_header_label);

    /* send */
    result = ctcn_link_send (link);

    if (result != CTC_SUCCESS)
    {
        fprintf (stderr, "link send failed in ctcp_send_stop_capture_result ()\n");
        fflush (stderr);
    }
    else
    {
        /* send success */
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_link_label)
    {
        result = CTC_ERR_NULL_LINK_FAILED;
    }
    CTC_EXCEPTION (err_job_desc)
    {
        /* ERROR: critical problem, anyway failed */
        result = CTC_FAILURE;
    }
    CTC_EXCEPTION (err_make_protocol_header_label)
    {
        /* maybe.. buffer managing problem occurred something like overflow */
        result = CTC_ERR_BUFFER_OVERFLOW_FAILED;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcp_process_protocol (void *inlink, int sgid)
{
    BOOL is_timeout = CTC_FALSE;
    int result; 
    int result_code = CTCP_RC_SUCCESS;
    CTCP_HEADER header;
    CTCN_LINK *link = (CTCN_LINK *)inlink;

    /* recv packet */
    CTC_TEST_EXCEPTION (ctcn_link_recv (link, 
                                        CTCN_RECV_TIMEOUT_MAX, 
                                        &is_timeout),
                        err_link_recv_socket_label);

    CTC_COND_EXCEPTION (is_timeout == CTC_TRUE, err_timeout_exceed_label);

    /* analyze protocol */
    result = ctcp_analyze_protocol_header (link, 
                                           CTCP_UNKNOWN_OPERATION, 
                                           &header);

    if (result != CTC_SUCCESS)
    {
        switch (result)
        {
            case CTC_ERR_INVALID_JOB_FAILED:
                result_code = CTCP_RC_FAILED_INVALID_JOB;
                break;

            case CTC_ERR_INVALID_TYPE_FAILED:
                result_code = CTCP_RC_FAILED_OUT_OF_RANGE;
                break;

            case CTC_ERR_INVALID_VALUE_FAILED:
            default:
                result_code = CTCP_RC_FAILED_WRONG_PACKET;
                break;
        }

        /* make protocol header */
        CTC_TEST_EXCEPTION (ctcp_make_protocol_header (link,
                                                       (unsigned char)header.op_id,
                                                       (unsigned char)result_code,
                                                       header.job_desc,
                                                       header.session_group_id,
                                                       0),
                            err_make_protocol_header_label);

        /* send */
        result = ctcn_link_send (link);

        if (result != CTC_SUCCESS)
        {
            fprintf (stderr, "link send failed in ctcp_process_protocol ()\n");
            fflush (stderr);
        }
        else
        {
            /* send success */
        }
    }
    else
    {
        /* execute protocol */
        result = ctcp_execute_protocol (link, &header);
        CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                            err_execute_prcl_failed_label);
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_link_recv_socket_label)
    {
        result = CTC_ERR_LINK_RECV_FAILED;
    }
    CTC_EXCEPTION (err_timeout_exceed_label)
    {
        result = CTC_ERR_TIMEOUT_FAILED;
    }
    CTC_EXCEPTION (err_make_protocol_header_label)
    {
        /* ERROR: critical problem, anyway failed */
        fprintf (stderr, "err_make_protocol_header_label in ctcp_process_protocol ()\n");
        fflush (stderr);
        result = CTC_FAILURE;
    }
    CTC_EXCEPTION (err_execute_prcl_failed_label)
    {
        /* error info set from sub-function */
    }
    EXCEPTION_END;

    return result;
}



static int ctcp_execute_protocol (void *inlink, CTCP_HEADER *header)
{
    int result;
    int sgid;
    int table_len;
    int user_len;
    int data_len;
    int result_code;
    int status;
    int close_cond;
    unsigned short job_desc;
    char user_name[CTC_NAME_LEN] = {0,};
    char table_name[CTC_NAME_LEN] = {0,};
    CTCJ_JOB_TAB_INFO tab_info;
    CTCJ_JOB_ATTR job_attr;
    CTCN_LINK *link = (CTCN_LINK *)inlink;

    assert (header != NULL);

    sgid = header->session_group_id;    

    switch (header->op_id)
    {
        case CTCP_DESTROY_CONTROL_SESSION:

            ctcp_do_destroy_ctrl_session (sgid, &result_code);

            result = ctcp_send_destroy_ctrl_session_result (link, 
                                                            result_code, 
                                                            sgid);
            
            CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                err_send_result_failed_label);

            /* need to destroy link ? */
            
            break;

        case CTCP_CREATE_JOB_SESSION:

            result = ctcp_do_create_job_session (link, 
                                                 sgid,
                                                 header,
                                                 &job_desc,
                                                 &result_code);

            CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                err_create_job_session_failed_label);

            result = ctcp_send_create_job_session_result (link,
                                                          result_code,
                                                          job_desc,
                                                          sgid);

            CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                err_send_result_failed_label);

            break;

        case CTCP_DESTROY_JOB_SESSION:

            job_desc = header->job_desc;

            result = ctcp_do_destroy_job_session (link,
                                                  sgid,
                                                  header,
                                                  job_desc,
                                                  &result_code);

            CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                err_destroy_job_session_failed_label);

            result = ctcp_send_destroy_job_session_result (link,
                                                           result_code,
                                                           job_desc,
                                                           sgid);

            CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                err_send_result_failed_label);

            break;

        case CTCP_REQUEST_JOB_STATUS:

            job_desc = header->job_desc;

            result = ctcp_do_request_job_status (link,
                                                 sgid,
                                                 header,
                                                 job_desc,
                                                 &status,
                                                 &result_code);

            CTC_COND_EXCEPTION (result != CTC_SUCCESS,
                                err_request_job_status_failed_label);

            result = ctcp_send_request_job_status_result (link,
                                                          result_code,
                                                          job_desc,
                                                          sgid,
                                                          status);

            CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                err_send_result_failed_label);

            break;

        case CTCP_REQUEST_SERVER_STATUS:

            result = ctcp_do_request_server_status (link,
                                                    sgid,
                                                    header,
                                                    &status,
                                                    &result_code);

            CTC_COND_EXCEPTION (result != CTC_SUCCESS,
                                err_request_server_status_failed_label);

            result = ctcp_send_request_server_status_result (link,
                                                             result_code,
                                                             sgid,
                                                             status);

            CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                err_send_result_failed_label);

            break;

        case CTCP_REGISTER_TABLE:

            job_desc = header->job_desc;
            data_len = header->data_len;
            user_len = 0;
            table_len = 0;

            if (data_len > 0)
            {
                /* read user name length from rbuf of link */
                result = ctcn_link_read_four_byte_number (link, 
                                                          (void*)&user_len);

                if (result != CTC_SUCCESS)
                {
                    /* wrong packet */
                    result_code = CTCP_RC_FAILED_WRONG_PACKET;
                }
                else
                {
                    /* read user_name */
                    result = ctcn_link_read (link, 
                                             (void *)user_name, 
                                             user_len);

                    /* DEBUG */
                    fprintf (stdout, "user_name = %s\n", user_name);
                    fflush (stdout);

                    if (result != CTC_SUCCESS)
                    {
                        result_code = CTCP_RC_FAILED_WRONG_PACKET;
                    }
                    else
                    {
                        /* read table name length */
                        result = ctcn_link_read_four_byte_number (link, 
                                                                  (void*)&table_len);

                        if (result != CTC_SUCCESS)
                        {
                            result_code = CTCP_RC_FAILED_WRONG_PACKET;
                        }
                        else
                        {
                            /* read table name */
                            result = ctcn_link_read (link, 
                                                     (void *)table_name, 
                                                     table_len);
                    /* DEBUG */
                    fprintf (stdout, "table_name = %s\n", table_name);
                    fflush (stdout);

                            if (result != CTC_SUCCESS)
                            {
                                result_code = CTCP_RC_FAILED_WRONG_PACKET;
                            }
                            else
                            {
                                /* table table name from rbuf of link */
                                result = ctcp_do_register_table (link, 
                                                                 sgid, 
                                                                 header, 
                                                                 job_desc, 
                                                                 user_name,
                                                                 table_name, 
                                                                 &result_code);
                        
                                CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                                    err_register_table_failed_label);
                    /* DEBUG */
                    fprintf (stdout, "register table SUCCESS\n");
                    fflush (stdout);

                            }
                        }
                    }
                }
            }
            else
            {
                result_code = CTCP_RC_FAILED_WRONG_PACKET;
            }

            result = ctcp_send_register_table_result (link, 
                                                      result_code, 
                                                      job_desc, 
                                                      sgid);
                
            CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                err_send_result_failed_label);

            break;

        case CTCP_UNREGISTER_TABLE:

            job_desc = header->job_desc;
            data_len = header->data_len;
            user_len = 0;
            table_len = 0;

            if (data_len > 0)
            {
                /* read user name length from rbuf of link */
                result = ctcn_link_read_four_byte_number (link, 
                                                          (void*)&user_len);

                if (result != CTC_SUCCESS)
                {
                    /* wrong packet */
                    result_code = CTCP_RC_FAILED_WRONG_PACKET;
                }
                else
                {
                    /* read user_name */
                    result = ctcn_link_read (link, 
                                             (void *)user_name, 
                                             user_len);

                    /* DEBUG */
                    fprintf (stdout, "user_name = %s\n", user_name);
                    fflush (stdout);

                    if (result != CTC_SUCCESS)
                    {
                        result_code = CTCP_RC_FAILED_WRONG_PACKET;
                    }
                    else
                    {
                        /* read table name length */
                        result = ctcn_link_read_four_byte_number (link, 
                                                                  (void*)&table_len);

                        if (result != CTC_SUCCESS)
                        {
                            result_code = CTCP_RC_FAILED_WRONG_PACKET;
                        }
                        else
                        {
                            /* read table name */
                            result = ctcn_link_read (link, 
                                                     (void *)table_name, 
                                                     table_len);
                    
                    /* DEBUG */
                    fprintf (stdout, "table_name = %s\n", table_name);
                    fflush (stdout);

                            if (result != CTC_SUCCESS)
                            {
                                result_code = CTCP_RC_FAILED_WRONG_PACKET;
                            }
                            else
                            {
                                result = ctcp_do_unregister_table (link, 
                                                                   sgid, 
                                                                   header, 
                                                                   job_desc, 
                                                                   user_name, 
                                                                   table_name, 
                                                                   &result_code);
                        
                                CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                                    err_unregister_table_failed_label);
                    /* DEBUG */
                    fprintf (stdout, "register table SUCCESS\n");
                    fflush (stdout);

                            }
                        }
                    }
                }
            }
            else
            {
                result_code = CTCP_RC_FAILED_WRONG_PACKET;
            }

            result = ctcp_send_unregister_table_result (link, 
                                                        result_code, 
                                                        job_desc, 
                                                        sgid);

            CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                err_send_result_failed_label);

            break;

        case CTCP_SET_JOB_ATTRIBUTE:

            job_attr.id = (CTCJ_JOB_ATTR_ID)header->op_param;
            job_attr.value = header->data_len;

            result = ctcp_do_set_job_attribute (link,
                                                sgid,
                                                header,
                                                job_desc,
                                                &job_attr,
                                                &result_code);

            CTC_COND_EXCEPTION (result != CTC_SUCCESS,
                                err_set_job_attribute_failed_label);

            result = ctcp_send_set_job_attribute_result (link,
                                                         result_code,
                                                         job_desc,
                                                         sgid);

            CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                err_send_result_failed_label);

            break;

        case CTCP_START_CAPTURE:

            job_desc = header->job_desc;

            result = ctcp_do_start_capture (link,
                                            sgid,
                                            header,
                                            job_desc,
                                            &result_code);

            CTC_COND_EXCEPTION (result != CTC_SUCCESS,
                                err_start_capture_failed_label);

            result = ctcp_send_start_capture_result (link,
                                                     result_code,
                                                     job_desc,
                                                     sgid);

            CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                err_send_result_failed_label);

            /* */

            break;

        case CTCP_STOP_CAPTURE:

            job_desc = header->job_desc;
            close_cond = (int)header->op_param;

            result = ctcp_do_stop_capture (link,
                                           sgid,
                                           header,
                                           job_desc,
                                           close_cond,
                                           &result_code);

            CTC_COND_EXCEPTION (result != CTC_SUCCESS,
                                err_stop_capture_failed_label);

            result = ctcp_send_stop_capture_result (link, 
                                                    result_code, 
                                                    job_desc, 
                                                    sgid);

            CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                err_send_result_failed_label);

            break;

        default:
            /* invalid opid came in this function, 
             * critical situation but ignore */
            break;
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_link_label)
    {
        /* error info set from sub-function */
    }
    CTC_EXCEPTION (err_make_protocol_header_label)
    {
        /* error info set from sub-function */
    }
    CTC_EXCEPTION (err_create_job_session_failed_label)
    {
        /* error info set from sub-function */
    }
    CTC_EXCEPTION (err_destroy_job_session_failed_label)
    {
        /* error info set from sub-function */
    }
    CTC_EXCEPTION (err_request_job_status_failed_label)
    {
        /* error info set from sub-function */
    }
    CTC_EXCEPTION (err_request_server_status_failed_label)
    {
        /* error info set from sub-function */
    }
    CTC_EXCEPTION (err_register_table_failed_label)
    {
        /* error info set from sub-function */
    }
    CTC_EXCEPTION (err_unregister_table_failed_label)
    {
        /* error info set from sub-function */
    }
    CTC_EXCEPTION (err_set_job_attribute_failed_label)
    {
        /* error info set from sub-function */
    }
    CTC_EXCEPTION (err_start_capture_failed_label)
    {
        /* error info set from sub-function */
    }
    CTC_EXCEPTION (err_stop_capture_failed_label)
    {
        /* error info set from sub-function */
    }
    CTC_EXCEPTION (err_send_result_failed_label)
    {
        /* error info set from sub-function */
    }
    EXCEPTION_END;

    return result;
}


