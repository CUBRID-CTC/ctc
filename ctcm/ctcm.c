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
 * ctcm.c : ctc main routine implementation
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#include "ctcp.h"
#include "ctcg_conf.h"
#include "ctcg_list.h"
#include "ctcn_link.h"
#include "ctcs.h"
#include "ctcm.h"
#include "ctcj.h"
#include "ctcl.h"
#include "ctc_common.h"
#include "ctc_types.h"


static CTC_SIG_HANDLER_FUNC ctc_register_sig_handler (int signal,
                                                      CTC_SIG_HANDLER_FUNC func);

static void ctc_shutdown (int signal);
static void ctc_status (int signal);

static int ctc_load_conf (void);
static int ctc_conf_get_ctc_port (unsigned short *port);
static int ctc_start_listen (unsigned short ctc_port);

static int ctc_make_link (CTCN_LINK **link);
static int ctc_listen (CTCN_LINK *link, unsigned short ctc_port);
static int ctc_accept_and_read_protocol (CTCN_LINK *link, void *header);

static void ctc_stop_listen (void);
static void ctc_finalize (void);



BOOL is_stop_listen;
CTC_SERV_STATUS server_Status;
char ctc_source_db_name [CTC_NAME_LEN] = {0,};
const char *start_time_string = NULL;
const char *proc_status_str[] = { "NOT_READY", "RUNNING", "CLOSING" };

/*
 *  Description: 
 *  When the process catches the SIGTERM signal, process shutdown itself.
 *     
 *  Note:
 *  After setting shutdown flag as CTC_TRUE, each threads process "stop"
 */ 

static void ctc_shutdown (int signal)
{
    server_Status = CTC_SERV_STATUS_CLOSING;
    ctc_stop_listen ();
    ctc_finalize ();
}


static void ctc_status (int signal)
{
    int open_connection_cnt = 0;
    int registered_job_cnt = 0;
    int cur_processing_job_cnt = 0;
    int extracted_log_cnt = 0;

    (void)ctcs_mgr_get_sg_cnt (&open_connection_cnt);
    registered_job_cnt = ctcs_mgr_total_registered_job_cnt ();
    cur_processing_job_cnt = ctcl_mgr_get_cur_job_cnt ();

    extracted_log_cnt = ctcl_mgr_get_extracted_log_cnt ();

    fprintf (stdout, "\nPROCESS_STATUS: %s", proc_status_str[server_Status]);
    fprintf (stdout, "\nSTART_TIME: %s", start_time_string);
    fprintf (stdout, "\nSOURCE_DATABASE: %s", ctc_source_db_name);
    fprintf (stdout, "\nOPEN_CONNECTION_COUNT: %d", open_connection_cnt);
    fprintf (stdout, "\nREGISTERED_JOB_COUNT: %s", registered_job_cnt);
    fprintf (stdout, "\nCURRENT_PROCESSING_JOB_COUNT: %d", cur_processing_job_cnt);
    fprintf (stdout, "\nEXTRACTED_LOG_COUNT: %d\n", extracted_log_cnt);
    fflush (stdout);
}


int main (int argc, char **argv)
{
    int result;
    int stage = 0;
    int thr_ret;
    unsigned short ctc_port;
    char *log_path;
    char *env_root;
    char ctc_root_name[] = "CUBRID";
    char log_file_path[CTCG_PATH_MAX];
    time_t start_time; 
    pthread_t la_thr_id;

    CTCL_CONF_ITEMS ctcl_conf_items;

    is_stop_listen = CTC_FALSE;
    server_Status = CTC_SERV_STATUS_NOT_READY;

    printf ("\n[ctc main function]\n database name : %s\n", argv[1]);

    memset (ctc_source_db_name, 0, CTC_NAME_LEN);
    strncpy (ctc_source_db_name, argv[1], strlen (argv[1]));

    /* 1. signal handling: is_stop_listen set CTC_TRUE */
    (void)ctc_register_sig_handler (SIGSTOP, ctc_shutdown);
    (void)ctc_register_sig_handler (SIGTERM, ctc_shutdown);
    (void)ctc_register_sig_handler (SIGPIPE, SIG_IGN);
    (void)ctc_register_sig_handler (SIGUSR1, ctc_shutdown);
    (void)ctc_register_sig_handler (SIGUSR2, ctc_status);

    /* for debugging */
    (void)ctc_register_sig_handler (SIGINT, ctc_shutdown);

    CTC_TEST_EXCEPTION (ctc_load_conf (), err_load_conf_failed_label);

    ctcp_initialize ();

    CTC_TEST_EXCEPTION (ctcj_initialize (), err_ctcj_init_failed_label);
    stage = 1;

    CTC_TEST_EXCEPTION (ctcs_initialize (), err_ctcs_init_failed_label);
    stage = 2;

    /* TODO: get conf item value for log manager into ctcl_conf_item */
    memset (&ctcl_conf_items, 0, sizeof (CTCL_CONF_ITEMS));

    ctcl_conf_items.max_mem_size = 0x7fffffff;

    strncpy (ctcl_conf_items.db_name, argv[1], strlen(argv[1]));
/*
    result = ctcg_conf_get_item_value (CTCG_CONF_ID_CTC_TRAN_LOG_FILE_PATH, 
                                       CTCG_CONF_ITEM_VAL_SET_STR, 
                                       (void *)&log_path);
    CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_get_conf_item_label);
    */

    log_path = CONF_GET_STRING (conf_item_Def[CTCG_CONF_ID_CTC_TRAN_LOG_FILE_PATH].value);

    if (log_path)
    {
        if (log_path[0] == '$')
        {
            if (strncmp (log_path, ctc_root_name, strlen (ctc_root_name)))
            {
                env_root = getenv (ctc_root_name);

                snprintf (log_file_path, sizeof (log_file_path), 
                          "%s%s", 
                          env_root, 
                          log_path + strlen (ctc_root_name) + 1);
            }
        }
        else if (log_path[0] == '/')
        {
            /* from root directory, so just use it */
        }
        else
        {
            /* invalid log file path in configuration */
        }
    }

    strncpy (ctcl_conf_items.log_path, log_file_path, strlen(log_file_path));

    /* TEST */
    printf("ctcl_conf_items.log_path = %s\n", ctcl_conf_items.log_path);

    /* log analyzer start */
    CTC_TEST_EXCEPTION (ctcl_initialize (&ctcl_conf_items, &la_thr_id), 
                        err_ctcl_init_failed_label);

    printf ("log_analyzer_thr_id = %d\n", la_thr_id);

    server_Status = CTC_SERV_STATUS_RUNNING;
    stage = 3;

    CTC_TEST_EXCEPTION (ctc_conf_get_ctc_port (&ctc_port), 
                        err_get_conf_port_failed_label);

    start_time = time (NULL);

    if (start_time == ((time_t)-1))
    {
        (void)fprintf (stderr, "Failure to obtain the start time.\n");
        exit (EXIT_FAILURE);
    }

    start_time_string = ctime (&start_time);

    if (start_time_string == NULL)
    {
        (void)fprintf (stderr, "Failure to convert time.\n");
        exit (EXIT_FAILURE);
    }

    /* listener start */
    CTC_TEST_EXCEPTION (ctc_start_listen (ctc_port), err_listen_failed_label);

    pthread_join (la_thr_id, (void **)&thr_ret);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_load_conf_failed_label)
    {
        fprintf (stdout, "\n ERROR: configuration loading failed.\n\t \
                 Please check each item settings of configuration \t  \
                 and configuration file path and name is ctc.conf \n");
        fflush (stdout);
    }
    CTC_EXCEPTION (err_ctcj_init_failed_label)
    {
        fprintf (stdout, "\n ERROR(for DEBUG): job manager initialize failed.\n");
        fflush (stdout);
    }
    CTC_EXCEPTION (err_ctcs_init_failed_label)
    {
        fprintf (stdout, "\n ERROR(for DEBUG): session manager initialize failed.\n");
        fflush (stdout);
    }
    CTC_EXCEPTION (err_ctcl_init_failed_label)
    {
        fprintf (stdout, "\n ERROR(for DEBUG): log manager initialize failed.\n");
        fflush (stdout);
    }
    CTC_EXCEPTION (err_get_conf_port_failed_label)
    {
        fprintf (stdout, "\n ERROR(for DEBUG): failed to get ctc port.\n");
        fflush (stdout);
    }
    CTC_EXCEPTION (err_get_conf_item_label)
    {
        fprintf (stdout, "\n ERROR(for DEBUG): failed to get log file path.\n");
        fflush (stdout);
    }
    CTC_EXCEPTION (err_listen_failed_label)
    {
        fprintf (stdout, "\n ERROR(for DEBUG): failed to start listener.\n");
        fflush (stdout);
    }
    EXCEPTION_END;

    switch (stage)
    {
        case 3:
            (void)ctcl_finalize ();
        case 2:
            (void)ctcs_finalize ();
        case 1:
            (void)ctcj_finalize ();
            break;
    }

    return CTC_FAILURE;
}


static CTC_SIG_HANDLER_FUNC ctc_register_sig_handler (int signal,
                                                      CTC_SIG_HANDLER_FUNC func)
{
    struct sigaction act;
    struct sigaction oact;

    act.sa_handler = func;
    act.sa_flags = 0;

    if (sigemptyset (&act.sa_mask) < 0)
    {   
        return (SIG_ERR);
    }   

    switch (signal)
    {   
        case SIGALRM:
#if defined(SA_INTERRUPT)
            act.sa_flags |= SA_INTERRUPT;     /* disable other interrupts */
#endif /* SA_INTERRUPT */
            break;
        default:
#if defined(SA_RESTART)
            act.sa_flags |= SA_RESTART;       /* making certain system calls
                                                 restartable across signals */
#endif /* SA_RESTART */
            break;
    }   

    if (sigaction (signal, &act, &oact) < 0)
    {   
        return (SIG_ERR);
    }   

    return (oact.sa_handler);
}


static int ctc_load_conf (void)
{
    CTC_TEST_EXCEPTION (ctcg_load_conf (), err_load_conf_label);

    /* >>> for test */
    int i;
    for (i = 0; i < CTCG_CONF_ID_LAST; i++)
    {
        if (conf_item_Def[i].datatype == CTCG_CONF_INTEGER)
        {
            printf ("CONFIGURATION ITEM NO[%d]:\n\t NAME: %s\n\t VALUE: %d\n", 
                    i, conf_item_Def[i].name, CONF_GET_INT(conf_item_Def[i].value));
        }
        else if (conf_item_Def[i].datatype == CTCG_CONF_STRING)
        {
            printf ("CONFIGURATION ITEM NO[%d]:\n\t NAME: %s\n\t VALUE: %s\n", 
                    i, conf_item_Def[i].name, CONF_GET_STRING(conf_item_Def[i].value));
        }
        else
        {
        }
    }
    /* <<< for test */

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_load_conf_label)
    EXCEPTION_END;

    return CTC_FAILURE;
}


/*
 * Description: main listener thread
 *
 *  1. setup listen socket 
 *  2. listen connection request from CTC API library
 *  3. LOOP: accept and read protocol
 *  4-1. if protocol is 'CTC_CREATE_CTRL_SESSION', create control session thread
 *  4-2. if protocol is 'CTC_CREATE_JOB_SESSION', copy new sd into session grp.
 *
 */
static int ctc_start_listen (unsigned short ctc_port)
{
    int result;
    int result_code;
    int sgid = CTCP_SGID_NULL;
    int total_session_cnt = 0;
    unsigned short job_desc;
    CTCS_SESSION_GROUP *sg = NULL;
    CTCS_CTRL_SESSION *ctrl_session;
    CTCN_LINK *link = NULL;
    CTCP_HEADER header;

    /* 1. setup listen socket */
    CTC_TEST_EXCEPTION (ctc_make_link (&link), err_make_link_failed_label);

    /* 2. listen connection request */
    CTC_TEST_EXCEPTION (ctc_listen (link, ctc_port), err_ctc_listen_label);

    /* 3. accept and read protocol */
    while (!is_stop_listen)
    {
        /* accept --> read packet --> packet validation */
        result = ctc_accept_and_read_protocol (link, (void *)&header);

        if (result == CTC_SUCCESS)
        {
            switch (header.op_id)
            {
                case CTCP_CREATE_CONTROL_SESSION:

                    (void)ctcp_do_create_ctrl_session (link, 
                                                       &header, 
                                                       &sgid, 
                                                       &result_code);

                    ctcp_send_create_ctrl_session_result (link, 
                                                          result_code, 
                                                          sgid);

                    if (result_code == CTCP_RC_SUCCESS)
                    {
                        CTC_TEST_EXCEPTION (ctcs_mgr_inc_session_count (),
                                            err_inc_session_cnt_failed_label);
                    }

                    sg = ctcs_find_session_group_by_id (sgid);

                    if (sg != NULL)
                    {
                        ctrl_session = ctcs_sg_get_ctrl_session (sg);
                        pthread_join (ctrl_session->thread, NULL);
                    }
                    else
                    {
                        /* ERROR: critical but ignore */
                    }

                    break;

                case CTCP_CREATE_JOB_SESSION:

                    sgid = ctcp_header_get_sgid (&header);

                    (void)ctcp_do_create_job_session (link, 
                                                      sgid, 
                                                      &header, 
                                                      &job_desc,
                                                      &result_code);

                    ctcp_send_create_job_session_result (link, 
                                                         result_code, 
                                                         job_desc, 
                                                         sgid);

                    if (result_code == CTCP_RC_SUCCESS)
                    {
                        CTC_TEST_EXCEPTION (ctcs_mgr_inc_session_count (),
                                            err_inc_session_cnt_failed_label);
                    }

                    break;

                default:
                    break;
            }
        }
        else
        {
            continue;
        }

        CTC_TEST_EXCEPTION (ctcs_mgr_get_session_count (&total_session_cnt),
                            err_get_session_cnt_failed_label);

        if (total_session_cnt >= CTCN_MAX_LISTEN)
        {
            /* WARNING: session count meets max listen allowed */
            break;
        }
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_make_link_failed_label)
    {
        printf ("err_make_link_failed_label\n");
        result = CTC_ERR_ALLOC_FAILED;
    }
    CTC_EXCEPTION (err_ctc_listen_label)
    {
        printf ("err_ctc_listen_label\n");
    }
    CTC_EXCEPTION (err_inc_session_cnt_failed_label)
    {
        /* lock fail */
    }
    CTC_EXCEPTION (err_get_session_cnt_failed_label)
    {
        /* lock fail */
    }
    EXCEPTION_END;

    return result;
}


static int ctc_make_link (CTCN_LINK **link)
{
    CTC_TEST_EXCEPTION (ctcn_link_create (link), 
                        err_link_create_failed_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_link_create_failed_label)
    {
        /* ERROR: memory allocation, process this error in caller
         * so, just return CTC_FAILURE */
    }
    EXCEPTION_END;

    return CTC_FAILURE;
}


static int ctc_listen (CTCN_LINK *link, unsigned short ctc_port)
{
    unsigned int timeout = CTC_LISTEN_TIMEOUT;

    CTC_TEST_EXCEPTION (ctcn_link_listen (link, ctc_port, timeout),
                        err_link_listen);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_link_listen)
    {
    }
    EXCEPTION_END;

    return CTC_FAILURE;
}


static int ctc_accept_and_read_protocol (CTCN_LINK *listen_link,
                                         void *header)
{
    BOOL is_timeout = CTC_FALSE;
    int addr_len;
    int result = CTC_SUCCESS;
    ctc_sock_addr_t addr;
    CTCN_LINK *new_link = NULL;

    /* make new link */
    CTC_TEST_EXCEPTION (ctcn_link_create (&new_link), err_link_create_label);

    while (1)
    {
        result = ctcn_link_poll_socket (listen_link, 1000, &is_timeout);

        CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                            err_link_poll_socket_failed_label);

        if (is_timeout == CTC_TRUE)
        {
            usleep (1000 * 1000);
            continue;
        }
        else
        {
            /* accept new clnt socket */
            CTC_TEST_EXCEPTION (ctcn_sock_accept (&new_link->sock, 
                                                  &listen_link->sock, 
                                                  &addr, 
                                                  &addr_len),
                                err_sock_accept_label);

            //ctcn_sock_accept (&new_link->sock, &listen_link->sock, NULL, NULL);

            /* recv packet */
            CTC_TEST_EXCEPTION (ctcn_link_recv (new_link, 100, &is_timeout),
                                err_link_recv_socket_label);

            CTC_COND_EXCEPTION (is_timeout == CTC_TRUE, err_sock_recv_timeout_label);

            /* read protocol header */
            CTC_TEST_EXCEPTION (ctcp_analyze_protocol_header (new_link, 
                                                              CTCP_UNKNOWN_OPERATION, 
                                                              (CTCP_HEADER *)header),
                                err_analyze_protocol_header);

            break;
        }
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_link_create_label)
    {
        result = CTC_ERR_ALLOC_FAILED;
    }
    CTC_EXCEPTION (err_link_poll_socket_failed_label)
    {
        result = CTC_ERR_ALLOC_FAILED;
    }
    CTC_EXCEPTION (err_sock_accept_label)
    {
        result = CTC_FAILURE;
    }
    CTC_EXCEPTION (err_link_recv_socket_label)
    {
        result = CTC_FAILURE;
    }
    CTC_EXCEPTION (err_sock_recv_timeout_label)
    {
        result = CTC_ERR_TIMEOUT_FAILED;
    }
    CTC_EXCEPTION (err_analyze_protocol_header)
    {
        result = CTC_ERR_INVALID_VALUE_FAILED;
    }
    EXCEPTION_END;

    return result;
}


static int ctc_conf_get_ctc_port (unsigned short *port)
{
    int result;
    unsigned short ctc_port;

    result = ctcg_conf_get_item_value (CTCG_CONF_ID_CTC_PORT,
                                       CTCG_CONF_ITEM_VAL_SET_INT,
                                       (void *)&ctc_port);

    CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_get_ctc_port_failed_label);

    *port = ctc_port;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_get_ctc_port_failed_label)
    {
        /* ERROR: configuration */
    }
    EXCEPTION_END;

    return result;
}


static void ctc_finalize (void)
{
    (void)ctcj_finalize ();
    (void)ctcs_finalize ();
//    (void)ctcl_finalize ();

    return;
}


static void ctc_stop_listen (void)
{
    is_stop_listen = CTC_TRUE;
}


extern void ctc_get_server_status (int *status)
{
    *status = server_Status;
}


