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
 * ctcs.h : ctc session manager header
 *
 */

#ifndef _CTCS_H_
#define _CTCS_H_ 1

#include "ctcs_def.h"
#include "ctc_types.h"


extern CTCS_MGR ctcs_Mgr;


extern int ctcs_initialize (void);
extern void ctcs_finalize (void);

/* session manager functions */
extern int ctcs_mgr_get_session_count (int *cnt);
extern int ctcs_mgr_inc_session_count (void);
extern int ctcs_mgr_dec_session_count (void);
extern int ctcs_mgr_get_sg_cnt (int *sg_cnt);
extern CTCG_LIST *ctcs_mgr_get_sg_list (void);
extern int ctcs_mgr_total_registered_job_cnt (void);
extern int ctcs_mgr_create_session_group (CTCN_LINK *link, int *sgid);


/* session group functions */
extern CTCS_SESSION_GROUP *ctcs_find_session_group_by_id (int sgid);

extern int ctcs_sg_initialize (CTCS_SESSION_GROUP *sg, 
                               CTCN_LINK *link, 
                               int sgid);

extern int ctcs_sg_finalize (CTCS_SESSION_GROUP *sg);

extern int ctcs_sg_add_job (CTCS_SESSION_GROUP *sg, 
                            CTCN_LINK *link,
                            unsigned short *job_desc);

extern int ctcs_sg_delete_job (CTCS_SESSION_GROUP *sg, unsigned short job_desc);

extern CTCS_JOB_SESSION *ctcs_sg_find_job_session (CTCS_SESSION_GROUP *sg, 
                                                   unsigned short job_desc);

extern CTCS_CTRL_SESSION *ctcs_sg_get_ctrl_session (CTCS_SESSION_GROUP *sg);

extern int ctcs_sg_is_table_registered (CTCS_SESSION_GROUP *sg,
                                        unsigned short job_desc,
                                        char *user_Name,
                                        char *table_name,
                                        BOOL *is_exist);

extern int ctcs_sg_get_job_status (CTCS_SESSION_GROUP *sg,
                                   unsigned short job_desc,
                                   int *job_status);

extern int ctcs_sg_register_table (CTCS_SESSION_GROUP *sg,
                                   unsigned short job_desc,
                                   char *table_name, 
                                   char *user_name);

extern int ctcs_sg_unregister_table (CTCS_SESSION_GROUP *sg,
                                     unsigned short job_desc, 
                                     char *table_name, 
                                     char *user_name);

extern int ctcs_sg_set_job_attr (CTCS_SESSION_GROUP *sg,
                                 unsigned short job_desc,
                                 CTCJ_JOB_ATTR *job_attr);

extern int ctcs_sg_start_capture (CTCS_SESSION_GROUP *sg,
                                  unsigned short job_desc);

extern int ctcs_sg_stop_capture (CTCS_SESSION_GROUP *sg, 
                                 unsigned short job_desc,
                                 int stop_cond);


/* job session functions */
extern CTCJ_JOB_INFO *ctcs_job_session_get_job (CTCS_JOB_SESSION *job_session);

extern int ctcs_job_session_start_capture (CTCS_JOB_SESSION *job_session);

extern int ctcs_disconnect_job_session (CTCS_JOB_SESSION * job_session);

extern int ctcs_destroy_all_job_session (CTCS_SESSION_GROUP *sg,
                                         int close_cond);

extern int ctcs_destroy_job_session (CTCS_SESSION_GROUP *sg,
                                     unsigned short job_desc,
                                     int close_cond);


#endif /* _CTCS_H_ */
