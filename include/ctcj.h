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
 * ctcj.h : ctc job manager header
 *
 */

#ifndef _CTCJ_H_
#define _CTCJ_H_ 1

#include "ctcj_def.h"


extern CTC_JOB_REF_TABLE job_ref_Tbl;

/* 
 * functions 
 *
 */

/* ctcj */
extern int ctcj_initialize (void);
extern void ctcj_finalize (void);


/* reference table */
extern int ctcj_ref_table_job_lock (void);
extern int ctcj_ref_table_job_unlock (void);
extern int ctcj_ref_table_table_lock (void);
extern int ctcj_ref_table_table_unlock (void);

extern int ctcj_ref_table_add_job (CTCJ_JOB_INFO *job);
extern int ctcj_ref_table_remove_job (CTCJ_JOB_INFO *job);

extern int ctcj_ref_table_add_table (CTCJ_JOB_TAB_INFO *tab_info);
extern int ctcj_ref_table_remove_table (CTCJ_JOB_TAB_INFO *tab_info);


/* job info */
extern int ctcj_make_new_job (CTCJ_JOB_INFO **job_info);
extern int ctcj_init_job_info (CTCJ_JOB_INFO *job_info, 
                               unsigned short job_id, 
                               int sgid, 
                               int job_qsize, 
                               int long_tran_qsize);

extern void ctcj_destroy_job_info (CTCJ_JOB_INFO *job_info);

extern CTCG_LIST *ctcj_job_get_table_list (CTCJ_JOB_INFO *job_info);


/* job status */
extern int ctcj_set_job_status (CTCJ_JOB_INFO *job_info, int status);
extern int ctcj_get_job_status (CTCJ_JOB_INFO *job_info, int *status);


/* register/unregister table */
extern int ctcj_job_register_table (CTCJ_JOB_INFO *job, 
                                    const char *table_name,
                                    const char *user_name);

extern int ctcj_job_unregister_table (CTCJ_JOB_INFO *job,
                                      const char *table_name,
                                      const char *user_name);


/* capture */
extern void *ctcj_capture_thr_func (void *args);

extern void ctcj_stop_capture_immediately (pthread_t job_thr_id, 
                                           CTCJ_JOB_INFO *job);

extern void ctcj_stop_capture (pthread_t job_thr_id, CTCJ_JOB_INFO *job);


#endif /* _CTCJ_H_ */
