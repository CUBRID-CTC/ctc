/*
 *  Copyright (C) 2018 CUBRID Corporation. All right reserved by CUBRID.
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
 *   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 US
 *                
 */

/*
 * ctcg_conf.h : ctc configuration header file 
 *
 */

#ifndef _CTCG_CONF_H_
#define _CTCG_CONF_H_ 1

#include "ctc_types.h"


/* configuration items in ctc.conf */
#define CONF_NAME_CTC_TRAN_LOG_FILE_PATH        "ctc_tran_log_file_path"
#define CONF_NAME_CTC_PORT                      "ctc_port"
#define CONF_NAME_CTC_SESSION_GROUP_MAX         "ctc_session_group_max"
#define CONF_NAME_CTC_JOB_QUEUE_SIZE            "ctc_job_queue_size"
#define CONF_NAME_CTC_LONG_TRAN_FILE_PATH       "ctc_long_tran_file_path"
#define CONF_NAME_CTC_LONG_TRAN_QUEUE_SIZE      "ctc_long_tran_queue_size"

#define CTCG_CONF_DEFAULT_CTC_PORT              (48397)

#define _ENVVAR_MAX_LENGTH                      (255)

#define CTCG_INI_BUF_SIZE                       (512)
#define CTCG_INI_INVALID_KEY                    ((char*)-1)
#define CTCG_PATH_MAX                           (256)

#define CTCG_CONF_EMPTY_FLAG                     0x00000000
#define CTCG_CONF_FOR_CLIENT                     0x00000002
#define CTCG_CONF_FOR_SERVER                     0x00000004

#define CONF_IS_STRING(x)                       ((x)->datatype \
                                                 == CTCG_CONF_STRING)
#define CONF_IS_INTEGER(x)                      ((x)->datatype \
                                                 == CTCG_CONF_INTEGER)

#define CONF_GET_INT(x)                         (*((int *) (x)))
#define CONF_GET_STRING(x)                      (*((char **) (x)))

#define CONF_SET                                 0x00000001  /* set */
#define CONF_ALLOCATED                           0x00000002  /* memory allocated */
#define CONF_DEFAULT_USED                        0x00000004  /* default value used */
#define CONF_DIFFERENT	                         0x00000008  /* mark that have value
                                                               different from default.*/
#define CONF_IS_SET(x)                          (x & CONF_SET)
#define CONF_IS_ALLOCATED(x)                    (x & CONF_ALLOCATED)
#define CONF_DEFAULT_VAL_USED(x)                (x & CONF_DEFAULT_USED)
#define CONF_IS_DIFFERENT(x)	                (x & CONF_DIFFERENT)
                                         
#define CONF_CLEAR_BIT(this, here)              (here &= ~this)
#define CONF_SET_BIT(this, here)                (here |= this)


typedef enum ctcg_ini_line_status
{
    CTCG_LINE_UNPROCESSED,
    CTCG_LINE_ERROR,
    CTCG_LINE_EMPTY,
    CTCG_LINE_COMMENT,
    CTCG_LINE_SECTION,
    CTCG_LINE_VALUE
} CTCG_INI_LINE_STATUS;


typedef enum ctcg_conf_datatype
{
    CTCG_CONF_INTEGER = 0,
    CTCG_CONF_STRING,
    CTCG_CONF_NO_TYPE
} CTCG_CONF_DATATYPE;


typedef enum ctcg_conf_id
{
    CTCG_CONF_ID_FIRST = 0,
    CTCG_CONF_ID_CTC_TRAN_LOG_FILE_PATH = 0,
    CTCG_CONF_ID_CTC_PORT,
    CTCG_CONF_ID_CTC_SESSION_GROUP_MAX,
    CTCG_CONF_ID_CTC_JOB_QUEUE_SIZE,
    CTCG_CONF_ID_CTC_LONG_TRAN_FILE_PATH,
    CTCG_CONF_ID_CTC_LONG_TRAN_QUEUE_SIZE,
    CTCG_CONF_ID_LAST
} CTCG_CONF_ID;


typedef enum ctcg_conf_err
{
    CTCG_CONF_ERR_UNKNOWN = 1000,
    CTCG_CONF_ERR_SET_FAILED,
    CTCG_CONF_ERR_CONF_PARSE,
    CTCG_CONF_ERR_CHK_RANGE,
    CTCG_CONF_ERR_STR_DUP,
    CTCG_CONF_ERR_CONVERT_VALUE,
    CTCG_CONF_ERR_BAD_VALUE
} CTCG_CONF_ERR;

/* for extern functions to get conf item value */
typedef enum ctcg_conf_item_val_type
{
    CTCG_CONF_ITEM_VAL_SET_INT = 0,
    CTCG_CONF_ITEM_VAL_SET_STR,
    CTCG_CONF_ITEM_VAL_STR,
    CTCG_CONF_ITEM_VAL_MIN,
    CTCG_CONF_ITEM_VAL_MAX,
    CTCG_CONF_ITEM_VAL_DEFAULT
} CTCG_CONF_ITEM_VAL_TYPE;


typedef struct ctcg_ini_table CTCG_INI_TABLE;
struct ctcg_ini_table
{
    int size;                     /* storage size */
    int n;                        /* number of entries in CTCG_INI_TABLE */
    int nsec;                     /* number of sector in CTCG_INI_TABLE */
    char **key;                   /* list of string keys */
    char **val;                   /* list of string values */
    int *lineno;                  /* list of lineno values for keys */
    unsigned int *hash;           /* list of hash values for keys */
};

typedef union ctcg_conf_value CTCG_CONF_VALUE;
union ctcg_conf_value
{
    int i;
    BOOL b;
    float f;
    char *str;
    int *integer_list;
    UINT_64 bi;
};

typedef struct ctcg_keyval CTCG_KEYVAL;
struct ctcg_keyval
{
    const char *key;
    int val;
};

static CTCG_KEYVAL ctcg_null_words[] = {
    {"null", 0},
    {"0", 0}
};

typedef int (*CTCG_CONF_DUP_FUNC) (void *, CTCG_CONF_DATATYPE, 
                                   void *, CTCG_CONF_DATATYPE);

typedef struct ctcg_conf_item CTCG_CONF_ITEM;
struct ctcg_conf_item
{
    const char *name;             /* the keyword expected */
    unsigned int static_flag;     /* bitmask flag representing status words */
    CTCG_CONF_DATATYPE datatype;  /* value data type */
    unsigned int *dynamic_flag;   /* shared by both original and duplicated */
    void *default_value;          /* address of (pointer to) default value */
    void *value;                  /* address of (pointer to) current value */
    void *upper_limit;            /* highest allowable value */
    void *lower_limit;            /* lowest allowable value */
    char *force_value;            /* address of (pointer to) force value string */
    CTCG_CONF_DUP_FUNC set_dup;   /* set duplicated value to original value */
    CTCG_CONF_DUP_FUNC get_dup;   /* get duplicated value from original value */
};


extern CTCG_CONF_ITEM conf_item_Def[CTCG_CONF_ID_LAST];

/* read file and parse */
extern int ctcg_load_conf (void);
extern int ctcg_conf_get_item_value (CTCG_CONF_ID id, 
                                     CTCG_CONF_ITEM_VAL_TYPE value_type, 
                                     void *val);


#endif /* _CTCG_CONF_H_ */
