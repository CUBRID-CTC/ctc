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
 * ctcg_conf.c : ctc configuration implementation
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <float.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <assert.h>
#include <ctype.h>
#include <wctype.h>


#include "ctcg_conf.h"
#include "ctc_common.h"

/* static functions */
static int ctcg_conf_read_and_parse_ini_file (const char *file_name);
static void ctcg_ini_parser_free (CTCG_INI_TABLE *ini);
static int ctcg_conf_set_default (CTCG_CONF_ITEM *conf_item);

static int ctcg_conf_set (CTCG_CONF_ITEM *conf_item,
                          const char *value,
                          BOOL set_flag);

static int ctcg_conf_generate_new_value (CTCG_CONF_ITEM *conf_item,
                                         const char *value,
                                         CTCG_CONF_VALUE *new_value);

static int ctcg_check_range (CTCG_CONF_ITEM *conf_item, void *value);
static int ctcg_parse_int (int *ret_p, const char *str_p, int base);
static int ctcg_str_to_int32 (int *ret_p,
                              char **end_p,
                              const char *str_p,
                              int base);

static const CTCG_KEYVAL *ctcg_keyword (int val,
                                        const char *name,
                                        const CTCG_KEYVAL *tbl,
                                        int dim);

static int ctcg_intl_mbs_casecmp (const char *mbs1, const char *mbs2);

static int ctcg_conf_set_value (CTCG_CONF_ITEM *conf_item,
                                CTCG_CONF_VALUE value,
                                BOOL set_flag);

static void ctcg_conf_set_system_parameter_value (CTCG_CONF_ITEM *conf_item,
                                                  CTCG_CONF_VALUE value);
static void ctcg_set_string_value (CTCG_CONF_ID id, char *value);
static void ctcg_set_integer_value (CTCG_CONF_ID id, int value);
static CTCG_CONF_ID ctcg_conf_get_id (const CTCG_CONF_ITEM *conf_item);
static char *ctcg_envvar_confdir_file (char *path,
                                       size_t size,
                                       const char *filename);

static int ctcg_conf_item_load (CTCG_INI_TABLE *ini);
static CTCG_CONF_ITEM *ctcg_find_conf_item (const char *conf_name);
static CTCG_INI_TABLE *ctcg_ini_parser_load (const char *file_name);
static int ctcg_char_isspace (int c);
static CTCG_INI_LINE_STATUS ctcg_ini_parse_line (char *input_line,
                                                 char *section,
                                                 char *key,
                                                 char *value);
static char *ctcg_ini_str_lower (const char *str);
static int ctcg_char_tolower (int c);
static int ctcg_char_isupper (int c);
static char *ctcg_ini_str_trim (char *str);
static CTCG_INI_TABLE *ctcg_ini_table_new (int size);
static int ctcg_ini_table_set (CTCG_INI_TABLE *ini,
                               char *key,
                               char *val,
                               int lineno);

static char *ctcg_strdup (const char *str);
static void *ctcg_ini_realloc_dubble (void *memptr, int size);
static unsigned int ctcg_ini_table_hash (char *key);
static void ctcg_ini_table_free (CTCG_INI_TABLE *ini);


/* static variables */
static const char ctc_conf_file_name[] = "ctc.conf";
static const char ctc_envvar_Prefix_name[] = "CUBRID";
static const char *ctc_envvar_Prefix = NULL;
static const char *ctc_envvar_Root = NULL;

static CTCG_KEYVAL nullwords[] = {
    {"null", 0},
    {"0", 0}
};

const char *CONF_ITEM_CTC_TRAN_LOG_FILE_PATH = ""; 
static char *conf_item_ctc_tran_log_file_path_default = NULL; 
static unsigned int conf_item_ctc_tran_log_file_path_flag = 0;

int CONF_ITEM_CTC_PORT = CTCG_CONF_DEFAULT_CTC_PORT;
static int conf_item_ctc_port_default = CTCG_CONF_DEFAULT_CTC_PORT;
static unsigned int conf_item_ctc_port_flag = 0;

int CONF_ITEM_CTC_SESSION_GROUP_MAX = 10;
static int conf_item_ctc_sesson_group_max_default = 10;
static int conf_item_ctc_sesson_group_max_upper = 100;
static int conf_item_ctc_sesson_group_max_lower = 1;
static unsigned int conf_item_ctc_sesson_group_max_flag = 0;

int CONF_ITEM_CTC_JOB_QUEUE_SIZE = 1000;
static int conf_item_ctc_job_queue_size_default = 1000;
static int conf_item_ctc_job_queue_size_upper = 10000;
static int conf_item_ctc_job_queue_size_lower = 1000;
static unsigned int conf_item_ctc_job_queue_size_flag = 0;

const char *CONF_ITEM_CTC_LONG_TRAN_FILE_PATH = ""; 
static char *conf_item_ctc_long_tran_file_path_default = NULL; 
static unsigned int conf_item_ctc_long_tran_file_path_flag = 0;

int CONF_ITEM_CTC_LONG_TRAN_QUEUE_SIZE = 2000;
static int conf_item_ctc_long_tran_queue_size_default = 2000;
static int conf_item_ctc_long_tran_queue_size_upper = 100000;
static int conf_item_ctc_long_tran_queue_size_lower = 2000;
static unsigned int conf_item_ctc_long_tran_queue_size_flag = 0;


CTCG_CONF_ITEM conf_item_Def[] = {
    {CONF_NAME_CTC_TRAN_LOG_FILE_PATH,
        CTCG_CONF_FOR_SERVER,
        CTCG_CONF_STRING,
        (void *) &conf_item_ctc_tran_log_file_path_flag,
        (void *) &conf_item_ctc_tran_log_file_path_default,
        (void *) &CONF_ITEM_CTC_TRAN_LOG_FILE_PATH,
        (void *) NULL, 
        (void *) NULL,
        (char *) NULL,
        (CTCG_CONF_DUP_FUNC) NULL,
        (CTCG_CONF_DUP_FUNC) NULL},
    {CONF_NAME_CTC_PORT,
        (CTCG_CONF_FOR_SERVER | CTCG_CONF_FOR_CLIENT),
        CTCG_CONF_INTEGER,
        (void *) &conf_item_ctc_port_flag,
        (void *) &conf_item_ctc_port_default,
        (void *) &CONF_ITEM_CTC_PORT,
        (void *) NULL, 
        (void *) NULL,
        (char *) NULL,
        (CTCG_CONF_DUP_FUNC) NULL,
        (CTCG_CONF_DUP_FUNC) NULL},
    {CONF_NAME_CTC_SESSION_GROUP_MAX,
        CTCG_CONF_FOR_SERVER,
        CTCG_CONF_INTEGER,
        (void *) &conf_item_ctc_sesson_group_max_flag,
        (void *) &conf_item_ctc_sesson_group_max_default,
        (void *) &CONF_ITEM_CTC_SESSION_GROUP_MAX,
        (void *) &conf_item_ctc_sesson_group_max_upper, 
        (void *) &conf_item_ctc_sesson_group_max_lower,
        (char *) NULL,
        (CTCG_CONF_DUP_FUNC) NULL,
        (CTCG_CONF_DUP_FUNC) NULL},
    {CONF_NAME_CTC_JOB_QUEUE_SIZE,
        CTCG_CONF_FOR_SERVER,
        CTCG_CONF_INTEGER,
        (void *) &conf_item_ctc_job_queue_size_flag,
        (void *) &conf_item_ctc_job_queue_size_default,
        (void *) &CONF_ITEM_CTC_JOB_QUEUE_SIZE,
        (void *) &conf_item_ctc_job_queue_size_upper, 
        (void *) &conf_item_ctc_job_queue_size_lower,
        (char *) NULL,
        (CTCG_CONF_DUP_FUNC) NULL,
        (CTCG_CONF_DUP_FUNC) NULL},
    {CONF_NAME_CTC_LONG_TRAN_FILE_PATH,
        CTCG_CONF_FOR_SERVER,
        CTCG_CONF_STRING,
        (void *) &conf_item_ctc_long_tran_file_path_flag,
        (void *) &conf_item_ctc_long_tran_file_path_default,
        (void *) &CONF_ITEM_CTC_LONG_TRAN_FILE_PATH,
        (void *) NULL, 
        (void *) NULL,
        (char *) NULL,
        (CTCG_CONF_DUP_FUNC) NULL,
        (CTCG_CONF_DUP_FUNC) NULL},
    {CONF_NAME_CTC_LONG_TRAN_QUEUE_SIZE,
        CTCG_CONF_FOR_SERVER,
        CTCG_CONF_INTEGER,
        (void *) &conf_item_ctc_long_tran_queue_size_flag,
        (void *) &conf_item_ctc_long_tran_queue_size_default,
        (void *) &CONF_ITEM_CTC_LONG_TRAN_QUEUE_SIZE,
        (void *) &conf_item_ctc_long_tran_queue_size_upper, 
        (void *) &conf_item_ctc_long_tran_queue_size_lower,
        (char *) NULL,
        (CTCG_CONF_DUP_FUNC) NULL,
        (CTCG_CONF_DUP_FUNC) NULL}
};


/* functions */
extern int ctcg_load_conf (void)
{
    int i;
    char *s;
    char file_being_dealt_with[CTCG_PATH_MAX];
    int result;

    ctcg_envvar_confdir_file (file_being_dealt_with, 
                              CTCG_PATH_MAX, 
                              ctc_conf_file_name);
 
    result = ctcg_conf_read_and_parse_ini_file (file_being_dealt_with);
    CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                        err_read_and_parse_ini_failed_label);

    for (i = 0; i < CTCG_CONF_ID_LAST; i++)
    {
        if (!CONF_IS_SET (*conf_item_Def[i].dynamic_flag))
        {
            CTC_TEST_EXCEPTION (ctcg_conf_set_default (&conf_item_Def[i]),
                                err_conf_set_default_failed_label);
        }
    }

    /*
     * Perform forced system parameter setting.
     */
    for (i = 0; i < CTCG_CONF_ID_LAST; i++)
    {
        if (conf_item_Def[i].force_value)
        {
            ctcg_conf_set (&conf_item_Def[i], 
                           conf_item_Def[i].force_value, 
                           CTC_FALSE);
        }
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_read_and_parse_ini_failed_label)
    {
        /* ERROR: parse */
    }
    CTC_EXCEPTION (err_conf_set_default_failed_label)
    {
        fprintf (stderr,
                 "set default value to configuration item [%s]\n",
                 conf_item_Def[i].name);
    }
    EXCEPTION_END;

    return CTC_FAILURE;
}


static int ctcg_conf_set (CTCG_CONF_ITEM *conf_item, 
                          const char *value, 
                          BOOL set_flag)
{
    int result;
    CTCG_CONF_VALUE new_value;

    result = ctcg_conf_generate_new_value (conf_item, value, &new_value);
    CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                        err_generate_new_value_failed_label);

    return ctcg_conf_set_value (conf_item, new_value, set_flag);

    CTC_EXCEPTION (err_generate_new_value_failed_label)
    {
        /* error info set from sub-function */
    }
    EXCEPTION_END;

    return result;
}


static int ctcg_conf_generate_new_value (CTCG_CONF_ITEM *conf_item, 
                                         const char *value, 
                                         CTCG_CONF_VALUE *new_value)
{
    int result;
    int int_val;
    char *str_val = NULL;

    CTC_COND_EXCEPTION (conf_item == NULL, err_null_conf_item_label);
    CTC_COND_EXCEPTION (value == NULL, err_null_val_label);
    
    assert (new_value != NULL);

    switch (conf_item->datatype)
    {
        case CTCG_CONF_INTEGER:

            result = ctcg_parse_int (&int_val, value, 10);
            CTC_COND_EXCEPTION (result != CTC_SUCCESS, 
                                err_parse_int_failed_label);

            CTC_TEST_EXCEPTION (ctcg_check_range (conf_item, 
                                                  (void *)&int_val),
                                err_check_range_label);

            new_value->i = int_val;
            break;

        case CTCG_CONF_STRING:

            if (ctcg_keyword (-1, value, nullwords, 2) != NULL)
            {
                str_val = NULL;
            }
            else
            {
                str_val = ctcg_strdup (value);
                CTC_COND_EXCEPTION (str_val == NULL, 
                                    err_alloc_failed_label);
            }

            new_value->str = str_val;

            break;

        case CTCG_CONF_NO_TYPE:
            break;

        default:
            break;
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_conf_item_label)
    {
        result = CTCG_CONF_ERR_UNKNOWN;
    }
    CTC_EXCEPTION (err_null_val_label)
    {
        result = CTCG_CONF_ERR_BAD_VALUE;
    }
    CTC_EXCEPTION (err_parse_int_failed_label)
    {
        result = CTCG_CONF_ERR_BAD_VALUE;
    }
    CTC_EXCEPTION (err_check_range_label)
    {
        result = CTCG_CONF_ERR_BAD_VALUE;
    }
    CTC_EXCEPTION (err_alloc_failed_label)
    {
        result = CTCG_CONF_ERR_STR_DUP;
    }
    EXCEPTION_END;

    return result;
}


static int ctcg_check_range (CTCG_CONF_ITEM *conf_item, void *value)
{
    int val;

    if (CONF_IS_INTEGER (conf_item))
    {
        val = *((int *) value);

        if ((conf_item->upper_limit && CONF_GET_INT (conf_item->upper_limit) < val) || 
            (conf_item->lower_limit && CONF_GET_INT (conf_item->lower_limit) > val))
        {
            return CTCG_CONF_ERR_CHK_RANGE;
        }
    }
    else
    {
        return CTCG_CONF_ERR_BAD_VALUE;
    }

    return CTC_SUCCESS;
}


static int ctcg_parse_int (int *ret_p, const char *str_p, int base)
{
    int error = 0;
    int val;
    char *end_p;

    assert (ret_p != NULL);
    assert (str_p != NULL);

    *ret_p = 0;

    error = ctcg_str_to_int32 (&val, &end_p, str_p, base);

    if (error < 0)
    {
        return -1;
    }

    if (*end_p != '\0')
    {
        return -1;
    }

    *ret_p = val;

    return 0;
}


static int ctcg_str_to_int32 (int *ret_p, 
                              char **end_p, 
                              const char *str_p, 
                              int base)
{
    long val = 0;

    assert (ret_p != NULL);
    assert (end_p != NULL);
    assert (str_p != NULL);

    *ret_p = 0;
    *end_p = NULL;

    errno = 0;

    val = strtol (str_p, end_p, base);

    if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) || 
        (errno != 0 && val == 0))
    {
        return -1;
    }

    if (*end_p == str_p)
    {
        return -1;
    }

    if (val < INT_MIN || val > INT_MAX)
    {
        return -1;
    }

    *ret_p = (int) val;

    return 0;
}


static const CTCG_KEYVAL *ctcg_keyword (int val, 
                                        const char *name, 
                                        const CTCG_KEYVAL *tbl, 
                                        int dim)
{
    int i;

    if (name != NULL)
    {
        for (i = 0; i < dim; i++)
        {
            if (ctcg_intl_mbs_casecmp (name, tbl[i].key) == 0)
            {
                return &tbl[i];
            }
        }
    }
    else
    {
        for (i = 0; i < dim; i++)
        {
            if (tbl[i].val == val)
            {
                return &tbl[i];
            }
        }
    }

    return NULL;
}


static int ctcg_intl_mbs_casecmp (const char *mbs1, const char *mbs2)
{
    wchar_t wc1, wc2;
    int mb1_len, mb2_len;

    assert (mbs1 != NULL && mbs2 != NULL);

    for (mb1_len = mbtowc (&wc1, mbs1, MB_LEN_MAX),
         mb2_len = mbtowc (&wc2, mbs2, MB_LEN_MAX);
         mb1_len > 0 && mb2_len > 0 && wc1 && wc2
         && !(towlower (wc1) - towlower (wc2));)
    {
        mbs1 += mb1_len;
        mbs2 += mb2_len;

        mb1_len = mbtowc (&wc1, mbs1, MB_LEN_MAX);
        mb2_len = mbtowc (&wc2, mbs2, MB_LEN_MAX);
    }

    if (mb1_len < 0 || mb2_len < 0)
    {
        errno = EINVAL;
    }

    return (int)(towlower (wc1) - towlower (wc2));
}


static int ctcg_conf_set_value (CTCG_CONF_ITEM *conf_item, 
                                CTCG_CONF_VALUE value, 
                                BOOL set_flag)
{
    int result;

    CTC_COND_EXCEPTION (conf_item == NULL, err_null_item_label);

    ctcg_conf_set_system_parameter_value (conf_item, value);

    if (set_flag)
    {
        CONF_SET_BIT (CONF_SET, *conf_item->dynamic_flag);
        CONF_CLEAR_BIT (CONF_DEFAULT_USED, *conf_item->dynamic_flag);
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_item_label)
    {
        result = CTCG_CONF_ERR_UNKNOWN;
    }
    EXCEPTION_END;

    return result;
}


static void ctcg_conf_set_system_parameter_value (CTCG_CONF_ITEM *conf_item, 
                                                  CTCG_CONF_VALUE value)
{
    CTCG_CONF_ID id = ctcg_conf_get_id (conf_item);

    switch (conf_item->datatype)
    {
        case CTCG_CONF_INTEGER:
            ctcg_set_integer_value (id, value.i);
            break;

        case CTCG_CONF_STRING:
            ctcg_set_string_value (id, value.str);
            break;

        case CTCG_CONF_NO_TYPE:
            break;
    }

    return;
}


static void ctcg_set_string_value (CTCG_CONF_ID id, char *value)
{
    char *str;

    assert (id <= CTCG_CONF_ID_LAST);
    assert (CONF_IS_STRING (&conf_item_Def[id]));

    if (CONF_IS_ALLOCATED (*conf_item_Def[id].dynamic_flag))
    {
        str = CONF_GET_STRING (conf_item_Def[id].value);

        if (str != NULL)
        {
            free (str);
            str = NULL;
        }

        CONF_CLEAR_BIT (CONF_ALLOCATED, *conf_item_Def[id].dynamic_flag);
    }

    CONF_GET_STRING (conf_item_Def[id].value) = value;

    if (CONF_GET_STRING (conf_item_Def[id].value) != NULL)
    {
        CONF_SET_BIT (CONF_ALLOCATED, *conf_item_Def[id].dynamic_flag);
    }

    return;
}


static void ctcg_set_integer_value (CTCG_CONF_ID id, int value)
{
    assert (id <= CTCG_CONF_ID_LAST);
    assert (CONF_IS_INTEGER (&conf_item_Def[id]));

    CONF_GET_INT (conf_item_Def[id].value) = value;

    return;
}


static CTCG_CONF_ID ctcg_conf_get_id (const CTCG_CONF_ITEM *conf_item)
{
    int id = (conf_item - conf_item_Def);

    assert (id >= 0 && id <= CTCG_CONF_ID_LAST);

    return (CTCG_CONF_ID)id;
}


static int ctcg_conf_set_default (CTCG_CONF_ITEM *conf_item)
{
    int int_val;
    int *int_val_ptr;
    char *str;
    char *str_val;
    char **str_val_ptr;

    CTC_COND_EXCEPTION (conf_item == NULL, err_null_item_label);

    if (CONF_IS_INTEGER (conf_item)) 
    {
        int_val = CONF_GET_INT (conf_item->default_value);
        int_val_ptr = (int *)conf_item->value;
        *int_val_ptr = int_val;
    }
    else if (CONF_IS_STRING (conf_item))
    {
        if (CONF_IS_ALLOCATED (*conf_item->dynamic_flag))
        {
            str = CONF_GET_STRING (conf_item->value);

            if (str)
            {
                free (str);
                str = NULL;
            }

            CONF_CLEAR_BIT (CONF_ALLOCATED, *conf_item->dynamic_flag);
        }

        str_val = *(char **)conf_item->default_value;
        str_val_ptr = (char **)conf_item->value;
        *str_val_ptr = str_val;
    }

    CONF_SET_BIT (CONF_DEFAULT_USED, *conf_item->dynamic_flag);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_item_label)
    EXCEPTION_END;

    return CTC_FAILURE;
}


static char *ctcg_envvar_confdir_file (char *path, 
                                       size_t size, 
                                       const char *filename)
{
    assert (filename != NULL);
  
    ctc_envvar_Root = getenv (ctc_envvar_Prefix_name);

    if (ctc_envvar_Root)
    {
        ctc_envvar_Prefix = ctc_envvar_Prefix_name;
    }

    snprintf (path, size, "%s/conf/%s", ctc_envvar_Root, filename);

    path[size - 1] = '\0';

    return path;
}


static int ctcg_conf_read_and_parse_ini_file (const char *file_name)
{
    int result;
    CTCG_INI_TABLE *ini = NULL;

    ini = ctcg_ini_parser_load (file_name);

    CTC_COND_EXCEPTION (ini == NULL, err_ini_parser_load_failed_label);

    result = ctcg_conf_item_load (ini);

    ctcg_ini_parser_free (ini);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_ini_parser_load_failed_label)
    {
        fprintf (stderr, "ERROR (msg for debug): load parser"); 
        result = CTC_FAILURE;
    }
    EXCEPTION_END;

    return result;
}


static int ctcg_conf_item_load (CTCG_INI_TABLE *ini)
{
    int i; 
    int result;
    const char *key;
    const char *value;
    CTCG_CONF_ITEM *conf_item;

    for (i = 0; i < ini->size; i++)
    {
        if (ini->key[i] == NULL || ini->val[i] == NULL)
        {
            continue;
        }

        key = ini->key[i];
        value = ini->val[i];

        conf_item = ctcg_find_conf_item (key);
        CTC_COND_EXCEPTION (conf_item == NULL, err_invalid_item_label);

        result = ctcg_conf_set (conf_item, value, CTC_TRUE);
        CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_set_failed_label);
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_invalid_item_label)
    {
        result = CTCG_CONF_ERR_UNKNOWN;
    }
    CTC_EXCEPTION (err_set_failed_label)
    {
        /* error info set from sub-function */
    }
    EXCEPTION_END;

    return result;
}


static CTCG_CONF_ITEM *ctcg_find_conf_item (const char *conf_name) 
{
    int i;
    char *key;

    if (conf_name != NULL)
    {
        key = (char *)conf_name;

        for (i = 0; i < CTCG_CONF_ID_LAST; i++)
        {
            if (ctcg_intl_mbs_casecmp (conf_item_Def[i].name, key) == 0)
            {
                return &conf_item_Def[i];
            }
        }
    }
    else
    {
        /* nothing to do */
    }

    return NULL;
}


static CTCG_INI_TABLE *ctcg_ini_parser_load (const char *file_name)
{
    FILE *conf_fd;
    int last = 0;
    int len;
    int line_number = 0;
    int errs = 0;
    char line[CTCG_INI_BUF_SIZE + 1];
    char section[CTCG_INI_BUF_SIZE + 1];
    char key[CTCG_INI_BUF_SIZE + 1];
    char tmp[CTCG_INI_BUF_SIZE + 1];
    char val[CTCG_INI_BUF_SIZE + 1];
    CTCG_INI_TABLE *ini;

    conf_fd = fopen (file_name, "r");
    CTC_COND_EXCEPTION (conf_fd == NULL, err_open_file_failed_label);

    ini = ctcg_ini_table_new (0);
    CTC_COND_EXCEPTION (ini == NULL, err_ini_table_new_label);

    memset (line, 0, CTCG_INI_BUF_SIZE);
    memset (section, 0, CTCG_INI_BUF_SIZE);
    memset (key, 0, CTCG_INI_BUF_SIZE);
    memset (val, 0, CTCG_INI_BUF_SIZE);

    while (fgets (line + last, CTCG_INI_BUF_SIZE - last, conf_fd) != NULL)
    {
        line_number++;
        len = (int)strlen (line) - 1;

        CTC_COND_EXCEPTION (line[len] != '\n' && 
                            len >= CTCG_INI_BUF_SIZE - 2,
                            err_buf_overflow_label);

        while ((len > 0) && 
               ((line[len] == '\n') || ctcg_char_isspace (line[len])))
        {
            line[len] = 0;
            len--;
        }

        if (line[len] == '\\')
        {
            last = len;
            continue;
        }
        else
        {
            last = 0;
        }

        switch (ctcg_ini_parse_line (line, section, key, val))
        {
            case CTCG_LINE_EMPTY:
            case CTCG_LINE_COMMENT:
                break;

            case CTCG_LINE_SECTION:
                errs = ctcg_ini_table_set (ini, section, NULL, line_number);
                break;

            case CTCG_LINE_VALUE:
                sprintf (tmp, "%s", key);
                errs = ctcg_ini_table_set (ini, tmp, val, line_number);
                break;

            case CTCG_LINE_ERROR:
                errs++;
                break;

            default:
                break;
        }

        memset (line, 0, CTCG_INI_BUF_SIZE);
        last = 0;

        if (errs < 0)
        {
            fprintf (stderr, "ctcg_ini_parser: memory alloc failed\n");
            break;
        }
        else
        {
            /* just counting errs */
        }
    }

    CTC_COND_EXCEPTION (errs != 0, err_error_occurred_label);

    fclose (conf_fd);

    return ini;

    CTC_EXCEPTION (err_open_file_failed_label)
    {
        fprintf (stderr, "ctcg_ini_parser: cannot open %s\n", 
                 file_name);
    }
    CTC_EXCEPTION (err_ini_table_new_label)
    {
        fclose (conf_fd);
    }
    CTC_EXCEPTION (err_buf_overflow_label)
    {
        fprintf (stderr, "ctcg_ini_parser: input line too long in %s (%d)\n",
                 file_name, line_number);

        ctcg_ini_table_free (ini);
        fclose (conf_fd);
    }
    CTC_EXCEPTION (err_error_occurred_label)
    {
        ctcg_ini_table_free (ini);
        fclose (conf_fd);
    }
    EXCEPTION_END;

    return NULL;
}


static int ctcg_char_isspace (int c)
{
    return ((c) == ' '  || 
            (c) == '\t' || 
            (c) == '\r' || 
            (c) == '\n' || 
            (c) == '\f' || 
            (c) == '\v');
}


static CTCG_INI_LINE_STATUS ctcg_ini_parse_line (char *input_line, 
                                                 char *section,
                                                 char *key, 
                                                 char *value)
{
    CTCG_INI_LINE_STATUS status;
    char line[CTCG_INI_BUF_SIZE + 1];
    int len;

    strcpy (line, ctcg_ini_str_trim (input_line));
    len = (int)strlen (line);

    status = CTCG_LINE_UNPROCESSED;

    if (len < 1)
    {
        status = CTCG_LINE_EMPTY;
    }
    else if (line[0] == '#')
    {
        status = CTCG_LINE_COMMENT;
    }
    else if (line[0] == '[' && line[len - 1] == ']')
    {
        char leading_char;

        sscanf (line, "[%[^]]", section);
        strcpy (section, ctcg_ini_str_trim (section));
        leading_char = section[0];

        if (leading_char == '@' || leading_char == '%')
        {
            sprintf (section, "%c%s", leading_char, ctcg_ini_str_trim (section + 1));
        }

        strcpy (section, ctcg_ini_str_lower (section));
        status = CTCG_LINE_SECTION;
    }
    else if (sscanf (line, "%[^=] = \"%[^\"]\"", key, value) == 2 || 
             sscanf (line, "%[^=] = '%[^\']'", key, value) == 2   || 
             sscanf (line, "%[^=] = %[^;#]", key, value) == 2)
    {
        strcpy (key, ctcg_ini_str_trim (key));
        strcpy (key, ctcg_ini_str_lower (key));
        strcpy (value, ctcg_ini_str_trim (value));

        if (!strcmp (value, "\"\"") || (!strcmp (value, "''")))
        {
            value[0] = 0;
        }
        else
        {
            /* nothing to do */
        }

        status = CTCG_LINE_VALUE;
    }
    else if (sscanf (line, "%[^=] = %[;#]", key, value) == 2 || 
             sscanf (line, "%[^=] %[=]", key, value) == 2)
    {
        /*
         * Special cases:
         * key=
         * key=;
         * key=#
         */
        strcpy (key, ctcg_ini_str_trim (key));
        strcpy (key, ctcg_ini_str_lower (key));
        value[0] = 0;
        status = CTCG_LINE_VALUE;
    }
    else
    {
        /* Generate syntax error */
        status = CTCG_LINE_ERROR;
    }

    return status;
}


static char *ctcg_ini_str_lower (const char *str)
{
    int i = 0;
    static char result[CTCG_INI_BUF_SIZE + 1];

    if (str == NULL)
    {
        return NULL;
    }

    memset (result, 0, CTCG_INI_BUF_SIZE + 1);

    while (str[i] && i < CTCG_INI_BUF_SIZE)
    {
        result[i] = (char)ctcg_char_tolower ((int) str[i]);
        i++;
    }

    result[CTCG_INI_BUF_SIZE] = '\0';

    return result;
}


static int ctcg_char_tolower (int c)
{
    return (ctcg_char_isupper ((c)) ? ((c) - ('A' - 'a')) : (c));
}


static int ctcg_char_isupper (int c)
{
    return ((c) >= 'A' && (c) <= 'Z');
}


static char *ctcg_ini_str_trim (char *str)
{
    char *last;
    static char trim_str[CTCG_INI_BUF_SIZE + 1];

    if (str == NULL)
    {
        return NULL;
    }

    while (ctcg_char_isspace ((int)*str) && *str)
    {
        str++;
    }

    memset (trim_str, 0, CTCG_INI_BUF_SIZE + 1);
    strcpy (trim_str, str);
    last = trim_str + strlen (trim_str);

    while (last > trim_str)
    {
        if (!ctcg_char_isspace ((int)*(last - 1)))
        {
            break;
        }

        last--;
    }

    *last = '\0';

    return trim_str;
}


static CTCG_INI_TABLE *ctcg_ini_table_new (int size)
{
    CTCG_INI_TABLE *ini;

    /* If no size was specified, allocate space for 128 */
    if (size < 128)
    {
        size = 128;
    }

    ini = (CTCG_INI_TABLE *) calloc (1, sizeof (CTCG_INI_TABLE));

    if (ini == NULL)
    {
        return NULL;
    }

    ini->size = size;

    ini->val = (char **) calloc (size, sizeof (char *));

    if (ini->val == NULL)
    {
        goto error;
    }

    ini->key = (char **) calloc (size, sizeof (char *));

    if (ini->key == NULL)
    {
        goto error;
    }

    ini->lineno = (int *) calloc (size, sizeof (int));

    if (ini->lineno == NULL)
    {
        goto error;
    }

    ini->hash = (unsigned int *) calloc (size, sizeof (unsigned int));

    if (ini->hash == NULL)
    {
        goto error;
    }

    return ini;

error:
    if (ini->hash != NULL)
    {
        free (ini->hash);
    }
    if (ini->lineno != NULL)
    {
        free (ini->lineno);
    }
    if (ini->key != NULL)
    {
        free (ini->key);
    }
    if (ini->val != NULL)
    {
        free (ini->val);
    }
    if (ini != NULL)
    {
        free (ini);
    }

    return NULL;
}


static int ctcg_ini_table_set (CTCG_INI_TABLE *ini, 
                               char *key, 
                               char *val, 
                               int lineno)
{
    int i;
    int stage = 0;
    unsigned int hash;

    CTC_COND_EXCEPTION (ini == NULL, err_null_ini_table_label);
    CTC_COND_EXCEPTION (key == NULL, err_null_key_label);

    /* Compute hash for this key */
    hash = ctcg_ini_table_hash (key);

    /* check already exist value in CTCG_INI_TABLE */
    if (ini->n > 0)
    {
        for (i = 0; i < ini->size; i++)
        {
            if (ini->key[i] != NULL)
            {
                if (hash == ini->hash[i])
                {	
                    if (strcmp (key, ini->key[i]) == 0)
                    {		
                        if (ini->val[i] != NULL)
                        {
                            free (ini->val[i]);
                        }
                        else
                        {
                            /* value is not exist */
                        }

                        ini->val[i] = val ? ctcg_strdup (val) : NULL;

                        return CTC_SUCCESS;
                    }
                    else
                    {
                        /* different key */
                    }
                }
                else
                {
                    /* different hash value */
                }
            }
            else
            {
                continue;
            }
        }
    }

    /* add new value */
    if (ini->n == ini->size)
    {
        ini->val = (char **)ctcg_ini_realloc_dubble (ini->val, 
                                                     ini->size * sizeof (char *));
        CTC_COND_EXCEPTION (ini->val == NULL, err_alloc_failed_label);
        stage = 1;

        ini->key = (char **)ctcg_ini_realloc_dubble (ini->key, 
                                                     ini->size * sizeof (char *));
        CTC_COND_EXCEPTION (ini->key == NULL, err_alloc_failed_label);
        stage = 2;

        ini->lineno = (int *)ctcg_ini_realloc_dubble (ini->lineno, 
                                                      ini->size * sizeof (int));
        CTC_COND_EXCEPTION (ini->lineno == NULL, err_alloc_failed_label);
        stage = 3;

        ini->hash = (unsigned int *)ctcg_ini_realloc_dubble (ini->hash, 
                                                             ini->size * sizeof (unsigned int));
        CTC_COND_EXCEPTION (ini->hash == NULL, err_alloc_failed_label);
        stage = 4;

        ini->size *= 2;
    }

    for (i = 0; i < ini->size; i++)
    {
        if (ini->key[i] == NULL)
        {
            /* Add key here */
            break;
        }
        else
        {
            /* nothing to do */
        }
    }

    ini->n++;
    ini->lineno[i] = lineno;
    ini->hash[i] = hash;
    ini->key[i] = ctcg_strdup (key);

    if (val == NULL)
    {
        ini->nsec++;		/* section */
        ini->val[i] = NULL;
    }
    else
    {
        ini->val[i] = ctcg_strdup (val);
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_null_ini_table_label)
    {
    }
    CTC_EXCEPTION (err_null_key_label)
    {
    }
    CTC_EXCEPTION (err_alloc_failed_label)
    {
    }
    EXCEPTION_END;

    switch (stage)
    {
        case 4:
            free (ini->hash);
        case 3:
            free (ini->lineno);
        case 2:
            free (ini->key);
        case 1:
            free (ini->val);
            break;
        default:
            break;
    }

    return CTC_FAILURE;
}


static char *ctcg_strdup (const char *str)
{
    int str_len;
    char *dup_str = NULL;

    if (str != NULL)
    {
        str_len = strlen (str) + 1;
        dup_str = (char *)malloc (str_len);

        if (dup_str != NULL)
        {
            memcpy (dup_str, str, str_len);
        }
        else
        {
            /* alloc failed but ignore */
        }
    }
    else
    {
        /* do nothing */
    }

    return dup_str;
}


static void *ctcg_ini_realloc_dubble (void *memptr, int size)
{
    void *alloc_memptr = NULL;

    alloc_memptr = calloc (2 * size, 1);

    if (alloc_memptr != NULL)
    {
        memcpy (alloc_memptr, memptr, size);
        free (memptr);
    }
    else
    {
        /* calloc failed but process error in caller */
    }

    return alloc_memptr;
}


static unsigned int ctcg_ini_table_hash (char *key)
{
    int len, i;
    unsigned int hash;

    len = strlen (key);

    for (hash = 0, i = 0; i < len; i++)
    {
        hash += (unsigned) key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }

    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);

    return hash;
}


static void ctcg_ini_table_free (CTCG_INI_TABLE *ini)
{
    int i;

    if (ini != NULL)
    {
        for (i = 0; i < ini->size; i++)
        {
            if (ini->key[i] != NULL)
            {
                free (ini->key[i]);
            }

            if (ini->val[i] != NULL)
            {
                free (ini->val[i]);
            }
        }

        free (ini->val);
        ini->val = NULL;

        free (ini->key);
        ini->key = NULL;

        free (ini->lineno);
        ini->lineno = NULL;

        free (ini->hash);
        ini->hash = NULL;

        free (ini);
        ini = NULL;
    }
    else
    {
        /* nothing to do */
    }

    return;
}


static void ctcg_ini_parser_free (CTCG_INI_TABLE *ini)
{
    ctcg_ini_table_free (ini);
}


extern int ctcg_conf_get_item_value (CTCG_CONF_ID id, 
                                     CTCG_CONF_ITEM_VAL_TYPE value_type, 
                                     void *val)
{
    int result;
    int str_len;
    CTCG_CONF_ITEM *item = NULL;

    assert (val != NULL);

    /* id validation */
    CTC_COND_EXCEPTION (id >= CTCG_CONF_ID_LAST, err_invalid_conf_id_label);

    CTC_COND_EXCEPTION (value_type > CTCG_CONF_ITEM_VAL_DEFAULT,
                        err_invalid_value_type_label);

    /* get item */
    item = &conf_item_Def[id];

    switch (id)
    {
        case CTCG_CONF_ID_CTC_TRAN_LOG_FILE_PATH:
        case CTCG_CONF_ID_CTC_LONG_TRAN_FILE_PATH:

            CTC_COND_EXCEPTION (value_type != CTCG_CONF_ITEM_VAL_SET_STR && 
                                value_type != CTCG_CONF_ITEM_VAL_STR,
                                err_invalid_value_type_label);

            if (value_type == CTCG_CONF_ITEM_VAL_SET_STR)
            {
                val = CONF_GET_STRING (item->value);
            }
            else
            {
                val = CONF_GET_STRING (item->default_value);
            }

            break;

        case CTCG_CONF_ID_CTC_PORT:

            CTC_COND_EXCEPTION (value_type != CTCG_CONF_ITEM_VAL_SET_INT && 
                                value_type != CTCG_CONF_ITEM_VAL_DEFAULT,
                                err_invalid_value_type_label);

            if (value_type == CTCG_CONF_ITEM_VAL_SET_INT)
            {
                *(int *)val = CONF_GET_INT (item->value);
            }
            else
            {
                *(int *)val = CONF_GET_INT (item->default_value);
            }

            break;

        case CTCG_CONF_ID_CTC_SESSION_GROUP_MAX:
        case CTCG_CONF_ID_CTC_JOB_QUEUE_SIZE:
        case CTCG_CONF_ID_CTC_LONG_TRAN_QUEUE_SIZE:

            CTC_COND_EXCEPTION (value_type == CTCG_CONF_ITEM_VAL_SET_STR || 
                                value_type == CTCG_CONF_ITEM_VAL_STR,
                                err_invalid_value_type_label);

            if (value_type == CTCG_CONF_ITEM_VAL_SET_INT)
            {
                *(int *)val = CONF_GET_INT (item->value);
            }
            else if (value_type == CTCG_CONF_ITEM_VAL_MIN)
            {
                *(int *)val = CONF_GET_INT (item->lower_limit);
            }
            else if (value_type == CTCG_CONF_ITEM_VAL_MAX)
            {
                *(int *)val = CONF_GET_INT (item->upper_limit);
            }
            else 
            {
                *(int *)val = CONF_GET_INT (item->default_value);
            }

            break;

        default:
            break;
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_invalid_conf_id_label)
    {
        result = CTCG_CONF_ERR_UNKNOWN;
    }
    CTC_EXCEPTION (err_invalid_value_type_label)
    {
        result = CTCG_CONF_ERR_UNKNOWN;
    }
    EXCEPTION_END;

    return result;
}


