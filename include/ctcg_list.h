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
 * ctcg_list.h : ctc general(list) header
 * 
 */

#ifndef _CTCG_LIST_H_
#define _CTCG_LIST_H_ 1


#include "ctc_types.h"


typedef struct ctcg_list CTCG_LIST;
typedef struct ctcg_list CTCG_LIST_NODE;

struct ctcg_list
{
    CTCG_LIST *prev;
    CTCG_LIST *next;
    void *obj;
};


#define CTCG_LIST_IS_EMPTY(list) \
    ((((list)->prev == (list)) && ((list)->next == (list))) ? CTC_TRUE : CTC_FALSE)

#define CTCG_LIST_INIT(list)                                    \
    do {                                                        \
        (list)->prev = (list);                                  \
        (list)->next = (list);                                  \
        (list)->obj = NULL;                                     \
    } while (0)

#define CTCG_LIST_INIT_OBJ(list, object)                        \
    do {                                                        \
        (list)->prev = (list);                                  \
        (list)->next = (list);                                  \
        (list)->obj = (object);                                 \
    } while (0)

#define CTCG_LIST_ADD_AFTER(node1, node2)                       \
    do {                                                        \
        (node1)->next->prev = (node2);                          \
        (node2)->next = (node1)->next;                          \
        (node2)->prev = (node1);                                \
        (node1)->next = (node2);                                \
    } while (0)

#define CTCG_LIST_ADD_BEFORE(node1, node2)                      \
    do {                                                        \
        (node1)->prev->next = (node2);                          \
        (node2)->prev = (node1)->prev;                          \
        (node1)->prev = (node2);                                \
        (node2)->next = (node1);                                \
    } while (0)

#define CTCG_LIST_REMOVE(node)                                  \
    do {                                                        \
        (node)->next->prev = (node)->prev;                      \
        (node)->prev->next = (node)->next;                      \
    } while (0)

#define CTCG_LIST_ADD_FIRST(head, node) CTCG_LIST_ADD_AFTER(head, node)
#define CTCG_LIST_ADD_LAST(head, node) CTCG_LIST_ADD_BEFORE(head, node)

#define CTCG_LIST_GET_PREV(node) (node)->prev
#define CTCG_LIST_GET_NEXT(node) (node)->next
#define CTCG_LIST_GET_FIRST(base) (base)->next
#define CTCG_LIST_GET_LAST(base) (base)->prev

#define CTCG_LIST_ITERATE(head, itr) \
    for ((itr) = (head)->next; (itr) != (head); (itr) = (itr)->next) 

#define CTCG_LIST_ITERATE_REVERSE(head, itr) \
    for ((itr) = (head)->prev; (itr) != (head); (itr) = (itr)->prev)

#define CTCG_LIST_ITERATE_FROM_CURRENT(head, node, itr) \
    for ((itr) = (node)->next; (itr) != (head); (itr) = (itr)->next)

#define CTCG_LIST_SPLIT_LIST(src_list, node, new_list)          \
    do {                                                        \
        if ((node) != (src_list)) {                             \
            if (CTCG_LIST_IS_EMPTY((src_list)) != CTC_TRUE) {       \
                (new_list)->prev = (src_list)->prev;            \
                (new_list)->next = (node);                      \
                (src_list)->prev = (node)->prev;                \
                (src_list)->prev->next = (src_list);            \
                (node)->prev = (new_list);                      \
                (new_list)->prev->next = (new_list);            \
            }                                                   \
        }                                                       \
    } while (0)

#define CTCG_LIST_JOIN_NODE(list, node)                         \
    do {                                                        \
        ctcg_list *temp_node;                                   \
        (list)->prev->next = (node);                            \
        (node)->prev->next = (list);                            \
        temp_node = (list)->prev;                               \
        (list)->prev = (node)->prev;                            \
        (node)->prev = temp_node;                               \
    } while (0)

#define CTCG_LIST_JOIN_LIST(list1, list2)                       \
    do {                                                        \
        if (CTCG_LIST_IS_EMPTY(list2) != CTC_TRUE) {                \
            CTCG_LIST_REMOVE(list2);                            \
            CTCG_LIST_JOIN_NODE(list1, (list2)->next);          \
            CTCG_LIST_INIT(list2);                              \
        }                                                       \
    } while (0)


#endif /* _CTCG_LIST_H_ */
