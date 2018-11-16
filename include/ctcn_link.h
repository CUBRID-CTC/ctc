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
 * ctcn_link.h : ctc network facilities
 *
 */

#ifndef _CTCN_LINK_H_
#define _CTCN_LINK_H_ 1


#include <sys/socket.h>
#include "ctc_types.h"

#define CTCN_MAX_LISTEN                 (11 * 100)  /* session cnt per sg * 100 */
#define CTCN_SOCK_INVALID_HANDLE        (-1)
#define CTCN_NONBLOCK                   (1)
#define CTCN_LINK_BUF_SIZE              (4 * 1024)
#define CTCN_HDR_LEN                    (16) /* sync with CTCP_HDR_LEN */

#define CTCN_SHUTDW_R                   (0)
#define CTCN_SHUTDW_W                   (1)
#define CTCN_SHUTDW_RW                  (2)

#define CTCN_RESULT                     (20000)
#define CTCN_RESULT_EINVAL              (CTCN_RESULT + 1)
#define CTCN_RESULT_EINTR               (CTCN_RESULT + 2)
#define CTCN_RESULT_ESRCH               (CTCN_RESULT + 3)
#define CTCN_RESULT_ENAMETOOLONG        (CTCN_RESULT + 4)
#define CTCN_RESULT_EEXIST              (CTCN_RESULT + 5)
#define CTCN_RESULT_ENOENT              (CTCN_RESULT + 6)
#define CTCN_RESULT_ENOTEMPTY           (CTCN_RESULT + 7)
#define CTCN_RESULT_ERANGE              (CTCN_RESULT + 8)
#define CTCN_RESULT_EBUSY               (CTCN_RESULT + 9)
#define CTCN_RESULT_EDEADLOCK           (CTCN_RESULT + 10)
#define CTCN_RESULT_EPERM               (CTCN_RESULT + 11)
#define CTCN_RESULT_EACCESS             (CTCN_RESULT + 12)
#define CTCN_RESULT_EAGAIN              (CTCN_RESULT + 13)
#define CTCN_RESULT_EINPROGRESS         (CTCN_RESULT + 14)
#define CTCN_RESULT_ETIMEDOUT           (CTCN_RESULT + 15)
#define CTCN_RESULT_ENOTSOCK            (CTCN_RESULT + 16)
#define CTCN_RESULT_EOF                 (CTCN_RESULT + 17)

#define CTCN_ONE_SEC                    (1000)
#define CTCN_32INT_MAX                  (0x7FFFFFFF)
#define CTCN_64INT_MAX                  (0x7FFFFFFFFFFFFFFF)

#define CTCN_RECV_TIMEOUT_MAX           CTCN_32INT_MAX

#define CTCN_TCP_NODELAY                (1)


typedef struct sockaddr_un ctc_sock_addr_un_t;
/*
struct sockaddr_un
{
    short sun_family;
    char sun_path[108];
};

struct in_addr
{
    unsigned long s_addr;
};
*/

typedef struct sockaddr_in ctc_sock_addr_in_t;
/*
struct sockaddr_in
{
    unsigned char sin_len;
    unsigned char sin_family;
    unsigned short sin_port;
    struct in_addr sin_addr;
    char sin_zero[8];
};
*/
typedef struct sockaddr ctc_sock_addr_t;
/*
struct sockaddr
{
    unsigned char sa_len;
    unsigned char sa_family;
    char sa_data[14];
};
*/
typedef struct addrinfo ctc_addr_info_t;
/*
struct addrinfo
{
    int ai_flags;       
    int ai_family;      
    int ai_socktype;    
    int ai_protocol;    
    int ai_addrlen;     
    
    struct sockaddr *ai_addr; 
    char *ai_canonname; 
    struct addrinfo *ai_next;
};
*/
typedef struct ctc_sock_t CTC_SOCK;
struct ctc_sock_t
{
    int handle;
    BOOL block_mode;
};


typedef struct ctcn_link CTCN_LINK;
struct ctcn_link
{
    CTC_SOCK sock;
    BOOL is_sock_opened;
    unsigned short session_id;
    unsigned int next_seq_no;
    unsigned int rbuf_pos;
    char rbuf[CTCN_LINK_BUF_SIZE];
    unsigned int read_data_size;
    unsigned int wbuf_pos;
    char wbuf[CTCN_LINK_BUF_SIZE];
};


/* 
 * ctc link functions 
 *
 */
extern int ctcn_link_create (CTCN_LINK **link);
extern void ctcn_link_destroy (CTCN_LINK *link);

extern int ctcn_link_set_sock_opt (CTCN_LINK *link);

extern int ctcn_link_listen (CTCN_LINK *link, 
                             unsigned short port, 
                             unsigned int timeout);

extern int ctcn_link_connect (CTCN_LINK *link, 
                              char *addr, 
                              unsigned short port, 
                              unsigned int timeout);

extern int ctcn_link_disconnect (CTCN_LINK *link, BOOL is_reuse);

extern int ctcn_link_recv (CTCN_LINK *link,
                           unsigned long timeout,
                           BOOL *is_timeout);

extern int ctcn_link_poll_socket (CTCN_LINK *link, 
                                  unsigned int timeout_msec, 
                                  BOOL *is_timeout);

extern int ctcn_link_recv_socket (CTCN_LINK *link,
                                  void *buf,
                                  int buf_size,
                                  int *recv_size);

extern int ctcn_link_send (CTCN_LINK *link);

extern int ctcn_link_read (CTCN_LINK *link, void *dest, unsigned int len);
extern int ctcn_link_read_one_byte_number (CTCN_LINK *link, void *dest);
extern int ctcn_link_read_two_byte_number (CTCN_LINK *link, void *dest);
extern int ctcn_link_read_four_byte_number (CTCN_LINK *link, void *dest);

extern int ctcn_link_write (CTCN_LINK *link, void *src, unsigned int len);
extern int ctcn_link_write_one_byte_number (CTCN_LINK *link, void *src);
extern int ctcn_link_write_two_byte_number (CTCN_LINK *link, void *src);
extern int ctcn_link_write_four_byte_number (CTCN_LINK *link, void *src);
extern int ctcn_link_forward_wbuf_pos (CTCN_LINK *link, int size);
extern int ctcn_link_backward_wbuf_pos (CTCN_LINK *link, int size);
extern void ctcn_link_move_wbuf_pos (CTCN_LINK *link, int pos);

extern int ctcn_sock_accept (CTC_SOCK *acpt_sock,
                             CTC_SOCK *lstn_sock,
                             ctc_sock_addr_t *addr,
                             int *addr_len);


#endif /* _CTCN_LINK_H_ */
