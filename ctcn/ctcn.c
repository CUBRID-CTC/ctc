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
 * ctcn.c : ctc network functions implementation
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>

#include "ctcp.h"
#include "ctc_common.h"
#include "ctcn_link.h"
#include "ctc_types.h"


static int ctcn_create_new_sock (CTC_SOCK **sock);
extern int ctcn_sock_open (CTC_SOCK *sock, int family, int type, int prcl);
extern int ctcn_sock_close (CTC_SOCK *sock);
extern int ctcn_sock_shutdown (CTC_SOCK *sock, int how);

extern int ctcn_sock_set_block_mode (CTC_SOCK *sock, BOOL block_mode);
extern BOOL ctcn_sock_get_block_mode (CTC_SOCK *sock);

extern int ctcn_sock_get_opt (CTC_SOCK *sock, 
                              int level, 
                              int opt_name, 
                              void *opt_val, 
                              int *opt_len);

extern int ctcn_sock_set_opt (CTC_SOCK *sock, 
                              int level, 
                              int opt_name, 
                              const void *opt_val, 
                              int opt_len); 

extern int ctcn_sock_bind (CTC_SOCK *sock, 
                           const ctc_sock_addr_t *addr, 
                           int addr_len, 
                           BOOL is_reuse);

extern int ctcn_sock_connect (CTC_SOCK *sock, 
                              ctc_sock_addr_t *addr, 
                              int addr_len); 

extern int ctcn_sock_listen (CTC_SOCK *sock, int backlog);

extern int ctcn_sock_poll (CTC_SOCK *sock, int event, int timeout);

extern int ctcn_sock_get_name (CTC_SOCK *sock, 
                               ctc_sock_addr_t *name, 
                               int *name_len);

extern int ctcn_sock_get_peer_name (CTC_SOCK *sock, 
                                    ctc_sock_addr_t *name, 
                                    int *name_len);

static int ctcn_sock_recv (CTC_SOCK *sock, 
                           void *buf, 
                           int buf_size, 
                           int *recv_size, 
                           int flag);

static int ctcn_sock_send (CTC_SOCK *sock, 
                           void *buf, 
                           int buf_size, 
                           int *recv_size, 
                           int flag);

static void ctcn_assign_number_two (unsigned char *src, unsigned char *dest);
static void ctcn_assign_number_four (unsigned char *src, unsigned char *dest);



static int ctcn_create_new_sock (CTC_SOCK **sock)
{
    *sock = (CTC_SOCK *)malloc (sizeof (CTC_SOCK));
    CTC_COND_EXCEPTION (*sock == NULL, err_sock_alloc_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_sock_alloc_label)
    EXCEPTION_END;

    return CTC_FAILURE;
}


extern int ctcn_sock_open (CTC_SOCK *sock, int family, int type, int prcl)
{
    sock->handle = socket (family, type, prcl);

    if (sock->handle < 0)
    {
        return CTC_FAILURE;
    }
    else
    {
        sock->block_mode = CTC_TRUE;

        return CTC_SUCCESS;
    }
}

extern int ctcn_sock_close (CTC_SOCK *sock)
{
    CTC_TEST_EXCEPTION (close (sock->handle), err_sock_close_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_sock_close_label)
    EXCEPTION_END;

    return CTC_FAILURE;
}


extern int ctcn_sock_shutdown (CTC_SOCK *sock, int how)
{
    CTC_TEST_EXCEPTION (shutdown (sock->handle, how), err_sock_shutdown_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_sock_shutdown_label)
    EXCEPTION_END;

    return CTC_FAILURE;
}


extern int ctcn_sock_set_block_mode (CTC_SOCK *sock, BOOL block_mode)
{
    int result;

    result = fcntl (sock->handle, 0, 0);
    CTC_COND_EXCEPTION (result != CTC_SUCCESS, err_fcntl_label);

    if (block_mode == CTC_TRUE)
    {
        result &= ~CTCN_NONBLOCK;
    }
    else
    {
        result |= CTCN_NONBLOCK;
    }

    CTC_TEST_EXCEPTION (fcntl (sock->handle, 1, result), err_fcntl_label);

    sock->block_mode = block_mode;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_fcntl_label)
    EXCEPTION_END;

    return CTC_FAILURE;
}

extern int ctcn_sock_get_opt (CTC_SOCK *sock, 
                              int level, 
                              int opt_name, 
                              void *opt_val, 
                              int *opt_len)
{
    int result;

    CTC_TEST_EXCEPTION (getsockopt (sock->handle,
                                    level, 
                                    opt_name, 
                                    opt_val, 
                                    (socklen_t *)opt_len),
                        err_get_sock_opt_label);

    CTC_COND_EXCEPTION (level == 0 && opt_name == 0, err_opt_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_get_sock_opt_label)
    {
        result = CTC_FAILURE;
    }
    CTC_EXCEPTION (err_opt_label)
    {
        result = *(int *)opt_val;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcn_sock_set_opt (CTC_SOCK *sock,
                              int level,
                              int opt_name,
                              const void *opt_val, 
                              int opt_len)
{
    CTC_TEST_EXCEPTION (setsockopt (sock->handle, 
                                    level, 
                                    opt_name, 
                                    opt_val, 
                                    opt_len),
                                    err_set_sock_opt_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_set_sock_opt_label)
    EXCEPTION_END;

    return CTC_FAILURE;
}


extern int ctcn_sock_bind (CTC_SOCK *sock,
                           const ctc_sock_addr_t *addr,
                           int addr_len,
                           BOOL is_reuse)
{
    int reuse_opt = 1;
    int result;

    if (is_reuse == CTC_TRUE)
    {
        result = ctcn_sock_set_opt (sock, 
                                    0, 
                                    SO_REUSEADDR, 
                                    &reuse_opt,
                                    sizeof (reuse_opt));
    }
    else
    {
        result = CTC_SUCCESS;
    }

    if (result == CTC_SUCCESS)
    {
        CTC_TEST_EXCEPTION (bind (sock->handle, addr, addr_len),
                            err_sock_bind_label);
    }
    else
    {
        /* do nothing */
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_sock_bind_label)
    EXCEPTION_END;

    return CTC_FAILURE;
}


extern int ctcn_sock_listen (CTC_SOCK *sock, int backlog)
{
    CTC_TEST_EXCEPTION (listen (sock->handle, backlog), 
                        err_sock_listen_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_sock_listen_label)
    EXCEPTION_END;

    return CTC_FAILURE;
}


extern int ctcn_sock_accept (CTC_SOCK *acpt_sock,
                             CTC_SOCK *lstn_sock,
                             ctc_sock_addr_t *addr,
                             int *addr_len)
{
    int result;

    acpt_sock->handle = accept (lstn_sock->handle, addr, (socklen_t *)addr_len);

    CTC_COND_EXCEPTION (acpt_sock->handle == CTCN_SOCK_INVALID_HANDLE,
                        err_sock_accept_label);

    CTC_TEST_EXCEPTION (ctcn_sock_set_block_mode (acpt_sock, lstn_sock->block_mode),
                        err_sock_set_block_mode_after_accept_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_sock_accept_label)
    CTC_EXCEPTION (err_sock_set_block_mode_after_accept_label)
    {
        ctcn_sock_close (acpt_sock);
    }
    EXCEPTION_END;

    return CTC_FAILURE;
}


/* ctcn_sock_connect function is not for ctc server */
extern int ctcn_sock_connect (CTC_SOCK *sock,
                              ctc_sock_addr_t *addr,
                              int addr_len)
{
    int result = CTC_SUCCESS;

    CTC_TEST_EXCEPTION (connect (sock->handle, addr, addr_len), 
                        err_sock_connect_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_sock_connect_label)
    EXCEPTION_END;

    return CTC_FAILURE;

}


extern int ctcn_sock_get_name (CTC_SOCK *sock,
                               ctc_sock_addr_t *name,
                               int *name_len)
{
    CTC_TEST_EXCEPTION (getsockname (sock->handle, name, (socklen_t *)name_len), 
                        err_get_sock_name_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_get_sock_name_label)
    {
    }
    EXCEPTION_END;

    return CTC_FAILURE;
}


extern int ctcn_sock_get_peer_name (CTC_SOCK *sock,
                                    ctc_sock_addr_t *name,
                                    int *name_len)
{
    CTC_TEST_EXCEPTION (getpeername (sock->handle, name, (socklen_t *)name_len), 
                        err_get_peer_name_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_get_peer_name_label)
    {
    }
    EXCEPTION_END;

    return CTC_FAILURE;
}


extern int ctcn_sock_poll (CTC_SOCK *sock, int event, int timeout)
{
    /*
    struct pollfd poll;
    int ret;
    int result;

    poll.fd = sock->handle;
    poll.events = event;
    poll.revents = 0;

    ret = poll(&poll, 1, timeout);
    */
    int time_out;
    int handle;
    int ret;
    int result;
    struct epoll_event epl_change;
    struct epoll_event epl_event;

    handle = epoll_create (1);
    CTC_COND_EXCEPTION (handle == -1, err_epoll_create_failed_label);

    if (timeout == CTCN_RECV_TIMEOUT_MAX)
    {
        time_out = -1;
    }
    else
    {
        time_out = timeout; /* msec */
    }

    memset (&epl_event, 0, sizeof (struct epoll_event));
    epl_event.events = event;

    ret = epoll_ctl (handle, EPOLL_CTL_ADD, sock->handle, &epl_event);
    CTC_COND_EXCEPTION (ret == -1, err_epoll_add_failed_label);

    ret = epoll_wait (handle, &epl_change, 1, time_out);

    if (ret == -1)
    {
        result = errno;
    }
    else if (ret == 0)
    {
        result = CTCN_RESULT_ETIMEDOUT;
    }
    else
    {
        result = CTC_SUCCESS;
    }

    ret = epoll_ctl (handle, EPOLL_CTL_DEL, sock->handle, &epl_event);
    CTC_COND_EXCEPTION (ret == -1, err_epoll_del_failed_label);

    (void)close (handle);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_epoll_create_failed_label)
    {
        result = errno;
    }
    CTC_EXCEPTION (err_epoll_add_failed_label)
    {
        result = errno;
        (void)close (handle);
    }
    CTC_EXCEPTION (err_epoll_del_failed_label)
    {
        result = errno;
        (void)close (handle);
    }
    EXCEPTION_END;

    return result;
}


static int ctcn_sock_recv (CTC_SOCK *sock, void *buf, int buf_size, int *recv_size, int flag)
{
    int recv_result;
    int result;

    if (buf_size == 0)
    {
        recv_result = 0;
    }
    else
    {
        CTC_COND_EXCEPTION (buf_size > CTCN_32INT_MAX, err_invalid_buf_size_label);
            
        recv_result = recv (sock->handle, buf, buf_size, flag);

        CTC_COND_EXCEPTION (recv_result == -1, err_sock_recv_label);
        CTC_COND_EXCEPTION (recv_result == 0, err_eof_success_label);
    }

    if (recv_size != NULL)
    {
        *recv_size = recv_result;
    }
    else
    {
        /* nothing to do */
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_invalid_buf_size_label)
    {
        result = CTCN_RESULT_EINVAL;
    }
    CTC_EXCEPTION (err_sock_recv_label)
    {
        result = CTC_FAILURE;
    }
    CTC_EXCEPTION (err_eof_success_label)
    {
        result = CTCN_RESULT_EOF;
    }
    EXCEPTION_END;

    return result;
}


static int ctcn_sock_send (CTC_SOCK *sock, 
                           void *buf, 
                           int buf_size, 
                           int *send_size, 
                           int flag)
{
    int send_result;
    int result;

    if (buf_size == 0)
    {
        send_result = 0;
    }
    else
    {
        CTC_COND_EXCEPTION (buf_size > CTCN_LINK_BUF_SIZE, 
                            err_invalid_buf_size_label);
            
        send_result = send (sock->handle, buf, buf_size, flag);

        CTC_COND_EXCEPTION (send_result == -1, err_sock_send_label);
    }

    if (send_size != NULL)
    {
        *send_size = send_result;
    }
    else
    {
        /* nothing to do */
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_invalid_buf_size_label)
    {
        /* for debugging */
        result = CTCN_RESULT_EINVAL;
    }
    CTC_EXCEPTION (err_sock_send_label)
    {
        result = CTC_FAILURE;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcn_link_create (CTCN_LINK **link)
{
    BOOL is_link_allocated = CTC_FALSE;
    CTCN_LINK *link_ptr = NULL;

    link_ptr = (CTCN_LINK *)malloc (sizeof (CTCN_LINK));
    CTC_COND_EXCEPTION (link_ptr == NULL, err_alloc_link_failed_label);

    memset (link_ptr, 0, sizeof (*link_ptr));

    link_ptr->is_sock_opened = CTC_FALSE;
    link_ptr->next_seq_no = 0;
    link_ptr->rbuf_pos = 0;
    link_ptr->read_data_size = 0;
    link_ptr->wbuf_pos = 0;

    *link = link_ptr;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_alloc_link_failed_label)
    {
        /* ERROR: memory allocation, process this error in caller
         * so, just return CTC_FAILURE */
    }
    EXCEPTION_END;

    if (is_link_allocated)
    {
        free (link_ptr);
    }

    return CTC_FAILURE;
}


extern void ctcn_link_destroy (CTCN_LINK *link)
{
    if (link != NULL)
    {
        free (link);
    }

    link = NULL;
}


extern int ctcn_link_set_sock_opt (CTCN_LINK *link)
{
    int opt;

    /* SO_KEEPALIVE */
    opt = 1;
    /*
    CTC_TEST_EXCEPTION (ctcn_sock_set_opt (&(link->sock), 
                                           0, 
                                           SO_KEEPALIVE, 
                                           (void *)&opt, 
                                           sizeof (opt)),
                        err_set_sock_opt_keepalive_label);
                        */

    (void)ctcn_sock_set_opt (&(link->sock), 
                             0, 
                             SO_KEEPALIVE, 
                             (void *)&opt, 
                             sizeof (opt));

    /* SO_REUSEADDR */
    opt = 1;
    CTC_TEST_EXCEPTION (ctcn_sock_set_opt (&(link->sock), 
                                           0, 
                                           SO_REUSEADDR, 
                                           (void *)&opt, 
                                           sizeof (opt)),
                        err_set_sock_opt_reuseaddr_label);

    /* TCP_NODELAY */
    opt = 1;
    CTC_TEST_EXCEPTION (ctcn_sock_set_opt (&(link->sock), 
                                           IPPROTO_TCP, 
                                           CTCN_TCP_NODELAY, 
                                           (void *)&opt, 
                                           sizeof (opt)),
                        err_set_sock_opt_nodelay_label);

    /* SO_SNDBUF */
    opt = CTCN_LINK_BUF_SIZE * 2;
    CTC_TEST_EXCEPTION (ctcn_sock_set_opt (&(link->sock), 
                                           0, 
                                           SO_SNDBUF, 
                                           (void *)&opt, 
                                           sizeof (opt)),
                        err_set_sock_opt_sendbuf_label);

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_set_sock_opt_keepalive_label)
    CTC_EXCEPTION (err_set_sock_opt_reuseaddr_label)
    CTC_EXCEPTION (err_set_sock_opt_nodelay_label)
    CTC_EXCEPTION (err_set_sock_opt_sendbuf_label)
    EXCEPTION_END;

    return CTC_FAILURE;
}


extern int ctcn_link_listen (CTCN_LINK *link, 
                             unsigned short port, 
                             unsigned int timeout)
{
    int addr_len;
    ctc_sock_addr_in_t addr_in;
    ctc_sock_addr_t addr;
    ctc_addr_info_t addr_info;

    CTC_COND_EXCEPTION (port <= 0, err_not_allowed_port_number_label);

    /* set addr_in */
    memset ((void *)&addr_in, 0, sizeof (addr_in));
    addr_in.sin_family = AF_INET;
    addr_in.sin_port = htons (port);
    addr_in.sin_addr.s_addr = htonl (INADDR_ANY);

    /* set addr_info */
    addr_info.ai_family = AF_INET;
    addr_info.ai_socktype = SOCK_STREAM;
    addr_info.ai_protocol = 0;

    /* create socket */
    CTC_TEST_EXCEPTION (ctcn_sock_open (&link->sock, 
                                        addr_info.ai_family,
                                        addr_info.ai_socktype,
                                        addr_info.ai_protocol),
                        err_sock_open_label);

    CTC_TEST_EXCEPTION (ctcn_link_set_sock_opt (link),
                        err_link_set_sock_opt);


    CTC_TEST_EXCEPTION (ctcn_sock_bind (&link->sock,
                                        (ctc_sock_addr_t *)&addr_in,
                                        sizeof (addr_in),
                                        CTC_TRUE),
                        err_sock_bind_label);

    CTC_TEST_EXCEPTION (ctcn_sock_listen (&link->sock, CTCN_MAX_LISTEN),
                        err_sock_listen_label);


    return CTC_SUCCESS;

    CTC_EXCEPTION (err_not_allowed_port_number_label)
    {
    }
    CTC_EXCEPTION (err_sock_open_label)
    {
    }
    CTC_EXCEPTION (err_link_set_sock_opt)
    {
    }
    CTC_EXCEPTION (err_sock_bind_label)
    {
    }
    CTC_EXCEPTION (err_sock_listen_label)
    {
    }
    EXCEPTION_END;

    (void)ctcn_sock_close (&(link->sock));

    return CTC_FAILURE;
}

/*
extern int ctcn_link_disconnect (CTC_LINK *link, BOOL is_reuse)
{
    (void)ctcn_sock_shutdown (&(link->sock), CTCN_SHUTDW_RW);

    if (is_reuse == CTC_TRUE)
    {
    }
    else
    {
        ctcn_sock_close (&(link->sock));
        link->is_sock_opened = CTC_FALSE;
    }

    return CTC_SUCCESS;
}
*/

extern int ctcn_link_recv (CTCN_LINK *link,
                           unsigned long timeout,
                           BOOL *is_timeout)
{
    BOOL read_header_flag = CTC_FALSE;
    BOOL timeout_flag = CTC_FALSE;
    int result;
    int recv_size = 0;
    int offset = 0; 
    int remained_data_len = 0; 
    int length_of_data = 0; 
    unsigned long i = 0;

    remained_data_len = CTCP_HDR_LEN;

    for (i = 0; i < timeout; i++)
    {    
        timeout_flag = CTC_FALSE;

        CTC_TEST_EXCEPTION (ctcn_link_poll_socket (link, 
                                                   CTCN_ONE_SEC, 
                                                   &timeout_flag),
                            err_sock_poll_label);

        if ( timeout_flag == CTC_TRUE )
        {
            continue;
        }
        else
        {
            /* nothing to do */ 
        }

        CTC_TEST_EXCEPTION (ctcn_link_recv_socket (link, 
                                                   link->rbuf + offset, 
                                                   remained_data_len, 
                                                   &recv_size), 
                            err_link_recv_socket_label);

        offset += recv_size;

        assert (remained_data_len >= recv_size);

        remained_data_len -= recv_size;

        if (remained_data_len == 0)
        {
            if (read_header_flag == CTC_FALSE)
            {
                length_of_data = ctcp_header_get_data_len ((CTCP_HEADER *)link->rbuf);

                remained_data_len = length_of_data;
                read_header_flag = CTC_TRUE;
            }
            else
            {
                break;
            }
        }
        else
        {
            /* do nothing */
        }
    }

    if (i == timeout)
    {
        timeout_flag = CTC_TRUE;
    }
    else
    {
        /* nothing to do */ 
    }

    link->rbuf_pos = CTCP_HDR_LEN;
    link->read_data_size = offset;

    *is_timeout = timeout_flag;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_sock_poll_label)
    {
        /* ERROR: epoll retry? */
    }
    CTC_EXCEPTION (err_link_recv_socket_label)
    {
        result = CTC_ERR_LINK_RECV_FAILED;
    }
    EXCEPTION_END;

    return result;
}


extern int ctcn_link_poll_socket (CTCN_LINK *link, 
                                  unsigned int timeout_msec, 
                                  BOOL *is_timeout)
{
    int result = CTC_SUCCESS;

    *is_timeout = CTC_FALSE;

    result = ctcn_sock_poll (&(link->sock), EPOLLIN, timeout_msec);

    switch (result)
    {
        case CTC_SUCCESS:
            break;

        case CTCN_RESULT_ETIMEDOUT:
        case CTCN_RESULT_EINTR:

            *is_timeout = CTC_TRUE;
            break;

        default:

            CTC_COND_EXCEPTION (CTC_TRUE, err_sock_poll_label);
            break;
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION(err_sock_poll_label)
    {
        /* select socket error */
    }
    EXCEPTION_END;

    return CTC_FAILURE;
}


extern int ctcn_link_recv_socket (CTCN_LINK *link, 
                                  void *buf, 
                                  int buf_size, 
                                  int *recv_size) 
{
    int result = CTC_SUCCESS;

    result = ctcn_sock_recv (&(link->sock), buf, buf_size, recv_size, 0);

    switch (result)
    {
        case CTC_SUCCESS:
            break;

        case CTCN_RESULT_EINTR:
            break;

        default:
            CTC_COND_EXCEPTION (CTC_TRUE, err_sock_recv_label);
            break;
    }

    return CTC_SUCCESS;

    CTC_EXCEPTION(err_sock_recv_label)
    {
    }
    EXCEPTION_END;

    return CTC_FAILURE;
}


extern BOOL ctcn_sock_get_block_mode (CTC_SOCK *sock)
{
    return sock->block_mode;
}


extern int ctcn_link_send (CTCN_LINK *link)
{
    int send_len = 0;
    int result = CTC_SUCCESS;

    CTC_TEST_EXCEPTION (ctcn_sock_send (&(link->sock), 
                                        link->wbuf, 
                                        link->wbuf_pos, 
                                        &send_len, 
                                        0),
                        err_sock_send_label);

    link->next_seq_no++;

    if (link->next_seq_no == 0xffffffff)
    {
        link->next_seq_no = 0;
    }

    link->wbuf_pos = 0;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_sock_send_label)
    EXCEPTION_END;

    return CTC_FAILURE;
}


extern int ctcn_link_read (CTCN_LINK *link, void *dest, unsigned int len)
{
    CTC_COND_EXCEPTION (link->rbuf_pos + len > link->read_data_size,
                        err_no_space_in_read_buf);

    memcpy (dest, link->rbuf + link->rbuf_pos, len);
    link->rbuf_pos += len;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_no_space_in_read_buf)
    {
        /* ERR_NOT_ENOUGH_DATA_IN_R_BUF */
    }
    EXCEPTION_END;

    return CTC_FAILURE;
}


extern int ctcn_link_read_one_byte_number (CTCN_LINK *link, void *dest)
{
    CTC_COND_EXCEPTION (link->rbuf_pos + 1 > link->read_data_size,
                        err_no_space_in_read_buf);

    *(unsigned char *)dest = link->rbuf[link->rbuf_pos];
    link->rbuf_pos++;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_no_space_in_read_buf)
    {
        /* ERR_NOT_ENOUGH_DATA_IN_R_BUF */
    }
    EXCEPTION_END;

    return CTC_FAILURE;
}


extern int ctcn_link_read_two_byte_number (CTCN_LINK *link, void *dest)
{
    CTC_COND_EXCEPTION (link->rbuf_pos + 2 > link->read_data_size,
                        err_no_space_in_read_buf);

    *(unsigned char *)dest = link->rbuf[link->rbuf_pos];
    link->rbuf_pos++;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_no_space_in_read_buf)
    {
        /* ERR_NOT_ENOUGH_DATA_IN_RBUF */
    }
    EXCEPTION_END;

    return CTC_FAILURE;
}


extern int ctcn_link_read_four_byte_number (CTCN_LINK *link, void *dest)
{
    CTC_COND_EXCEPTION (link->rbuf_pos + 4 > link->read_data_size,
                        err_no_space_in_read_buf);

    ctcn_assign_number_four ((unsigned char *)link->rbuf + link->rbuf_pos, 
                             (unsigned char *)dest);

    link->rbuf_pos += 4;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_no_space_in_read_buf)
    {
        /* ERR_NOT_ENOUGH_DATA_IN_RBUF */
    }
    EXCEPTION_END;

    return CTC_FAILURE;
}


extern int ctcn_link_write (CTCN_LINK *link, void *src, unsigned int len)
{
    CTC_COND_EXCEPTION (link->wbuf_pos + len > CTCN_LINK_BUF_SIZE,
                        err_write_buf_overflow_label);

    memcpy (link->wbuf + link->wbuf_pos, src, len);
    link->wbuf_pos += len;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_write_buf_overflow_label)
    {
        /* ERR_NOT_ENOUGH_SPACE_IN_WBUF */
    }
    EXCEPTION_END;

    return CTC_FAILURE;
}


extern int ctcn_link_write_one_byte_number (CTCN_LINK *link, void *src)
{
    CTC_COND_EXCEPTION (link->wbuf_pos + 1 > CTCN_LINK_BUF_SIZE,
                        err_write_buf_overflow_label);

    link->wbuf[link->wbuf_pos] = *(unsigned char *)src;
    link->wbuf_pos++;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_write_buf_overflow_label)
    {
        /* ERR_NOT_ENOUGH_SPACE_IN_WBUF */
    }
    EXCEPTION_END;

    return CTC_FAILURE;
}


extern int ctcn_link_write_two_byte_number (CTCN_LINK *link, void *src)
{
    CTC_COND_EXCEPTION (link->wbuf_pos + 2 > CTCN_LINK_BUF_SIZE,
                        err_write_buf_overflow_label);

    ctcn_assign_number_two ((unsigned char *)src, 
                            (unsigned char *)(link->wbuf + link->wbuf_pos));

    link->wbuf_pos += 2;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_write_buf_overflow_label)
    {
        /* ERR_NOT_ENOUGH_SPACE_IN_WBUF */
    }
    EXCEPTION_END;

    return CTC_FAILURE;
}


extern int ctcn_link_write_four_byte_number (CTCN_LINK *link, void *src)
{
    CTC_COND_EXCEPTION (link->wbuf_pos + 4 > CTCN_LINK_BUF_SIZE,
                        err_write_buf_overflow_label);

    ctcn_assign_number_four ((unsigned char *)src, 
                             (unsigned char *)(link->wbuf + link->wbuf_pos));

    link->wbuf_pos += 4;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_write_buf_overflow_label)
    {
        /* ERR_NOT_ENOUGH_SPACE_IN_WBUF */
    }
    EXCEPTION_END;

    return CTC_FAILURE;
}


extern int ctcn_link_forward_wbuf_pos (CTCN_LINK *link, int size)
{
    CTC_COND_EXCEPTION (link->wbuf_pos + size > CTCN_LINK_BUF_SIZE,
                        err_write_buf_overflow_label);

    link->wbuf_pos += size;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_write_buf_overflow_label)
    {
        /* ERR_NOT_ENOUGH_SPACE_IN_WBUF */
    }
    EXCEPTION_END;

    return CTC_FAILURE;
}


extern int ctcn_link_backward_wbuf_pos (CTCN_LINK *link, int size)
{
    CTC_COND_EXCEPTION (link->wbuf_pos - size < CTCN_HDR_LEN,
                        err_write_buf_overflow_label);

    link->wbuf_pos -= size;

    return CTC_SUCCESS;

    CTC_EXCEPTION (err_write_buf_overflow_label)
    {
        /* ERR_NOT_ENOUGH_SPACE_IN_WBUF */
    }
    EXCEPTION_END;

    return CTC_FAILURE;
}


extern void ctcn_link_move_wbuf_pos (CTCN_LINK *link, int pos)
{
    link->wbuf_pos = pos;
}


static void ctcn_assign_number_two (unsigned char *src, unsigned char *dest)
{
#ifdef ENDIAN_IS_BIG_ENDIAN
    dest[0] = src[0];
    dest[1] = src[1];

#else
    dest[1] = src[0];
    dest[0] = src[1];

#endif
}


static void ctcn_assign_number_four (unsigned char *src, unsigned char *dest)
{
#ifdef ENDIAN_IS_BIG_ENDIAN
    dest[0] = src[0];
    dest[1] = src[1];
    dest[2] = src[2];
    dest[3] = src[3];

#else
    dest[3] = src[0];
    dest[2] = src[1];
    dest[1] = src[2];
    dest[0] = src[3];

#endif
}


