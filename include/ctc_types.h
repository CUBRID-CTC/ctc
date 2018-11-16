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
 * ctc_types.h : ctc types definition header
 *
 */

#ifndef _CTC_TYPES_H_
#define _CTC_TYPES_H_ 1


#define UINT_64 unsigned long int
#define SINT_64 long int
#define UINT_32 unsigned int
#define SINT_32 int
#define INT_16 short int


typedef enum ctc_type_bool
{
    CTC_FALSE = 0,
    CTC_TRUE
} BOOL;


#endif /* _CTC_TYPES_H_ */
