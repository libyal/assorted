/*
 * CRC-32 functions
 *
 * Copyright (C) 2008-2022, Joachim Metz <joachim.metz@gmail.com>
 *
 * Refer to AUTHORS for acknowledgements.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#if !defined( _CRC32_H )
#define _CRC32_H

#include <common.h>
#include <types.h>

#include "assorted_libcerror.h"

#if defined( __cplusplus )
extern "C" {
#endif

void crc32_initialize_table(
      uint32_t polynomial );

int crc32_calculate_modulo2(
     uint32_t *crc32,
     const uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     uint8_t weak_crc,
     libcerror_error_t **error );

int crc32_calculate(
     uint32_t *crc32,
     const uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     uint8_t weak_crc,
     libcerror_error_t **error );

int crc32_validate(
     uint32_t crc32,
     uint32_t calculated_crc32,
     uint8_t *bit_index,
     libcerror_error_t **error );

int crc32_locate_error_offset(
     uint32_t crc32,
     uint32_t calculated_crc32,
     const uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _CRC32_H ) */

