/*
 * XOR-64 functions
 *
 * Copyright (C) 2008-2023, Joachim Metz <joachim.metz@gmail.com>
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

#if !defined( _ASSORTED_XOR64_H )
#define _ASSORTED_XOR64_H

#include <common.h>
#include <types.h>

#include "assorted_libcerror.h"

#if defined( __cplusplus )
extern "C" {
#endif

int assorted_xor64_calculate_checksum_little_endian_basic(
     uint64_t *checksum_value,
     const uint8_t *buffer,
     size_t size,
     uint64_t initial_value,
     libcerror_error_t **error );

int assorted_xor64_calculate_checksum_little_endian_cpu_aligned(
     uint64_t *checksum_value,
     const uint8_t *buffer,
     size_t size,
     uint64_t initial_value,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _ASSORTED_XOR64_H ) */

