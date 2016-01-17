/*
 * Adler-32 functions
 *
 * Copyright (C) 2008-2016, Joachim Metz <joachim.metz@gmail.com>
 *
 * Refer to AUTHORS for acknowledgements.
 *
 * This software is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software.  If not, see <http://www.gnu.org/licenses/>.
 */

#if !defined( _ADLER32_H )
#define _ADLER32_H

#include <common.h>
#include <types.h>

#include "assorted_libcerror.h"

#if defined( __cplusplus )
extern "C" {
#endif

int checksum_calculate_adler32_basic1(
     uint32_t *checksum_value,
     uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     libcerror_error_t **error );

int checksum_calculate_adler32_basic2(
     uint32_t *checksum_value,
     uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     libcerror_error_t **error );

int checksum_calculate_adler32_unfolded4_1(
     uint32_t *checksum_value,
     uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     libcerror_error_t **error );

int checksum_calculate_adler32_unfolded4_2(
     uint32_t *checksum_value,
     uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     libcerror_error_t **error );

int checksum_calculate_adler32_unfolded16_1(
     uint32_t *checksum_value,
     uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     libcerror_error_t **error );

int checksum_calculate_adler32_unfolded16_2(
     uint32_t *checksum_value,
     uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     libcerror_error_t **error );

int checksum_calculate_adler32_unfolded16_3(
     uint32_t *checksum_value,
     uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     libcerror_error_t **error );

int checksum_calculate_adler32_unfolded16_4(
     uint32_t *checksum_value,
     uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     libcerror_error_t **error );

int checksum_calculate_adler32_cpu_aligned(
     uint32_t *checksum_value,
     const uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     libcerror_error_t **error );

int checksum_calculate_adler32_simd(
     uint32_t *checksum_value,
     const uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif

