/*
 * RC4 (de/en)crypt functions
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

#if !defined( _RC4_H )
#define _RC4_H

#include <common.h>
#include <types.h>

#include "assorted_libcerror.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct rc4_context rc4_context_t;

struct rc4_context
{
	/* The permutations table
	 */
	uint8_t permutations[ 256 ];

	/* The permutations table indexes
	 */
	uint8_t index[ 2 ];
};

int rc4_context_initialize(
     rc4_context_t **context,
     libcerror_error_t **error );

int rc4_context_free(
     rc4_context_t **context,
     libcerror_error_t **error );

int rc4_context_set_key(
     rc4_context_t *context,
     const uint8_t *key,
     size_t key_bit_size,
     libcerror_error_t **error );

int rc4_crypt(
     rc4_context_t *context,
     const uint8_t *input_data,
     size_t input_data_size,
     uint8_t *output_data,
     size_t output_data_size,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif

