/*
 * Bit-stream functions
 *
 * Copyright (C) 2008-2021, Joachim Metz <joachim.metz@gmail.com>
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

#if !defined( _BIT_STREAM_H )
#define _BIT_STREAM_H

#include <common.h>
#include <types.h>

#include "assorted_libcerror.h"

#if defined( __cplusplus )
extern "C" {
#endif

/* The storage type
 */
enum BIT_STREAM_STORAGE_TYPES
{
	BIT_STREAM_STORAGE_TYPE_UNKNOWN			= 0x00,
	BIT_STREAM_STORAGE_TYPE_BYTE_FRONT_TO_BACK	= 0x01,
	BIT_STREAM_STORAGE_TYPE_BYTE_BACK_TO_FRONT	= 0x02,
	BIT_STREAM_STORAGE_TYPE_16BIT_LITTLE_ENDIAN	= 0x03
};

/* The largest primary (or scalar) available
 * supported by a single load and store instruction
 */
typedef unsigned long int bit_stream_aligned_t;

typedef struct bit_stream bit_stream_t;

struct bit_stream
{
	/* The byte stream
	 */
	const uint8_t *byte_stream;

	/* The aligned byte stream
	 */
	bit_stream_aligned_t *aligned_byte_stream;

	/* The byte stream size
	 */
	size_t byte_stream_size;

	/* The byte stream offset
	 */
	size_t byte_stream_offset;

	/* The storage type
	 */
	uint8_t storage_type;

	/* The bit buffer
	 */
	uint32_t bit_buffer;

	/* The number of bits remaining in the bit buffer
	 */
	uint8_t bit_buffer_size;
};

int bit_stream_initialize(
     bit_stream_t **bit_stream,
     const uint8_t *byte_stream,
     size_t byte_stream_size,
     libcerror_error_t **error );

int bit_stream_free(
     bit_stream_t **bit_stream,
     libcerror_error_t **error );

int bit_stream_read(
     bit_stream_t *bit_stream,
     uint8_t number_of_bits,
     libcerror_error_t **error );

int bit_stream_get_value(
     bit_stream_t *bit_stream,
     uint8_t number_of_bits,
     uint32_t *value_32bit,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _BIT_STREAM_H ) */

