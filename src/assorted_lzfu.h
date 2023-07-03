/*
 * LZFu (un)compression functions
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

#if !defined( _ASSORTED_LZFU_H )
#define _ASSORTED_LZFU_H

#include <common.h>
#include <types.h>

#include "assorted_libcerror.h"

#if defined( __cplusplus )
extern "C" {
#endif

/* The LZFu compression header (compressed RTF header)
 */
typedef struct assorted_lzfu_header assorted_lzfu_header_t;

struct assorted_lzfu_header
{
	/* The size of the compressed data after the header
	 */
	uint32_t compressed_data_size;

	/* The size of the uncompressed data after the header
	 */
	uint32_t uncompressed_data_size;

	/* The (un)compressed data signature
	 */
	uint32_t signature;

	/* A CRC32 of the compressed data
	 */
	uint32_t crc;
};

int assorted_lzfu_get_uncompressed_data_size(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     size_t *uncompressed_data_size,
     libcerror_error_t **error );

int assorted_lzfu_compress(
     const uint8_t *uncompressed_data,
     size_t uncompressed_data_size,
     uint8_t *compressed_data,
     size_t *compressed_data_size,
     libcerror_error_t **error );

int assorted_lzfu_decompress(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     uint8_t *uncompressed_data,
     size_t *uncompressed_data_size,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _ASSORTED_LZFU_H ) */

