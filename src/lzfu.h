/*
 * LZFu (un)compression functions
 *
 * Copyright (C) 2008-2017, Joachim Metz <joachim.metz@gmail.com>
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

#if !defined( _LZFU_H )
#define _LZFU_H

#include <common.h>
#include <types.h>

#include "assorted_libcerror.h"

#if defined( __cplusplus )
extern "C" {
#endif

/* The LZFu compression header (compressed RTF header)
 */
typedef struct lzfu_header lzfu_header_t;

struct lzfu_header
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

int lzfu_get_uncompressed_data_size(
     uint8_t *compressed_data,
     size_t compressed_data_size,
     size_t *uncompressed_data_size,
     libcerror_error_t **error );

int lzfu_compress(
     uint8_t *uncompressed_data,
     size_t uncompressed_data_size,
     uint8_t *compressed_data,
     size_t *compressed_data_size,
     libcerror_error_t **error );

int lzfu_decompress(
     uint8_t *compressed_data,
     size_t compressed_data_size,
     uint8_t *uncompressed_data,
     size_t *uncompressed_data_size,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LZFU_H ) */

