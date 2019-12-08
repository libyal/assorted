/*
 * Deflate (zlib) (un)compression functions
 *
 * Copyright (C) 2008-2019, Joachim Metz <joachim.metz@gmail.com>
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

#if !defined( _DEFLATE_COMPRESSION_H )
#define _DEFLATE_COMPRESSION_H

#include <common.h>
#include <types.h>

#include "assorted_libcerror.h"
#include "bit_stream.h"
#include "huffman_tree.h"

#if defined( __cplusplus )
extern "C" {
#endif

/* The block types
 */
enum DEFLATE_BLOCK_TYPES
{
	DEFLATE_BLOCK_TYPE_UNCOMPRESSED		= 0x00,
	DEFLATE_BLOCK_TYPE_HUFFMAN_FIXED	= 0x01,
	DEFLATE_BLOCK_TYPE_HUFFMAN_DYNAMIC	= 0x02,
	DEFLATE_BLOCK_TYPE_RESERVED		= 0x03
};

int deflate_build_dynamic_huffman_trees(
     bit_stream_t *bit_stream,
     huffman_tree_t *literals_huffman_tree,
     huffman_tree_t *distances_huffman_tree,
     libcerror_error_t **error );

int deflate_build_fixed_huffman_trees(
     huffman_tree_t *literals_huffman_tree,
     huffman_tree_t *distances_huffman_tree,
     libcerror_error_t **error );

int deflate_decode_huffman(
     bit_stream_t *bit_stream,
     huffman_tree_t *literals_huffman_tree,
     huffman_tree_t *distances_huffman_tree,
     uint8_t *uncompressed_data,
     size_t uncompressed_data_size,
     size_t *uncompressed_data_offset,
     libcerror_error_t **error );

int deflate_calculate_adler32(
     uint32_t *checksum_value,
     const uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     libcerror_error_t **error );

int deflate_compress(
     const uint8_t *uncompressed_data,
     size_t uncompressed_data_size,
     int compression_level,
     uint8_t *compressed_data,
     size_t *compressed_data_size,
     libcerror_error_t **error );

int deflate_decompress(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     uint8_t *uncompressed_data,
     size_t *uncompressed_data_size,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _DEFLATE_COMPRESSION_H ) */

