/*
 * LZX (un)compression functions
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

#if !defined( _LZX_H )
#define _LZX_H

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
enum LZX_BLOCK_TYPES
{
	LZX_BLOCK_TYPE_INVALID		= 0x00,
	LZX_BLOCK_TYPE_VERBATIM		= 0x01,
	LZX_BLOCK_TYPE_ALIGNED		= 0x02,
	LZX_BLOCK_TYPE_UNCOMPRESSED	= 0x03
};

int lzx_read_huffman_code_sizes(
     bit_stream_t *bit_stream,
     uint8_t *code_size_array,
     int number_of_code_sizes,
     libcerror_error_t **error );

int lzx_build_main_huffman_tree(
     bit_stream_t *bit_stream,
     huffman_tree_t *main_huffman_tre,
     libcerror_error_t **error );

int lzx_build_lengths_huffman_tree(
     bit_stream_t *bit_stream,
     huffman_tree_t *lengths_huffman_tre,
     libcerror_error_t **error );

int lzx_build_aligned_offsets_huffman_tree(
     bit_stream_t *bit_stream,
     huffman_tree_t *aligned_offsets_huffman_tre,
     libcerror_error_t **error );

int lzx_decode_huffman(
     bit_stream_t *bit_stream,
     uint32_t block_size,
     huffman_tree_t *main_huffman_tree,
     huffman_tree_t *lengths_huffman_tree,
     huffman_tree_t *aligned_offsets_huffman_tree,
     uint32_t *recent_compression_offsets,
     const uint8_t *number_of_footer_bits,
     uint8_t *uncompressed_data,
     size_t uncompressed_data_size,
     size_t *uncompressed_data_offset,
     libcerror_error_t **error );

int lzx_decompress(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     uint8_t *uncompressed_data,
     size_t *uncompressed_data_size,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LZX_H ) */

