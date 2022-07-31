/*
 * BZip (un)compression functions
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

#if !defined( _BZIP_COMPRESSION_H )
#define _BZIP_COMPRESSION_H

#include <common.h>
#include <types.h>

#include "assorted_libcerror.h"
#include "bit_stream.h"
#include "huffman_tree.h"

#if defined( __cplusplus )
extern "C" {
#endif

void bzip_initialize_crc32_table(
      void );

int bzip_calculate_crc32(
     uint32_t *crc32,
     const uint8_t *data,
     size_t data_size,
     uint32_t initial_value,
     libcerror_error_t **error );

int bzip_reverse_burrows_wheeler_transform(
     const uint8_t *input_data,
     size_t input_data_size,
     size_t *permutations,
     uint32_t origin_pointer,
     uint8_t *uncompressed_data,
     size_t uncompressed_data_size,
     size_t *uncompressed_data_offset,
     libcerror_error_t **error );

int bzip_read_stream_header(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     uint8_t *compression_level,
     libcerror_error_t **error );

int bzip_read_signature(
     bit_stream_t *bit_stream,
     uint64_t *signature,
     libcerror_error_t **error );

int bzip_read_block_header(
     bit_stream_t *bit_stream,
     uint64_t signature,
     uint32_t *origin_pointer,
     libcerror_error_t **error );

int bzip_read_symbol_stack(
     bit_stream_t *bit_stream,
     uint8_t *symbol_stack,
     uint16_t *number_of_symbols,
     libcerror_error_t **error );

int bzip_read_selectors(
     bit_stream_t *bit_stream,
     uint8_t *selectors,
     uint8_t number_of_trees,
     uint16_t number_of_selectors,
     libcerror_error_t **error );

int bzip_read_huffman_tree(
     bit_stream_t *bit_stream,
     huffman_tree_t *huffman_tree,
     uint16_t number_of_symbols,
     libcerror_error_t **error );

int bzip_read_huffman_trees(
     bit_stream_t *bit_stream,
     huffman_tree_t **huffman_trees,
     uint8_t number_of_trees,
     uint16_t number_of_symbols,
     libcerror_error_t **error );

int bzip_read_symbol(
     bit_stream_t *bit_stream,
     uint32_t *symbol,
     libcerror_error_t **error );

int bzip_read_block_data(
     bit_stream_t *bit_stream,
     huffman_tree_t **huffman_trees,
     uint8_t number_of_trees,
     uint8_t *selectors,
     uint16_t number_of_selectors,
     uint8_t *symbol_stack,
     uint16_t number_of_symbols,
     uint8_t *block_data,
     size_t *block_data_size,
     libcerror_error_t **error );

int bzip_read_stream_footer(
     bit_stream_t *bit_stream,
     uint64_t signature,
     uint32_t *checksum,
     libcerror_error_t **error );

int bzip_decompress(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     uint8_t *uncompressed_data,
     size_t *uncompressed_data_size,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _BZIP_COMPRESSION_H ) */

