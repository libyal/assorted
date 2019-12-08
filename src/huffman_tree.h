/*
 * Huffman tree functions
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

#if !defined( _HUFFMAN_TREE_H )
#define _HUFFMAN_TREE_H

#include <common.h>
#include <types.h>

#include "assorted_libcerror.h"
#include "bit_stream.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct huffman_tree huffman_tree_t;

struct huffman_tree
{
	/* The maximum number of bits allowed for a Huffman code
	 */
	uint8_t maximum_code_size;

	/* The symbols array
	 */
	int *symbols;

	/* The code size counts array
	 */
	int *code_size_counts;
};

int huffman_tree_initialize(
     huffman_tree_t **huffman_tree,
     int number_of_symbols,
     uint8_t maximum_code_size,
     libcerror_error_t **error );

int huffman_tree_free(
     huffman_tree_t **huffman_tree,
     libcerror_error_t **error );

int huffman_tree_build(
     huffman_tree_t *tree,
     const uint8_t *code_sizes_array,
     int number_of_code_sizes,
     libcerror_error_t **error );

int huffman_tree_get_symbol_from_bit_stream(
     huffman_tree_t *huffman_tree,
     bit_stream_t *bit_stream,
     uint32_t *symbol,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _HUFFMAN_TREE_H ) */

