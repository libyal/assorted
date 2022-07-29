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

#include <common.h>
#include <byte_stream.h>
#include <memory.h>
#include <types.h>

#include "assorted_libcerror.h"
#include "assorted_libcnotify.h"
#include "bit_stream.h"
#include "bzip.h"
#include "huffman_tree.h"

/* Reads the stream header
 * Returns 1 on success or -1 on error
 */
int bzip_read_stream_header(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     size_t *compressed_data_offset,
     libcerror_error_t **error )
{
	static char *function              = "bzip_read_stream_header";
	size_t safe_compressed_data_offset = 0;
	uint8_t compression_level          = 0;

	if( compressed_data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid compressed data.",
		 function );

		return( -1 );
	}
	if( compressed_data_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid compressed data size value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( compressed_data_offset == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid compressed data offset.",
		 function );

		return( -1 );
	}
	safe_compressed_data_offset = *compressed_data_offset;

	if( ( compressed_data_size < 4 )
	 || ( safe_compressed_data_offset > ( compressed_data_size - 4 ) ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: invalid compressed data value too small.",
		 function );

		return( -1 );
	}
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: stream header data:\n",
		 function );
		libcnotify_print_data(
		 &( compressed_data[ safe_compressed_data_offset ] ),
		 4,
		 0 );
	}
	if( ( compressed_data[ safe_compressed_data_offset ] != 'B' )
	 || ( compressed_data[ safe_compressed_data_offset + 1 ] != 'Z' ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported signature.",
		 function );

		return( -1 );
	}
	compression_level = compressed_data[ safe_compressed_data_offset + 3 ];

	if( ( compression_level < '1' )
	 || ( compression_level > '9' ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported compression level.",
		 function );

		return( -1 );
	}
	compression_level -= '0';

	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: signature\t\t\t\t: %c%c\n",
		 function,
		 compressed_data[ safe_compressed_data_offset ],
		 compressed_data[ safe_compressed_data_offset + 1 ] );

		libcnotify_printf(
		 "%s: format version\t\t\t\t: 0x%02" PRIx8 "\n",
		 function,
		 compressed_data[ safe_compressed_data_offset + 2 ] );

		libcnotify_printf(
		 "%s: compression level\t\t\t: %" PRIu8 "\n",
		 function,
		 compression_level );

		libcnotify_printf(
		 "\n" );
	}
	if( compressed_data[ safe_compressed_data_offset + 2 ] != 0x68 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported format version.",
		 function );

		return( -1 );
	}
	*compressed_data_offset = safe_compressed_data_offset + 4;

	return( 1 );
}

/* Reads a (stream) block header
 * Returns 1 on success or -1 on error
 */
int bzip_read_block_header(
     bit_stream_t *bit_stream,
     libcerror_error_t **error )
{
	static char *function   = "bzip_read_block_header";
	uint64_t signature      = 0;
	uint32_t checksum       = 0;
	uint32_t origin_pointer = 0;
	uint32_t value_32bit    = 0;
	uint8_t is_randomized   = 0;

	if( bit_stream_get_value(
	     bit_stream,
	     32,
	     &value_32bit,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve value from bit stream.",
		 function );

		return( -1 );
	}
	signature = value_32bit;

	if( bit_stream_get_value(
	     bit_stream,
	     16,
	     &value_32bit,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve value from bit stream.",
		 function );

		return( -1 );
	}
	signature <<= 16;
	signature  |= value_32bit;

	if( bit_stream_get_value(
	     bit_stream,
	     32,
	     &checksum,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve value from bit stream.",
		 function );

		return( -1 );
	}
	if( bit_stream_get_value(
	     bit_stream,
	     25,
	     &value_32bit,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve value from bit stream.",
		 function );

		return( -1 );
	}
	is_randomized  = (uint8_t) ( value_32bit & 0x00000001UL );
	origin_pointer = value_32bit >> 1;

	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: signature\t\t\t\t: 0x%08" PRIx64 "\n",
		 function,
		 signature );

		libcnotify_printf(
		 "%s: checksum\t\t\t\t: 0x%08" PRIx32 "\n",
		 function,
		 checksum );

		libcnotify_printf(
		 "%s: is randomized\t\t\t\t: %" PRIu8 "\n",
		 function,
		 is_randomized );

		libcnotify_printf(
		 "%s: origin pointer\t\t\t\t: 0x%06" PRIx32 "\n",
		 function,
		 origin_pointer );

		libcnotify_printf(
		 "\n" );
	}
	if( signature != 0x314159265359UL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported signature.",
		 function );

		return( -1 );
	}
	if( is_randomized != 0 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported is randomized flag.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Reads a (stream block) symbol stack
 * Returns 1 on success or -1 on error
 */
int bzip_read_symbol_stack(
     bit_stream_t *bit_stream,
     uint8_t *symbol_stack,
     uint16_t *number_of_symbols,
     libcerror_error_t **error )
{
	static char *function    = "bzip_read_symbol_stack";
	uint32_t level1_bitmask  = 0;
	uint32_t level1_value    = 0;
	uint32_t level2_bitmask  = 0;
	uint32_t level2_value    = 0;
	uint16_t symbol_index    = 0;
	uint8_t level1_bit_index = 0;
	uint8_t level2_bit_index = 0;
	uint8_t symbol_value     = 0;

	if( symbol_stack == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid symbol stack.",
		 function );

		return( -1 );
	}
	if( number_of_symbols == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid number of symbols.",
		 function );

		return( -1 );
	}
	if( bit_stream_get_value(
	     bit_stream,
	     16,
	     &level1_value,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve value from bit stream.",
		 function );

		return( -1 );
	}
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: level 1 value\t\t\t\t: 0x%04" PRIx32 "\n",
		 function,
		 level1_value );
	}
	level1_bitmask = 0x00008000UL;

	for( level1_bit_index = 0;
	     level1_bit_index < 16;
	     level1_bit_index++ )
	{
		if( ( level1_value & level1_bitmask ) != 0 )
		{
			if( bit_stream_get_value(
			     bit_stream,
			     16,
			     &level2_value,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to retrieve value from bit stream.",
				 function );

				return( -1 );
			}
			if( libcnotify_verbose != 0 )
			{
				libcnotify_printf(
				 "%s: level 2 value: %" PRIu8 "\t\t\t\t: 0x%04" PRIx32 "\n",
				 function,
				 level1_bit_index,
				 level2_value );
			}
			level2_bitmask = 0x00008000UL;

			for( level2_bit_index = 0;
			     level2_bit_index < 16;
			     level2_bit_index++ )
			{
				if( ( level2_value & level2_bitmask ) != 0 )
				{
					symbol_value = ( 16 * level1_bit_index ) + level2_bit_index;

					if( libcnotify_verbose != 0 )
					{
						libcnotify_printf(
						 "%s: symbol value: %" PRIu16 "\t\t\t\t: 0x%02" PRIx8 "\n",
						 function,
						 symbol_index,
						 symbol_value );
					}
					if( symbol_index > 256 )
					{
						libcerror_error_set(
						 error,
						 LIBCERROR_ERROR_DOMAIN_RUNTIME,
						 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
						 "%s: invalid symbol index value out of bounds.",
						 function );

						return( -1 );
					}
					symbol_stack[ symbol_index++ ] = symbol_value;
				}
				level2_bitmask >>= 1;
			}
		}
		level1_bitmask >>= 1;
	}
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "\n" );
	}
	*number_of_symbols = symbol_index + 2;

	return( 1 );
}

/* Reads selectors
 * Returns 1 on success or -1 on error
 */
int bzip_read_selectors(
     bit_stream_t *bit_stream,
     uint8_t *selectors,
     uint8_t number_of_trees,
     uint16_t number_of_selectors,
     libcerror_error_t **error )
{
	uint8_t stack[ 7 ]      = { 0, 1, 2, 3, 4, 5, 6 };
	static char *function   = "bzip_read_selectors";
	uint32_t value_32bit    = 0;
	uint16_t selector_index = 0;
	uint8_t selector_value  = 0;
	uint8_t stack_index     = 0;
	uint8_t tree_index      = 0;

	if( selectors == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid selectors.",
		 function );

		return( -1 );
	}
	for( selector_index = 0;
	     selector_index < number_of_selectors;
	     selector_index++ )
	{
		tree_index = 0;

		while( tree_index < number_of_trees )
		{
			if( bit_stream_get_value(
			     bit_stream,
			     1,
			     &value_32bit,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to retrieve value from bit stream.",
				 function );

				return( -1 );
			}
			if( value_32bit == 0 )
			{
				break;
			}
			tree_index += 1;
		}
		if( tree_index >= number_of_trees )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
			 "%s: invalid tree index value out of bounds.",
			 function );

			return( -1 );
		}
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: tree index: %" PRIu16 "\t\t\t\t: %" PRIu8 "\n",
			 function,
			 selector_index,
			 tree_index );
		}
		selector_value = stack[ tree_index ];

		selectors[ selector_index ] = selector_value;

		for( stack_index = tree_index;
		     stack_index > 0;
		     stack_index-- )
		{
			stack[ stack_index ] = stack[ stack_index - 1 ];
		}
		stack[ 0 ] = selector_value;
	}
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "\n" );
	}
	return( 1 );
}

/* Reads a Huffman tree
 * Returns 1 on success or -1 on error
 */
int bzip_read_huffman_tree(
     bit_stream_t *bit_stream,
     huffman_tree_t *huffman_tree,
     uint16_t number_of_symbols,
     libcerror_error_t **error )
{
	uint8_t code_size_array[ 258 ];

	static char *function     = "bzip_read_huffman_tree";
	uint32_t check_value      = 0;
	uint32_t value_32bit      = 0;
	uint16_t symbol_index     = 0;
	uint8_t code_size         = 0;
	uint8_t largest_code_size = 0;

	if( bit_stream_get_value(
	     bit_stream,
	     5,
	     &value_32bit,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve value from bit stream.",
		 function );

		return( -1 );
	}
	code_size = (uint8_t) ( value_32bit & 0x0000001fUL );

	for( symbol_index = 0;
	     symbol_index < number_of_symbols;
	     symbol_index++ )
	{
		while( code_size < 20 )
		{
			if( bit_stream_get_value(
			     bit_stream,
			     1,
			     &value_32bit,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to retrieve value from bit stream.",
				 function );

				return( -1 );
			}
			if( value_32bit == 0 )
			{
				break;
			}
			if( bit_stream_get_value(
			     bit_stream,
			     1,
			     &value_32bit,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to retrieve value from bit stream.",
				 function );

				return( -1 );
			}
			if( value_32bit == 0 )
			{
				code_size += 1;
			}
			else
			{
				code_size -= 1;
			}
		}
		if( code_size >= 20 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
			 "%s: invalid code size value out of bounds.",
			 function );

			return( -1 );
		}
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: symbol: % 3" PRIu16 " code size\t\t\t\t: %" PRIu8 "\n",
			 function,
			 symbol_index,
			 code_size );
		}
		code_size_array[ symbol_index ] = code_size;

		if( code_size > largest_code_size )
		{
			largest_code_size = code_size;
		}
	}
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "\n" );
	}
	if( largest_code_size > 32 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid largest code size value out of bounds.",
		 function );

		return( -1 );
	}
	check_value = 1 << largest_code_size;

	for( symbol_index = 0;
	     symbol_index < number_of_symbols;
	     symbol_index++ )
	{
		code_size    = code_size_array[ symbol_index ];
		check_value -= 1 << ( largest_code_size - code_size );
	}
	if( check_value != 0 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid check value out of bounds.",
		 function );

		return( -1 );
	}
	if( huffman_tree_build(
	     huffman_tree,
	     code_size_array,
	     number_of_symbols,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to build Huffman tree.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Reads the Huffman trees
 * Returns 1 on success or -1 on error
 */
int bzip_read_huffman_trees(
     bit_stream_t *bit_stream,
     huffman_tree_t **huffman_trees,
     uint8_t number_of_trees,
     uint16_t number_of_symbols,
     libcerror_error_t **error )
{
	huffman_tree_t *huffman_tree = NULL;
	static char *function        = "bzip_read_huffman_trees";
	uint8_t tree_index           = 0;

	if( huffman_trees == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid Huffman trees.",
		 function );

		return( -1 );
	}
	for( tree_index = 0;
	     tree_index < number_of_trees;
	     tree_index++ )
	{
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: reading Huffman tree: %" PRIu8 "\n",
			 function,
			 tree_index );
		}
		if( huffman_tree_initialize(
		     &huffman_tree,
		     number_of_symbols,
		     20,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
			 "%s: unable to create Huffman tree: %" PRIu8 ".",
			 function,
			 tree_index );

			goto on_error;
		}
		if( bzip_read_huffman_tree(
		     bit_stream,
		     huffman_tree,
		     number_of_symbols,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_IO,
			 LIBCERROR_IO_ERROR_READ_FAILED,
			 "%s: unable to read Huffman tree: %" PRIu8 ".",
			 function,
			 tree_index );

			goto on_error;
		}
		huffman_trees[ tree_index ] = huffman_tree;
		huffman_tree                = NULL;
	}
	return( 1 );

on_error:
	if( huffman_tree != NULL )
	{
		huffman_tree_free(
		 &huffman_tree,
		 NULL );
	}
	return( -1 );
}

/* Reads block data
 * Returns 1 on success or -1 on error
 */
int bzip_read_block_data(
     bit_stream_t *bit_stream,
     huffman_tree_t **huffman_trees,
     uint8_t number_of_trees,
     uint8_t *symbol_stack,
     uint16_t number_of_symbols,
     uint8_t *uncompressed_data,
     size_t uncompressed_data_size,
     libcerror_error_t **error )
{
	huffman_tree_t *huffman_tree         = NULL;
	static char *function                = "bzip_read_block_data";
	size_t data_index                    = 0;
	uint64_t run_length                  = 0;
	uint64_t run_length_value            = 0;
	uint32_t symbol                      = 0;
	uint16_t end_of_block_symbol         = 0;
	uint8_t number_of_run_length_symbols = 0;
	uint8_t stack_index                  = 0;
	uint8_t stack_value                  = 0;
	uint8_t stack_value_index            = 0;

	if( bit_stream == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid bit stream.",
		 function );

		return( -1 );
	}
	if( huffman_trees == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid Huffman trees.",
		 function );

		return( -1 );
	}
	if( symbol_stack == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid symbol stack.",
		 function );

		return( -1 );
	}
	if( uncompressed_data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid uncompressed data.",
		 function );

		return( -1 );
	}
	if( uncompressed_data_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid uncompressed data size value exceeds maximum.",
		 function );

		return( -1 );
	}
	end_of_block_symbol = number_of_symbols - 1;

	huffman_tree = huffman_trees[ 0 ];

	do
	{
		if( huffman_tree_get_symbol_from_bit_stream(
		     huffman_tree,
		     bit_stream,
		     &symbol,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve symbol from literals Huffman tree.",
			 function );

			return( -1 );
		}
		if( ( number_of_run_length_symbols != 0 )
		 && ( symbol > 1 ) )
		{
			run_length = ( ( (uint64_t) 1 << number_of_run_length_symbols ) | run_length_value ) - 1;

			if( libcnotify_verbose != 0 )
			{
				libcnotify_printf(
				 "%s: 0-byte run-length\t\t\t\t\t: %" PRIu64 "\n",
				 function,
				 run_length );
			}
			run_length_value             = 0;
			number_of_run_length_symbols = 0;

/* TODO MTF transform of run-length */
		}
		if( ( symbol == 0 )
		 || ( symbol == 1 ) )
		{
			run_length_value            <<= 1;
			run_length_value             |= symbol;
			number_of_run_length_symbols += 1;

			if( libcnotify_verbose != 0 )
			{
				libcnotify_printf(
				 "%s: symbol\t\t\t\t\t\t: %" PRIu32 " (run-length)\n",
				 function,
				 symbol );
			}
		}
		else if( symbol < end_of_block_symbol )
		{
			stack_value_index = symbol - 1;
			stack_value       = symbol_stack[ stack_value_index ];

			for( stack_index = stack_value_index;
			     stack_index > 0;
			     stack_index-- )
			{
				symbol_stack[ stack_index ] = symbol_stack[ stack_index - 1 ];
			}
			symbol_stack[ 0 ] = stack_value;

			if( libcnotify_verbose != 0 )
			{
				libcnotify_printf(
				 "%s: symbol\t\t\t\t\t\t: %" PRIu32 " (MTF: %" PRIu8 ")\n",
				 function,
				 symbol,
				 stack_value );
			}
		}
	}
	while( symbol != end_of_block_symbol );

/* TODO perform BTW */

	return( 1 );
}

/* Reads a stream foorter
 * Returns 1 on success or -1 on error
 */
int bzip_read_stream_footer(
     bit_stream_t *bit_stream,
     libcerror_error_t **error )
{
	static char *function = "bzip_read_stream_footer";
	uint64_t signature    = 0;
	uint32_t checksum     = 0;
	uint32_t value_32bit  = 0;

	if( bit_stream_get_value(
	     bit_stream,
	     32,
	     &value_32bit,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve value from bit stream.",
		 function );

		return( -1 );
	}
	signature = value_32bit;

	if( bit_stream_get_value(
	     bit_stream,
	     16,
	     &value_32bit,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve value from bit stream.",
		 function );

		return( -1 );
	}
	signature <<= 16;
	signature  |= value_32bit;

	if( bit_stream_get_value(
	     bit_stream,
	     32,
	     &checksum,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve value from bit stream.",
		 function );

		return( -1 );
	}
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: signature\t\t\t\t: 0x%08" PRIx64 "\n",
		 function,
		 signature );

		libcnotify_printf(
		 "%s: checksum\t\t\t\t: 0x%08" PRIx32 "\n",
		 function,
		 checksum );

		libcnotify_printf(
		 "\n" );
	}
	if( signature != 0x177245385090UL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported signature.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Decompresses data using BZIP2 compression
 * Returns 1 on success or -1 on error
 */
int bzip_decompress(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     uint8_t *uncompressed_data,
     size_t *uncompressed_data_size,
     libcerror_error_t **error )
{
	uint8_t symbol_stack[ 256 ];
	uint8_t selectors[ ( 1 << 15 ) + 1 ];

	huffman_tree_t *huffman_trees[ 7 ] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL };

	bit_stream_t *bit_stream           = NULL;
	static char *function              = "bzip_decompress";
	size_t compressed_data_offset      = 0;
	size_t safe_uncompressed_data_size = 0;
	size_t uncompressed_data_offset    = 0;
	uint32_t value_32bit               = 0;
	uint16_t number_of_selectors       = 0;
	uint16_t number_of_symbols         = 0;
	uint8_t number_of_trees            = 0;
	uint8_t tree_index                 = 0;

	if( compressed_data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid compressed data.",
		 function );

		return( -1 );
	}
	if( compressed_data_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid compressed data size value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( uncompressed_data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid uncompressed data.",
		 function );

		return( -1 );
	}
	if( uncompressed_data_size == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid uncompressed data size.",
		 function );

		return( -1 );
	}
	if( *uncompressed_data_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid uncompressed data size value exceeds maximum.",
		 function );

		return( -1 );
	}
	safe_uncompressed_data_size = *uncompressed_data_size;

	if( bzip_read_stream_header(
	     compressed_data,
	     compressed_data_size,
	     &compressed_data_offset,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_READ_FAILED,
		 "%s: unable to read stream header.",
		 function );

		goto on_error;
	}
	if( ( compressed_data_size < 10 )
	 || ( compressed_data_offset > ( compressed_data_size - 10 ) ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: invalid compressed data value too small.",
		 function );

		return( -1 );
	}
	if( ( compressed_data[ compressed_data_offset ] == 0x31 )
	 && ( compressed_data[ compressed_data_offset + 1 ] == 0x41 )
	 && ( compressed_data[ compressed_data_offset + 2 ] == 0x59 )
	 && ( compressed_data[ compressed_data_offset + 3 ] == 0x26 )
	 && ( compressed_data[ compressed_data_offset + 4 ] == 0x53 )
	 && ( compressed_data[ compressed_data_offset + 5 ] == 0x59 ) )
	{
		if( bit_stream_initialize(
		     &bit_stream,
		     compressed_data,
		     compressed_data_size,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
			 "%s: unable to create bit-stream.",
			 function );

			goto on_error;
		}
		bit_stream->storage_type = BIT_STREAM_STORAGE_TYPE_BYTE_FRONT_TO_BACK;

/* TODO add seek byte offset function */
		bit_stream->byte_stream_offset = compressed_data_offset;

		while( bit_stream->byte_stream_offset < bit_stream->byte_stream_size )
		{
			if( bzip_read_block_header(
			     bit_stream,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_IO,
				 LIBCERROR_IO_ERROR_READ_FAILED,
				 "%s: unable to read block header.",
				 function );

				goto on_error;
			}
			if( memory_set(
			     symbol_stack,
			     0,
			     256 ) == NULL )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_MEMORY,
				 LIBCERROR_MEMORY_ERROR_SET_FAILED,
				 "%s: unable to clear symbol stack.",
				 function );

				goto on_error;
			}
			if( bzip_read_symbol_stack(
			     bit_stream,
			     symbol_stack,
			     &number_of_symbols,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_IO,
				 LIBCERROR_IO_ERROR_READ_FAILED,
				 "%s: unable to read symbol stack.",
				 function );

				goto on_error;
			}
			if( bit_stream_get_value(
			     bit_stream,
			     18,
			     &value_32bit,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to retrieve value from bit stream.",
				 function );

				goto on_error;
			}
			number_of_selectors = (uint16_t) ( value_32bit & 0x00007fffUL );
			value_32bit       >>= 15;
			number_of_trees     = (uint8_t) ( value_32bit & 0x00000007UL );

			if( libcnotify_verbose != 0 )
			{
				libcnotify_printf(
				 "%s: number of trees\t\t\t\t: %" PRIu8 "\n",
				 function,
				 number_of_trees );

				libcnotify_printf(
				 "%s: number of selectors\t\t\t\t: %" PRIu16 "\n",
				 function,
				 number_of_selectors );

				libcnotify_printf(
				 "\n" );
			}
			if( bzip_read_selectors(
			     bit_stream,
			     selectors,
			     number_of_trees,
			     number_of_selectors,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_IO,
				 LIBCERROR_IO_ERROR_READ_FAILED,
				 "%s: unable to read selectors.",
				 function );

				goto on_error;
			}
			if( bzip_read_huffman_trees(
			     bit_stream,
			     huffman_trees,
			     number_of_trees,
			     number_of_symbols,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_IO,
				 LIBCERROR_IO_ERROR_READ_FAILED,
				 "%s: unable to read Huffman trees.",
				 function );

				goto on_error;
			}
			if( bzip_read_block_data(
			     bit_stream,
			     huffman_trees,
			     number_of_trees,
			     symbol_stack,
			     number_of_symbols,
			     uncompressed_data,
			     safe_uncompressed_data_size,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_IO,
				 LIBCERROR_IO_ERROR_READ_FAILED,
				 "%s: unable to read block data.",
				 function );

				goto on_error;
			}
			for( tree_index = 0;
			     tree_index < number_of_trees;
			     tree_index++ )
			{
				if( huffman_tree_free(
				     &( huffman_trees[ tree_index ] ),
				     error ) != 1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
					 "%s: unable to free Huffman tree: %" PRIu8 ".",
					 function,
					 tree_index );

					goto on_error;
				}
			}
			break;
		}
	}
/* TODO check stream footer */

	if( bit_stream_free(
	     &bit_stream,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
		 "%s: unable to free bit-stream.",
		 function );

		goto on_error;
	}
	*uncompressed_data_size = uncompressed_data_offset;

	return( 1 );

on_error:
	if( bit_stream != NULL )
	{
		bit_stream_free(
		 &bit_stream,
		 NULL );
	}
	return( -1 );
}

