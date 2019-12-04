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

#include <common.h>
#include <memory.h>
#include <types.h>

#include "assorted_libcerror.h"
#include "assorted_libcnotify.h"
#include "bit_stream.h"
#include "lzx.h"

/* Initializes a Huffman table
 * Returns 1 on success or -1 on error
 */
int lzx_initialize_huffman_table(
     bit_stream_t *bit_stream,
     libcerror_error_t **error )
{
	uint8_t code_size_array[ 20 ];

	static char *function = "lzx_initialize_huffman_table";
	uint32_t value_32bit  = 0;
	int array_index       = 0;

	if( bit_stream == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid bit-stream.",
		 function );

		return( -1 );
	}
	for( array_index = 0;
	     array_index < 20;
	     array_index++ )
	{
		if( bit_stream_get_value(
		     bit_stream,
		     4,
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
		code_size_array[ array_index ] = (uint8_t) value_32bit;
	}
	/* TODO create Huffman table */

	/* TODO read code sizes */

	/* TODO create Huffman table */

	return( 1 );
}

/* Decompresses LZX compressed data
 * Returns 1 on success or -1 on error
 */
int lzx_decompress(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     uint8_t *uncompressed_data,
     size_t *uncompressed_data_size,
     libcerror_error_t **error )
{
	uint8_t aligned_offset_code_size_array[ 256 ];

	bit_stream_t bit_stream;

	static char *function = "lzx_decompress";
	uint32_t block_size   = 0;
	uint32_t value_32bit  = 0;
	uint8_t block_type    = 0;
	int array_index       = 0;

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
	bit_stream.byte_stream        = compressed_data;
	bit_stream.byte_stream_size   = compressed_data_size;
	bit_stream.byte_stream_offset = 0;
	bit_stream.bit_buffer         = 0;
	bit_stream.bit_buffer_size    = 0;

/* TODO find optimized solution to read bit stream from bytes */
	while( bit_stream.byte_stream_offset < bit_stream.byte_stream_size )
	{
		if( bit_stream_get_value(
		     &bit_stream,
		     3,
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
		block_type = (uint8_t) value_32bit;

		if( bit_stream_get_value(
		     &bit_stream,
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
			block_size = 32768;
		}
		else
		{
			if( bit_stream_get_value(
			     &bit_stream,
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
			block_size = value_32bit;

/* TODO add extended block size support */
		}
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: block header block type\t\t\t\t\t: %" PRIu8 " (",
			 function,
			 block_type );

			switch( block_type )
			{
				case LZX_BLOCK_TYPE_ALIGNED:
					libcnotify_printf(
					 "Aligned" );
					break;

				case LZX_BLOCK_TYPE_VERBATIM:
					libcnotify_printf(
					 "Verbatim" );
					break;

				case LZX_BLOCK_TYPE_UNCOMPRESSED:
					libcnotify_printf(
					 "Uncompressed" );
					break;

				case LZX_BLOCK_TYPE_INVALID:
				default:
					libcnotify_printf(
					 "Invalid" );
					break;
			}
			libcnotify_printf(
			 ")\n" );

			libcnotify_printf(
			 "%s: block header block size\t\t\t\t\t: %" PRIu32 "\n",
			 function,
			 block_size );

			libcnotify_printf(
			 "\n" );
		}
		if( block_type == LZX_BLOCK_TYPE_ALIGNED )
		{
			for( array_index = 0;
			     array_index < 256;
			     array_index++ )
			{
				if( bit_stream_get_value(
				     &bit_stream,
				     3,
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
				aligned_offset_code_size_array[ array_index ] = (uint8_t) value_32bit;
			}
		}
		if( ( block_type == LZX_BLOCK_TYPE_ALIGNED )
		 || ( block_type == LZX_BLOCK_TYPE_VERBATIM ) )
		{
			/* TODO lzx_initialize_huffman_table literal symbols 256 */
			/* TODO lzx_initialize_huffman_table match headers */
			/* TODO lzx_initialize_huffman_table lengths */
		}
		switch( block_type )
		{
			case LZX_BLOCK_TYPE_ALIGNED:
			case LZX_BLOCK_TYPE_VERBATIM:
				break;

			case LZX_BLOCK_TYPE_UNCOMPRESSED:
				break;

			default:
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
				 "%s: unsupported block type.",
				 function );

				return( -1 );
		}
/* TODO implement */
	}
	return( 1 );
}

