/*
 * MS Search (de/en)code functions
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

#include <common.h>
#include <byte_stream.h>
#include <memory.h>
#include <types.h>

#include "assorted_libcerror.h"
#include "assorted_libcnotify.h"
#include "mssearch.h"

/* Decode data using Windows Search encoding
 * Returns 1 on success or -1 on error
 */
int mssearch_decode(
     uint8_t *data,
     size_t data_size,
     uint8_t *encoded_data,
     size_t encoded_data_size,
     libcerror_error_t **error )
{
	static char *function        = "mssearch_decode";
	size_t data_iterator         = 0;
	size_t encoded_data_iterator = 0;
	uint32_t bitmask32           = 0;
	uint8_t bitmask              = 0;

	if( encoded_data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid encoded data.",
		 function );

		return( -1 );
	}
	if( encoded_data_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid encoded data size value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( data_size < encoded_data_size )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: data size value too small.",
		 function );

		return( -1 );
	}
	bitmask32 = 0x05000113 ^ (uint32_t) encoded_data_size;

	for( encoded_data_iterator = 0;
	     encoded_data_iterator < encoded_data_size;
	     encoded_data_iterator++ )
	{
		switch( encoded_data_iterator & 0x03 )
		{
			case 3:
				bitmask = (uint8_t) ( ( bitmask32 >> 24 ) & 0xff );
				break;
			case 2:
				bitmask = (uint8_t) ( ( bitmask32 >> 16 ) & 0xff );
				break;
			case 1:
				bitmask = (uint8_t) ( ( bitmask32 >> 8 ) & 0xff );
				break;
			default:
				bitmask = (uint8_t) ( bitmask32 & 0xff );
				break;
		}
		bitmask ^= encoded_data_iterator;

		data[ data_iterator++ ] = encoded_data[ encoded_data_iterator ]
		                        ^ bitmask;
	}
	return( 1 );
}

/* Determines the uncompressed size of a run-length compressed UTF-16 string
 * Returns 1 on success or -1 on error
 */
int mssearch_get_run_length_uncompressed_utf16_string_size(
     uint8_t *compressed_data,
     size_t compressed_data_size,
     size_t *uncompressed_data_size,
     libcerror_error_t **error )
{
	static char *function           = "mssearch_get_run_length_uncompressed_utf16_string_size";
	size_t compressed_data_iterator = 0;
	uint8_t compression_size        = 0;

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
	*uncompressed_data_size = 0;

	while( compressed_data_iterator < compressed_data_size )
	{
		if( compressed_data_iterator >= compressed_data_size )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
			 "%s: compressed data size value too small.",
			 function );

			*uncompressed_data_size = 0;

			return( -1 );
		}
		compression_size = compressed_data[ compressed_data_iterator++ ];

		/* Check if the last byte in the compressed string was the compression size
		 * or the run-length byte value
		 */
		if( ( compressed_data_iterator + 1 ) >= compressed_data_size )
		{
			break;
		}
		/* Check if the compressed string was cut-short at the end
		 */
		if( ( compressed_data_iterator + 1 + compression_size ) > compressed_data_size )
		{
#if defined( HAVE_DEBUG_OUTPUT )
fprintf( stderr, "MARKER: %zd, %d, %zd, %zd\n",
 compressed_data_iterator, compression_size, compressed_data_size,
 compressed_data_size - compressed_data_iterator - 1 );
#endif
			compression_size = (uint8_t) ( compressed_data_size - compressed_data_iterator - 1 );
		}
		*uncompressed_data_size  += compression_size * 2;
		compressed_data_iterator += compression_size + 1;
	}
	if( compressed_data_iterator > compressed_data_size )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: compressed data size value too small.",
		 function );

		*uncompressed_data_size = 0;

		return( -1 );
	}
	return( 1 );
}

/* Decompresses a run-length compressed UTF-16 string
 * Returns 1 on success or -1 on error
 */
int mssearch_decompress_run_length_compressed_utf16_string(
     uint8_t *uncompressed_data,
     size_t uncompressed_data_size,
     uint8_t *compressed_data,
     size_t compressed_data_size,
     libcerror_error_t **error )
{
	static char *function             = "mssearch_decompress_run_length_compressed_utf16_string";
	size_t compressed_data_iterator   = 0;
	size_t uncompressed_data_iterator = 0;
	uint8_t compression_size          = 0;
	uint8_t compression_byte          = 0;

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
	while( compressed_data_iterator < compressed_data_size )
	{
		if( compressed_data_iterator >= compressed_data_size )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
			 "%s: compressed data size value too small.",
			 function );

			return( -1 );
		}
		compression_size = compressed_data[ compressed_data_iterator++ ];

		/* Check if the last byte in the compressed string was the compression size
		 * or the run-length byte value
		 */
		if( ( compressed_data_iterator + 1 ) >= compressed_data_size )
		{
			break;
		}
		/* Check if the compressed string was cut-short at the end
		 */
		if( ( compressed_data_iterator + 1 + compression_size ) > compressed_data_size )
		{
			compression_size = (uint8_t) ( compressed_data_size - compressed_data_iterator - 1 );
		}
		if( compressed_data_iterator >= compressed_data_size )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
			 "%s: compressed data size value too small.",
			 function );

			return( -1 );
		}
		compression_byte = compressed_data[ compressed_data_iterator++ ];

		while( compression_size > 0 )
		{
			if( compressed_data_iterator >= compressed_data_size )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
				 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
				 "%s: compressed data size value too small.",
				 function );

				return( -1 );
			}
			if( ( uncompressed_data_iterator + 1 ) >= uncompressed_data_size )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
				 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
				 "%s: uncompressed data size value too small.",
				 function );

				return( -1 );
			}
			uncompressed_data[ uncompressed_data_iterator++ ] = compressed_data[ compressed_data_iterator++ ];
			uncompressed_data[ uncompressed_data_iterator++ ] = compression_byte;

			compression_size--;
		}
	}
	return( 1 );
}

/* Determines the uncompressed data size of a run-length compressed UTF-16 string
 * Returns 1 on success or -1 on error
 */
int mssearch_get_byte_index_uncompressed_data_size(
     uint8_t *compressed_data,
     size_t compressed_data_size,
     size_t *uncompressed_data_size,
     libcerror_error_t **error )
{
	static char *function                  = "mssearch_get_byte_index_uncompressed_size";
	uint16_t stored_uncompressed_data_size = 0;

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
	/* The first 2 bytes contain the uncompressed data size
	 */
	byte_stream_copy_to_uint16_little_endian(
	 compressed_data,
	 stored_uncompressed_data_size );

	*uncompressed_data_size = (size_t) stored_uncompressed_data_size;

	return( 1 );
}

/* Decompresses byte-index compressed data
 * Returns 1 on success or -1 on error
 */
int mssearch_decompress_byte_indexed_compressed_data(
     uint8_t *uncompressed_data,
     size_t uncompressed_data_size,
     uint8_t *compressed_data,
     size_t compressed_data_size,
     libcerror_error_t **error )
{
	uint16_t compression_value_table[ 2048 ];

	uint32_t nibble_count_table[ 16 ]       = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	uint32_t total_nibble_count_table[ 16 ] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	static char *function                   = "mssearch_decompress_byte_indexed_compressed_data";
	size_t compressed_data_iterator         = 0;
	size_t compression_iterator             = 0;
	size_t uncompressed_data_iterator       = 0;

	uint32_t compressed_data_bit_stream     = 0;
	uint32_t compression_offset             = 0;
	uint32_t nibble_count                   = 0;
	uint32_t total_nibble_count             = 0;
	uint32_t value_32bit                    = 0;
	int32_t compression_value_table_index   = 0;
	uint16_t compression_size               = 0;
	uint16_t compression_value              = 0;
	uint16_t stored_uncompressed_data_size  = 0;
	uint16_t value_0x0400                   = 0;
	uint16_t value_0x0800                   = 0;
	uint16_t value_0x2000                   = 0;
	uint8_t nibble_count_table_index        = 0;
	int8_t number_of_bits_available         = 0;
	int8_t number_of_bits_used              = 0;

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
	if( compressed_data_size <= 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: compressed data size value too small.",
		 function );

		return( -1 );
	}
	if( memory_set(
	     compression_value_table,
	     0,
	     2048 * 2 ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear compression value table.",
		 function );

		return( -1 );
	}
#if defined( HAVE_DEBUG_OUTPUT ) && defined( HAVE_EXTRA_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: compressed data header:\n",
		 function );
		libcnotify_print_data(
		 compressed_data,
		 258,
		 0 );
	}
#endif
	/* Byte 0 - 1 contain the uncompressed data size
	 */
	byte_stream_copy_to_uint16_little_endian(
	 compressed_data,
	 stored_uncompressed_data_size );

	if( uncompressed_data_size < stored_uncompressed_data_size )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: uncompressed data size value too small.",
		 function );

		return( -1 );
	}
	/* Byte 2 - 257 contain the compression table
	 *
	 * The table contains a compression value for every byte
	 * bits 0 - 3 contain ???
	 * bits 4 - 7 contain the number of bits used to store the compressed data
	 */
	for( compressed_data_iterator = 0;
	     compressed_data_iterator < 256;
	     compressed_data_iterator++ )
	{
		nibble_count_table_index = compressed_data[ 2 + compressed_data_iterator ];

		nibble_count_table[ nibble_count_table_index & 0x0f ] += 1;
		nibble_count_table[ nibble_count_table_index >> 4 ]   += 1;
	}
#if defined( HAVE_DEBUG_OUTPUT ) && defined( HAVE_EXTRA_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: uncompressed data size:\t%" PRIu16 "\n",
		 function,
		 stored_uncompressed_data_size );

		for( nibble_count_table_index = 0;
		     nibble_count_table_index < 16;
		     nibble_count_table_index++ )
		{
			libcnotify_printf(
			 "%s: nibble count table index: %02d value:\t\t0x%08" PRIx32 " (%" PRIu32 ")\n",
			 function,
			 nibble_count_table_index,
			 nibble_count_table[ nibble_count_table_index ],
			 nibble_count_table[ nibble_count_table_index ] );
		}
		libcnotify_printf(
		 "\n" );
	}
#endif
	if( nibble_count_table[ 0 ] >= 0x01ff )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: first nibble count table entry value exceeds maximum.",
		 function );

		return( -1 );
	}
	/* Make copy of the nibble count table
	 */
	for( nibble_count_table_index = 0;
	     nibble_count_table_index < 16;
	     nibble_count_table_index++ )
	{
		total_nibble_count_table[ nibble_count_table_index ] = nibble_count_table[ nibble_count_table_index ];
	}
	/* TODO why this loop */
	nibble_count = 0;

	for( nibble_count_table_index = 15;
	     nibble_count_table_index > 0;
	     nibble_count_table_index-- )
	{
		nibble_count += total_nibble_count_table[ nibble_count_table_index ];

		if( nibble_count == 1 )
		{
			break;
		}
		nibble_count >>= 1;
	}
	if( nibble_count != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: nibble count value exceeds maximum.",
		 function );

		return( -1 );
	}
	/* Determine the total nible counts
	 */
	nibble_count = 0;

#if defined( HAVE_DEBUG_OUTPUT ) && defined( HAVE_EXTRA_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: total nibble count table index: %02d value:\t0x%08" PRIx32 " (%" PRIu32 ")\n",
		 function,
		 0,
		 total_nibble_count_table[ 0 ],
		 total_nibble_count_table[ 0 ] );
	}
#endif

	for( nibble_count_table_index = 1;
	     nibble_count_table_index < 16;
	     nibble_count_table_index++ )
	{
		total_nibble_count_table[ nibble_count_table_index ] += nibble_count;
		nibble_count                                          = total_nibble_count_table[ nibble_count_table_index ];

#if defined( HAVE_DEBUG_OUTPUT ) && defined( HAVE_EXTRA_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: total nibble count table index: %02d value:\t0x%08" PRIx32 " (%" PRIu32 ")\n",
			 function,
			 nibble_count_table_index,
			 total_nibble_count_table[ nibble_count_table_index ],
			 total_nibble_count_table[ nibble_count_table_index ] );
		}
#endif
	}
#if defined( HAVE_DEBUG_OUTPUT ) && defined( HAVE_EXTRA_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "\n" );
	}
#endif

	total_nibble_count = nibble_count;

	/* Fill the compression value table
	 */
	value_0x2000 = 0x2000;

	while( value_0x2000 > 0 )
	{
		value_0x2000 -= 0x10;

		compressed_data_iterator = value_0x2000 >> 5;

		nibble_count_table_index = compressed_data[ 2 + compressed_data_iterator ] >> 4;

		if( nibble_count_table_index > 0 )
		{
			total_nibble_count_table[ nibble_count_table_index ] -= 1;
			compression_value_table_index                         = total_nibble_count_table[ nibble_count_table_index ];

			if( compression_value_table_index > 2048 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
				 "%s: compression value table index value exceeds maximum.",
				 function );

				return( -1 );
			}
			compression_value_table[ compression_value_table_index ] = value_0x2000 | nibble_count_table_index;
		}
		value_0x2000 -= 0x10;

		compressed_data_iterator = value_0x2000 >> 5;

		nibble_count_table_index = compressed_data[ 2 + compressed_data_iterator ] & 0x0f;

		if( nibble_count_table_index > 0 )
		{
			total_nibble_count_table[ nibble_count_table_index ] -= 1;
			compression_value_table_index                         = total_nibble_count_table[ nibble_count_table_index ];

			if( compression_value_table_index > 2048 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
				 "%s: compression value table index value exceeds maximum.",
				 function );

				return( -1 );
			}
			compression_value_table[ compression_value_table_index ] = value_0x2000 | nibble_count_table_index;
		}
	}
	compression_value_table_index = 0x0800;
	value_0x0800                  = 0x0800;
	value_0x0400                  = 0x0400;

	if( total_nibble_count > 2048 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: total nibble count value exceeds maximum.",
		 function );

		return( -1 );
	}
	for( nibble_count_table_index = 15;
	     nibble_count_table_index > 10;
	     nibble_count_table_index-- )
	{
		if( value_0x0800 > compression_value_table_index )
		{
			value_0x0800                  -= 2;
			compression_value_table_index -= 1;

			compression_value_table[ compression_value_table_index ] = value_0x0800 | 0x8000;
		}
		for( nibble_count = nibble_count_table[ nibble_count_table_index ];
		     nibble_count > 0;
		     nibble_count-- )
		{
			total_nibble_count -= 1;

			compression_value              = compression_value_table[ total_nibble_count ];
			compression_value_table_index -= 1;

			compression_value_table[ compression_value_table_index ] = compression_value;
		}
	}
	while( value_0x0800 > compression_value_table_index )
	{
		value_0x0800 -= 2;
		value_0x0400 -= 1;

		compression_value_table[ value_0x0400 ] = value_0x0800 | 0x8000;
	}
	while( total_nibble_count > 0 )
	{
		total_nibble_count -= 1;

		compression_value             = compression_value_table[ total_nibble_count ];
		compression_value_table_index = value_0x0400 - ( 0x0400 >> ( compression_value & 0x0f ) );

		do
		{
			value_0x0400 -= 1;

			compression_value_table[ value_0x0400 ] = compression_value;
		}
		while( value_0x0400 > compression_value_table_index );
	}

#if defined( HAVE_DEBUG_OUTPUT ) && defined( HAVE_EXTRA_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: compression value table:\n",
		 function );
		libcnotify_print_data(
		 (uint8_t *) compression_value_table,
		 2 * 2048,
		 0 );
	}
#endif
	/* Byte 258 - end contain the compression data bit stream
	 */
	compressed_data_iterator = 2 + 0x100;

	if( ( compressed_data_iterator + 3 ) >= compressed_data_size )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: compressed data size value too small.",
		 function );

		return( -1 );
	}
	/* Read the data as 16-bit little endian values
	 */
	compressed_data_bit_stream   = compressed_data[ compressed_data_iterator + 1 ];
	compressed_data_bit_stream <<= 8;
	compressed_data_bit_stream  += compressed_data[ compressed_data_iterator ];
	compressed_data_bit_stream <<= 8;
	compressed_data_bit_stream  += compressed_data[ compressed_data_iterator + 3 ];
	compressed_data_bit_stream <<= 8;
	compressed_data_bit_stream  += compressed_data[ compressed_data_iterator + 2 ];

	compressed_data_iterator += 4;

	number_of_bits_available = 0x10;

	/* The compression data is stored a 16-bit little-endian values
	 * it contains a bit stream which contains the following values
	 * starting with the first bit in the stream
	 * 0 - 9 compression value table index (where 0 is the MSB of the value)
	 */
	while( compressed_data_iterator < compressed_data_size )
	{
		/* Read a 10-bit table index from the decoded data
		 * maximum index of 1023
		 */
		compression_value_table_index = compressed_data_bit_stream >> 0x16;

		/* Check if the table entry contains an ignore index flag (bit 15)
		 */
		if( ( compression_value_table[ compression_value_table_index ] & 0x8000 ) != 0 )
		{
			/* Ignore the 10-bit index
			 */
			compressed_data_bit_stream <<= 10;

			do
			{
				compression_value_table_index = compression_value_table[ compression_value_table_index ] & 0x7fff;

				/* Add the MSB of the compressed data bit stream to the
				 * compression value table index
				 */
				compression_value_table_index += compressed_data_bit_stream >> 31;

				/* Ignore 1 bit for empty compression values
				 */
				compressed_data_bit_stream <<= 1;

				if( compression_value_table_index > 2048 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
					 "%s: compression value table index value exceeds maximum.",
					 function );

					return( -1 );
				}
			}
			while( compression_value_table[ compression_value_table_index ] == 0 );

			/* Retrieve the number of bits used (lower 4-bit) of from the table entry
			 */
			number_of_bits_used = (int8_t) ( compression_value_table[ compression_value_table_index ] & 0x0f );

			/* Retrieve the compression value from the table entry
			 */
			compression_value = compression_value_table[ compression_value_table_index ] >> 4;

			number_of_bits_available -= number_of_bits_used;
		}
		else
		{
			/* Retrieve the number of bits used (lower 4-bit) of from the table entry
			 */
			number_of_bits_used = (int8_t) ( compression_value_table[ compression_value_table_index ] & 0x0f );

			/* Retrieve the compression value from the table entry
			 */
			compression_value = compression_value_table[ compression_value_table_index ] >> 4;

			number_of_bits_available    -= number_of_bits_used;
			compressed_data_bit_stream <<= number_of_bits_used;
		}
		if( number_of_bits_available < 0 )
		{
			number_of_bits_used = -1 * number_of_bits_available;

			if( ( compressed_data_iterator + 1 ) >= compressed_data_size )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
				 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
				 "%s: compressed data size value too small.",
				 function );

				return( -1 );
			}
			/* Read the data as 16-bit little endian values
			 */
			value_32bit   = compressed_data[ compressed_data_iterator + 1 ];
			value_32bit <<= 8;
			value_32bit  += compressed_data[ compressed_data_iterator ];

			compressed_data_iterator += 2;

			value_32bit               <<= number_of_bits_used;
			compressed_data_bit_stream += value_32bit;

			number_of_bits_available += 0x10;
		}
		/* Check if the table entry contains a compression tuple flag (bit 12)
		 */
		if( ( compression_value_table[ compression_value_table_index ] & 0x1000 ) != 0 )
		{
			/* Retrieve the size of the compression (bit 4-7) from the table entry
			 */
			compression_size = (uint16_t) ( ( compression_value_table[ compression_value_table_index ] >> 4 ) & 0x0f );

			/* Retrieve the size of the compression (bit 8-11) from the table entry
			 */
			number_of_bits_used = (int8_t) ( ( compression_value_table[ compression_value_table_index ] >> 8 ) & 0x0f );

			/* Break if the end of the compressed data is reached
			 * and both the compression size and number of bits used for the compression offset are 0
			 */
			if( ( compressed_data_iterator == compressed_data_size )
			 && ( compression_size == 0 )
			 && ( number_of_bits_used == 0 ) )
			{
				break;
			}
			/* Retrieve the compression offset from the decoded data
			 */
			compression_offset = ( compressed_data_bit_stream >> 1 ) | 0x80000000;

			compression_offset = ( compression_offset >> ( 31 - number_of_bits_used ) );

			compressed_data_bit_stream <<= number_of_bits_used;
			number_of_bits_available    -= number_of_bits_used;

			if( compression_size == 0x0f )
			{
				if( compressed_data_iterator >= compressed_data_size )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
					 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
					 "%s: compressed data size value too small.",
					 function );

					return( -1 );
				}
				compression_size += compressed_data[ compressed_data_iterator ];

				compressed_data_iterator += 1;
			}
			if( compression_size == ( 0xff + 0x0f ) )
			{
				if( ( compressed_data_iterator + 1 ) >= compressed_data_size )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
					 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
					 "%s: compressed data size value too small.",
					 function );

					return( -1 );
				}
				byte_stream_copy_to_uint16_little_endian(
				 &( compressed_data[ compressed_data_iterator ] ),
				 compression_size );

				compressed_data_iterator += 2;

				if( compression_size < ( 0xff + 0x0f ) )
				{
					/* TODO error */
					return( -1 );
				}
			}
			compression_size += 3;

			if( number_of_bits_available < 0 )
			{
				number_of_bits_used = -1 * number_of_bits_available;

				if( ( compressed_data_iterator + 1 ) >= compressed_data_size )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
					 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
					 "%s: compressed data size value too small.",
					 function );

					return( -1 );
				}
				/* Read the data as 16-bit little endian values
				 */
				value_32bit   = compressed_data[ compressed_data_iterator + 1 ];
				value_32bit <<= 8;
				value_32bit  += compressed_data[ compressed_data_iterator ];

				compressed_data_iterator += 2;

				value_32bit               <<= number_of_bits_used;
				compressed_data_bit_stream += value_32bit;

				number_of_bits_available += 0x10;
			}
			if( ( uncompressed_data_iterator + compression_size ) > uncompressed_data_size )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
				 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
				 "%s: uncompressed data size value too small.",
				 function );

				return( -1 );
			}
			if( compression_offset > uncompressed_data_iterator )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
				 "%s: compression offset value exceeds uncompressed data iterator.",
				 function );

				return( -1 );
			}
			compression_iterator = uncompressed_data_iterator - compression_offset;

			while( compression_size > 0 )
			{
				uncompressed_data[ uncompressed_data_iterator++ ] = uncompressed_data[ compression_iterator++ ];

				compression_size--;
			}
		}
		else
		{
			if( uncompressed_data_iterator >= uncompressed_data_size )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
				 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
				 "%s: uncompressed data size value too small.",
				 function );

				return( -1 );
			}
			uncompressed_data[ uncompressed_data_iterator++ ] = (uint8_t) ( compression_value & 0xff );
		}
	}
#if defined( HAVE_DEBUG_OUTPUT ) && defined( HAVE_EXTRA_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: uncompressed data:\n",
		 function );
		libcnotify_print_data(
		 uncompressed_data,
		 uncompressed_data_iterator,
		 0 );
	}
#endif
	return( 1 );
}

