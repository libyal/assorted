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

#define BLOCK_DATA_SIZE 8192

/* Table of the CRC-32 of all 8-bit messages.
 */
uint32_t bzip_crc32_table[ 256 ];

/* Value to indicate the CRC-32 table been computed
 */
int bzip_crc32_table_computed = 0;

/* Initializes the internal CRC-32 table
 * The table speeds up the CRC-32 calculation
 * The table is calcuted in reverse bit-order
 */
void bzip_initialize_crc32_table(
      void )
{
	uint32_t crc32             = 0;
	uint16_t crc32_table_index = 0;
	uint8_t bit_iterator       = 0;

	for( crc32_table_index = 0;
	     crc32_table_index < 256;
	     crc32_table_index++ )
	{
		crc32 = (uint32_t) crc32_table_index << 24;

		for( bit_iterator = 0;
		     bit_iterator < 8;
		     bit_iterator++ )
		{
			if( crc32 & 0x80000000UL )
			{
				crc32 = 0x04c11db7UL ^ ( crc32 << 1 );
			}
			else
			{
				crc32 = crc32 << 1;
			}
		}
		bzip_crc32_table[ crc32_table_index ] = crc32;
	}
	bzip_crc32_table_computed = 1;
}

/* Calculates the CRC-32 of a buffer
 * Use a previous key of 0 to calculate a new CRC-32
 * Returns 1 if successful or -1 on error
 */
int bzip_calculate_crc32(
     uint32_t *crc32,
     const uint8_t *data,
     size_t data_size,
     uint32_t initial_value,
     libcerror_error_t **error )
{
	static char *function      = "bzip_calculate_crc32";
	size_t data_offset         = 0;
	uint32_t crc32_table_index = 0;
	uint32_t safe_crc32        = 0;

	if( crc32 == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid CRC-32.",
		 function );

		return( -1 );
	}
	if( data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid data.",
		 function );

		return( -1 );
	}
	if( data_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid data size value exceeds maximum.",
		 function );

		return( -1 );
	}
        if( bzip_crc32_table_computed == 0 )
	{
		bzip_initialize_crc32_table();
	}
	safe_crc32 = initial_value ^ (uint32_t) 0xffffffffUL;

        for( data_offset = 0;
	     data_offset < data_size;
	     data_offset++ )
	{
		/* Use the upper 8-bits of the pre-calculated CRC-32 values due to BZip bit ordering
		 */
		crc32_table_index = ( ( safe_crc32 >> 24 ) ^ data[ data_offset ] ) & 0x000000ffUL;

		safe_crc32 = bzip_crc32_table[ crc32_table_index ] ^ ( safe_crc32 << 8 );
        }
        *crc32 = safe_crc32 ^ (uint32_t) 0xffffffffUL;

	return( 1 );
}

/* Reverses a Burrows-Wheeler transform and run-length encoded strings
 * Returns 1 on success or -1 on error
 */
int bzip_reverse_burrows_wheeler_transform(
     const uint8_t *input_data,
     size_t input_data_size,
     size_t *permutations,
     uint32_t origin_pointer,
     uint8_t *uncompressed_data,
     size_t uncompressed_data_size,
     size_t *uncompressed_data_offset,
     libcerror_error_t **error )
{
	size_t distributions[ 256 ];

	static char *function                = "bzip_reverse_burrows_wheeler_transform";
	size_t input_data_offset             = 0;
	size_t distribution_value            = 0;
	size_t number_of_values              = 0;
	size_t permutation_value             = 0;
	size_t safe_uncompressed_data_offset = 0;
	uint16_t byte_value                  = 0;
	uint16_t last_byte_value             = 0;
	uint8_t number_of_last_byte_values   = 0;

	if( input_data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid input data.",
		 function );

		return( -1 );
	}
	if( input_data_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid input data size value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( permutations == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid permutations.",
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
	if( uncompressed_data_offset == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid uncompressed data offset.",
		 function );

		return( -1 );
	}
	safe_uncompressed_data_offset = *uncompressed_data_offset;

	if( safe_uncompressed_data_offset > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid uncompressed data offset value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( memory_set(
	     distributions,
	     0,
	     sizeof( size_t ) * 256 ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear distributions.",
		 function );

		return( -1 );
	}
	for( input_data_offset = 0;
	     input_data_offset < input_data_size;
	     input_data_offset++ )
	{
		byte_value = input_data[ input_data_offset ];

		distributions[ byte_value ] += 1;
	}
	for( byte_value = 0;
	     byte_value < 256;
	     byte_value++ )
	{
		number_of_values = distributions[ byte_value ];

		distributions[ byte_value ] = distribution_value;

		distribution_value += number_of_values;
	}
	for( input_data_offset = 0;
	     input_data_offset < input_data_size;
	     input_data_offset++ )
	{
		byte_value = input_data[ input_data_offset ];

		distribution_value = distributions[ byte_value ];

		permutations[ distribution_value ] = input_data_offset;

		distributions[ byte_value ] += 1;
	}
	permutation_value = permutations[ origin_pointer ];

	for( input_data_offset = 0;
	     input_data_offset < input_data_size;
	     input_data_offset++ )
	{
		byte_value = input_data[ permutation_value ];

		if( number_of_last_byte_values == 4 )
		{
			if( ( byte_value > uncompressed_data_size )
			 || ( safe_uncompressed_data_offset > ( uncompressed_data_size - byte_value ) ) )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
				 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
				 "%s: invalid uncompressed data value too small.",
				 function );

				return( -1 );
			}
			while( byte_value > 0 )
			{
				uncompressed_data[ safe_uncompressed_data_offset++ ] = (uint8_t) last_byte_value;

				byte_value--;
			}
			last_byte_value            = 0;
			number_of_last_byte_values = 0;
		}
		else
		{
			if( byte_value != last_byte_value )
			{
				number_of_last_byte_values = 0;
			}
			last_byte_value             = byte_value;
			number_of_last_byte_values += 1;

			if( safe_uncompressed_data_offset >= uncompressed_data_size )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
				 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
				 "%s: invalid uncompressed data value too small.",
				 function );

				return( -1 );
			}
			uncompressed_data[ safe_uncompressed_data_offset++ ] = (uint8_t) byte_value;
		}
		permutation_value = permutations[ permutation_value ];
	}
	*uncompressed_data_offset = safe_uncompressed_data_offset;

	return( 1 );
}

/* Reads the stream header
 * Returns 1 on success or -1 on error
 */
int bzip_read_stream_header(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     uint8_t *compression_level,
     libcerror_error_t **error )
{
	static char *function          = "bzip_read_stream_header";
	uint8_t safe_compression_level = 0;

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
	if( ( compressed_data_size < 4 )
	 || ( compressed_data_size > (size_t) SSIZE_MAX ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid compressed data size value out of bounds.",
		 function );

		return( -1 );
	}
	if( compression_level == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid compression level.",
		 function );

		return( -1 );
	}
#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: stream header data:\n",
		 function );
		libcnotify_print_data(
		 compressed_data,
		 4,
		 0 );
	}
#endif
	if( ( compressed_data[ 0 ] != 'B' )
	 || ( compressed_data[ 1 ] != 'Z' ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported signature.",
		 function );

		return( -1 );
	}
	safe_compression_level = compressed_data[ 3 ];

	if( ( safe_compression_level < '1' )
	 || ( safe_compression_level > '9' ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported compression level.",
		 function );

		return( -1 );
	}
	safe_compression_level -= '0';

#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: signature\t\t\t\t: %c%c\n",
		 function,
		 compressed_data[ 0 ],
		 compressed_data[ 1 ] );

		libcnotify_printf(
		 "%s: format version\t\t\t\t: 0x%02" PRIx8 "\n",
		 function,
		 compressed_data[ 2 ] );

		libcnotify_printf(
		 "%s: compression level\t\t\t: %" PRIu8 "\n",
		 function,
		 safe_compression_level );

		libcnotify_printf(
		 "\n" );
	}
#endif /* defined( HAVE_DEBUG_OUTPUT ) */

	if( compressed_data[ 2 ] != 0x68 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported format version.",
		 function );

		return( -1 );
	}
	*compression_level = safe_compression_level;

	return( 1 );
}

/* Reads a (stream) block header or stream footer signature
 * Returns 1 on success or -1 on error
 */
int bzip_read_signature(
     bit_stream_t *bit_stream,
     uint64_t *signature,
     libcerror_error_t **error )
{
	static char *function   = "bzip_read_signature";
	uint32_t value_32bit    = 0;
	uint64_t safe_signature = 0;

	if( signature == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid signature.",
		 function );

		return( -1 );
	}
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
	safe_signature = value_32bit;

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
	safe_signature <<= 16;
	safe_signature  |= value_32bit;

	*signature = safe_signature;

	return( 1 );
}

/* Reads a (stream) block header
 * Returns 1 on success or -1 on error
 */
int bzip_read_block_header(
     bit_stream_t *bit_stream,
     uint64_t signature,
     uint32_t *origin_pointer,
     libcerror_error_t **error )
{
	static char *function        = "bzip_read_block_header";
	uint32_t checksum            = 0;
	uint32_t safe_origin_pointer = 0;
	uint32_t value_32bit         = 0;
	uint8_t is_randomized        = 0;

	if( origin_pointer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid origin pointer.",
		 function );

		return( -1 );
	}
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
	safe_origin_pointer = value_32bit & 0x00ffffffUL;
	value_32bit       >>= 24;
	is_randomized       = (uint8_t) ( value_32bit & 0x00000001UL );

#if defined( HAVE_DEBUG_OUTPUT )
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
		 safe_origin_pointer );

		libcnotify_printf(
		 "\n" );
	}
#endif /* defined( HAVE_DEBUG_OUTPUT ) */

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
	*origin_pointer = safe_origin_pointer;

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
#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: level 1 value\t\t\t\t: 0x%04" PRIx32 "\n",
		 function,
		 level1_value );
	}
#endif
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
#if defined( HAVE_DEBUG_OUTPUT )
			if( libcnotify_verbose != 0 )
			{
				libcnotify_printf(
				 "%s: level 2 value: %" PRIu8 "\t\t\t\t: 0x%04" PRIx32 "\n",
				 function,
				 level1_bit_index,
				 level2_value );
			}
#endif
			level2_bitmask = 0x00008000UL;

			for( level2_bit_index = 0;
			     level2_bit_index < 16;
			     level2_bit_index++ )
			{
				if( ( level2_value & level2_bitmask ) != 0 )
				{
					symbol_value = ( 16 * level1_bit_index ) + level2_bit_index;

#if defined( HAVE_DEBUG_OUTPUT )
					if( libcnotify_verbose != 0 )
					{
						libcnotify_printf(
						 "%s: symbol value: %" PRIu16 "\t\t\t\t: 0x%02" PRIx8 "\n",
						 function,
						 symbol_index,
						 symbol_value );
					}
#endif
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
#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "\n" );
	}
#endif
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
#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: tree index: %" PRIu16 "\t\t\t\t: %" PRIu8 "\n",
			 function,
			 selector_index,
			 tree_index );
		}
#endif
		/* Inverse move-to-front transform
		 */
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
#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "\n" );
	}
#endif
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
#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: symbol: % 3" PRIu16 " code size\t\t\t\t: %" PRIu8 "\n",
			 function,
			 symbol_index,
			 code_size );
		}
#endif
		code_size_array[ symbol_index ] = code_size;

		if( code_size > largest_code_size )
		{
			largest_code_size = code_size;
		}
	}
#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "\n" );
	}
#endif
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
/* TODO build tree inside fill array loop ? */
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
#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: reading Huffman tree: %" PRIu8 "\n",
			 function,
			 tree_index );
		}
#endif
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
     uint8_t *selectors,
     uint16_t number_of_selectors,
     uint8_t *symbol_stack,
     uint16_t number_of_symbols,
     uint8_t *block_data,
     size_t *block_data_size,
     libcerror_error_t **error )
{
	static char *function                = "bzip_read_block_data";
	size_t block_data_offset             = 0;
	size_t safe_block_data_size          = 0;
	size_t selector_index                = 0;
	size_t symbol_index                  = 0;
	uint64_t run_length                  = 0;
	uint64_t run_length_value            = 0;
	uint16_t end_of_block_symbol         = 0;
	uint16_t symbol                      = 0;
	uint8_t number_of_run_length_symbols = 0;
	uint8_t stack_index                  = 0;
	uint8_t stack_value                  = 0;
	uint8_t stack_value_index            = 0;
	uint8_t tree_index                   = 0;

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
	if( block_data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid block data.",
		 function );

		return( -1 );
	}
	if( block_data_size == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid block data size.",
		 function );

		return( -1 );
	}
	if( *block_data_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid block data size value exceeds maximum.",
		 function );

		return( -1 );
	}
	safe_block_data_size = *block_data_size;

	tree_index = selectors[ 0 ];

	if( tree_index > number_of_trees )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid tree index value out of bounds.",
		 function );

		return( -1 );
	}
	end_of_block_symbol = number_of_symbols - 1;

	do
	{
		if( huffman_tree_get_symbol_from_bit_stream(
		     huffman_trees[ tree_index ],
		     bit_stream,
		     &symbol,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve symbol from Huffman tree: %" PRIu8 ".",
			 function,
			 tree_index );

			return( -1 );
		}
		if( ( number_of_run_length_symbols != 0 )
		 && ( symbol > 1 ) )
		{
			run_length = ( ( (uint64_t) 1 << number_of_run_length_symbols ) | run_length_value ) - 1;

#if defined( HAVE_DEBUG_OUTPUT )
			if( libcnotify_verbose != 0 )
			{
				libcnotify_printf(
				 "%s: 0-byte run-length\t\t\t\t\t: %" PRIu64 "\n",
				 function,
				 run_length );
			}
#endif
			if( ( run_length > safe_block_data_size )
			 || ( block_data_offset > ( safe_block_data_size - run_length ) ) )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
				 "%s: invalid run length value out of bounds.",
				 function );

				return( -1 );
			}
			run_length_value             = 0;
			number_of_run_length_symbols = 0;

			while( run_length > 0 )
			{
				/* Inverse move-to-front transform
				 * Note that 0 is already at the front of the stack hence the stack does not need to be reordered.
				 */
				block_data[ block_data_offset++ ] = symbol_stack[ 0 ];

				run_length--;
			}
		}
		if( symbol > end_of_block_symbol )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
			 "%s: invalid symbol value out of bounds.",
			 function );

			return( -1 );
		}
		if( ( symbol == 0 )
		 || ( symbol == 1 ) )
		{
			run_length_value             |= (uint64_t) symbol << number_of_run_length_symbols;
			number_of_run_length_symbols += 1;

#if defined( HAVE_DEBUG_OUTPUT )
			if( libcnotify_verbose != 0 )
			{
				libcnotify_printf(
				 "%s: symbol\t\t\t\t\t\t: %" PRIu16 " (run-length)\n",
				 function,
				 symbol );
			}
#endif
		}
		else if( symbol < end_of_block_symbol )
		{
			/* Inverse move-to-front transform
			 */
			stack_value_index = symbol - 1;
			stack_value       = symbol_stack[ stack_value_index ];

			for( stack_index = stack_value_index;
			     stack_index > 0;
			     stack_index-- )
			{
				symbol_stack[ stack_index ] = symbol_stack[ stack_index - 1 ];
			}
			symbol_stack[ 0 ] = stack_value;

#if defined( HAVE_DEBUG_OUTPUT )
			if( libcnotify_verbose != 0 )
			{
				libcnotify_printf(
				 "%s: symbol\t\t\t\t\t\t: %" PRIu16 " (MTF: %" PRIu8 ")\n",
				 function,
				 symbol,
				 stack_value );
			}
#endif
			if( block_data_offset > ( safe_block_data_size - 1 ) )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
				 "%s: invalid block data index value out of bounds.",
				 function );

				return( -1 );
			}
			block_data[ block_data_offset++ ] = stack_value;
		}
#if defined( HAVE_DEBUG_OUTPUT )
		else if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: symbol\t\t\t\t\t\t: %" PRIu16 "\n",
			 function,
			 symbol );
		}
#endif
		symbol_index++;

		if( ( symbol_index % 50 ) == 0 )
		{
			selector_index = symbol_index / 50;

			if( selector_index > number_of_selectors )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
				 "%s: invalid selector index value out of bounds.",
				 function );

				return( -1 );
			}
			tree_index = selectors[ selector_index ];

			if( tree_index > number_of_trees )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
				 "%s: invalid tree index value out of bounds.",
				 function );

				return( -1 );
			}
		}
	}
	while( symbol != end_of_block_symbol );

	*block_data_size = block_data_offset;

	return( 1 );
}

/* Reads a stream foorter
 * Returns 1 on success or -1 on error
 */
int bzip_read_stream_footer(
     bit_stream_t *bit_stream,
     uint64_t signature,
     uint32_t *checksum,
     libcerror_error_t **error )
{
	static char *function  = "bzip_read_stream_footer";
	uint32_t safe_checksum = 0;

	if( checksum == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid checksum.",
		 function );

		return( -1 );
	}
	if( bit_stream_get_value(
	     bit_stream,
	     32,
	     &safe_checksum,
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
#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: signature\t\t\t\t\t: 0x%08" PRIx64 "\n",
		 function,
		 signature );

		libcnotify_printf(
		 "%s: checksum\t\t\t\t\t: 0x%08" PRIx32 "\n",
		 function,
		 safe_checksum );

		libcnotify_printf(
		 "\n" );
	}
#endif
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
	*checksum = safe_checksum;

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
	uint8_t block_data[ BLOCK_DATA_SIZE ];
	uint8_t symbol_stack[ 256 ];
	uint8_t selectors[ ( 1 << 15 ) + 1 ];
	size_t permutations[ BLOCK_DATA_SIZE ];

	huffman_tree_t *huffman_trees[ 7 ] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL };

	bit_stream_t *bit_stream           = NULL;
	static char *function              = "bzip_decompress";
	size_t block_data_offset           = 0;
	size_t block_data_size             = 0;
	size_t compressed_data_offset      = 0;
	size_t safe_uncompressed_data_size = 0;
	size_t uncompressed_data_offset    = 0;
	uint64_t signature                 = 0;
	uint32_t calculated_checksum       = 0;
	uint32_t origin_pointer            = 0;
	uint32_t stored_checksum           = 0;
	uint32_t value_32bit               = 0;
	uint16_t number_of_selectors       = 0;
	uint16_t number_of_symbols         = 0;
	uint8_t compression_level          = 0;
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
	if( ( compressed_data_size < 14 )
	 || ( compressed_data_size > (size_t) SSIZE_MAX ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid compressed data size value out of bounds.",
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
	safe_uncompressed_data_size = *uncompressed_data_size;

	if( bzip_read_stream_header(
	     compressed_data,
	     compressed_data_size,
	     &compression_level,
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
	compressed_data_offset += 4;

	if( compressed_data_offset > ( compressed_data_size - 10 ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: invalid compressed data value too small.",
		 function );

		return( -1 );
	}
	if( bit_stream_initialize(
	     &bit_stream,
	     compressed_data,
	     compressed_data_size,
	     compressed_data_offset,
	     BIT_STREAM_STORAGE_TYPE_BYTE_FRONT_TO_BACK,
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
	while( bit_stream->byte_stream_offset < bit_stream->byte_stream_size )
	{
		if( bzip_read_signature(
		     bit_stream,
		     &signature,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_IO,
			 LIBCERROR_IO_ERROR_READ_FAILED,
			 "%s: unable to read signature.",
			 function );

			goto on_error;
		}
		if( ( signature != 0x177245385090UL )
		 && ( signature != 0x314159265359UL ) )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
			 "%s: unsupported signature.",
			 function );

			return( -1 );
		}
		if( signature == 0x177245385090UL )
		{
			break;
		}
		if( bzip_read_block_header(
		     bit_stream,
		     signature,
		     &origin_pointer,
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

#if defined( HAVE_DEBUG_OUTPUT )
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
#endif
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
		block_data_size = BLOCK_DATA_SIZE;

		if( bzip_read_block_data(
		     bit_stream,
		     huffman_trees,
		     number_of_trees,
		     selectors,
		     number_of_selectors,
		     symbol_stack,
		     number_of_symbols,
		     block_data,
		     &block_data_size,
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
		block_data_offset = uncompressed_data_offset;

		if( memory_set(
		     permutations,
		     0,
		     sizeof( size_t ) * BLOCK_DATA_SIZE ) == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_SET_FAILED,
			 "%s: unable to clear permutations.",
			 function );

			goto on_error;
		}
		/* Perform Burrows-Wheeler transform
		 */
		if( bzip_reverse_burrows_wheeler_transform(
		     block_data,
		     block_data_size,
		     permutations,
		     origin_pointer,
		     uncompressed_data,
		     safe_uncompressed_data_size,
		     &uncompressed_data_offset,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to reverse Burrows-Wheeler transform.",
			 function );

			goto on_error;
		}
#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: block data:\n",
			 function );
			libcnotify_print_data(
			 &( uncompressed_data[ block_data_offset ] ),
			 uncompressed_data_offset - block_data_offset,
			 0 );
		}
#endif
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
	}
	if( bzip_read_stream_footer(
	     bit_stream,
	     signature,
	     &stored_checksum,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_READ_FAILED,
		 "%s: unable to read stream footer.",
		 function );

		goto on_error;
	}
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
	if( bzip_calculate_crc32(
	     &calculated_checksum,
	     uncompressed_data,
	     uncompressed_data_offset,
	     0,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to calculate checksum.",
		 function );

		goto on_error;
	}
#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: stored checksum\t\t\t\t\t: 0x%08" PRIx32 "\n",
		 function,
		 stored_checksum );

		libcnotify_printf(
		 "%s: calculated checksum\t\t\t\t\t: 0x%08" PRIx32 "\n",
		 function,
		 calculated_checksum );
	}
#endif
	if( stored_checksum != calculated_checksum )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_INPUT,
		 LIBCERROR_INPUT_ERROR_CHECKSUM_MISMATCH,
		 "%s: checksum does not match (stored: 0x%08" PRIx32 ", calculated: 0x%08" PRIx32 ").",
		 function,
		 stored_checksum,
		 calculated_checksum );

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

