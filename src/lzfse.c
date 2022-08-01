/*
 * LZFSE (un)compression functions
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
#include "lzfse.h"
#include "lzvn.h"

#define LZFSE_ENDOFSTREAM_BLOCK_MARKER		0x24787662UL
#define LZFSE_UNCOMPRESSED_BLOCK_MARKER		0x2d787662UL
#define LZFSE_COMPRESSED_BLOCK_V1_MARKER	0x31787662UL
#define LZFSE_COMPRESSED_BLOCK_V2_MARKER	0x32787662UL
#define LZFSE_COMPRESSED_BLOCK_LZVN_MARKER	0x6e787662UL

#define LZFSE_MATCHES_PER_BLOCK			10000
#define LZFSE_LITERALS_PER_BLOCK		( 4 * LZFSE_MATCHES_PER_BLOCK )

const uint8_t lzfse_frequency_number_of_bits_table[ 32 ] = {
      2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14,
      2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14 };

const uint16_t lzfse_frequency_value_table[ 32 ] = {
      0, 2, 1, 4, 0, 3, 1, 0xffff, 0, 2, 1, 5, 0, 3, 1, 0xffff,
      0, 2, 1, 6, 0, 3, 1, 0xffff, 0, 2, 1, 7, 0, 3, 1, 0xffff };

const uint8_t lzfse_d_value_bits_table[ LZFSE_NUMBER_OF_D_VALUE_SYMBOLS ] = {
	0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
	4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,
	8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 11,
	12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15 };

const int32_t lzfse_d_value_base_table[ LZFSE_NUMBER_OF_D_VALUE_SYMBOLS ] = {
	0, 1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 28, 36, 44, 52,
       	60, 76, 92, 108, 124, 156, 188, 220, 252, 316, 380, 444, 508, 636, 764, 892,
       	1020, 1276, 1532, 1788, 2044, 2556, 3068, 3580, 4092, 5116, 6140, 7164, 8188, 10236, 12284, 14332,
       	16380, 20476, 24572, 28668, 32764, 40956, 49148, 57340, 65532, 81916, 98300, 114684, 131068, 163836, 196604, 229372 };

const uint8_t lzfse_l_value_bits_table[ LZFSE_NUMBER_OF_L_VALUE_SYMBOLS ] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	2, 3, 5, 8 };

const int32_t lzfse_l_value_base_table[ LZFSE_NUMBER_OF_L_VALUE_SYMBOLS ] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
       	16, 20, 28, 60 };

const uint8_t lzfse_m_value_bits_table[ LZFSE_NUMBER_OF_M_VALUE_SYMBOLS ] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       	3, 5, 8, 11 };

const int32_t lzfse_m_value_base_table[ LZFSE_NUMBER_OF_M_VALUE_SYMBOLS ] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
       	16, 24, 56, 312 };

#define lzfse_count_leading_zeros( value ) \
	__builtin_clz( value )

/* Creates a bit stream
 * Make sure the value bit_stream is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int lzfse_bit_stream_initialize(
     lzfse_bit_stream_t **bit_stream,
     const uint8_t *byte_stream,
     size_t byte_stream_size,
     libcerror_error_t **error )
{
	static char *function = "lzfse_bit_stream_initialize";

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
	if( *bit_stream != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid bit stream value already set.",
		 function );

		return( -1 );
	}
	if( byte_stream == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid byte stream.",
		 function );

		return( -1 );
	}
	if( byte_stream_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid byte stream size value exceeds maximum.",
		 function );

		return( -1 );
	}
	*bit_stream = memory_allocate_structure(
	               lzfse_bit_stream_t );

	if( *bit_stream == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create bit stream.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     *bit_stream,
	     0,
	     sizeof( lzfse_bit_stream_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear bit stream.",
		 function );

		goto on_error;
	}
	( *bit_stream )->byte_stream        = byte_stream;
	( *bit_stream )->byte_stream_size   = byte_stream_size;
	( *bit_stream )->byte_stream_offset = byte_stream_size;

	return( 1 );

on_error:
	if( *bit_stream != NULL )
	{
		memory_free(
		 *bit_stream );

		*bit_stream = NULL;
	}
	return( -1 );
}

/* Frees a bit stream
 * Returns 1 if successful or -1 on error
 */
int lzfse_bit_stream_free(
     lzfse_bit_stream_t **bit_stream,
     libcerror_error_t **error )
{
	static char *function = "lzfse_bit_stream_free";

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
	if( *bit_stream != NULL )
	{
		memory_free(
		 *bit_stream );

		*bit_stream = NULL;
	}
	return( 1 );
}

/* Reads bits from the underlying byte stream
 * Returns 1 on success, 0 if no more bits are available or -1 on error
 */
int lzfse_bit_stream_read(
     lzfse_bit_stream_t *bit_stream,
     uint8_t number_of_bits,
     libcerror_error_t **error )
{
	static char *function = "lzfse_bit_stream_read";
	int result            = 0;

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
	if( ( number_of_bits == 0 )
	 || ( number_of_bits > 32 ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: number of bits value out of bounds.",
		 function );

		return( -1 );
	}
	while( bit_stream->bit_buffer_size < number_of_bits )
	{
		if( bit_stream->byte_stream_offset == 0 )
		{
			break;
		}
		bit_stream->byte_stream_offset -= 1;
		bit_stream->bit_buffer        <<= 8;
		bit_stream->bit_buffer         |= bit_stream->byte_stream[ bit_stream->byte_stream_offset ];
		bit_stream->bit_buffer_size    += 8;

		result = 1;
	}
	return( result );
}

/* Retrieves a value from the bit stream
 * Returns 1 on success or -1 on error
 */
int lzfse_bit_stream_get_value(
     lzfse_bit_stream_t *bit_stream,
     uint8_t number_of_bits,
     uint32_t *value_32bit,
     libcerror_error_t **error )
{
	static char *function             = "lzfse_bit_stream_get_value";
	uint32_t safe_value_32bit         = 0;
	uint8_t remaining_bit_buffer_size = 0;

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
	if( number_of_bits > (uint8_t) 32 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid number of bits value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( value_32bit == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid 32-bit value.",
		 function );

		return( -1 );
	}
	if( number_of_bits == 0 )
	{
		*value_32bit = 0;

		return( 1 );
	}
	if( bit_stream->bit_buffer_size < number_of_bits )
	{
		if( lzfse_bit_stream_read(
		     bit_stream,
		     number_of_bits,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_IO,
			 LIBCERROR_IO_ERROR_READ_FAILED,
			 "%s: unable to read bits.",
			 function );

			return( -1 );
		}
	}
	safe_value_32bit = bit_stream->bit_buffer;

	if( number_of_bits < 32 )
	{
		bit_stream->bit_buffer_size -= number_of_bits;
		safe_value_32bit           >>= bit_stream->bit_buffer_size;
		remaining_bit_buffer_size    = 32 - bit_stream->bit_buffer_size;
		bit_stream->bit_buffer      &= 0xffffffffUL >> remaining_bit_buffer_size;
	}
	else
	{
		bit_stream->bit_buffer      = 0;
		bit_stream->bit_buffer_size = 0;
	}
	*value_32bit = safe_value_32bit;

	return( 1 );
}

/* Creates a state
 * Make sure the value state is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int lzfse_state_initialize(
     lzfse_state_t **state,
     libcerror_error_t **error )
{
	static char *function = "lzfse_state_initialize";

	if( state == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid state.",
		 function );

		return( -1 );
	}
	if( *state != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid state value already set.",
		 function );

		return( -1 );
	}
	*state = memory_allocate_structure(
	          lzfse_state_t );

	if( *state == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create state.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     *state,
	     0,
	     sizeof( lzfse_state_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear state.",
		 function );

		goto on_error;
	}
	return( 1 );

on_error:
	if( *state != NULL )
	{
		memory_free(
		 *state );

		*state = NULL;
	}
	return( -1 );
}

/* Frees a state
 * Returns 1 if successful or -1 on error
 */
int lzfse_state_free(
     lzfse_state_t **state,
     libcerror_error_t **error )
{
	static char *function = "lzfse_state_free";

	if( state == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid state.",
		 function );

		return( -1 );
	}
	if( *state != NULL )
	{
		memory_free(
		 *state );

		*state = NULL;
	}
	return( 1 );
}

/* Builds a decoder table
 * Returns 1 on success or -1 on error
 */
int lzfse_build_decoder_table(
     int number_of_states,
     uint16_t number_of_symbols,
     const uint16_t *frequency_table,
     lzfse_decoder_entry_t *decoder_table,
     libcerror_error_t **error )
{
	lzfse_decoder_entry_t *decoder_entry = NULL;
	static char *function                = "lzfse_build_decoder_table";
	uint16_t symbol                      = 0;
	int16_t delta                        = 0;
	int base_decoder_weight              = 0;
	int decoder_weight                   = 0;
	int decoder_table_index              = 0;
	int frequency                        = 0;
	int number_of_bits                   = 0;
	int number_of_leading_zeros          = 0;
	int sum_of_frequencies               = 0;

	if( number_of_symbols > 256 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid number of symbols value out of bounds.",
		 function );

		return( -1 );
	}
	if( frequency_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid frequency table.",
		 function );

		return( -1 );
	}
	if( decoder_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid decoder table.",
		 function );

		return( -1 );
	}
/* TODO fse_check_freq */

	number_of_leading_zeros = lzfse_count_leading_zeros( number_of_states );

	for( symbol = 0;
	     symbol < number_of_symbols;
	     symbol++ )
	{
		frequency = frequency_table[ symbol ];

		/* 0 occurrences of the symbol
		 */
		if( frequency == 0 )
		{
			continue;
		}
		sum_of_frequencies += frequency;

		if( sum_of_frequencies > number_of_states )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
			 "%s: invalid sum of frequencies value out of bounds.",
			 function );

			return( -1 );
		}
		number_of_bits = lzfse_count_leading_zeros( frequency ) - number_of_leading_zeros;

		base_decoder_weight = ( ( 2 * number_of_states ) >> number_of_bits ) - frequency;

		for( decoder_weight = 0;
		     decoder_weight < frequency;
		     decoder_weight++ )
		{
			decoder_entry = &( decoder_table[ decoder_table_index++ ] );

			decoder_entry->number_of_bits = (int8_t) number_of_bits;
			decoder_entry->symbol         = (uint8_t) symbol;

			if( decoder_weight < base_decoder_weight )
			{
				delta = (int16_t) ( ( ( frequency + decoder_weight ) << number_of_bits ) - number_of_states );
			}
			else
			{
				decoder_entry->number_of_bits -= 1;

				delta = (int16_t) ( ( decoder_weight - base_decoder_weight ) << ( number_of_bits - 1 ) );
			}
			decoder_entry->delta = delta;
		}
	}
	return( 1 );
}

/* Builds a value decoder table
 * Returns 1 on success or -1 on error
 */
int lzfse_build_value_decoder_table(
     int number_of_states,
     uint16_t number_of_symbols,
     const uint16_t *frequency_table,
     const uint8_t *value_bits_table,
     const int32_t *value_base_table,
     lzfse_value_decoder_entry_t *value_decoder_table,
     libcerror_error_t **error )
{
	lzfse_value_decoder_entry_t *value_decoder_entry = NULL;
	static char *function                            = "lzfse_build_value_decoder_table";
	int32_t value_base                               = 0;
	uint16_t symbol                                  = 0;
	int16_t delta                                    = 0;
	uint8_t value_bits                               = 0;
	int base_decoder_weight                          = 0;
	int decoder_weight                               = 0;
	int decoder_table_index                          = 0;
	int frequency                                    = 0;
	int number_of_bits                               = 0;
	int number_of_leading_zeros                      = 0;

	if( number_of_symbols > 256 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid number of symbols value out of bounds.",
		 function );

		return( -1 );
	}
	if( frequency_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid frequency table.",
		 function );

		return( -1 );
	}
	if( value_bits_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid value bits table.",
		 function );

		return( -1 );
	}
	if( value_base_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid value base table.",
		 function );

		return( -1 );
	}
	if( value_decoder_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid value decoder table.",
		 function );

		return( -1 );
	}
/* TODO fse_check_freq */

	number_of_leading_zeros = lzfse_count_leading_zeros( number_of_states );

	for( symbol = 0;
	     symbol < number_of_symbols;
	     symbol++ )
	{
		frequency = frequency_table[ symbol ];

		/* 0 occurrences of the symbol
		 */
		if( frequency == 0 )
		{
			continue;
		}
		number_of_bits = lzfse_count_leading_zeros( frequency ) - number_of_leading_zeros;

		base_decoder_weight = ( ( 2 * number_of_states ) >> number_of_bits ) - frequency;

		value_bits = value_bits_table[ symbol ];
		value_base = value_base_table[ symbol ];

		for( decoder_weight = 0;
		     decoder_weight < frequency;
		     decoder_weight++ )
		{
			value_decoder_entry = &( value_decoder_table[ decoder_table_index++ ] );

			value_decoder_entry->value_bits     = value_bits;
			value_decoder_entry->value_base     = value_base;
			value_decoder_entry->value_bitmask  = ( (uint32_t) 1UL << value_bits ) - 1;
			value_decoder_entry->number_of_bits = number_of_bits + value_bits;

			if( decoder_weight < base_decoder_weight )
			{
				delta = (int16_t) ( ( ( frequency + decoder_weight ) << number_of_bits ) - number_of_states );
			}
			else
			{
				value_decoder_entry->number_of_bits -= 1;

				delta = (int16_t) ( ( decoder_weight - base_decoder_weight ) << ( number_of_bits - 1 ) );
			}
			value_decoder_entry->delta = delta;
		}
	}
	return( 1 );
}

/* Reads a LZFSE compressed block header with uncompressed tables (version 1)
 * Returns 1 on success or -1 on error
 */
int lzfse_read_block_v1_header(
     lzfse_state_t *state,
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     size_t *compressed_data_offset,
     uint16_t *frequency_table,
     libcerror_error_t **error )
{
	static char *function              = "lzfse_read_block_v1_header";
	size_t safe_compressed_data_offset = 0;
	uint32_t compressed_block_size     = 0;
	uint32_t literal_bits              = 0;
	uint32_t lmd_values_bits           = 0;
	uint16_t table_index               = 0;
	uint8_t literal_state_index        = 0;

	if( state == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid state.",
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
	if( ( compressed_data_size < 762 )
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

	if( safe_compressed_data_offset > ( compressed_data_size - 762 ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid compressed data offset value out of bounds.",
		 function );

		return( -1 );
	}
	if( frequency_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid frequency table.",
		 function );

		return( -1 );
	}
#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: v1 block header data:\n",
		 function );
		libcnotify_print_data(
		 &( compressed_data[ safe_compressed_data_offset ] ),
		 762,
		 0 );
	}
#endif
	byte_stream_copy_to_uint32_little_endian(
	 &( compressed_data[ safe_compressed_data_offset ] ),
	 compressed_block_size );

	safe_compressed_data_offset += 4;

	byte_stream_copy_to_uint32_little_endian(
	 &( compressed_data[ safe_compressed_data_offset ] ),
	 state->number_of_literals );

	safe_compressed_data_offset += 4;

	byte_stream_copy_to_uint32_little_endian(
	 &( compressed_data[ safe_compressed_data_offset ] ),
	 state->number_of_lmd_values );

	safe_compressed_data_offset += 4;

	byte_stream_copy_to_uint32_little_endian(
	 &( compressed_data[ safe_compressed_data_offset ] ),
	 state->literals_data_size );

	safe_compressed_data_offset += 4;

	byte_stream_copy_to_uint32_little_endian(
	 &( compressed_data[ safe_compressed_data_offset ] ),
	 state->lmd_values_data_size );

	safe_compressed_data_offset += 4;

	byte_stream_copy_to_uint32_little_endian(
	 &( compressed_data[ safe_compressed_data_offset ] ),
	 literal_bits );

	safe_compressed_data_offset += 4;

	for( literal_state_index = 0;
	     literal_state_index < 4;
	     literal_state_index++ )
	{
		byte_stream_copy_to_uint16_little_endian(
		 &( compressed_data[ safe_compressed_data_offset ] ),
		 state->literal_states[ literal_state_index ] );

		safe_compressed_data_offset += 2;
	}
	byte_stream_copy_to_uint32_little_endian(
	 &( compressed_data[ safe_compressed_data_offset ] ),
	 lmd_values_bits );

	safe_compressed_data_offset += 4;

	byte_stream_copy_to_uint16_little_endian(
	 &( compressed_data[ safe_compressed_data_offset ] ),
	 state->l_value_state );

	safe_compressed_data_offset += 2;

	byte_stream_copy_to_uint16_little_endian(
	 &( compressed_data[ safe_compressed_data_offset ] ),
	 state->m_value_state );

	safe_compressed_data_offset += 2;

	byte_stream_copy_to_uint16_little_endian(
	 &( compressed_data[ safe_compressed_data_offset ] ),
	 state->d_value_state );

	safe_compressed_data_offset += 2;

	for( table_index = 0;
	     table_index < 360;
	     table_index++ )
	{
		byte_stream_copy_to_uint16_little_endian(
		 &( compressed_data[ safe_compressed_data_offset ] ),
		 frequency_table[ table_index ] );

		safe_compressed_data_offset += 2;
	}
#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: compressed block size\t\t\t: %" PRIu32 "\n",
		 function,
		 compressed_block_size );

		libcnotify_printf(
		 "%s: number of literals\t\t\t\t: %" PRIu32 "\n",
		 function,
		 state->number_of_literals );

		libcnotify_printf(
		 "%s: number of L, M, D values\t\t\t: %" PRIu32 "\n",
		 function,
		 state->number_of_lmd_values );

		libcnotify_printf(
		 "%s: literals data size\t\t\t\t: %" PRIu32 "\n",
		 function,
		 state->literals_data_size );

		libcnotify_printf(
		 "%s: L, M, D values data size\t\t\t: %" PRIu32 "\n",
		 function,
		 state->lmd_values_data_size );

		libcnotify_printf(
		 "%s: literal_bits\t\t\t\t: %" PRIi32 "\n",
		 function,
		 (int32_t) literal_bits );

		for( literal_state_index = 0;
		     literal_state_index < 4;
		     literal_state_index++ )
		{
			libcnotify_printf(
			 "%s: literal_state[ %" PRIu8 " ]\t\t\t\t: %" PRIu16 "\n",
			 function,
			 literal_state_index,
			 state->literal_states[ literal_state_index ] );
		}
		libcnotify_printf(
		 "%s: lmd_values_bits\t\t\t\t: %" PRIi32 "\n",
		 function,
		 (int32_t) lmd_values_bits );

		libcnotify_printf(
		 "%s: L value state\t\t\t\t: %" PRIu16 "\n",
		 function,
		 state->l_value_state );

		libcnotify_printf(
		 "%s: M value state\t\t\t\t: %" PRIu16 "\n",
		 function,
		 state->m_value_state );

		libcnotify_printf(
		 "%s: D value state\t\t\t\t: %" PRIu16 "\n",
		 function,
		 state->d_value_state );

		for( table_index = 0;
		     table_index < 360;
		     table_index++ )
		{
			if( frequency_table[ table_index ] != 0 )
			{
				libcnotify_printf(
				 "%s: frequency table: %d value\t\t\t: %" PRIu16 "\n",
				 function,
				 table_index,
				 frequency_table[ table_index ] );
			}
		}
	}
#endif /* defined( HAVE_DEBUG_OUTPUT ) */

	state->literal_bits    = (int32_t) literal_bits;
	state->lmd_values_bits = (int32_t) lmd_values_bits;

	*compressed_data_offset = safe_compressed_data_offset;

	return( 1 );
}

/* Reads a LZFSE compressed block header with compressed tables (version 2)
 * Returns 1 on success or -1 on error
 */
int lzfse_read_block_v2_header(
     lzfse_state_t *state,
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     size_t *compressed_data_offset,
     uint16_t *frequency_table,
     libcerror_error_t **error )
{
	static char *function              = "lzfse_read_block_v2_header";
	size_t safe_compressed_data_offset = 0;
	uint64_t packed_fields1            = 0;
	uint64_t packed_fields2            = 0;
	uint64_t packed_fields3            = 0;
	uint32_t header_size               = 0;

#if defined( HAVE_DEBUG_OUTPUT )
	uint16_t table_index               = 0;
	uint8_t literal_state_index        = 0;
#endif

	if( state == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid state.",
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
	if( ( compressed_data_size < 24 )
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

	if( safe_compressed_data_offset > ( compressed_data_size - 24 ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid compressed data offset value out of bounds.",
		 function );

		return( -1 );
	}
	if( frequency_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid frequency table.",
		 function );

		return( -1 );
	}
#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: v2 block header data:\n",
		 function );
		libcnotify_print_data(
		 &( compressed_data[ safe_compressed_data_offset ] ),
		 24,
		 0 );
	}
#endif
	byte_stream_copy_to_uint64_little_endian(
	 &( compressed_data[ safe_compressed_data_offset ] ),
	 packed_fields1 );

	safe_compressed_data_offset += 8;

	byte_stream_copy_to_uint64_little_endian(
	 &( compressed_data[ safe_compressed_data_offset ] ),
	 packed_fields2 );

	safe_compressed_data_offset += 8;

	byte_stream_copy_to_uint64_little_endian(
	 &( compressed_data[ safe_compressed_data_offset ] ),
	 packed_fields3 );

	safe_compressed_data_offset += 8;

#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: packed fields 1\t\t\t\t: 0x%08" PRIx64 "\n",
		 function,
		 packed_fields1 );

		libcnotify_printf(
		 "%s: packed fields 2\t\t\t\t: 0x%08" PRIx64 "\n",
		 function,
		 packed_fields2 );

		libcnotify_printf(
		 "%s: packed fields 3\t\t\t\t: 0x%08" PRIx64 "\n",
		 function,
		 packed_fields3 );
	}
#endif /* defined( HAVE_DEBUG_OUTPUT ) */

	state->number_of_literals   = (uint32_t) ( packed_fields1 & 0x000fffffUL );
	state->literals_data_size   = (uint32_t) ( ( packed_fields1 >> 20 ) & 0x000fffffUL );
	state->number_of_lmd_values = (uint32_t) ( ( packed_fields1 >> 40 ) & 0x000fffffUL );
	state->literal_bits         = (int32_t) ( ( packed_fields1 >> 60 ) & 0x00000007UL ) - 7;

	state->literal_states[ 0 ]  = (uint16_t) ( packed_fields2 & 0x000003ffUL );
	state->literal_states[ 1 ]  = (uint16_t) ( ( packed_fields2 >> 10 ) & 0x000003ffUL );
	state->literal_states[ 2 ]  = (uint16_t) ( ( packed_fields2 >> 20 ) & 0x000003ffUL );
	state->literal_states[ 3 ]  = (uint16_t) ( ( packed_fields2 >> 30 ) & 0x000003ffUL );
	state->lmd_values_data_size = (uint32_t) ( ( packed_fields2 >> 40 ) & 0x000fffffUL );
	state->lmd_values_bits      = (int32_t) ( ( packed_fields2 >> 60 ) & 0x00000007UL ) - 7;

	header_size                 = (uint32_t) ( packed_fields3 & 0xffffffffUL );
	state->l_value_state        = (uint16_t) ( ( packed_fields3 >> 32 ) & 0x000003ffUL );
	state->m_value_state        = (uint16_t) ( ( packed_fields3 >> 42 ) & 0x000003ffUL );
	state->d_value_state        = (uint16_t) ( ( packed_fields3 >> 52 ) & 0x000003ffUL );

	if( ( header_size < 32 )
	 || ( header_size > 720 ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid header size value out of bounds.",
		 function );

		return( -1 );
	}
	if( header_size > 32 )
	{
#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: compressed frequency table data:\n",
			 function );
			libcnotify_print_data(
			 &( compressed_data[ safe_compressed_data_offset ] ),
			 header_size - 32,
			 0 );
		}
#endif
		if( ( header_size > compressed_data_size )
		 || ( safe_compressed_data_offset > ( compressed_data_size - header_size ) ) )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
			 "%s: compressed data size value too small.",
			 function );

			return( -1 );
		}
		if( lzfse_read_compressed_frequency_table(
		     &( compressed_data[ safe_compressed_data_offset ] ),
		     header_size - 32,
		     frequency_table,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_IO,
			 LIBCERROR_IO_ERROR_READ_FAILED,
			 "%s: unable to read compressed frequency table.",
			 function );

			return( -1 );
		}
		safe_compressed_data_offset += (size_t) header_size - 32;
	}
#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: number of literals\t\t\t\t: %" PRIu32 "\n",
		 function,
		 state->number_of_literals );

		libcnotify_printf(
		 "%s: number of L, M, D values\t\t\t: %" PRIu32 "\n",
		 function,
		 state->number_of_lmd_values );

		libcnotify_printf(
		 "%s: literals data size\t\t\t\t: %" PRIu32 "\n",
		 function,
		 state->literals_data_size );

		libcnotify_printf(
		 "%s: L, M, D values data size\t\t\t: %" PRIu32 "\n",
		 function,
		 state->lmd_values_data_size );

		libcnotify_printf(
		 "%s: literal_bits\t\t\t\t: %" PRIi32 "\n",
		 function,
		 state->literal_bits );

		for( literal_state_index = 0;
		     literal_state_index < 4;
		     literal_state_index++ )
		{
			libcnotify_printf(
			 "%s: literal_states[ %" PRIu8 " ]\t\t\t\t: %" PRIu16 "\n",
			 function,
			 literal_state_index,
			 state->literal_states[ literal_state_index ] );
		}
		libcnotify_printf(
		 "%s: lmd_bits\t\t\t\t\t: %" PRIi32 "\n",
		 function,
		 state->lmd_values_bits );

		libcnotify_printf(
		 "%s: header size\t\t\t\t\t: %" PRIu32 "\n",
		 function,
		 header_size );

		libcnotify_printf(
		 "%s: L value state\t\t\t\t: %" PRIu16 "\n",
		 function,
		 state->l_value_state );

		libcnotify_printf(
		 "%s: M value state\t\t\t\t: %" PRIu16 "\n",
		 function,
		 state->m_value_state );

		libcnotify_printf(
		 "%s: D value state\t\t\t\t: %" PRIu16 "\n",
		 function,
		 state->d_value_state );

		for( table_index = 0;
		     table_index < 360;
		     table_index++ )
		{
			if( frequency_table[ table_index ] != 0 )
			{
				libcnotify_printf(
				 "%s: frequency table: %d value\t\t\t: %" PRIu16 "\n",
				 function,
				 table_index,
				 frequency_table[ table_index ] );
			}
		}
	}
#endif /* defined( HAVE_DEBUG_OUTPUT ) */

	*compressed_data_offset = safe_compressed_data_offset;

	return( 1 );
}

/* Reads a compressed frequency table bit stream
 * Returns 1 on success or -1 on error
 */
int lzfse_read_compressed_frequency_table(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     uint16_t *frequency_table,
     libcerror_error_t **error )
{
	static char *function         = "lzfse_read_compressed_frequency_table";
	size_t compressed_data_offset = 0;
	uint32_t value_32bit          = 0;
	uint16_t frequency_value      = 0;
	int16_t table_index           = 0;
	uint8_t frequency_value_size  = 0;
	uint8_t lookup_index          = 0;
	uint8_t number_of_bits        = 0;

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
	if( frequency_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid frequency table.",
		 function );

		return( -1 );
	}
	for( table_index = 0;
	     table_index < 360;
	     table_index++ )
	{
		while( ( number_of_bits <= 24 )
		    && ( compressed_data_offset < compressed_data_size ) )
		{
			value_32bit    |= (uint32_t) compressed_data[ compressed_data_offset++ ] << number_of_bits;
			number_of_bits += 8;
		}
		lookup_index         = (uint8_t) ( value_32bit & 0x0000001fUL );
		frequency_value_size = lzfse_frequency_number_of_bits_table[ lookup_index ];

		if( frequency_value_size == 8 )
		{
			frequency_value = (uint16_t) ( ( value_32bit >> 4 ) & 0x0000000fUL ) + 8;
		}
		else if( frequency_value_size == 14 )
		{
			frequency_value = (uint16_t) ( ( value_32bit >> 4 ) & 0x000003ffUL ) + 24;
		}
		else
		{
			frequency_value = lzfse_frequency_value_table[ lookup_index ];
		}
		frequency_table[ table_index ] = frequency_value;

		value_32bit   >>= frequency_value_size;
		number_of_bits -= frequency_value_size;
	}
	return( 1 );
}

/* Reads a LZFSE compressed block
 * Returns 1 on success or -1 on error
 */
int lzfse_read_block(
     lzfse_state_t *state,
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     size_t *compressed_data_offset,
     uint8_t *uncompressed_data,
     size_t uncompressed_data_size,
     size_t *uncompressed_data_offset,
     libcerror_error_t **error )
{
	uint8_t literal_values[ LZFSE_LITERALS_PER_BLOCK + 64 ];

	lzfse_bit_stream_t *bit_stream     = NULL;
	static char *function              = "lzfse_read_block";
	size_t safe_compressed_data_offset = 0;

	if( state == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid state.",
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
	if( compressed_data_offset == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid compressed offset.",
		 function );

		return( -1 );
	}
	safe_compressed_data_offset = *compressed_data_offset;

	if( ( state->literals_data_size > compressed_data_size )
	 || ( safe_compressed_data_offset > ( compressed_data_size - state->literals_data_size ) ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid compressed data size value out of bounds.",
		 function );

		return( -1 );
	}
	if( lzfse_bit_stream_initialize(
	     &bit_stream,
	     &( compressed_data[ safe_compressed_data_offset ] ),
	     state->literals_data_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create literals bit stream.",
		 function );

		goto on_error;
	}
	if( lzfse_read_literal_values(
	     state,
	     bit_stream,
	     literal_values,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_READ_FAILED,
		 "%s: unable to read literal values.",
		 function );

		goto on_error;
	}
	if( lzfse_bit_stream_free(
	     &bit_stream,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
		 "%s: unable to free literals bit stream.",
		 function );

		goto on_error;
	}
	safe_compressed_data_offset += state->literals_data_size;

	if( ( state->lmd_values_data_size > compressed_data_size )
	 || ( safe_compressed_data_offset > ( compressed_data_size - state->lmd_values_data_size ) ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid compressed data size value out of bounds.",
		 function );

		return( -1 );
	}
	if( lzfse_bit_stream_initialize(
	     &bit_stream,
	     &( compressed_data[ safe_compressed_data_offset ] ),
	     state->lmd_values_data_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create L, M, D values bit stream.",
		 function );

		goto on_error;
	}
	if( lzfse_read_lmd_values(
	     state,
	     bit_stream,
	     literal_values,
	     uncompressed_data,
	     uncompressed_data_size,
	     uncompressed_data_offset,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_READ_FAILED,
		 "%s: unable to read L, M, D values.",
		 function );

		goto on_error;
	}
	if( lzfse_bit_stream_free(
	     &bit_stream,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
		 "%s: unable to free L, M, D values bit stream.",
		 function );

		goto on_error;
	}
	safe_compressed_data_offset += state->lmd_values_data_size;

	*compressed_data_offset = safe_compressed_data_offset;

	return( 1 );

on_error:
	if( bit_stream != NULL )
	{
		lzfse_bit_stream_free(
		 &bit_stream,
		 NULL );
	}
	return( -1 );
}

/* Reads literal values
 * Returns 1 on success or -1 on error
 */
int lzfse_read_literal_values(
     lzfse_state_t *state,
     lzfse_bit_stream_t *bit_stream,
     uint8_t *literal_values,
     libcerror_error_t **error )
{
	uint16_t literal_states[ 4 ];

	lzfse_decoder_entry_t *decoder_entry = NULL;
	static char *function                = "lzfse_read_literal_values";
	uint32_t value_32bit                 = 0;
	int32_t literal_value_index          = 0;
	int32_t literal_state                = 0;
	uint8_t literal_state_index          = 0;

	if( state == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid state.",
		 function );

		return( -1 );
	}
	if( literal_values == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid literal values.",
		 function );

		return( -1 );
	}
	literal_states[ 0 ] = state->literal_states[ 0 ];
	literal_states[ 1 ] = state->literal_states[ 1 ];
	literal_states[ 2 ] = state->literal_states[ 2 ];
	literal_states[ 3 ] = state->literal_states[ 3 ];

	if( lzfse_bit_stream_get_value(
	     bit_stream,
	     -1 * state->literal_bits,
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
	for( literal_value_index = 0;
	     literal_value_index < state->number_of_literals;
	     literal_value_index += 4 )
	{
		for( literal_state_index = 0;
		     literal_state_index < 4;
		     literal_state_index++ )
		{
			literal_state = literal_states[ literal_state_index ];
			decoder_entry = &( state->literal_decoder_table[ literal_state ] );

			if( lzfse_bit_stream_get_value(
			     bit_stream,
			     decoder_entry->number_of_bits,
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
			literal_state = (int32_t) decoder_entry->delta + (int32_t) value_32bit;

			literal_values[ literal_value_index + literal_state_index ] = decoder_entry->symbol;

			literal_states[ literal_state_index ] = (uint16_t) literal_state;
		}
	}
	return( 1 );
}

/* Reads L, M, D values
 * Returns 1 on success or -1 on error
 */
int lzfse_read_lmd_values(
     lzfse_state_t *state,
     lzfse_bit_stream_t *bit_stream,
     uint8_t *literal_values,
     uint8_t *uncompressed_data,
     size_t uncompressed_data_size,
     size_t *uncompressed_data_offset,
     libcerror_error_t **error )
{
	lzfse_value_decoder_entry_t *value_decoder_entry = NULL;
	static char *function                            = "lzfse_read_lmd_values";
	size_t safe_uncompressed_data_offset             = 0;
	size_t remaining_uncompressed_data_size          = 0;
	uint32_t lmd_value_index                         = 0;
	uint32_t value_32bit                             = 0;
	int32_t d_value                                  = -1;
	int32_t d_value_state                            = 0;
	int32_t l_value                                  = 0;
	int32_t l_value_index                            = 0;
	int32_t l_value_state                            = 0;
	int32_t literal_value_index                      = 0;
	int32_t m_value                                  = 0;
	int32_t m_value_index                            = 0;
	int32_t m_value_state                            = 0;
	int32_t safe_d_value                             = 0;

	if( state == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid state.",
		 function );

		return( -1 );
	}
	if( literal_values == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid literal values.",
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
		 "%s: invalid uncompressed offset.",
		 function );

		return( -1 );
	}
	safe_uncompressed_data_offset = *uncompressed_data_offset;

	if( safe_uncompressed_data_offset > uncompressed_data_size )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid uncompressed data offset value out of bounds.",
		 function );

		return( -1 );
	}
	remaining_uncompressed_data_size = uncompressed_data_size - safe_uncompressed_data_offset;

	l_value_state = state->l_value_state;
	m_value_state = state->m_value_state;
	d_value_state = state->d_value_state;

	if( l_value_state > LZFSE_NUMBER_OF_L_VALUE_STATES )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid L value state value out of bounds.",
		 function );

		return( -1 );
	}
	if( m_value_state > LZFSE_NUMBER_OF_M_VALUE_STATES )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid M value state value out of bounds.",
		 function );

		return( -1 );
	}
	if( d_value_state > LZFSE_NUMBER_OF_D_VALUE_STATES )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid D value state value out of bounds.",
		 function );

		return( -1 );
	}
	if( lzfse_bit_stream_get_value(
	     bit_stream,
	     -1 * state->lmd_values_bits,
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
	for( lmd_value_index = 0; 
	     lmd_value_index < state->number_of_lmd_values;
	     lmd_value_index++ )
	{
		value_decoder_entry = &( state->l_value_decoder_table[ l_value_state ] );

		if( lzfse_bit_stream_get_value(
		     bit_stream,
		     value_decoder_entry->number_of_bits,
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
		l_value_state = (int32_t) value_decoder_entry->delta + (int32_t) ( value_32bit >> value_decoder_entry->value_bits );
		l_value       = value_decoder_entry->value_base + (int32_t) ( value_32bit & value_decoder_entry->value_bitmask );

		value_decoder_entry = &( state->m_value_decoder_table[ m_value_state ] );

		if( lzfse_bit_stream_get_value(
		     bit_stream,
		     value_decoder_entry->number_of_bits,
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
		m_value_state = (int32_t) value_decoder_entry->delta + (int32_t) ( value_32bit >> value_decoder_entry->value_bits );
		m_value       = value_decoder_entry->value_base + (int32_t) ( value_32bit & value_decoder_entry->value_bitmask );

		value_decoder_entry = &( state->d_value_decoder_table[ d_value_state ] );

		if( lzfse_bit_stream_get_value(
		     bit_stream,
		     value_decoder_entry->number_of_bits,
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
		d_value_state = (int32_t) value_decoder_entry->delta + (int32_t) ( value_32bit >> value_decoder_entry->value_bits );
		safe_d_value  = value_decoder_entry->value_base + (int32_t) ( value_32bit & value_decoder_entry->value_bitmask );

		if( d_value_state > LZFSE_NUMBER_OF_D_VALUE_STATES )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
			 "%s: invalid D value state value out of bounds.",
			 function );

			return( -1 );
		}
		if( safe_d_value != 0 )
		{
			d_value = safe_d_value;
		}
		if( l_value > remaining_uncompressed_data_size )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
			 "%s: invalid L value out of bounds.",
			 function );

			return( -1 );
		}
		for( l_value_index = 0;
		     l_value_index < l_value;
		     l_value_index++ )
		{
			uncompressed_data[ safe_uncompressed_data_offset++ ] = literal_values[ literal_value_index + l_value_index ];
		}
		literal_value_index              += l_value;
		remaining_uncompressed_data_size -= l_value;

		if( m_value > remaining_uncompressed_data_size )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
			 "%s: invalid M value out of bounds.",
			 function );

			return( -1 );
		}
		if( d_value > safe_uncompressed_data_offset )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
			 "%s: invalid D value out of bounds.",
			 function );

			return( -1 );
		}
		for( m_value_index = 0;
		     m_value_index < m_value;
		     m_value_index++ )
		{
			uncompressed_data[ safe_uncompressed_data_offset ] = uncompressed_data[ safe_uncompressed_data_offset - d_value ];

			safe_uncompressed_data_offset++;
		}
		remaining_uncompressed_data_size -= m_value;
	}
#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: block data:\n",
		 function );
		libcnotify_print_data(
		 &( uncompressed_data[ *uncompressed_data_offset ] ),
		 safe_uncompressed_data_offset - *uncompressed_data_offset,
		 0 );
	}
#endif
	*uncompressed_data_offset = safe_uncompressed_data_offset;

	return( 1 );
}

/* Decompresses LZFSE compressed data
 * Returns 1 on success or -1 on error
 */
int lzfse_decompress(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     uint8_t *uncompressed_data,
     size_t *uncompressed_data_size,
     libcerror_error_t **error )
{
	uint16_t frequency_table[ 360 ];

	lzfse_state_t *state                = NULL;
	static char *function               = "lzfse_decompress";
	size_t compressed_data_offset       = 0;
	size_t safe_uncompressed_block_size = 0;
	size_t safe_uncompressed_data_size  = 0;
	size_t uncompressed_data_offset     = 0;
	uint32_t block_marker               = 0;
	uint32_t compressed_block_size      = 0;
	uint32_t uncompressed_block_size    = 0;

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
	safe_uncompressed_data_size = *uncompressed_data_size;

	if( safe_uncompressed_data_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid uncompressed data size value exceeds maximum.",
		 function );

		return( -1 );
	}
	while( compressed_data_offset < compressed_data_size )
	{
		if( uncompressed_data_offset >= safe_uncompressed_data_size )
		{
			break;
		}
		if( compressed_data_offset > ( compressed_data_size + 4 ) )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
			 "%s: compressed data size value too small.",
			 function );

			goto on_error;
		}
		byte_stream_copy_to_uint32_little_endian(
		 &( compressed_data[ compressed_data_offset ] ),
		 block_marker );

#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			if( ( block_marker != LZFSE_ENDOFSTREAM_BLOCK_MARKER )
			 && ( block_marker != LZFSE_UNCOMPRESSED_BLOCK_MARKER )
			 && ( block_marker != LZFSE_COMPRESSED_BLOCK_V1_MARKER )
			 && ( block_marker != LZFSE_COMPRESSED_BLOCK_V2_MARKER )
			 && ( block_marker != LZFSE_COMPRESSED_BLOCK_LZVN_MARKER ) )
			{
				libcnotify_printf(
				 "%s: block marker\t\t\t\t\t\t: 0x%08" PRIx32 "\n",
				 function,
				 block_marker );
			}
			else
			{
				libcnotify_printf(
				 "%s: block marker\t\t\t\t\t\t: %c%c%c%c (",
				 function,
				 compressed_data[ compressed_data_offset ],
				 compressed_data[ compressed_data_offset + 1 ],
				 compressed_data[ compressed_data_offset + 2 ],
				 compressed_data[ compressed_data_offset + 3 ] );

				switch( block_marker )
				{
					case LZFSE_ENDOFSTREAM_BLOCK_MARKER:
						libcnotify_printf(
						 "end-of-stream" );
						break;

					case LZFSE_UNCOMPRESSED_BLOCK_MARKER:
						libcnotify_printf(
						 "uncompressed" );
						break;

					case LZFSE_COMPRESSED_BLOCK_V1_MARKER:
						libcnotify_printf(
						 "compressed version 1" );
						break;

					case LZFSE_COMPRESSED_BLOCK_V2_MARKER:
						libcnotify_printf(
						 "compressed version 2" );
						break;

					case LZFSE_COMPRESSED_BLOCK_LZVN_MARKER:
						libcnotify_printf(
						 "compressed LZVN" );
						break;

					default:
						libcnotify_printf(
						 "UNKNOWN" );
						break;
				}
				libcnotify_printf(
				 ")\n" );
			}
		}
#endif /* defined( HAVE_DEBUG_OUTPUT ) */

		compressed_data_offset += 4;

		if( block_marker == LZFSE_ENDOFSTREAM_BLOCK_MARKER )
		{
			break;
		}
		else if( ( block_marker != LZFSE_UNCOMPRESSED_BLOCK_MARKER )
		      && ( block_marker != LZFSE_COMPRESSED_BLOCK_V1_MARKER )
		      && ( block_marker != LZFSE_COMPRESSED_BLOCK_V2_MARKER )
		      && ( block_marker != LZFSE_COMPRESSED_BLOCK_LZVN_MARKER ) )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
			 "%s: unsupported block marker: 0x%08" PRIx32 ".",
			 function,
			 block_marker );

			goto on_error;
		}
		if( compressed_data_offset > ( compressed_data_size + 4 ) )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
			 "%s: compressed data size value too small.",
			 function );

			goto on_error;
		}
		byte_stream_copy_to_uint32_little_endian(
		 &( compressed_data[ compressed_data_offset ] ),
		 uncompressed_block_size );

		compressed_data_offset += 4;

#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: uncompressed block size\t\t\t\t: %" PRIu32 "\n",
			 function,
			 uncompressed_block_size );
		}
#endif
/* TODO check if uncompressed data is sufficiently large and error if not */

		switch( block_marker )
		{
			case LZFSE_COMPRESSED_BLOCK_V1_MARKER:
				if( lzfse_state_initialize(
				     &state,
				     error ) != 1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
					 "%s: unable to create state.",
					 function );

					goto on_error;
				}
				if( lzfse_read_block_v1_header(
				     state,
				     compressed_data,
				     compressed_data_size,
				     &compressed_data_offset,
				     frequency_table,
				     error ) != 1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_IO,
					 LIBCERROR_IO_ERROR_READ_FAILED,
					 "%s: unable to read block v1 header.",
					 function );

					goto on_error;
				}
				break;

			case LZFSE_COMPRESSED_BLOCK_V2_MARKER:
				if( lzfse_state_initialize(
				     &state,
				     error ) != 1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
					 "%s: unable to create state.",
					 function );

					goto on_error;
				}
				if( lzfse_read_block_v2_header(
				     state,
				     compressed_data,
				     compressed_data_size,
				     &compressed_data_offset,
				     frequency_table,
				     error ) != 1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_IO,
					 LIBCERROR_IO_ERROR_READ_FAILED,
					 "%s: unable to read block v2 header.",
					 function );

					goto on_error;
				}
				break;

			case LZFSE_COMPRESSED_BLOCK_LZVN_MARKER:
				if( compressed_data_offset > ( compressed_data_size + 4 ) )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
					 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
					 "%s: compressed data size value too small.",
					 function );

					goto on_error;
				}
				byte_stream_copy_to_uint32_little_endian(
				 &( compressed_data[ compressed_data_offset ] ),
				 compressed_block_size );

				compressed_data_offset += 4;

#if defined( HAVE_DEBUG_OUTPUT )
				if( libcnotify_verbose != 0 )
				{
					libcnotify_printf(
					 "%s: compressed block size\t\t\t\t\t: %" PRIu32 "\n",
					 function,
					 compressed_block_size );

					libcnotify_printf(
					 "\n" );
				}
#endif
				break;
		}
		switch( block_marker )
		{
			case LZFSE_UNCOMPRESSED_BLOCK_MARKER:
				if( ( (size_t) uncompressed_block_size > compressed_data_size )
				 || ( compressed_data_offset > ( compressed_data_size - uncompressed_block_size ) ) )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
					 "%s: literal size value exceeds compressed data size.",
					 function );

					goto on_error;
				}
				if( ( (size_t) uncompressed_block_size > safe_uncompressed_data_size )
				 || ( uncompressed_data_offset > ( safe_uncompressed_data_size - uncompressed_block_size ) ) )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
					 "%s: literal size value exceeds uncompressed data size.",
					 function );

					goto on_error;
				}
#if defined( HAVE_DEBUG_OUTPUT )
				if( libcnotify_verbose != 0 )
				{
					libcnotify_printf(
					 "%s: uncompressed:\n",
					 function );
					libcnotify_print_data(
					 &( compressed_data[ compressed_data_offset ] ),
					 uncompressed_block_size,
					 LIBCNOTIFY_PRINT_DATA_FLAG_GROUP_DATA );
				}
#endif
				if( memory_copy(
				     &( uncompressed_data[ uncompressed_data_offset ] ),
				     &( compressed_data[ compressed_data_offset ] ),
				     (size_t) uncompressed_block_size ) == NULL )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_MEMORY,
					 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
					 "%s: unable to copy literal to uncompressed data.",
					 function );

					goto on_error;
				}
				compressed_data_offset   += (size_t) uncompressed_block_size;
				uncompressed_data_offset += (size_t) uncompressed_block_size;

				break;

			case LZFSE_COMPRESSED_BLOCK_V1_MARKER:
			case LZFSE_COMPRESSED_BLOCK_V2_MARKER:
				if( lzfse_build_decoder_table(
				     LZFSE_NUMBER_OF_LITERAL_STATES,
				     LZFSE_NUMBER_OF_LITERAL_SYMBOLS,
				     &( frequency_table[ 104 ] ),
				     state->literal_decoder_table,
				     error ) != 1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
					 "%s: unable to build literal decoder table.",
					 function );

					goto on_error;
				}
				if( lzfse_build_value_decoder_table(
				     LZFSE_NUMBER_OF_L_VALUE_STATES,
				     LZFSE_NUMBER_OF_L_VALUE_SYMBOLS,
				     &( frequency_table[ 0 ] ),
				     lzfse_l_value_bits_table,
				     lzfse_l_value_base_table,
				     state->l_value_decoder_table,
				     error ) != 1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
					 "%s: unable to build L value decoder table.",
					 function );

					goto on_error;
				}
				if( lzfse_build_value_decoder_table(
				     LZFSE_NUMBER_OF_M_VALUE_STATES,
				     LZFSE_NUMBER_OF_M_VALUE_SYMBOLS,
				     &( frequency_table[ 20 ] ),
				     lzfse_m_value_bits_table,
				     lzfse_m_value_base_table,
				     state->m_value_decoder_table,
				     error ) != 1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
					 "%s: unable to build M value decoder table.",
					 function );

					goto on_error;
				}
				if( lzfse_build_value_decoder_table(
				     LZFSE_NUMBER_OF_D_VALUE_STATES,
				     LZFSE_NUMBER_OF_D_VALUE_SYMBOLS,
				     &( frequency_table[ 40 ] ),
				     lzfse_d_value_bits_table,
				     lzfse_d_value_base_table,
				     state->d_value_decoder_table,
				     error ) != 1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
					 "%s: unable to build D value decoder table.",
					 function );

					goto on_error;
				}
				if( lzfse_read_block(
				     state,
				     compressed_data,
				     compressed_data_size,
				     &compressed_data_offset,
				     uncompressed_data,
				     safe_uncompressed_data_size,
				     &uncompressed_data_offset,
				     error ) != 1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_IO,
					 LIBCERROR_IO_ERROR_READ_FAILED,
					 "%s: unable to read block.",
					 function );

					goto on_error;
				}
				if( lzfse_state_free(
				     &state,
				     error ) != 1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
					 "%s: unable to free state.",
					 function );

					goto on_error;
				}
				break;

			case LZFSE_COMPRESSED_BLOCK_LZVN_MARKER:
				safe_uncompressed_block_size = (size_t) uncompressed_block_size;

				if( lzvn_decompress(
				     &( compressed_data[ compressed_data_offset ] ),
				     compressed_block_size,
				     &( uncompressed_data[ uncompressed_data_offset ] ),
				     &safe_uncompressed_block_size,
				     error ) != 1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_COMPRESSION,
					 LIBCERROR_COMPRESSION_ERROR_DECOMPRESS_FAILED,
					 "%s: unable to decompress LZVN compressed data.",
					 function );

					goto on_error;
				}
				compressed_data_offset   += (size_t) compressed_block_size;
				uncompressed_data_offset += (size_t) uncompressed_block_size;

				break;
		}
	}
	*uncompressed_data_size = uncompressed_data_offset;

	return( 1 );

on_error:
	if( state != NULL )
	{
		lzfse_state_free(
		 &state,
		 NULL );
	}
	return( -1 );
}

