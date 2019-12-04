/*
 * ASCII 7-bit (un)compression functions
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
#include <types.h>

#include "assorted_libcerror.h"
#include "ascii7.h"

/* Determines the uncompressed data size from the ASCII 7-bit compressed data
 * Return 1 on success or -1 on error
 */
int ascii7_get_uncompressed_data_size(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     size_t *uncompressed_data_size,
     libcerror_error_t **error )
{
	static char *function = "ascii7_get_uncompressed_data_size";

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
	*uncompressed_data_size = 1 + ( ( compressed_data_size - 1 ) * 8 ) / 7;

	return( 1 );
}

/* Decompresses data using ASCII 7-bit compression
 * Returns 1 on success or -1 on error
 */
int ascii7_decompress(
     uint8_t *uncompressed_data,
     size_t uncompressed_data_size,
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     libcerror_error_t **error )
{
	static char *function             = "ascii7_decompress";
	size_t compressed_data_iterator   = 0;
	size_t uncompressed_data_iterator = 0;
	uint16_t value_16bit              = 0;
	uint8_t bit_index                 = 0;

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
	if( uncompressed_data_size < ( 1 + ( ( compressed_data_size - 1 ) * 8 ) / 7 ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: uncompressed data size value too small.",
		 function );

		return( -1 );
	}
	uncompressed_data[ uncompressed_data_iterator++ ] = compressed_data[ 0 ];

	for( compressed_data_iterator = 1;
	     compressed_data_iterator < compressed_data_size;
	     compressed_data_iterator++ )
	{
		value_16bit |= (uint16_t) compressed_data[ compressed_data_iterator ] << bit_index;

		uncompressed_data[ uncompressed_data_iterator++ ] = (uint8_t) ( value_16bit & 0x7f );

		value_16bit >>= 7;

		bit_index++;

		if( bit_index == 7 )
		{
			uncompressed_data[ uncompressed_data_iterator++ ] = value_16bit & 0x7f;

			value_16bit >>= 7;

			bit_index = 0;
		}
	}
	if( value_16bit != 0 )
	{
		uncompressed_data[ uncompressed_data_iterator++ ] = value_16bit & 0x7f;
	}
	return( 1 );
}

