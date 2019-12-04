/*
 * Bit-stream functions
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
#include "bit_stream.h"

/* TODO use memory alignment in bit stream */

/* Retrieves a value from the bit stream
 * Returns 1 on success or -1 on error
 */
int bit_stream_get_value(
     bit_stream_t *bit_stream,
     uint8_t number_of_bits,
     uint32_t *value_32bit,
     libcerror_error_t **error )
{
	static char *function     = "bit_stream_get_value";
	uint32_t safe_value_32bit = 0;

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
	while( bit_stream->bit_buffer_size < number_of_bits )
	{
		if( bit_stream->byte_stream_offset >= bit_stream->byte_stream_size )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
			 "%s: invalid byte stream value to small.",
			 function );

			return( -1 );
		}
		safe_value_32bit   = bit_stream->byte_stream[ bit_stream->byte_stream_offset++ ];
		safe_value_32bit <<= bit_stream->bit_buffer_size;

		bit_stream->bit_buffer      |= safe_value_32bit;
		bit_stream->bit_buffer_size += 8;
	}
	safe_value_32bit = bit_stream->bit_buffer;

	if( number_of_bits < 32 )
	{
		/* On VS 2008 32-bit "~( 0xfffffffUL << 32 )" does not behave as expected
		 */
		safe_value_32bit &= ~( 0xffffffffUL << number_of_bits );

		bit_stream->bit_buffer     >>= number_of_bits;
		bit_stream->bit_buffer_size -= number_of_bits;
	}
	else
	{
		bit_stream->bit_buffer      = 0;
		bit_stream->bit_buffer_size = 0;
	}
	*value_32bit = safe_value_32bit;

	return( 1 );
}

