/*
 * Bit-stream functions
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
#include <memory.h>
#include <types.h>

#include "assorted_libcerror.h"
#include "bit_stream.h"

/* TODO use memory alignment in bit stream */

/* Creates a bit stream
 * Make sure the value bit_stream is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int bit_stream_initialize(
     bit_stream_t **bit_stream,
     const uint8_t *byte_stream,
     size_t byte_stream_size,
     libcerror_error_t **error )
{
	static char *function = "bit_stream_initialize";

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
	*bit_stream = memory_allocate_structure(
	               bit_stream_t );

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
	     sizeof( bit_stream_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear bit stream.",
		 function );

		goto on_error;
	}
	( *bit_stream )->byte_stream      = byte_stream;
	( *bit_stream )->byte_stream_size = byte_stream_size;
	( *bit_stream )->storage_type     = BIT_STREAM_STORAGE_TYPE_BYTE_BACK_TO_FRONT;

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
int bit_stream_free(
     bit_stream_t **bit_stream,
     libcerror_error_t **error )
{
	static char *function = "bit_stream_free";

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
int bit_stream_read(
     bit_stream_t *bit_stream,
     uint8_t number_of_bits,
     libcerror_error_t **error )
{
	static char *function          = "bit_stream_read";
	uint8_t minimum_number_of_bits = 0;
	int result                     = 0;

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
	if( bit_stream->storage_type == BIT_STREAM_STORAGE_TYPE_16BIT_LITTLE_ENDIAN )
	{
		minimum_number_of_bits = 16;
	}
	else
	{
		minimum_number_of_bits = 8;
	}
	while( bit_stream->bit_buffer_size < number_of_bits )
	{
		if( ( bit_stream->byte_stream_offset >= bit_stream->byte_stream_size )
		 || ( ( minimum_number_of_bits >> 3 ) > ( bit_stream->byte_stream_size - bit_stream->byte_stream_offset ) ) )
		{
			break;
		}
		if( bit_stream->storage_type == BIT_STREAM_STORAGE_TYPE_BYTE_BACK_TO_FRONT )
		{
			bit_stream->bit_buffer      |= (uint32_t) bit_stream->byte_stream[ bit_stream->byte_stream_offset ] << bit_stream->bit_buffer_size;
			bit_stream->bit_buffer_size += 8;

			bit_stream->byte_stream_offset += 1;
		}
		else if( bit_stream->storage_type == BIT_STREAM_STORAGE_TYPE_BYTE_FRONT_TO_BACK )
		{
			bit_stream->bit_buffer     <<= 8;
			bit_stream->bit_buffer      |= bit_stream->byte_stream[ bit_stream->byte_stream_offset ];
			bit_stream->bit_buffer_size += 8;

			bit_stream->byte_stream_offset += 1;
		}
		else if( bit_stream->storage_type == BIT_STREAM_STORAGE_TYPE_16BIT_LITTLE_ENDIAN )
		{
			bit_stream->bit_buffer     <<= 8;
			bit_stream->bit_buffer      |= bit_stream->byte_stream[ bit_stream->byte_stream_offset + 1 ];
			bit_stream->bit_buffer     <<= 8;
			bit_stream->bit_buffer      |= bit_stream->byte_stream[ bit_stream->byte_stream_offset ];
			bit_stream->bit_buffer_size += 16;

			bit_stream->byte_stream_offset += 2;
		}
		result = 1;
	}
	return( result );
}

/* Retrieves a value from the bit stream
 * Returns 1 on success or -1 on error
 */
int bit_stream_get_value(
     bit_stream_t *bit_stream,
     uint8_t number_of_bits,
     uint32_t *value_32bit,
     libcerror_error_t **error )
{
	static char *function             = "bit_stream_get_value";
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
		if( bit_stream_read(
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
		if( bit_stream->storage_type == BIT_STREAM_STORAGE_TYPE_BYTE_BACK_TO_FRONT )
		{
			/* On VS 2008 32-bit "~( 0xfffffffUL << 32 )" does not behave as expected
			 */
			safe_value_32bit &= ~( 0xffffffffUL << number_of_bits );

			bit_stream->bit_buffer     >>= number_of_bits;
			bit_stream->bit_buffer_size -= number_of_bits;
		}
		else if( ( bit_stream->storage_type == BIT_STREAM_STORAGE_TYPE_BYTE_FRONT_TO_BACK )
		      || ( bit_stream->storage_type == BIT_STREAM_STORAGE_TYPE_16BIT_LITTLE_ENDIAN ) )
		{
			safe_value_32bit >>= bit_stream->bit_buffer_size - number_of_bits;

			bit_stream->bit_buffer_size -= number_of_bits;
			remaining_bit_buffer_size    = 32 - bit_stream->bit_buffer_size;
			bit_stream->bit_buffer      &= 0xffffffffUL >> remaining_bit_buffer_size;
		}
	}
	else
	{
		bit_stream->bit_buffer      = 0;
		bit_stream->bit_buffer_size = 0;
	}
	*value_32bit = safe_value_32bit;

	return( 1 );
}

