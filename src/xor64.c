/*
 * XOR-64 functions
 *
 * Copyright (C) 2008-2019, Joachim Metz <joachim.metz@gmail.com>
 *
 * Refer to AUTHORS for acknowledgements.
 *
 * This software is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <common.h>
#include <byte_stream.h>
#include <types.h>

#include "assorted_libcerror.h"
#include "xor64.h"

/* The largest primary (or scalar) available
 * supported by a single load and store instruction
 */
typedef unsigned long int xor64_aligned_t;

/* Calculates the little-endian XOR-64 of a buffer
 * Use a intial value to calculate a new XOR-64
 * Returns 1 if successful or -1 on error
 */
int checksum_calculate_little_endian_xor64_basic(
     uint64_t *checksum_value,
     uint8_t *buffer,
     size_t size,
     uint64_t initial_value,
     libcerror_error_t **error )
{
	static char *function = "checksum_calculate_little_endian_xor64_basic";
	uint64_t value_64bit  = 0;

	if( checksum_value == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid checksum value.",
		 function );

		return( -1 );
	}
	if( buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid buffer.",
		 function );

		return( -1 );
	}
	if( size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid size value exceeds maximum.",
		 function );

		return( -1 );
	}
	*checksum_value = initial_value;

	while( size > 0 )
	{
		value_64bit = 0;

		if( size >= 8 )
		{
			value_64bit  |= buffer[ 7 ];
			value_64bit <<= 8;
			size         -= 1;
		}
		if( size >= 7 )
		{
			value_64bit  |= buffer[ 6 ];
			value_64bit <<= 8;
			size         -= 1;
		}
		if( size >= 6 )
		{
			value_64bit  |= buffer[ 5 ];
			value_64bit <<= 8;
			size         -= 1;
		}
		if( size >= 5 )
		{
			value_64bit  |= buffer[ 4 ];
			value_64bit <<= 8;
			size         -= 1;
		}
		if( size >= 4 )
		{
			value_64bit  |= buffer[ 3 ];
			value_64bit <<= 8;
			size         -= 1;
		}
		if( size >= 3 )
		{
			value_64bit  |= buffer[ 2 ];
			value_64bit <<= 8;
			size         -= 1;
		}
		if( size >= 2 )
		{
			value_64bit  |= buffer[ 1 ];
			value_64bit <<= 8;
			size         -= 1;
		}
		value_64bit |= buffer[ 0 ];
		size        -= 1;

		*checksum_value ^= value_64bit;

		buffer += 4;
	}
	return( 1 );
}

/* Calculates the little-endian XOR-64 of a buffer
 * It uses the initial value to calculate a new XOR-64
 * Returns 1 if successful or -1 on error
 */
int checksum_calculate_little_endian_xor64_cpu_aligned(
     uint64_t *checksum_value,
     const uint8_t *buffer,
     size_t size,
     uint64_t initial_value,
     libcerror_error_t **error )
{
	xor64_aligned_t *aligned_buffer_iterator = NULL;
	uint8_t *buffer_iterator                 = NULL;
	static char *function                    = "checksum_calculate_little_endian_xor64_cpu_aligned";
	xor64_aligned_t value_aligned            = 0;
	uint64_t value_64bit                     = 0;
	uint8_t alignment_count                  = 0;
	uint8_t alignment_size                   = 0;
	uint8_t byte_count                       = 0;
	uint8_t byte_order                       = 0;
	uint8_t byte_size                        = 0;

	if( checksum_value == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid checksum value.",
		 function );

		return( -1 );
	}
	if( buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid buffer.",
		 function );

		return( -1 );
	}
	if( size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid size value exceeds maximum.",
		 function );

		return( -1 );
	}
	*checksum_value = initial_value;

	buffer_iterator = (uint8_t *) buffer;

	/* Only optimize when there is the alignment is a multitude of 64-bit
	 * and for buffers larger than the alignment
	 */
	if( ( ( sizeof( xor64_aligned_t ) % 4 ) == 0 )
	 && ( size > ( 2 * sizeof( xor64_aligned_t ) ) ) )
	{
		/* Align the buffer iterator
		 */
		alignment_size = (uint8_t) ( (intptr_t) buffer_iterator % sizeof( xor64_aligned_t ) );

		byte_size = alignment_size;

		while( byte_size != 0 )
		{
			value_64bit = 0;
			byte_count  = 1;

			if( byte_size >= 4 )
			{
				value_64bit |= buffer_iterator[ 3 ];
				value_64bit <<= 8;

				byte_count++;
			}
			if( byte_size >= 3 )
			{
				value_64bit |= buffer_iterator[ 2 ];
				value_64bit <<= 8;

				byte_count++;
			}
			if( byte_size >= 2 )
			{
				value_64bit |= buffer_iterator[ 1 ];
				value_64bit <<= 8;

				byte_count++;
			}
			value_64bit |= buffer_iterator[ 0 ];

			buffer_iterator += byte_count;
			byte_size       -= byte_count;

			*checksum_value ^= value_64bit;
		}
		aligned_buffer_iterator = (xor64_aligned_t *) buffer_iterator;

		size -= alignment_size;

		if( *buffer_iterator != (uint8_t) ( *aligned_buffer_iterator & 0xff ) )
		{
			byte_order = _BYTE_STREAM_ENDIAN_BIG;
		}
		else
		{
			byte_order = _BYTE_STREAM_ENDIAN_LITTLE;
		}
		/* Determine the aligned XOR value
		 */
		while( size > sizeof( xor64_aligned_t ) )
		{
			value_aligned ^= *aligned_buffer_iterator;

			aligned_buffer_iterator++;

			size -= sizeof( xor64_aligned_t );
		}
		/* Align the aligned XOR value with the 64-bit XOR value
		 */
		if( alignment_size > 0 )
		{
			byte_count      = ( alignment_size % 4 ) * 8;
			alignment_count = ( sizeof( xor64_aligned_t ) - alignment_size ) * 8;

			if( byte_order == _BYTE_STREAM_ENDIAN_BIG )
			{
				/* Shift twice to set unused bytes to 0
				 */
				value_64bit = (uint64_t) ( ( value_aligned >> alignment_count ) << byte_count );

				/* Strip-off the used part of the aligned value
				 */
				value_aligned <<= byte_count;
			}
			else if( byte_order == _BYTE_STREAM_ENDIAN_LITTLE )
			{
				value_64bit = (uint64_t) ( value_aligned << byte_count );

				/* Strip-off the used part of the aligned value
				 */
				value_aligned >>= alignment_count;
			}
			*checksum_value ^= value_64bit;
		}
		/* Update the 64-bit XOR value with the aligned XOR value
		 */
		byte_size = (uint8_t) sizeof( xor64_aligned_t );

		while( byte_size != 0 )
		{
			byte_count = ( ( byte_size / 4 ) - 1 ) * 64;

			if( byte_order == _BYTE_STREAM_ENDIAN_BIG )
			{
				value_64bit = (uint64_t) ( value_aligned >> byte_count );

				/* Change big-endian into little-endian
				 */
				value_64bit = ( ( value_64bit & 0x00ff ) << 24 )
				            | ( ( value_64bit & 0xff00 ) << 8 )
				            | ( ( value_64bit >> 8 ) & 0xff00 )
				            | ( ( value_64bit >> 24 ) & 0x00ff );

				value_aligned <<= byte_count;
			}
			else if( byte_order == _BYTE_STREAM_ENDIAN_LITTLE )
			{
				value_64bit = (uint64_t) value_aligned;

				value_aligned >>= byte_count;
			}
			byte_size -= 4;

			*checksum_value ^= value_64bit;
		}
		/* Re-align the buffer iterator
		 */
		buffer_iterator = (uint8_t *) aligned_buffer_iterator;

		byte_size = 4 - ( alignment_size % 4 );

		if( byte_size != 4 )
		{
			value_64bit   = buffer_iterator[ 0 ];
			value_64bit <<= 8;

			if( byte_size >= 2 )
			{
				value_64bit |= buffer_iterator[ 1 ];
			}
			value_64bit <<= 8;

			if( byte_size >= 3 )
			{
				value_64bit |= buffer_iterator[ 2 ];
			}
			value_64bit <<= 8;

			buffer_iterator += byte_size;
			size            -= byte_size;

			*checksum_value ^= value_64bit;
		}
	}
	while( size > 0 )
	{
		value_64bit = 0;
		byte_count  = 1;

		if( size >= 4 )
		{
			value_64bit |= buffer_iterator[ 3 ];
			value_64bit <<= 8;

			byte_count++;
		}
		if( size >= 3 )
		{
			value_64bit |= buffer_iterator[ 2 ];
			value_64bit <<= 8;

			byte_count++;
		}
		if( size >= 2 )
		{
			value_64bit |= buffer_iterator[ 1 ];
			value_64bit <<= 8;

			byte_count++;
		}
		value_64bit |= buffer_iterator[ 0 ];

		buffer_iterator += byte_count;
		size            -= byte_count;

		*checksum_value ^= value_64bit;
	}
	return( 1 );
}

