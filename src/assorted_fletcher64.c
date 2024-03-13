/*
 * Fletcher-64 functions
 *
 * Copyright (C) 2008-2024, Joachim Metz <joachim.metz@gmail.com>
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
#include <types.h>

#include "assorted_fletcher64.h"
#include "assorted_libcerror.h"

/* Calculates the Fletcher-64 of a buffer of data
 * Use a previous key of 0 to calculate a new Fletcher-64
 * Returns 1 if successful or -1 on error
 */
int assorted_fletcher64_calculate(
     uint64_t *fletcher64,
     const uint8_t *data,
     size_t data_size,
     uint64_t previous_key,
     libcerror_error_t **error )
{
	static char *function = "assorted_fletcher64_calculate";
	size_t data_offset    = 0;
	uint64_t lower_32bit  = 0;
	uint64_t upper_32bit  = 0;
	uint32_t value_32bit  = 0;

	if( fletcher64 == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid Fletcher-64.",
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
	if( ( data_size % 4 ) != 0 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid data size value out of bounds.",
		 function );

		return( -1 );
	}
	lower_32bit = previous_key & 0xffffffffUL;
	upper_32bit = ( previous_key >> 32 ) & 0xffffffffUL;

        for( data_offset = 0;
	     data_offset < data_size;
	     data_offset += 4 )
	{
		byte_stream_copy_to_uint32_little_endian(
		 &( data[ data_offset ] ),
		 value_32bit );

		lower_32bit += value_32bit;
		upper_32bit += lower_32bit;
	}
	lower_32bit %= 0xffffffffUL;
	upper_32bit %= 0xffffffffUL;

	*fletcher64 = ( upper_32bit << 32 ) | lower_32bit;

	return( 1 );
}

