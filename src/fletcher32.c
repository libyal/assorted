/*
 * Fletcher-32 functions
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
#include "fletcher32.h"

/* Calculates the Fletcher-32 of a buffer
 * Use a previous key of 0 to calculate a new Fletcher-32
 * Returns 1 if successful or -1 on error
 */
int fletcher32_calculate(
     uint32_t *fletcher32,
     const uint8_t *buffer,
     size_t size,
     uint32_t previous_key,
     libcerror_error_t **error )
{
	static char *function = "fletcher32_calculate";
	size_t tsize          = 0;
	uint32_t lower_word   = 0;
	uint32_t upper_word   = 0;

	if( fletcher32 == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid Fletcher-32.",
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
/*
	lower_word = previous_key & 0xffff;
	upper_word = ( previous_key >> 16 ) & 0xffff;
*/

	lower_word = 0xffff;
	upper_word = 0xffff;

        while( size )
	{
		if( size > 360 )
		{
			tsize = 360;
		}
		else
		{
			tsize = size;
		}
		size -= tsize;

                do
		{
			lower_word += *buffer;
			upper_word += lower_word;

			buffer += 1;
		}
		while( --tsize );

                lower_word = ( lower_word & 0xffff ) + ( lower_word >> 16 );
                upper_word = ( upper_word & 0xffff ) + ( upper_word >> 16 );
	}
        /* Second reduction step to reduce sums to 16 bits
	 */
        lower_word = ( lower_word & 0xffff ) + ( lower_word >> 16 );
        upper_word = ( upper_word & 0xffff ) + ( upper_word >> 16 );

	*fletcher32 = ( upper_word << 16 ) | lower_word;

	return( 1 );
}

